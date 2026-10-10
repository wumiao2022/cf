#!/usr/bin/env python3
"""VPN Gate 候选节点检测与静态订阅生成。运行一次，不包含定时部署。"""
import base64
import csv
import io
import json
import os
import re
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

import requests

for stream in (sys.stdout, sys.stderr):
    try:
        stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

ROOT = Path(__file__).resolve().parent
VPNGATE_API = os.getenv("VPNGATE_API", "http://www.vpngate.net/api/iphone/")
VPNGATE_MIRROR = os.getenv("VPNGATE_MIRROR", "https://raw.githubusercontent.com/fdciabdul/Vpngate-Scraper-API/main/json/data.json")
WORKER_CHECK_URL = os.getenv("CHECK_WORKER", "https://restless-salad-3df5.wumiao2022.workers.dev/check?sstp=vpn:vpn@")
# 默认沿用原 SSTP 接口。若 Worker 实际使用 proxyip，可设置 CHECK_PARAM=proxyip。
CHECK_PARAM = os.getenv("CHECK_PARAM", "").strip()
CONCURRENCY = max(1, int(os.getenv("CHECK_CONCURRENCY", "32")))
CHECK_TIMEOUT = float(os.getenv("CHECK_TIMEOUT", "90"))
HTTP_TIMEOUT = float(os.getenv("HTTP_TIMEOUT", "60"))
MAX_CHECK_NODES = int(os.getenv("MAX_CHECK_NODES", "0"))
PUBLIC_DIR = Path(os.getenv("PUBLIC_DIR", str(ROOT / "public")))
EDT_UUID = os.getenv("EDT_UUID", "df16df14-e71b-4658-9453-1da5b2239239")
EDT_DOMAIN = os.getenv("EDT_DOMAIN", "empty-dust-5b8d.wumiao2022.workers.dev")
EDT_FINGERPRINT = os.getenv("EDT_FINGERPRINT", "chrome")
CHAIN_URL = os.getenv("CHAIN_URL", "https://jerylihub.github.io/gate/chains.txt")
HOSTS_URL = os.getenv("HOSTS_URL", "https://jerylihub.github.io/gate/hosts.txt")
SUB_URL = os.getenv("SUB_URL", "https://jerylihub.github.io/gate/sub.txt")
EDGE_HOSTS = [s.strip() for s in os.getenv("HOSTS_ENTRY", "").split(",") if s.strip()] or [
    s.strip() for s in os.getenv("EDGE_HOSTS", "www.npmjs.com:443,www.speedtest.net:443,www.wto.org:443,www.meteorelectrical.com:443,www.chess.com:443,cdn.cnno.de:443,saas.sin.fan:443,cf.777791.xyz:443").split(",") if s.strip()
] or [f"{EDT_DOMAIN}:443"]
COUNTRY_ZH = dict(JP="日本", KR="韩国", US="美国", CA="加拿大", RU="俄罗斯", RO="罗马尼亚", TH="泰国", VN="越南", DE="德国", FR="法国", GB="英国", UK="英国", SG="新加坡", TW="台湾", HK="香港", CN="中国", AU="澳大利亚", NL="荷兰", SE="瑞典", CH="瑞士", IT="意大利", ES="西班牙", PL="波兰", IN="印度", BR="巴西", MX="墨西哥", ID="印度尼西亚", MY="马来西亚", PH="菲律宾", TR="土耳其", UA="乌克兰", CZ="捷克", GR="希腊", PT="葡萄牙", FI="芬兰", NO="挪威", DK="丹麦", IE="爱尔兰", BE="比利时", AT="奥地利", HU="匈牙利", AR="阿根廷", CL="智利", CO="哥伦比亚", NZ="新西兰", ZA="南非", IL="以色列", AE="阿联酋", SA="沙特", EG="埃及", HR="克罗地亚", BY="白俄罗斯", GD="格林纳达", LV="拉脱维亚", EE="爱沙尼亚", LT="立陶宛", SK="斯洛伐克", SI="斯洛文尼亚", BG="保加利亚", RS="塞尔维亚", GE="格鲁吉亚", MD="摩尔多瓦", AM="亚美尼亚", KZ="哈萨克斯坦", UZ="乌兹别克斯坦", MN="蒙古", NP="尼泊尔", LK="斯里兰卡", MM="缅甸")
DC_WORDS = "GOOGLE,AMAZON,AWS,MICROSOFT,OVH,HETZNER,DIGITALOCEAN,AKAMAI,CLOUDFLARE,FASTLY,RACKSPACE,EQUINIX,LINODE,VULTR,HURRICANE,TENCENT,ALIBABA,ALIYUN,LEASEWEB".split(",")
HOME_WORDS = "NTT EAST,NTT WEST,KDDI,DOCOMO,SOFTBANK,J:COM,JCOM,OCN,BIGLOBE,AT&T,COMCAST,XFINITY,VERIZON,TELUS,ROGERS,BELL CANADA,VODAFONE,ORANGE,DEUTSCHE TELEKOM,FASTWEB,BT OPEN".split(",")
_section = None


def log(section, message):
    global _section
    if section != _section:
        print(f"========== {section} ==========", flush=True)
        _section = section
    print(message, flush=True)


def die(message):
    log("FATAL", f"[失败] {message}")
    raise SystemExit(1)


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def parse_csv(text):
    lines = [s for s in text.splitlines() if s.strip()]
    start = next((i for i, s in enumerate(lines) if s.lstrip("#").startswith("HostName")), None)
    if start is None:
        raise ValueError("找不到 CSV 表头 HostName")
    reader = csv.DictReader(io.StringIO("\n".join([lines[start].lstrip("#")] + lines[start + 1:])))
    rows = []
    for row in reader:
        row = {str(k).strip().lstrip("*").lower(): v for k, v in row.items() if k is not None}
        host, ip = (row.get("hostname") or "").strip(), (row.get("ip") or "").strip()
        if host and ip:
            rows.append(dict(host=host, ip=ip, country_long=(row.get("countrylong") or "").strip(), country_short=(row.get("countryshort") or "").strip(), config_b64=(row.get("openvpn_configdata_base64") or "").strip()))
    return rows


def parse_mirror(data):
    servers = []
    for item in data if isinstance(data, list) else [data]:
        if isinstance(item, dict):
            servers.extend(item["servers"] if isinstance(item.get("servers"), list) else [item])
    rows = []
    for s in servers:
        if not isinstance(s, dict):
            continue
        host, ip = str(s.get("hostname") or s.get("host") or "").strip(), str(s.get("ip") or "").strip()
        if host and ip:
            rows.append(dict(host=host, ip=ip, country_long=str(s.get("countrylong") or s.get("country_long") or s.get("country") or ""), country_short=str(s.get("countryshort") or s.get("country_short") or ""), config_b64=str(s.get("openvpn_configdata_base64") or s.get("config_b64") or "")))
    return rows


def fetch_nodes():
    for url, parser, source in [(VPNGATE_API, lambda r: parse_csv(r.text), "vpngate.net/api/iphone"), (VPNGATE_MIRROR, lambda r: parse_mirror(r.json()), "github-mirror")]:
        try:
            log("VPN GATE", f"获取数据源: {url}")
            response = requests.get(url, timeout=HTTP_TIMEOUT, headers={"User-Agent": "Mozilla/5.0 (gate-checker)"})
            response.raise_for_status()
            rows = parser(response)
            if not rows:
                raise ValueError("返回 0 个节点")
            return rows, source
        except Exception as exc:
            log("VPN GATE", f"数据源失败: {type(exc).__name__}: {exc}")
    die("官方 API 与镜像均不可用；不覆盖已有输出")


def candidates(rows):
    nodes, seen = [], set()
    for row in rows:
        try:
            cfg = base64.b64decode(row["config_b64"]).decode("utf-8", "replace")
        except Exception:
            continue
        # OpenVPN TCP 只是 SSTP 候选依据，不等于确认支持 SSTP。
        if not re.search(r"^\s*proto\s+tcp(?:4|6)?(?:-client)?\b", cfg, re.M | re.I):
            continue
        host = row["host"].strip()
        if not host.lower().endswith(".opengw.net"):
            host += ".opengw.net"
        for port_text in re.findall(r"^\s*remote\s+\S+\s+(\d+)\b", cfg, re.M | re.I):
            port = int(port_text)
            key = (host.lower(), port, "sstp")
            if 1 <= port <= 65535 and key not in seen:
                seen.add(key)
                nodes.append(dict(host=host, port=port, ip=row["ip"], country=row["country_long"], country_code=row["country_short"].upper()))
    return nodes


def worker_url(node):
    parts = urlsplit(WORKER_CHECK_URL)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ValueError("CHECK_WORKER 必须是完整 HTTP/HTTPS URL")
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    param = CHECK_PARAM or next((k for k, _ in pairs if k in ("sstp", "proxyip")), "sstp")
    if param not in ("sstp", "proxyip"):
        raise ValueError("CHECK_PARAM 仅支持 sstp 或 proxyip")
    address = f"{node['host']}:{node['port']}"
    value = f"vpn:vpn@{address}" if param == "sstp" else address
    # 替换节点参数，保留接口其他参数，避免重复参数或错误的字符串拼接。
    pairs = [(k, v) for k, v in pairs if k not in ("sstp", "proxyip")]
    pairs.append((param, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs), ""))


def classify(exit_info):
    asn = exit_info.get("asn") or {}
    if not isinstance(asn, dict):
        asn = {}
    org = str(asn.get("org") or asn.get("name") or "").upper()
    if exit_info.get("is_datacenter") is True or any(w in org for w in DC_WORDS):
        return "datacenter"
    # 非机房标志不足以单独证明是住宅 IP。
    if any(w in org for w in HOME_WORDS):
        return "residential"
    return "unknown"


def check_one(node):
    out = dict(node, protocol="sstp", link=f"sstp://vpn:vpn@{node['host']}:{node['port']}", success=False, status="failed", checked_at=now(), exit=None, residential="unknown", worker_error=False)
    started = time.monotonic()
    try:
        # 每个任务使用独立请求，避免多线程共享可变 Session 状态。
        response = requests.get(worker_url(node), timeout=CHECK_TIMEOUT, headers={"User-Agent": "Mozilla/5.0 (gate-checker)", "Accept": "application/json"})
        out["http_status"] = response.status_code
        out["content_type"] = response.headers.get("Content-Type", "")
        out["response_excerpt"] = " ".join(response.text[:600].split())
        if response.status_code != 200:
            raise ValueError(f"HTTP {response.status_code}")
        try:
            payload = response.json()
        except ValueError as exc:
            raise ValueError("HTTP 200，但响应不是有效 JSON") from exc
        if not isinstance(payload, dict) or not isinstance(payload.get("success"), bool):
            raise ValueError("Worker 响应必须包含布尔字段 success")
        out["success"] = payload["success"]
        out["status"] = "success" if out["success"] else "failed"
        out["error"] = None if out["success"] else str(payload.get("error") or payload.get("message") or "节点检测失败")
        latency = payload.get("responseTime")
        out["latency_ms"] = latency if isinstance(latency, (int, float)) and not isinstance(latency, bool) else None
        out["colo"] = payload.get("colo")
        info = payload.get("exit")
        if isinstance(info, dict) and info:
            asn = info.get("asn") if isinstance(info.get("asn"), dict) else {}
            out["exit"] = {k: info.get(k) for k in ("ip", "country", "country_code", "city", "continent", "is_datacenter")}
            out["exit"].update(asn=asn.get("asn"), org=asn.get("org") or asn.get("name") or "", type=asn.get("type"))
            out["residential"] = classify(info)
    except Exception as exc:
        out.update(success=False, status="failed", worker_error=True, error=f"{type(exc).__name__}: {exc}")
    out["request_ms"] = round((time.monotonic() - started) * 1000)
    return out


def report_errors(results):
    failed = [r for r in results if not r["success"]]
    for error, count in Counter(r.get("error", "未知错误") for r in failed).most_common(10):
        log("CLOUDFLARE WORKER", f"错误汇总: {count} 个 -> {error}")
    for r in [r for r in failed if r["worker_error"]][:5]:
        log("CLOUDFLARE WORKER", f"异常样本 {r['host']}:{r['port']} -> {r['error']}")
        if r.get("response_excerpt"):
            log("CLOUDFLARE WORKER", f"响应类型: {r.get('content_type')}；内容: {r['response_excerpt']}")
    if failed and all(r["worker_error"] for r in results):
        log("CLOUDFLARE WORKER", "检查 CHECK_WORKER 地址、CHECK_PARAM 参数及 Worker 日志。403/429 常见于访问限制；404 检查路由；5xx 检查服务错误；200 非 JSON 检查是否返回网页。")


def sort_node(node):
    return (node.get("latency_ms") is None, node.get("latency_ms") or 0, node["host"], node["port"])


def build_data(results, raw_count, candidate_count, source):
    available = sorted((r for r in results if r["success"]), key=sort_node)
    countries = {}
    for node in available:
        group = countries.setdefault(node["country"] or "未知", dict(code=node["country_code"] or "?", nodes=[]))
        group["nodes"].append(node)
    for group in countries.values():
        group.update(count=len(group["nodes"]), residential=sum(n["residential"] == "residential" for n in group["nodes"]), datacenter=sum(n["residential"] == "datacenter" for n in group["nodes"]), unknown=sum(n["residential"] == "unknown" for n in group["nodes"]))
    stats = dict(raw_nodes=raw_count, sstp_nodes=candidate_count, checked=len(results), success=len(available), failed=len(results) - len(available), countries=len(countries), residential_est=sum(n["residential"] == "residential" for n in available), datacenter_est=sum(n["residential"] == "datacenter" for n in available))
    return dict(generated_at=now(), source=source, worker=WORKER_CHECK_URL, stats=stats, countries=countries, available=available)


def chain_encode(node):
    plain = json.dumps(dict(type="sstp", username="vpn", password="vpn", hostname=node["host"], port=node["port"]), separators=(",", ":")).encode("utf-8")
    secret = EDT_UUID.encode("utf-8")
    if not secret:
        raise ValueError("EDT_UUID 不能为空")
    return base64.b64encode(bytes(b ^ secret[i % len(secret)] for i, b in enumerate(plain))).decode("ascii")


def text_outputs(data):
    header = f"# 更新时间: {data['generated_at']}\n# 本脚本运行一次；定时更新需由外部 workflow 配置。\n"
    chains = [header + f"# SSTP 链式代理清单: {CHAIN_URL}"]
    hosts = [header + f"# 自定义优选IP清单: {HOSTS_URL}"]
    sub = [header + f"# VLESS 订阅: {SUB_URL}"]
    index = 0
    for country, group in sorted(data["countries"].items(), key=lambda item: (-item[1]["count"], item[0])):
        zh = COUNTRY_ZH.get(group["code"], country)
        ordered = sorted(group["nodes"], key=lambda n: (n["residential"] != "residential", sort_node(n)))
        counts = Counter()
        for i, node in enumerate(ordered, 1):
            category = {"residential": "住宅", "datacenter": "机房", "unknown": "未知"}[node["residential"]]
            counts[category] += 1
            name = f"{zh}-{category}-{counts[category]:02d}"
            chain = f"{name}${node['link']}"
            chains.append(chain)
            hosts.append(f"{EDGE_HOSTS[index % len(EDGE_HOSTS)]}#{chain}")
            index += 1
            path = "/video/" + chain_encode(node)
            query = urlencode(dict(security="tls", type="ws", host=EDT_DOMAIN, fp=EDT_FINGERPRINT, sni=EDT_DOMAIN, path=path, encryption="none", alpn=""), quote_via=quote)
            sub.append(f"vless://{EDT_UUID}@{EDT_DOMAIN}:443?{query}#{quote(f'{zh}-{i:02d}', safe='')}")
    return {"chains.txt": "\n".join(chains) + "\n", "hosts.txt": "\n".join(hosts) + "\n", "sub.txt": "\n".join(sub) + "\n"}


def write_outputs(data):
    files = text_outputs(data)
    files["data.json"] = json.dumps(data, ensure_ascii=False, indent=1)
    template = ROOT / "web" / "index.html"
    files["index.html"] = template.read_text(encoding="utf-8") if template.exists() else """<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>VPN Gate 节点</title><body><h1>VPN Gate 节点统计</h1><pre id="out">加载中</pre><p><a href="chains.txt">链式代理清单</a> · <a href="hosts.txt">优选IP清单</a> · <a href="sub.txt">VLESS订阅</a></p><script>fetch('data.json').then(r=>{if(!r.ok)throw Error(r.status);return r.json()}).then(d=>document.getElementById('out').textContent=JSON.stringify(d.stats,null,2)).catch(e=>document.getElementById('out').textContent='加载失败: '+e)</script></body></html>"""
    PUBLIC_DIR.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        target = PUBLIC_DIR / name
        temporary = target.with_suffix(target.suffix + ".tmp")
        temporary.write_text(content, encoding="utf-8")
        os.replace(temporary, target)
        log("WEBSITE", f"生成 {target}")


def main():
    if CHECK_TIMEOUT <= 0 or HTTP_TIMEOUT <= 0:
        die("超时时间必须大于 0")
    worker_url(dict(host="example.opengw.net", port=443))
    rows, source = fetch_nodes()
    nodes = candidates(rows)
    count = len(nodes)
    log("VPN GATE", f"获取原始节点: {len(rows)}；去重后的 TCP 候选节点: {count}")
    if not nodes:
        die("没有解析出 TCP 候选节点；不覆盖已有输出")
    if MAX_CHECK_NODES > 0:
        nodes = nodes[:MAX_CHECK_NODES]
    log("CLOUDFLARE WORKER", f"检测接口: {WORKER_CHECK_URL}")
    log("CLOUDFLARE WORKER", f"提交检测: {len(nodes)}；并发 {CONCURRENCY}；超时 {CHECK_TIMEOUT}s")
    start = time.monotonic()
    results = []
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        futures = [pool.submit(check_one, n) for n in nodes]
        for future in as_completed(futures):
            results.append(future.result())
            if len(results) % 10 == 0 or len(results) == len(nodes):
                log("CLOUDFLARE WORKER", f"进度 {len(results)}/{len(nodes)}；成功 {sum(r['success'] for r in results)}")
    success = sum(r["success"] for r in results)
    errors = sum(r["worker_error"] for r in results)
    log("CLOUDFLARE WORKER", f"成功 {success}；失败 {len(results) - success}；Worker 异常 {errors}；耗时 {time.monotonic() - start:.1f}s")
    report_errors(results)
    if errors == len(results):
        die("所有请求均出现 HTTP、网络或响应解析异常；不覆盖已有输出")
    # 与原脚本一致：正常 JSON 全部返回 success=false，允许生成空节点清单。
    data = build_data(results, len(rows), count, source)
    write_outputs(data)
    log("RESULT", f"完成：可用节点 {success}；国家数量 {data['stats']['countries']}。GitHub Pages 部署需由外部 workflow 执行。")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:
        die(f"程序异常: {type(exc).__name__}: {exc}")
