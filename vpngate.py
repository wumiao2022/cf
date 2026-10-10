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
