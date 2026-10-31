"""
BigCat server.

A Komari-compatible VPS monitoring server implemented with Flask.
Serves the LuminaPlus theme frontend and exposes the same public API
surface Komari themes expect:

  POST /api/rpc2                      JSON-RPC 2.0 over HTTP (methods below)
  WS   /api/rpc2                      JSON-RPC 2.0 over WebSocket (theme prefers WS)
  GET  /api/nodes                     node list (legacy REST)
  GET  /api/public                    public site settings
  GET  /api/version                   server version
  GET  /api/recent/<uuid>             recent reports of a node
  GET  /api/records/load             history records (uuid, load_type, hours)

  POST /api/agent/register            register a node, returns uuid+token
  POST /api/agent/report              agent metric report (token auth)
  POST /api/agent/basicinfo           agent static info (token auth)
  GET  /api/agent/ping_tasks          ping tasks this node should probe (token auth)

  POST /api/admin/login               admin login
  *    /api/admin/...                 node management (admin auth)

JSON-RPC methods implemented:
  public:getNodesInformation, public:getPublicSettings, public:getVersion,
  public:getMe, public:queryMetrics, public:getClientRecentRecords,
  public:getRecordsByUUID, public:listMetricDefinitions,
  public:getPublicPingTasks, public:getPingMetricStats, public:getPingRecords,
  common:getNodesLatestStatus
"""
import functools
import fnmatch
import json
import math
import os
import re
import secrets
import socket
import base64
import shutil
import sqlite3
import subprocess
import tempfile
import threading
import time
import ipaddress
import urllib.request
import requests
from datetime import date, datetime, timedelta, timezone
from importlib.metadata import version as _pkg_version

from flask import Flask, Response, g, jsonify, request, send_from_directory, session
from flask_cors import CORS

from storage import Storage

def _read_version() -> str:
    # bigcat 版本号唯一来源：server/VERSION 文件，每次修改按 semver 递增
    try:
        with open(
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "VERSION"),
            encoding="utf-8",
        ) as f:
            return f.read().strip() or "unknown"
    except Exception:
        return "unknown"


VERSION = _read_version()
VERSION_HASH = "bigcat"

STATIC_DIR = "static"

# 进程启动时间（用于 /api/admin/about 的运行时长）
STARTED_AT = time.time()

# Komari metric definitions (internal/metricstore)
METRIC_DEFS = {
    "cpu.usage":        {"type": "gauge",   "unit": "%",     "description": "CPU usage percentage"},
    "gpu.usage":        {"type": "gauge",   "unit": "%",     "description": "GPU usage percentage"},
    "memory.used":      {"type": "gauge",   "unit": "bytes", "description": "RAM used"},
    "swap.used":        {"type": "gauge",   "unit": "bytes", "description": "Swap used"},
    "load.average":     {"type": "gauge",   "unit": "",      "description": "System load average"},
    "disk.used":        {"type": "gauge",   "unit": "bytes", "description": "Disk used"},
    "net.in.rate":      {"type": "gauge",   "unit": "bytes/s","description": "Network in rate"},
    "net.out.rate":     {"type": "gauge",   "unit": "bytes/s","description": "Network out rate"},
    "net.total.up":     {"type": "counter", "unit": "bytes", "description": "Network total upload"},
    "net.total.down":   {"type": "counter", "unit": "bytes", "description": "Network total download"},
    "traffic.up":       {"type": "gauge",   "unit": "bytes", "description": "Traffic upload delta"},
    "traffic.down":     {"type": "gauge",   "unit": "bytes", "description": "Traffic download delta"},
    "process.count":    {"type": "gauge",   "unit": "count", "description": "Process count"},
    "connections.tcp":  {"type": "gauge",   "unit": "count", "description": "TCP connections"},
    "connections.udp":  {"type": "gauge",   "unit": "count", "description": "UDP connections"},
    # ping 探测指标（主控侧探测，供主题延迟曲线使用）
    "ping.latency_ms":  {"type": "gauge",   "unit": "ms",   "description": "Ping latency (avg of successful probes)"},
    "ping.loss":        {"type": "gauge",   "unit": "%",    "description": "Ping packet loss ratio"},
}

# ping 指标键集合（queryMetrics 走探测结果表而非 records 表）
PING_METRIC_KEYS = {"ping.latency_ms", "ping.loss"}

# record column -> metric key
RECORD_METRIC_MAP = {
    "cpu": "cpu.usage",
    "gpu": "gpu.usage",
    "ram": "memory.used",
    "swap": "swap.used",
    "load": "load.average",
    "disk": "disk.used",
    "net_in": "net.in.rate",
    "net_out": "net.out.rate",
    "net_total_up": "net.total.up",
    "net_total_down": "net.total.down",
    "traffic_up": "traffic.up",
    "traffic_down": "traffic.down",
    "process": "process.count",
    "connections": "connections.tcp",
    "connections_udp": "connections.udp",
}


# ------------------------------------------------------------ TOTP (2FA, stdlib only)
def _new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode()


def _totp_verify(secret_b32: str, code, window: int = 1) -> bool:
    """Verify a 6-digit TOTP code (RFC 6238, SHA1, 30s step)."""
    import hmac
    import hashlib
    import struct

    try:
        key = base64.b32decode(secret_b32.strip().upper())
    except Exception:
        return False
    want = str(code).strip()
    if not want.isdigit():
        return False
    t = int(time.time()) // 30
    for dt in range(-window, window + 1):
        msg = struct.pack(">Q", t + dt)
        h = hmac.new(key, msg, hashlib.sha1).digest()
        o = h[-1] & 0x0F
        c = struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF
        if str(c % 10 ** 6).zfill(6) == want:
            return True
    return False


def create_app(db_path: str = "data/bigcat.db", static_dir: str = STATIC_DIR,
               enable_monitor: bool = True):
    app = Flask(__name__, static_folder=None)
    app.secret_key = secrets.token_hex(32)
    CORS(app)
    store = Storage(db_path)
    app.config["store"] = store
    app.config["static_dir"] = static_dir

    # ------------------------------------------------------------ themes helpers
    # 前台主题：兼容 Komari 主题包（zip 根目录含 komari-theme.json，内含 dist/）。
    # 上传的主题解压到 <db_dir>/themes/<short>/；"default" 为内置主题（static_dir）。
    import shutil as _shutil
    import zipfile as _zipfile

    THEMES_DIR = os.path.join(os.path.dirname(os.path.abspath(db_path)), "themes")
    os.makedirs(THEMES_DIR, exist_ok=True)
    app.config["themes_dir"] = THEMES_DIR

    _THEME_SHORT_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
    _MAX_THEME_FILES = 10000
    _MAX_THEME_FILE_SIZE = 128 << 20
    _MAX_THEME_TOTAL_SIZE = 512 << 20

    def _theme_manifest(short):
        if not _THEME_SHORT_RE.match(short or ""):
            return None
        p = os.path.join(THEMES_DIR, short, "komari-theme.json")
        try:
            with open(p, encoding="utf-8") as f:
                m = json.load(f)
            if not isinstance(m, dict) or not m.get("name") or not m.get("short"):
                return None
            if m.get("short") != short:
                return None
            return m
        except Exception:
            return None

    def _active_theme_short():
        s = (store.get_setting("active_theme", "default") or "default").strip()
        if s != "default" and _theme_manifest(s):
            return s
        return "default"

    def _active_theme_dist():
        s = _active_theme_short()
        if s != "default":
            d = os.path.join(THEMES_DIR, s, "dist")
            if os.path.isfile(os.path.join(d, "index.html")):
                return d
        return app.config["static_dir"]

    # ------------------------------------------------------------ frontend
    _THEME_JS_PATCH_CACHE = {}  # (theme_short, path, mtime_ns) -> patched bytes | None

    def _patched_theme_js(p):
        """返回打过补丁的主题 JS（bytes）；无需补丁/补丁不适用时返回 None。"""
        dist = _active_theme_dist()
        full = os.path.join(dist, "assets", p)
        try:
            st = os.stat(full)
        except OSError:
            return None
        key = (_active_theme_short(), p, st.st_mtime_ns)
        if key in _THEME_JS_PATCH_CACHE:
            return _THEME_JS_PATCH_CACHE[key]
        try:
            with open(full, "rb") as f:
                text = f.read().decode("utf-8", "ignore")
        except OSError:
            return None
        # chartShared chunk: ping 图表时间选项 m 被硬编码为 p 中 <=168h 的子集；
        # 扩展 p 并放开 m，使 15/30/60/90/180 天可选（后端保留时长兜底过滤）。
        old = "{label:`7 天`,value:168},{label:`30 天`,value:720}],m=p.filter(e=>e.value<=168)"
        new = ("{label:`7 天`,value:168},{label:`15 天`,value:360},"
               "{label:`30 天`,value:720},{label:`60 天`,value:1440},"
               "{label:`90 天`,value:2160},{label:`180 天`,value:4320}],m=p")
        if old not in text:
            _THEME_JS_PATCH_CACHE[key] = None
            return None
        out = text.replace(old, new).encode("utf-8")
        _THEME_JS_PATCH_CACHE[key] = out
        return out

    _INSTANCE_JS_PATCH_CACHE = {}  # (theme_short, path, mtime_ns) -> patched bytes | None

    def _patched_instance_js(p):
        """返回打过补丁的 Instance chunk（bytes）；无需补丁/补丁不适用时返回 None。"""
        dist = _active_theme_dist()
        full = os.path.join(dist, "assets", p)
        try:
            st = os.stat(full)
        except OSError:
            return None
        key = (_active_theme_short(), p, st.st_mtime_ns)
        if key in _INSTANCE_JS_PATCH_CACHE:
            return _INSTANCE_JS_PATCH_CACHE[key]
        try:
            with open(full, "rb") as f:
                text = f.read().decode("utf-8", "ignore")
        except OSError:
            return None
        # Instance chunk: ping 图表断点修复 at() 用 ping 任务间隔（如 30s）作为预期
        # 数据间隔判断断点；长窗口服务端降采样到 500 点（7 天约 20 分钟一点）时，
        # 每个正常间隔都被误判为断点并插入 null，随后降采样把含 null 的桶整体置
        # null，导致 7 天以上曲线空白、Y 轴回退到 [0,100]。改为取任务间隔与实测
        # 中位间隔的最大值，短窗口行为不变，长窗口不再误杀。
        old = "let n=o.get(e),i=typeof n==`number`&&n>0?n:K(t,s);"
        new = "let n=o.get(e),i=Math.max(typeof n==`number`&&n>0?n:0,K(t,s));"
        if old not in text:
            _INSTANCE_JS_PATCH_CACHE[key] = None
            return None
        out = text.replace(old, new).encode("utf-8")
        _INSTANCE_JS_PATCH_CACHE[key] = out
        return out

    def _patched_index_js(p):
        """返回打过补丁的主 bundle（bytes）；无需补丁/补丁不适用时返回 None。

        1. 给服务器卡片包装 div 注入 data-uuid，供拖拽排序脚本识别卡片对应节点。
        2. 流量重置日：trafficReset 优先使用 traffic_reset_day（后台可设每月几号），
           未设置时回退到原逻辑（按 expired_at 到期日）。
        """
        dist = _active_theme_dist()
        full = os.path.join(dist, "assets", p)
        try:
            st = os.stat(full)
        except OSError:
            return None
        key = (_active_theme_short(), p, st.st_mtime_ns)
        if key in _INSTANCE_JS_PATCH_CACHE:
            return _INSTANCE_JS_PATCH_CACHE[key]
        try:
            with open(full, "rb") as f:
                text = f.read().decode("utf-8", "ignore")
        except OSError:
            return None
        old = "(0,F.jsx)(`div`,{className:`min-w-0`,children:"
        new = "(0,F.jsx)(`div`,{className:`min-w-0`,\"data-uuid\":e,children:"
        if old not in text:
            _INSTANCE_JS_PATCH_CACHE[key] = None
            return None
        out = text.replace(old, new)
        # 流量重置日补丁：优先使用后台设置的 traffic_reset_day（1-31）
        old_reset = "trafficReset:Hu(r.expired_at,_)"
        new_reset = (
            "trafficReset:Hu(r.traffic_reset_day>0&&r.traffic_reset_day<32"
            "?\"2000-01-\"+(\"0\"+r.traffic_reset_day).slice(-2):r.expired_at,_)"
        )
        if old_reset in out:
            out = out.replace(old_reset, new_reset)
        # 重置提示文案通用化（显式设置重置日时“默认按到期日”不准确）
        old_title = "流量重置日：${d} · 默认按到期日，每月${r}日重置（不足该日取月末）"
        new_title = "流量重置日：${d} · 每月${r}日重置（不足该日取月末）"
        if old_title in out:
            out = out.replace(old_title, new_title)
        # 品牌字标（与 BigCat B 同款）：站名拆为 🐈 + 名称 + 绿框字母徽章
        old_brand = "{className:`home-brand-title`,title:e,children:e}"
        new_brand = ("{className:`home-brand-title`,title:e,children:(()=>{"
                     "const m=/^(.*)\\s+([A-Za-z0-9])$/.exec(e||\"\");"
                     "if(!m)return e;"
                     "return[(0,F.jsx)(`span`,{className:`bct-cat`,children:`🐈`}),"
                     "(0,F.jsx)(`span`,{children:m[1]+\" \"}),"
                     "(0,F.jsx)(`span`,{className:`bct-badge`,children:m[2]})]})()}")
        if old_brand in out:
            out = out.replace(old_brand, new_brand)
        out = out.encode("utf-8")
        _INSTANCE_JS_PATCH_CACHE[key] = out
        return out

    def _ping_preserve_hours() -> int:
        """ping 记录保留时长（小时），默认 4320 = 180 天；钳制到 [24, 8760]。"""
        try:
            v = int(store.get_setting("ping_record_preserve_time", "4320") or 4320)
        except Exception:
            v = 4320
        return max(24, min(8760, v))

    # 前台首页底部快捷链接：serve-time 注入，与主题无关（换主题不丢失）。
    # 图片链接形式：点击图标新标签页打开 /crypto 实时监控页。
    _CRYPTO_LINK_SNIPPET = (
        '<div id="bigcat-crypto-link" style="text-align:center;padding:16px 12px 20px;'
        'font-size:13px;color:#8b949e;">'
        '<a href="/crypto" target="_blank" rel="noopener" title="加密货币实时监控（BTC / XCRCL 买卖盘）" '
        'style="text-decoration:none;">'
        '<img src="/crypto-icon.png" alt="加密货币监控" '
        'style="width:56px;height:56px;border-radius:14px;'
        'box-shadow:0 2px 10px rgba(0,0,0,0.35);transition:transform .15s ease;cursor:pointer;'
        'display:block;margin:0 auto;" '
        'onmouseover="this.style.transform=\'scale(1.12)\'" '
        'onmouseout="this.style.transform=\'scale(1)\'"/>'
        '<div style="margin-top:8px;color:#58a6ff;">加密货币快捷链接</div>'
        "</a></div>"
    )
    # 前台服务器卡片拖拽排序：serve-time 注入，与主题无关。
    # 依赖 index chunk 补丁给卡片包装 div 注入的 data-uuid。
    # 原理：卡片是 CSS grid 的直接子元素，用 style.order 控制视觉顺序；
    # 拖拽放下后把新顺序 POST 到 /api/public/server_card_order 持久化。
    _CARD_SORT_SNIPPET = (
        '<script id="bigcat-card-sort">(function(){"use strict";'
        'var API="/api/public/server_card_order",savedOrder=[],dragUuid=null,customActive=false;'
        'function load(){fetch(API).then(function(r){return r.json();}).then(function(d){'
        'savedOrder=(d&&d.order)||[];customActive=savedOrder.length>0;apply();}).catch(function(){});}'
        'function save(order){savedOrder=order;'
        'fetch(API,{method:"POST",headers:{"Content-Type":"application/json"},'
        'body:JSON.stringify({order:order})}).catch(function(){});}'
        'function cards(){return Array.prototype.slice.call('
        'document.querySelectorAll(\'div.min-w-0[data-uuid]\'));}'
        'function pos(u){var i=savedOrder.indexOf(u);return i<0?1e9:i;}'
        'function themeSorting(){'
        'var b=document.querySelector("button.home-sort-trigger");'
        'if(!b)return false;'
        'var l=b.getAttribute("aria-label")||"";'
        'return l.indexOf("默认")<0;}'
        'function apply(){var cs=cards();if(!cs.length)return;'
        'if(!customActive||themeSorting()){'
        'cs.forEach(function(el){el.style.order="";});return;}'
        'cs.forEach(function(el){'
        'el.style.order=pos(el.getAttribute("data-uuid"));'
        'el.style.cursor="grab";'
        'if(el.__bcsort)return;el.__bcsort=1;'
        'el.setAttribute("draggable","true");'
        'el.addEventListener("dragstart",function(e){'
        'dragUuid=this.getAttribute("data-uuid");'
        'e.dataTransfer.effectAllowed="move";'
        'try{e.dataTransfer.setData("text/plain",dragUuid);}catch(_){}'
        'this.style.opacity="0.45";});'
        'el.addEventListener("dragover",function(e){'
        'e.preventDefault();e.dataTransfer.dropEffect="move";'
        'if(!dragUuid||this.getAttribute("data-uuid")===dragUuid)return;'
        'var r=this.getBoundingClientRect(),before=(e.clientY-r.top)<r.height/2;'
        'this.__before=before;'
        'this.style.boxShadow=before?"0 -3px 0 0 #3b82f6":"0 3px 0 0 #3b82f6";});'
        'el.addEventListener("dragleave",function(){this.style.boxShadow="";});'
        'el.addEventListener("drop",function(e){'
        'e.preventDefault();this.style.boxShadow="";'
        'if(!dragUuid)return;'
        'var target=this.getAttribute("data-uuid");'
        'if(target===dragUuid)return;'
        'var r=this.getBoundingClientRect();'
        'var before=(e.clientY-r.top)<r.height/2;'
        'var vis=cards().sort(function(a,b){'
        'return parseInt(a.style.order||"1e9",10)-parseInt(b.style.order||"1e9",10);'
        '}).map(function(x){return x.getAttribute("data-uuid");});'
        'var from=vis.indexOf(dragUuid),to=vis.indexOf(target);'
        'if(from<0||to<0)return;'
        'vis.splice(from,1);'
        'var at=before?to:to+1;'
        'if(from<at)at--;'
        'vis.splice(at,0,dragUuid);'
        'var full=savedOrder.slice(),seen={},i,u;'
        'for(i=0;i<full.length;i++)seen[full[i]]=1;'
        'for(i=0;i<vis.length;i++){u=vis[i];if(!seen[u]){seen[u]=1;full.push(u);}}'
        'var vset={};for(i=0;i<vis.length;i++)vset[vis[i]]=1;'
        'var slots=[];for(i=0;i<full.length;i++)if(vset[full[i]])slots.push(i);'
        'slots.sort(function(a,b){return a-b;});'
        'for(i=0;i<slots.length;i++)full[slots[i]]=vis[i];'
        'customActive=true;save(full);apply();});'
        'el.addEventListener("dragend",function(){'
        'this.style.opacity="";dragUuid=null;'
        'cards().forEach(function(x){x.style.boxShadow="";});});'
        '});}'
        'function watchSortBtn(){'
        'var b=document.querySelector("button.home-sort-trigger");'
        'if(!b||b.__bcsortwatch)return;'
        'b.__bcsortwatch=1;'
        'new MutationObserver(function(muts){'
        'for(var i=0;i<muts.length;i++){'
        'if(muts[i].attributeName==="aria-label"){customActive=false;apply();break;}}'
        '}).observe(b,{attributes:true,attributeFilter:["aria-label"]});}'
        'var t=null;'
        'new MutationObserver(function(){'
        'if(t)clearTimeout(t);t=setTimeout(function(){watchSortBtn();apply();},300);'
        '}).observe(document.documentElement,{childList:true,subtree:true});'
        'load();'
        '})();</script>'
    )

    # 前台离线卡片「离线时间」：serve-time 注入。主题用 .is-offline::after 显示
    # 「主机已离线」徽章，本脚本在徽章下方补一行离线时间（= 最后一次上报时间，
    # 数据来自 /api/public/last-report），卡片恢复在线后自动撤除。
    _OFFLINE_SINCE_SNIPPET = (
        '<style>.bct-offline-since{position:absolute;left:50%;top:50%;'
        'transform:translate(-50%,0);margin-top:26px;z-index:6;pointer-events:none;'
        'white-space:nowrap;font-size:12px;font-weight:600;letter-spacing:.5px;'
        'color:var(--status-offline,#e5534b);opacity:.9}'
        '.mini-node-card .bct-offline-since{margin-top:19px;font-size:11px}'
        '.compact-node-card .bct-offline-since{margin-top:22px}</style>'
        '<script id="bigcat-offline-since">(function(){"use strict";'
        'var MAP={},NAMES={},BYNAME={},busy=false;'
        'var SEL=".node-card.is-offline,.compact-node-card.is-offline,.mini-node-card.is-offline,article.is-offline";'
        'function p2(n){return (n<10?"0":"")+n;}'
        'function fmt(ts){var d=new Date(ts);if(isNaN(d.getTime()))return "";'
        'return "\u79bb\u7ebf\u65f6\u95f4\uff1a" + (d.getMonth()+1) + "\u6708" + d.getDate() + "\u65e5 " + p2(d.getHours()) + ":" + p2(d.getMinutes());}'
        'function tsFor(card){'
        'var u=card.querySelector("[data-uuid]");'
        'if(u){var t=MAP[u.getAttribute("data-uuid")];if(t)return t;}'
        'var leaves=card.querySelectorAll("*");'
        'for(var i=0;i<leaves.length;i++){var el=leaves[i];'
        'if(el.children.length===0){var tx=(el.textContent||"").trim();'
        'if(tx&&BYNAME[tx])return BYNAME[tx];}}'
        'return null;}'
        'function apply(){if(busy)return;busy=true;try{'
        'document.querySelectorAll(SEL).forEach(function(card){'
        'var ts=tsFor(card);var el=card.querySelector(".bct-offline-since");'
        'if(!ts){if(el)el.remove();return;}'
        'if(!el){el=document.createElement("div");el.className="bct-offline-since";card.appendChild(el);}'
        'var t=fmt(ts);if(t&&el.textContent!==t)el.textContent=t;});'
        'document.querySelectorAll(".bct-offline-since").forEach(function(el){'
        'var c=el.parentElement;'
        'if(!c||!c.classList.contains("is-offline"))el.remove();});'
        '}finally{busy=false;}}'
        'function load(){fetch("/api/public/last-report").then(function(r){return r.json();})'
        '.then(function(d){if(d&&d.nodes){MAP=d.nodes;NAMES=d.names||{};BYNAME={};'
        'Object.keys(MAP).forEach(function(k){if(NAMES[k])BYNAME[NAMES[k]]=MAP[k];});'
        'apply();}}).catch(function(){});}'
        'new MutationObserver(function(){apply();}).observe(document.documentElement,'
        '{subtree:true,childList:true,attributes:true,attributeFilter:["class"]});'
        'load();setInterval(load,20000);setInterval(apply,30000);'
        '})();</script>'
    )

    _INDEX_PATCH_CACHE = {}  # (theme_short, mtime_ns) -> patched html | None

    def _patched_index_html():
        """返回注入了底部快捷链接的首页 HTML；无需注入/注入不适用时返回 None。"""
        dist = _active_theme_dist()
        full = os.path.join(dist, "index.html")
        try:
            st = os.stat(full)
        except OSError:
            return None
        key = (_active_theme_short(), st.st_mtime_ns)
        if key in _INDEX_PATCH_CACHE:
            return _INDEX_PATCH_CACHE[key]
        try:
            with open(full, encoding="utf-8") as f:
                text = f.read()
        except OSError:
            _INDEX_PATCH_CACHE[key] = None
            return None
        if "</body>" in text and "bigcat-crypto-link" not in text:
            text = text.replace("</body>", _CRYPTO_LINK_SNIPPET + "</body>", 1)
        if "</body>" in text and "bigcat-card-sort" not in text:
            text = text.replace("</body>", _CARD_SORT_SNIPPET + "</body>", 1)
        if "</body>" in text and "bigcat-offline-since" not in text:
            text = text.replace("</body>", _OFFLINE_SINCE_SNIPPET + "</body>", 1)
        _INDEX_PATCH_CACHE[key] = text
        return text

    @app.route("/")
    def index():
        patched = _patched_index_html()
        if patched is not None:
            resp = Response(patched, mimetype="text/html")
            resp.headers["Cache-Control"] = "no-store"
            return resp
        return send_from_directory(_active_theme_dist(), "index.html")

    @app.route("/crypto")
    def crypto_monitor():
        # 加密货币实时监控单页（BTC / XCRCL 买卖盘），与前台主题无关
        return send_from_directory(app.config["static_dir"], "crypto.html")

    @app.route("/crypto-icon.png")
    def crypto_icon():
        # 首页底部快捷链接的图标（与主题无关，存于服务端静态目录）
        return send_from_directory(app.config["static_dir"], "crypto-icon.png")

    @app.route("/assets/<path:p>")
    def assets(p):
        # LuminaPlus 的 ping 图表时间选项在主题 JS 里硬编码上限 7 天：
        # 对其 chartShared chunk 做 serve-time 补丁，扩展为 15/30/60/90/180 天。
        # Instance chunk 的 ping 断点修复 at() 长窗口误判断点导致曲线空白：
        # 做 serve-time 补丁，取任务间隔与实测间隔的最大值。
        # 主题更新导致特征串匹配失败时原样返回，不影响页面。
        bn = os.path.basename(p)
        if bn.startswith("chartShared-") and p.endswith(".js"):
            patched = _patched_theme_js(p)
            if patched is not None:
                return Response(patched, mimetype="application/javascript")
        if bn.startswith("Instance-") and p.endswith(".js"):
            patched = _patched_instance_js(p)
            if patched is not None:
                return Response(patched, mimetype="application/javascript")
        if bn.startswith("index-") and p.endswith(".js"):
            patched = _patched_index_js(p)
            if patched is not None:
                return Response(patched, mimetype="application/javascript")
        # 第三方主题（如 Komari Emerald）包内缺 logo 等静态资源时，
        # 回退到 BigCat 自带静态目录查找，避免图标裂图。
        # 候选位置：主题 dist/assets → 自带 static/assets → 自带 static/images
        for base in (_active_theme_dist() + "/assets",
                     app.config["static_dir"] + "/assets",
                     app.config["static_dir"] + "/images"):
            full = os.path.join(base, p)
            if os.path.isfile(full):
                return send_from_directory(base, p)
        return send_from_directory(_active_theme_dist() + "/assets", p)

    @app.route("/images/<path:p>")
    def images(p):
        return send_from_directory(_active_theme_dist() + "/images", p)

    @app.route("/manifest.json")
    def manifest():
        return send_from_directory(_active_theme_dist(), "manifest.json")

    @app.route("/icon.png")
    def app_icon():
        return send_from_directory(app.config["static_dir"], "icon.png")

    @app.route("/favicon.ico")
    def favicon():
        # 优先用 BigCat T 图标（server/static/icon.png），主题自带 favicon 兜底
        _icon_fp = os.path.join(app.config["static_dir"], "icon.png")
        if os.path.isfile(_icon_fp):
            return send_from_directory(app.config["static_dir"], "icon.png")
        try:
            return send_from_directory(_active_theme_dist(), "favicon.ico")
        except Exception:
            return send_from_directory(
                app.config["static_dir"] + "/images/logo", "linux.svg"
            )

    # bigcat 自带后台管理页：主题里的"后台登录/管理"按钮链向 /admin
    @app.route("/admin")
    @app.route("/admin/<path:_sub>")
    def admin_panel(_sub=None):
        return send_from_directory(
            os.path.dirname(os.path.abspath(__file__)), "admin.html"
        )

    # ------------------------------------------------------------ helpers
    def _public_node(c: dict) -> dict:
        """Node info as seen by guests (mirrors komari publicGetNodesInformation)."""
        out = dict(c)
        for k in ("ipv4", "ipv6", "remark", "version", "token"):
            out.pop(k, None)
        return out

    def _parse_time(v):
        if not v:
            return None
        try:
            s = str(v)
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            return datetime.fromisoformat(s)
        except Exception:
            return None

    def _parse_expiry_date(v):
        """宽松解析到期日期。

        后台到期日是手输文本框，除标准 YYYY-MM-DD 外还兼容
        YYYY/MM/DD、YYYY.MM.DD（含时间后缀），解析失败返回 None
        （调用方跳过该节点，而不是静默丢数）。
        """
        s = (v or "")
        if not isinstance(s, str):
            s = str(s)
        s = s.strip()
        if not s:
            return None
        if s.endswith(("Z", "z")):
            s = s[:-1] + "+00:00"
        try:
            return datetime.fromisoformat(s).date()
        except Exception:
            pass
        m = re.match(r"^(\d{4})[/.](\d{1,2})[/.](\d{1,2})(?:[ T].*)?$", s)
        if m:
            try:
                return date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
            except ValueError:
                return None
        return None

    _TRAFFIC_TZ = timezone(timedelta(hours=8))

    def _traffic_cycle_start(c, now=None):
        """节点当前流量周期的起始日期（date）；未配置周期时返回 None。

        周期日 = traffic_reset_day（1-31），未设置时按到期日期的“号”。
        按东八区计算，与用户在前台看到的“X 天后重置”口径一致；
        周期日超过当月天数时钳到当月最后一天。"""
        import calendar as _cal
        day = c.get("traffic_reset_day") or 0
        if not (1 <= day <= 31):
            exp = _parse_expiry_date(c.get("expired_at"))
            day = exp.day if exp else 0
        if not (1 <= day <= 31):
            return None
        now = now or datetime.now(_TRAFFIC_TZ)
        y, m = now.year, now.month
        if now.day >= min(day, _cal.monthrange(y, m)[1]):
            return date(y, m, min(day, _cal.monthrange(y, m)[1]))
        if m == 1:
            y, m = y - 1, 12
        else:
            m -= 1
        return date(y, m, min(day, _cal.monthrange(y, m)[1]))

    def _iso(dt: datetime) -> str:
        # 入库时间只到秒：查询边界也截断到秒，避免 "…16Z" > "…16.123456Z" 的字符串比较陷阱
        return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    # ============================================================ v3 core
    # 后台监控主循环：离线检测 / 负载告警 / 延迟监测 / 到期提醒 / 流量报告。
    # 取代 v2 只在 agent 上报时搭便车检测的方式（单节点全离线时无上报触发）。
    SESSION_TTL = 30 * 86400

    def _online_threshold() -> int:
        try:
            return max(30, min(3600, int(store.get_setting("offline_threshold", "180") or 180)))
        except Exception:
            return 180

    def _node_online(c: dict, now: datetime) -> bool:
        grace = c.get("offline_grace") or 0
        threshold = grace if grace else _online_threshold()
        t = _parse_time(c.get("last_report_at"))
        if not t:
            return False
        return (now - t).total_seconds() < threshold

    # ---------------- 通知渠道 ----------------
    def _get_channels() -> list:
        try:
            ch = json.loads(store.get_setting("notify_channels", "[]") or "[]")
        except Exception:
            ch = []
        # 兼容 v2 的单 webhook 配置：自动迁移为一个渠道
        legacy_url = (store.get_setting("notify_webhook", "") or "").strip()
        if legacy_url and not any(
            x.get("type") == "webhook" and x.get("config", {}).get("url") == legacy_url
            for x in ch
        ):
            ch.append({
                "name": "默认 Webhook",
                "type": "webhook",
                "enabled": (store.get_setting("notify_enabled", "0") or "0") == "1",
                "config": {"url": legacy_url},
            })
            store.set_setting("notify_channels", json.dumps(ch))
        return ch

    def _save_channels(ch: list):
        store.set_setting("notify_channels", json.dumps(ch))

    def _render_msg(event: str, message: str) -> str:
        tpl = store.get_setting("notify_template", "【{event}】{message}")
        return tpl.replace("{event}", str(event)).replace("{message}", str(message))

    def _send_channel(ch: dict, text: str) -> bool:
        """经单个渠道发送，返回是否成功。"""
        try:
            typ = ch.get("type")
            cfg = ch.get("config", {}) or {}
            if typ == "webhook":
                url = (cfg.get("url") or "").strip()
                if not url:
                    return False
                req = urllib.request.Request(
                    url, data=json.dumps({"text": text}).encode("utf-8"),
                    headers={"Content-Type": "application/json"}, method="POST")
                with urllib.request.urlopen(req, timeout=10) as resp:
                    return 200 <= resp.status < 300
            if typ == "telegram":
                token = (cfg.get("bot_token") or "").strip()
                chat_id = str(cfg.get("chat_id") or "").strip()
                if not token or not chat_id:
                    return False
                api = (cfg.get("api_base") or "https://api.telegram.org/bot").rstrip("/")
                url = f"{api}{token}/sendMessage"
                body = json.dumps({"chat_id": chat_id, "text": text}).encode("utf-8")
                req = urllib.request.Request(
                    url, data=body, headers={"Content-Type": "application/json"},
                    method="POST")
                with urllib.request.urlopen(req, timeout=10) as resp:
                    return 200 <= resp.status < 300
            if typ == "bark":
                key = (cfg.get("key") or "").strip()
                if not key:
                    return False
                server = (cfg.get("server") or "https://api.day.app").rstrip("/")
                url = f"{server}/{key}"
                body = json.dumps({"title": "BigCat", "body": text}).encode("utf-8")
                req = urllib.request.Request(
                    url, data=body, headers={"Content-Type": "application/json"},
                    method="POST")
                with urllib.request.urlopen(req, timeout=10) as resp:
                    return 200 <= resp.status < 300
            return False
        except Exception:
            return False

    def _notify(event: str, message: str):
        """经所有启用的渠道发送通知，并写入事件日志。"""
        text = _render_msg(event, message)
        for ch in _get_channels():
            if ch.get("enabled"):
                threading.Thread(target=_send_channel, args=(ch, text), daemon=True).start()
        try:
            store.log_event("info", "notify", f"[{event}] {message}")
        except Exception:
            pass

    # ---------------- 离线检测 ----------------
    def _offline_check():
        now = datetime.now(timezone.utc)
        try:
            prev = json.loads(store.get_setting("notify_state", "{}") or "{}")
        except Exception:
            prev = {}
        cur, changed = {}, False
        for c in store.list_clients():
            online = _node_online(c, now)
            cur[c["uuid"]] = online
            if c["uuid"] in prev and prev[c["uuid"]] != online:
                name = c.get("name") or c["uuid"][:8]
                if online:
                    _notify("上线", f"节点「{name}」恢复在线")
                    store.log_event("info", "node", f"节点「{name}」恢复在线")
                elif c.get("notify_offline", 1):
                    grace = c.get("offline_grace") or _online_threshold()
                    _notify("离线", f"节点「{name}」离线（超过 {grace} 秒未上报）")
                    store.log_event("warn", "node", f"节点「{name}」离线")
            if prev.get(c["uuid"]) != online:
                changed = True
        if changed:
            store.set_setting("notify_state", json.dumps(cur))

    # ---------------- 负载告警 ----------------
    def _rule_metric_value(metric: str, r: dict) -> float:
        try:
            if metric == "cpu":
                return float(r.get("cpu", 0))
            if metric == "ram":
                return float(r.get("ram", 0)) * 100.0 / float(r.get("ram_total") or 1)
            if metric == "disk":
                return float(r.get("disk", 0)) * 100.0 / float(r.get("disk_total") or 1)
        except Exception:
            pass
        return 0.0

    def _alerts_tick():
        now = datetime.now(timezone.utc)
        for rule in store.list_alert_rules():
            if not rule.get("enabled"):
                continue
            try:
                last_fired = _parse_time(rule.get("last_fired_at"))
                if last_fired and (now - last_fired).total_seconds() < int(rule.get("interval_min", 2)) * 60:
                    continue
            except Exception:
                pass
            try:
                targets = json.loads(rule.get("clients") or "[]") or []
            except Exception:
                targets = []
            if not targets:
                targets = [c["uuid"] for c in store.list_clients()]
            window_start = _iso(now - timedelta(minutes=int(rule.get("interval_min", 2))))
            window_end = _iso(now)
            for uuid in targets:
                rows = store.query_records(uuid, window_start, window_end, limit=10000)
                if not rows:
                    continue
                vals = [_rule_metric_value(rule.get("metric", "cpu"), r) for r in rows]
                ratio = sum(1 for v in vals if v > float(rule.get("threshold", 90))) / len(vals)
                if ratio >= float(rule.get("ratio", 0.8)):
                    c = store.get_client(uuid) or {}
                    name = c.get("name") or uuid[:8]
                    _notify("负载告警",
                            f"{rule.get('name')}：节点「{name}」"
                            f"{rule.get('metric')} {ratio * 100:.0f}% 的时间超过 {rule.get('threshold')}%")
                    store.log_event("warn", "alert",
                                    f"负载告警「{rule.get('name')}」触发：{name}")
                    store.set_rule_fired(rule["id"])
                    break

    # ---------------- 延迟监测 ----------------
    def _do_ping(task: dict):
        target = (task.get("target") or "").strip()
        typ = (task.get("type") or "tcp").lower()
        t0 = time.time()
        try:
            if typ == "tcp":
                host, _, port = target.partition(":")
                port = int(port.strip() or 80)
                s = socket.create_connection((host.strip(), port), timeout=5)
                s.close()
            elif typ == "http":
                url = target if target.startswith("http") else "http://" + target
                req = urllib.request.Request(url, headers={"User-Agent": "BigCat-ping/1.0"})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    resp.read(1024)
            elif typ == "icmp":
                host = target.split(":")[0].split("/")[0].strip()
                out = subprocess.run(["ping", "-c1", "-W2", host],
                                     capture_output=True, text=True, timeout=12)
                m = re.search(r"time[=<]([\d.]+)\s*ms", out.stdout)
                if not m:
                    return 0.0, False
                return float(m.group(1)), True
            else:
                return 0.0, False
            return (time.time() - t0) * 1000.0, True
        except Exception:
            return 0.0, False

    def _ping_tick(next_run: dict):
        now = time.time()
        for task in store.list_ping_tasks():
            if not task.get("enabled"):
                continue
            if now < next_run.get(task["id"], 0):
                continue
            latency, ok = _do_ping(task)
            store.insert_ping_result(task["id"], round(latency, 2), ok)
            next_run[task["id"]] = now + max(30, int(task.get("interval_sec") or 300))
        try:
            store.prune_ping_results(_ping_preserve_hours())
        except Exception:
            pass

    # ---------------- 到期提醒 / 流量报告 ----------------
    def _fmt_bytes(n) -> str:
        n = float(n or 0)
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if n < 1024 or unit == "TB":
                return f"{n:.2f} {unit}"
            n /= 1024
        return f"{n:.2f} TB"

    def _expiry_check():
        if (store.get_setting("expiry_remind_enabled", "1") or "1") != "1":
            return
        try:
            days = int(store.get_setting("expiry_remind_days", "10") or 10)
        except Exception:
            days = 10
        today = datetime.now(timezone.utc).date()
        for c in store.list_clients():
            exp = _parse_expiry_date(c.get("expired_at"))
            if exp is None:
                continue
            delta = (exp - today).days
            if 0 <= delta <= days:
                name = c.get("name") or c["uuid"][:8]
                _notify("到期提醒", f"节点「{name}」还有 {delta} 天到期（{exp.isoformat()}）")
                store.log_event("warn", "expiry", f"节点「{name}」{delta} 天后到期")

    def _traffic_reports_tick():
        today = datetime.now(timezone.utc).date()
        due = {}
        if store.get_setting("last_report_daily") != today.isoformat():
            due["daily"] = (today - timedelta(days=1), today, "日报")
        if today.weekday() == 0 and store.get_setting("last_report_weekly") != today.isoformat():
            due["weekly"] = (today - timedelta(days=7), today, "周报")
        if today.day == 1 and store.get_setting("last_report_monthly") != today.isoformat():
            due["monthly"] = (today - timedelta(days=30), today, "月报")
        if not due:
            return
        now_iso = _iso(datetime.now(timezone.utc))
        for c in store.list_clients():
            if not c.get("report_enabled"):
                continue
            types = [t.strip() for t in (c.get("report_types") or "").split(",") if t.strip()]
            name = c.get("name") or c["uuid"][:8]
            for key, (start_d, end_d, label) in due.items():
                if key not in types:
                    continue
                s = _iso(datetime(start_d.year, start_d.month, start_d.day, tzinfo=timezone.utc))
                t = store.sum_traffic(c["uuid"], s, now_iso)
                _notify("流量报告",
                        f"节点「{name}」{label}：上行 {_fmt_bytes(t['up'])} / "
                        f"下行 {_fmt_bytes(t['down'])}")
        for key in due:
            store.set_setting(f"last_report_{key}", today.isoformat())

    def _daily_tick():
        today = datetime.now(timezone.utc).date().isoformat()
        if store.get_setting("last_daily") == today:
            return
        store.set_setting("last_daily", today)
        try:
            _expiry_check()
        except Exception:
            pass
        try:
            _traffic_reports_tick()
        except Exception:
            pass

    def _monitor_tick(next_run: dict):
        try:
            store.prune_expired_sessions()
        except Exception:
            pass
        try:
            _offline_check()
        except Exception:
            pass
        try:
            _alerts_tick()
        except Exception:
            pass
        try:
            _ping_tick(next_run)
        except Exception:
            pass
        try:
            _daily_tick()
        except Exception:
            pass
        try:
            _domain_tick()
        except Exception:
            pass

    def _monitor_loop():
        next_run = {}
        while True:
            try:
                _monitor_tick(next_run)
            except Exception as e:  # noqa: BLE001
                print(f"[bigcat-monitor] tick failed: {e}")
            time.sleep(30)

    # expose for tests
    app.config["monitor_tick"] = _monitor_tick
    app.config["do_ping"] = _do_ping
    app.config["notify"] = _notify
    # ============ v3 core end ============

    # ==================== 域名 / HTTPS（BigCat T） ====================
    # 后台「域名」页：填域名 → acme.sh（webroot/HTTP-01）签发 Let's Encrypt
    # 证书 → 本进程额外监听 80（验证 + 跳转 HTTPS）与 443（TLS 服务同一
    # Flask 应用）；25774 明文端口保持不变（探针上报不受影响）。证书由
    # 监控线程每日跑 acme.sh --cron 续期，续期后自动重载 443 监听。
    _DOMAIN_DIR = os.path.join(os.path.dirname(os.path.abspath(db_path)), "domain")
    _DOMAIN_WEBROOT = os.path.join(_DOMAIN_DIR, "webroot")
    _DOMAIN_CERT_DIR = os.path.join(_DOMAIN_DIR, "cert")
    _DOMAIN_ACME_HOME = os.path.join(_DOMAIN_DIR, "acme-home")
    _DOMAIN_TOOLS = os.path.join(_DOMAIN_DIR, "tools")
    _DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")
    _domain_lock = threading.Lock()
    _domain_servers = {"http": None, "https": None, "cert_sig": ""}
    _domain_cron_running = {"v": False}
    for _d in (_DOMAIN_WEBROOT, _DOMAIN_CERT_DIR, _DOMAIN_ACME_HOME, _DOMAIN_TOOLS):
        os.makedirs(_d, exist_ok=True)

    def _domain_name():
        return (store.get_setting("domain_name", "") or "").strip().lower()

    def _domain_job_get():
        try:
            return json.loads(store.get_setting("domain_job", "") or "{}")
        except Exception:
            return {}

    def _domain_job_set(**kw):
        job = _domain_job_get()
        job.update(kw)
        job["updated"] = _iso(datetime.now(timezone.utc))
        store.set_setting("domain_job", json.dumps(job, ensure_ascii=False))
        return job

    def _domain_cert_files():
        return (os.path.join(_DOMAIN_CERT_DIR, "fullchain.cer"),
                os.path.join(_DOMAIN_CERT_DIR, "cert.key"))

    def _domain_cert_sig():
        fc, _ = _domain_cert_files()
        try:
            st = os.stat(fc)
            return f"{st.st_mtime:.0f}:{st.st_size}"
        except OSError:
            return ""

    def _domain_cert_expiry():
        fc, _ = _domain_cert_files()
        if not os.path.isfile(fc):
            return None
        try:
            out = subprocess.run(
                ["openssl", "x509", "-enddate", "-noout", "-in", fc],
                capture_output=True, text=True, timeout=10)
            m = re.search(r"notAfter=(.+)", out.stdout or "")
            if m:
                dt = datetime.strptime(m.group(1).strip(), "%b %d %H:%M:%S %Y %Z")
                return dt.replace(tzinfo=timezone.utc).date().isoformat()
        except Exception:
            pass
        return None

    def _domain_http_app(environ, start_response):
        """80 端口小应用：ACME 验证文件 + 全站 301 跳 HTTPS。"""
        path = environ.get("PATH_INFO", "/") or "/"
        if path.startswith("/.well-known/acme-challenge/"):
            name = path.rsplit("/", 1)[-1]
            if re.fullmatch(r"[A-Za-z0-9_-]+", name or ""):
                fp = os.path.join(_DOMAIN_WEBROOT, ".well-known",
                                  "acme-challenge", name)
                if os.path.isfile(fp):
                    with open(fp, "rb") as fh:
                        body = fh.read()
                    start_response("200 OK", [("Content-Type", "text/plain"),
                                              ("Content-Length", str(len(body)))])
                    return [body]
            start_response("404 Not Found", [("Content-Type", "text/plain")])
            return [b"not found"]
        domain = _domain_name()
        if domain:
            qs = environ.get("QUERY_STRING", "")
            loc = f"https://{domain}{path}" + (f"?{qs}" if qs else "")
            start_response("301 Moved Permanently", [("Location", loc)])
            return [b""]
        start_response("404 Not Found", [("Content-Type", "text/plain")])
        return [b"domain not configured"]

    def _domain_start_server(kind):
        from werkzeug.serving import make_server
        with _domain_lock:
            if _domain_servers[kind] is not None:
                return True
            try:
                if kind == "http":
                    srv = make_server("0.0.0.0", 80, _domain_http_app, threaded=True)
                else:
                    import ssl as _ssl
                    fc, key = _domain_cert_files()
                    ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
                    ctx.load_cert_chain(fc, key)
                    srv = make_server("0.0.0.0", 443, app, threaded=True,
                                      ssl_context=ctx)
                    _domain_servers["cert_sig"] = _domain_cert_sig()
                _domain_servers[kind] = srv
            except Exception as e:  # 端口被占/无权限等：记录到 job 状态供后台显示
                _domain_job_set(listen_error=f"{kind}: {e}")
                return False
            th = threading.Thread(target=srv.serve_forever, daemon=True,
                                  name=f"domain-{kind}")
            th.start()
            return True

    def _domain_stop_server(kind):
        with _domain_lock:
            srv = _domain_servers.get(kind)
            _domain_servers[kind] = None
        if srv is not None:
            try:
                srv.shutdown()
            except Exception:
                pass

    def _domain_ensure_servers():
        """按当前配置拉齐 80/443 监听；证书变化时重建 443。"""
        if not _domain_name():
            return
        _domain_start_server("http")
        fc, key = _domain_cert_files()
        if os.path.isfile(fc) and os.path.isfile(key):
            if _domain_servers["https"] is not None and \
                    _domain_servers["cert_sig"] != _domain_cert_sig():
                _domain_stop_server("https")
            _domain_start_server("https")

    def _domain_stop_servers():
        _domain_stop_server("http")
        _domain_stop_server("https")

    def _acme_cmd():
        return os.path.join(_DOMAIN_TOOLS, "acme.sh")

    def _acme_run(args, timeout=300):
        cmd = ["sh", _acme_cmd(), "--home", _DOMAIN_ACME_HOME,
               "--config-home", _DOMAIN_ACME_HOME,
               "--cert-home", os.path.join(_DOMAIN_ACME_HOME, "certs")] + args
        env = dict(os.environ)
        env["HOME"] = _DOMAIN_ACME_HOME
        p = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, env=env)
        tail = ((p.stdout or "") + (p.stderr or "")).strip().splitlines()
        return p.returncode, "\n".join(tail[-15:])

    def _domain_deploy_job(domain):
        try:
            _domain_job_set(state="running", step="准备", message="正在启动 80 端口验证服务…", log="")
            store.set_setting("domain_name", domain)
            _domain_ensure_servers()
            if _domain_servers["http"] is None:
                err = _domain_job_get().get("listen_error", "未知错误")
                _domain_job_set(state="error", step="监听失败",
                                message=f"80 端口监听失败（{err}）。请确认服务以 root 运行且 80 端口未被占用。")
                return
            _domain_job_set(step="检查解析", message="正在检查域名解析…")
            notes = []
            try:
                ips = sorted({ai[4][0] for ai in
                              socket.getaddrinfo(domain, 443, proto=socket.IPPROTO_TCP)})
            except Exception:
                ips = []
            egress = ""
            try:
                egress = requests.get("https://api.ipify.org", timeout=6).text.strip()
            except Exception:
                pass
            if ips and egress and egress not in ips:
                notes.append(f"提醒：域名当前解析到 {', '.join(ips)}，本机公网 IP 为 {egress}，不一致时证书验证会失败")
            elif not ips:
                notes.append("提醒：域名暂时解析不到任何 IP，请确认解析已生效")
            _domain_job_set(step="准备签发工具", message="正在准备证书签发工具…")
            if not os.path.isfile(_acme_cmd()):
                try:
                    r = requests.get(
                        "https://raw.githubusercontent.com/acmesh-official/acme.sh/master/acme.sh",
                        timeout=60)
                    r.raise_for_status()
                    with open(_acme_cmd(), "wb") as fh:
                        fh.write(r.content)
                    os.chmod(_acme_cmd(), 0o755)
                except Exception as e:
                    _domain_job_set(state="error", step="工具下载失败",
                                    message=f"acme.sh 下载失败：{e}")
                    return
            _domain_job_set(step="注册账户", message="正在注册 Let's Encrypt 账户…")
            _acme_run(["--register-account", "-m", f"admin@{domain}",
                       "--server", "letsencrypt"], timeout=120)
            _domain_job_set(step="签发证书",
                            message="正在向 Let's Encrypt 申请证书（需域名已解析到本机且 80 端口可达）…")
            rc, tail = _acme_run(["--issue", "-d", domain, "-w", _DOMAIN_WEBROOT,
                                  "--keylength", "ec-256", "--server", "letsencrypt"],
                                 timeout=420)
            fc, key = _domain_cert_files()
            if rc != 0:
                _domain_job_set(state="error", step="签发失败",
                                message="证书签发失败，请确认域名解析已指向本机、云厂商安全组已放行 80/443 端口后重试。",
                                log=tail)
                return
            _domain_job_set(step="安装证书", message="证书已签发，正在安装并启用 HTTPS…")
            rc, tail = _acme_run(
                ["--install-cert", "-d", domain, "--ecc",
                 "--key-file", key, "--fullchain-file", fc,
                 "--reloadcmd", f"touch {os.path.join(_DOMAIN_CERT_DIR, '.reload')}"],
                timeout=120)
            if rc != 0:
                _domain_job_set(state="error", step="安装失败",
                                message="证书安装失败。", log=tail)
                return
            _domain_ensure_servers()
            ok = False
            try:
                rr = requests.get("https://127.0.0.1:443/api/version",
                                  verify=False, timeout=8)
                ok = rr.status_code == 200
            except Exception:
                pass
            msg = f"部署完成：现在可以用 https://{domain} 访问面板（25774 端口照常可用）。"
            if notes:
                msg += "（" + "；".join(notes) + "）"
            if not ok:
                msg += " 注意：本机自检 443 未通过，可能是云厂商安全组未放行 443，请放行后重试部署。"
            _domain_job_set(state="active", step="完成", message=msg, log=tail)
        except subprocess.TimeoutExpired:
            _domain_job_set(state="error", step="超时", message="签发超时，请稍后重试。")
        except Exception as e:  # noqa: BLE001
            _domain_job_set(state="error", step="异常", message=f"部署异常：{e}")

    def _domain_tick():
        """监控线程调用：证书重载 + 每日续期检查。"""
        try:
            flag = os.path.join(_DOMAIN_CERT_DIR, ".reload")
            if os.path.isfile(flag):
                try:
                    os.remove(flag)
                except OSError:
                    pass
                _domain_stop_server("https")
            _domain_ensure_servers()
        except Exception:
            pass
        try:
            if not _domain_name() or not _domain_cert_sig():
                return
            today = datetime.now(timezone.utc).date().isoformat()
            if store.get_setting("domain_last_cron", "") == today:
                return
            if _domain_cron_running["v"]:
                return
            store.set_setting("domain_last_cron", today)
            _domain_cron_running["v"] = True

            def _renew():
                try:
                    if os.path.isfile(_acme_cmd()):
                        _acme_run(["--cron"], timeout=900)
                except Exception:
                    pass
                finally:
                    _domain_cron_running["v"] = False

            threading.Thread(target=_renew, daemon=True, name="domain-cron").start()
        except Exception:
            pass

    @app.route("/.well-known/acme-challenge/<name>")
    def acme_challenge(name):
        if not re.fullmatch(r"[A-Za-z0-9_-]+", name or ""):
            return Response("not found", status=404)
        fp = os.path.join(_DOMAIN_WEBROOT, ".well-known",
                          "acme-challenge", name)
        if not os.path.isfile(fp):
            return Response("not found", status=404)
        with open(fp, "rb") as fh:
            return Response(fh.read(), content_type="text/plain")



    def _query_series(metric_key, entity_ids, start, end, max_points):
        """Build queryMetrics-style series from the records table.

        在 SQL 侧按时间分桶聚合（query_records_bucketed），保证点数铺满
        整个请求窗口。旧逻辑先 ORDER BY time ASC LIMIT 取最旧一段，
        长窗口（7 天以上）下曲线会挤在开头一小段，看起来像没有数据。
        """
        col = next((c for c, m in RECORD_METRIC_MAP.items() if m == metric_key), None)
        if col is None:
            return []
        span = (end - start).total_seconds()
        if span <= 0 or max_points <= 0:
            return []
        bucket = span / max_points
        start_ts = start.timestamp()
        series = []
        for eid in entity_ids:
            points = store.query_records_bucketed(
                eid, _iso(start), _iso(end), col, start_ts, bucket, max_points)
            total = sum(p["count"] for p in points)
            series.append(
                {
                    "metric_key": metric_key,
                    "entity_id": eid,
                    "type": METRIC_DEFS[metric_key]["type"],
                    "unit": METRIC_DEFS[metric_key]["unit"],
                    "downsampled": total > max_points,
                    "fill_empty": False,
                    "max_points": max_points,
                    "count": len(points),
                    "points": points,
                }
            )
        return series

    def _report_from_record(client_uuid, r: dict) -> dict:
        c = store.get_client(client_uuid) or {}
        return {
            "uuid": client_uuid,
            "cpu": {
                "name": c.get("cpu_name", ""),
                "cores": c.get("cpu_cores", 0),
                "arch": c.get("arch", ""),
                "usage": r.get("cpu", 0),
            },
            "ram": {"total": r.get("ram_total", 0), "used": r.get("ram", 0)},
            "swap": {"total": r.get("swap_total", 0), "used": r.get("swap", 0)},
            "load": {
                "load1": r.get("load", 0),
                "load5": r.get("load", 0),
                "load15": r.get("load", 0),
            },
            "disk": {"total": r.get("disk_total", 0), "used": r.get("disk", 0)},
            "network": {
                "up": r.get("net_out", 0),
                "down": r.get("net_in", 0),
                "totalUp": r.get("net_total_up", 0),
                "totalDown": r.get("net_total_down", 0),
                "monthUp": r.get("net_month_up", 0),
                "monthDown": r.get("net_month_down", 0),
            },
            "connections": {
                "tcp": r.get("connections", 0),
                "udp": r.get("connections_udp", 0),
            },
            "uptime": r.get("uptime", 0),
            "process": r.get("process", 0),
            "message": "",
            "updated_at": r.get("time", ""),
        }

    # ------------------------------------------------------------ JSON-RPC
    def rpc_get_nodes_information(params):
        clients = store.list_clients()
        return [_public_node(c) for c in clients if not c.get("hidden")]

    def rpc_get_public_settings(params):
        out = store.get_public_settings()
        # Komari 兼容：theme 为当前主题 short，附带该主题的公开设置
        active = _active_theme_short()
        out["theme"] = active
        out["theme_settings"] = store.get_theme_settings(active)
        return out

    def rpc_get_version(params):
        return {"version": VERSION, "hash": VERSION_HASH}

    def rpc_get_me(params):
        if _admin_logged_in():
            return {"username": store.get_admin_username(), "logged_in": True, "uuid": ""}
        return {"username": "Guest", "logged_in": False, "uuid": ""}

    def rpc_list_metric_definitions(params):
        return [
            {"name": k, "type": v["type"], "unit": v["unit"],
             "description": v["description"], "retention_days": 1}
            for k, v in METRIC_DEFS.items()
        ]

    def rpc_query_metrics(params):
        params = params or {}
        keys = params.get("metric_keys") or params.get("metrics") or []
        if params.get("metric_key"):
            keys = [params["metric_key"]] + keys
        if not keys:
            raise ValueError("metric_keys is required")
        entity_ids = params.get("entity_ids") or []
        if params.get("entity_id"):
            entity_ids = [params["entity_id"]] + entity_ids
        if not entity_ids:
            entity_ids = [c["uuid"] for c in rpc_get_nodes_information({})]

        now = datetime.now(timezone.utc)
        end = _parse_time(params.get("end") or params.get("end_time")) or now
        start = _parse_time(params.get("start") or params.get("start_time"))
        if start is None:
            hours = float(params.get("hours") or 4)
            start = end - timedelta(hours=hours)
        max_points = int(params.get("max_points") or 500)
        task_id = params.get("task_id") or (params.get("tags") or {}).get("task_id")

        series = []
        for key in keys:
            if key not in METRIC_DEFS:
                raise ValueError(f"unknown metric key: {key}")
            if key in PING_METRIC_KEYS:
                series.extend(_ping_series(key, entity_ids, start, end, max_points, task_id))
            else:
                series.extend(_query_series(key, entity_ids, start, end, max_points))
        # 数据未覆盖整个请求窗口时（如任务新建不久、数据只有最近几天），
        # 把 start 收敛到实际数据起点。主题用 start/end 定图表 x 轴范围，
        # 否则长窗口下曲线会被挤到最右侧很窄一段，看起来像“没有数据显示”。
        try:
            data_min_ts = None
            for s in series:
                for p in s.get("points") or []:
                    t = _parse_time(p.get("time"))
                    if t is None:
                        continue
                    ts = t.timestamp()
                    if data_min_ts is None or ts < data_min_ts:
                        data_min_ts = ts
            if data_min_ts is not None:
                start_ts = start.timestamp()
                end_ts = end.timestamp()
                bucket_s = max(1.0, end_ts - start_ts) / max(1, max_points)
                if data_min_ts > start_ts + bucket_s and data_min_ts < end_ts - 60:
                    start = datetime.fromtimestamp(data_min_ts, tz=timezone.utc)
        except Exception:
            pass
        return {
            "start": _iso(start),
            "end": _iso(end),
            "server_downsample_default": True,
            "default_points": 500,
            "series": series,
            "count": len(series),
        }

    def rpc_get_client_recent_records(params):
        params = params or {}
        client_uuid = params.get("uuid") or params.get("entity_id") or ""
        if not client_uuid:
            raise ValueError("UUID is required")
        rows = store.query_records(
            client_uuid,
            _iso(datetime.now(timezone.utc) - timedelta(minutes=10)),
            _iso(datetime.now(timezone.utc)),
            limit=600,
        )
        # Komari 扁平格式 {count, records}（第三方主题按此消费；
        # LuminaPlus 未使用本接口，可安全改为扁平）。
        records = []
        for r in rows:
            try:
                conns = int(r.get("connections", 0) or 0)
            except (ValueError, TypeError):
                # 兼容老数据里 connections 存 JSON 字符串的情况
                try:
                    conns = int(json.loads(r.get("connections") or "{}")
                                .get("tcp", 0))
                except Exception:
                    conns = 0
            records.append({
                "client": client_uuid,
                "time": r.get("time", ""),
                "cpu": r.get("cpu", 0) or 0,
                "gpu": r.get("gpu", 0) or 0,
                "ram": r.get("ram", 0) or 0,
                "ram_total": r.get("ram_total", 0) or 0,
                "swap": r.get("swap", 0) or 0,
                "swap_total": r.get("swap_total", 0) or 0,
                "load": r.get("load", 0) or 0,
                "temp": r.get("temp", 0) or 0,
                "disk": r.get("disk", 0) or 0,
                "disk_total": r.get("disk_total", 0) or 0,
                "net_in": r.get("net_in", 0) or 0,
                "net_out": r.get("net_out", 0) or 0,
                "net_total_up": r.get("net_total_up", 0) or 0,
                "net_total_down": r.get("net_total_down", 0) or 0,
                "process": r.get("process", 0) or 0,
                "connections": conns,
                "connections_udp": r.get("connections_udp", 0) or 0,
                "uptime": r.get("uptime", 0) or 0,
            })
        return {"count": len(records), "records": records}

    def rpc_common_get_records(params):
        """common:getRecords — Komari 兼容。

        type=ping 时返回 {count, records: [{task_id,time,value,client}],
        tasks: [{id,name}], from, to}（value>=0 为延迟 ms，-1 为丢包）；
        type=load 或带 uuid 时走原有按节点查负载记录逻辑。
        """
        params = params or {}
        rtype = (params.get("type") or "").strip().lower()
        if rtype == "ping":
            hours = params.get("hours") or 1
            try:
                hours = max(1, int(hours))
            except (ValueError, TypeError):
                hours = 1
            uuid = params.get("uuid") or ""
            task_id = params.get("task_id", -1)
            try:
                task_id = int(task_id)
            except (ValueError, TypeError):
                task_id = -1
            max_count = params.get("maxCount", 4000)
            try:
                max_count = int(max_count)
            except (ValueError, TypeError):
                max_count = 4000
            if max_count <= 0:
                max_count = 4000
            now = datetime.now(timezone.utc)
            since = _iso(now - timedelta(hours=hours))
            until = _iso(now)
            hidden_uuids = {c["uuid"] for c in store.list_clients()
                            if c.get("hidden")}
            rows = store.query_ping_records(since, until, uuid, task_id,
                                            limit=max_count)
            records = [{"task_id": tid, "time": t, "value": v, "client": cu}
                       for cu, tid, t, v in rows if cu not in hidden_uuids]
            tasks = [{"id": t["id"], "name": t["name"]}
                     for t in store.list_ping_tasks() if t.get("enabled")]
            return {"count": len(records), "records": records,
                    "tasks": tasks, "from": since, "to": until}
        # load 类型：沿用原有逻辑（uuid 必填）
        return rpc_get_records_by_uuid(params)

    def rpc_get_records_by_uuid(params):
        params = params or {}
        client_uuid = params.get("uuid", "")
        if not client_uuid:
            raise ValueError("UUID is required")
        hours = float(params.get("hours") or 4)
        now = datetime.now(timezone.utc)
        rows = store.query_records(
            client_uuid, _iso(now - timedelta(hours=hours)), _iso(now), limit=2000
        )
        # legacy Record shape
        return [
            {
                "client": r["client"],
                "time": r["time"],
                "cpu": r["cpu"],
                "ram": r["ram"],
                "ram_total": r["ram_total"],
                "swap": r["swap"],
                "swap_total": r["swap_total"],
                "load": r["load"],
                "disk": r["disk"],
                "disk_total": r["disk_total"],
                "net_in": r["net_in"],
                "net_out": r["net_out"],
                "net_total_up": r["net_total_up"],
                "net_total_down": r["net_total_down"],
                "process": r["process"],
                "connections": r["connections"],
                "connections_udp": r["connections_udp"],
            }
            for r in rows
        ]

    def _public_ping_task(t):
        """Komari 形状的延迟任务（含 clients 绑定，供主题三网延迟/探测点绑定使用）。"""
        return {
            "id": t.get("id"),
            "name": t.get("name"),
            "target": t.get("target"),
            "type": t.get("type"),
            "interval": int(t.get("interval_sec") or 60),
            "interval_sec": int(t.get("interval_sec") or 60),
            "enabled": bool(t.get("enabled")),
            "clients": store.get_ping_task_clients(t.get("id")),
        }

    def rpc_get_public_ping_tasks(params):
        # Komari 形状的公开延迟任务列表（主题 ping 功能用 id/name/target/type/interval/clients）
        return [_public_ping_task(t) for t in store.list_ping_tasks()]

    def _ping_task_nodes(task, clients):
        """探测任务归属的节点。

        Komari 语义（与 /api/agent/ping_tasks 下发一致）：任务绑定了 clients 时，
        仅归属被绑定的节点；未绑定时为全局任务，归属所有候选节点（各节点分别探测）。
        """
        bound = store.get_ping_task_clients(task.get("id"))
        by_uuid = {c.get("uuid"): c for c in clients}
        if bound:
            return [by_uuid[u] for u in bound if u in by_uuid]
        return list(clients)

    def _auto_bind_ping_tasks(client_uuid: str) -> None:
        """新节点默认加入所有启用的 ping 探测任务，无需手动绑定。

        管理员仍可在后台 ping 任务中手动解绑某个节点。
        """
        try:
            for t in store.list_ping_tasks():
                if not t.get("enabled"):
                    continue
                bound = store.get_ping_task_clients(t.get("id"))
                if client_uuid not in bound:
                    store.set_ping_task_clients(t.get("id"), bound + [client_uuid])
        except Exception:
            pass

    def _ping_rows_for_node(task_id, node_uuid, since_iso, end_iso=None, limit=500):
        """某节点某任务的探测行（v1.9.4 分布式探测）。

        优先取该节点 agent 自行上报的行（client_uuid=节点 uuid）；
        该节点在整个窗口内无上报时回退到主控侧探测行（client_uuid=''），
        兼容未升级的 agent。
        v1.11.10 起在 SQL 侧按 client_uuid 过滤：数据量超过 limit 时均匀
        抽样覆盖整个窗口。修复旧实现"先按 task LIMIT 再在 Python 按节点
        过滤"的 bug——多节点混合写入时 limit 在混合数据上生效，长窗口下
        每个节点只剩最近约 1.5 天的数据。
        返回按时间升序（调用方依赖）。
        """
        cli = node_uuid or ""
        rows = store.ping_results_for_client(task_id, cli, since_iso, end_iso,
                                             limit=limit)
        if cli and not rows:
            rows = store.ping_results_for_client(task_id, "", since_iso, end_iso,
                                                 limit=limit)
        rows.sort(key=lambda r: r.get("time") or "")
        return rows

    def _pct(sorted_vals, p):
        """已排序序列的百分位数（线性插值）。"""
        if not sorted_vals:
            return None
        if len(sorted_vals) == 1:
            return float(sorted_vals[0])
        k = (len(sorted_vals) - 1) * p / 100.0
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            return float(sorted_vals[int(k)])
        return float(sorted_vals[f] + (sorted_vals[c] - sorted_vals[f]) * (k - f))

    def _ping_series(metric_key, entity_ids, start, end, max_points, task_id=None):
        """为 queryMetrics 构造 ping.latency_ms / ping.loss 曲线序列。

        按 (任务, 节点) 输出 series：entity_id=节点 uuid，tags.task_id=任务 id，
        points 按时间分桶聚合（latency 取成功样本均值，无成功样本记 -1；
        loss 记丢包百分比）。"""
        tasks = store.list_ping_tasks()
        if task_id not in (None, ""):
            tasks = [t for t in tasks if str(t.get("id")) == str(task_id)]
        clients = store.list_clients()
        if entity_ids:
            wanted = set(entity_ids)
            clients = [c for c in clients if c.get("uuid") in wanted]
        else:
            clients = [c for c in clients if not c.get("hidden")]
        span = (end - start).total_seconds()
        if span <= 0 or max_points <= 0:
            return []
        bucket = span / max_points
        start_ts = start.timestamp()
        end_iso = _iso(end)
        # 长时间跨度需要更多原始点：按最小 30s 探测间隔估算行数
        row_limit = max(200000, int(span / 30) + 1000)
        series = []
        for t in tasks:
            nodes = _ping_task_nodes(t, clients)
            if not nodes:
                continue
            for n in nodes:
                # v1.9.4：每个节点用自己的探测数据（agent 上报优先，主控探测回退）
                rows = _ping_rows_for_node(t.get("id"), n.get("uuid"),
                                            _iso(start), end_iso, row_limit)
                if not rows:
                    continue
                buckets = {}  # idx -> [total, ok_count, latency_sum]
                for r in rows:
                    ts = _parse_time(r.get("time")).timestamp()
                    idx = int((ts - start_ts) / bucket)
                    idx = max(0, min(max_points - 1, idx))
                    b = buckets.setdefault(idx, [0, 0, 0.0])
                    b[0] += 1
                    lat = r.get("latency_ms")
                    if r.get("ok") and lat is not None:
                        b[1] += 1
                        b[2] += float(lat)
                points = []
                for idx in sorted(buckets):
                    total, okc, latsum = buckets[idx]
                    bt = _iso(start + timedelta(seconds=idx * bucket))
                    if metric_key == "ping.latency_ms":
                        value = round(latsum / okc, 2) if okc else -1
                    else:  # ping.loss
                        value = round((total - okc) / total * 100, 2) if total else 0.0
                    points.append({"time": bt, "value": value, "count": total})
                if not points:
                    continue
                series.append({
                    "metric_key": metric_key,
                    "entity_id": n.get("uuid"),
                    "tags": {"task_id": str(t.get("id"))},
                    "type": METRIC_DEFS[metric_key]["type"],
                    "unit": METRIC_DEFS[metric_key]["unit"],
                    "interval_seconds": int(t.get("interval_sec") or 60),
                    "downsampled": False,
                    "fill_empty": False,
                    "max_points": max_points,
                    "count": len(points),
                    "points": [dict(p) for p in points],
                })
        return series

    def _ping_records_payload(uuid="", task_id="", hours="4"):
        """Komari 形状的延迟记录：{count, records[{task_id,time,value,client}], tasks}。
        v1.9.4 起为分布式探测：每条记录归属实际执行探测的节点（agent 上报优先，
        未上报的节点回退到主控探测数据）；uuid 查询时返回该节点应探测的任务
        （绑定到该节点的，或未绑定的全局任务），没有则返回空。"""
        try:
            h = max(1, min(_ping_preserve_hours(), int(hours)))
        except (TypeError, ValueError):
            h = 4
        since = (datetime.now(timezone.utc) - timedelta(hours=h)).isoformat()
        tasks = store.list_ping_tasks()
        if task_id:
            try:
                tid = int(task_id)
            except (TypeError, ValueError):
                return {"count": 0, "records": [], "tasks": []}
            tasks = [t for t in tasks if t.get("id") == tid]
        if uuid:
            node = next((c for c in store.list_clients() if c.get("uuid") == uuid), None)
            if node is None:
                tasks = []
            else:
                # 与 _ping_task_nodes 一致：绑定任务仅归属被绑定节点，
                # 未绑定任务为全局任务，归属所有节点
                keep = []
                for t in tasks:
                    bound = store.get_ping_task_clients(t.get("id"))
                    if not bound or uuid in bound:
                        keep.append(t)
                tasks = keep
        records = []
        all_clients = store.list_clients()
        for t in tasks:
            # uuid 查询时 client 直接用所查节点，保证主题按节点归并统计正确
            if uuid:
                node_uuids = [uuid]
            else:
                nodes = _ping_task_nodes(t, all_clients)
                node_uuids = [nodes[0].get("uuid")] if nodes else [""]
            for node_uuid in node_uuids:
                # v1.9.4：该节点的 agent 上报优先，无上报时回退主控探测数据
                rows = _ping_rows_for_node(t.get("id"), node_uuid, since, limit=20000)
                # 长窗口降采样：在已取到的时间范围均匀取至多 2000 点，
                # 避免数据量大时曲线只覆盖窗口一小段。
                if len(rows) > 2000:
                    step = len(rows) / 2000
                    rows = [rows[int(i * step)] for i in range(2000)]
                for r in rows:
                    ok = bool(r.get("ok"))
                    lat = r.get("latency_ms")
                    records.append({
                        "task_id": t.get("id"),
                        "time": r.get("time"),
                        "value": int(round(lat)) if (ok and lat is not None) else -1,
                        "client": node_uuid,
                    })
        records.sort(key=lambda r: r.get("time") or "")
        return {
            "count": len(records),
            "records": records,
            "tasks": [{"id": t.get("id"), "name": t.get("name"),
                       "target": t.get("target"), "type": t.get("type"),
                       "interval": int(t.get("interval_sec") or 60)} for t in tasks],
        }

    def rpc_get_ping_metric_stats(params):
        """Komari 形状的延迟统计：按 (任务, 节点) 返回 total/valid/loss/min/max/
        avg/latest/p50/p99/stddev，供主题延迟曲线与统计表使用。"""
        now = datetime.now(timezone.utc)
        params = params or {}
        hours = float(params.get("hours") or 4)
        start = _parse_time(params.get("start") or params.get("start_time")) or (now - timedelta(hours=hours))
        end = _parse_time(params.get("end") or params.get("end_time")) or now
        entity_ids = params.get("entity_ids") or []
        if params.get("entity_id"):
            entity_ids = [params["entity_id"]] + entity_ids
        task_id = params.get("task_id") or (params.get("tags") or {}).get("task_id")
        tasks = store.list_ping_tasks()
        if task_id not in (None, ""):
            tasks = [t for t in tasks if str(t.get("id")) == str(task_id)]
        clients = store.list_clients()
        if entity_ids:
            wanted = set(entity_ids)
            clients = [c for c in clients if c.get("uuid") in wanted]
        else:
            clients = [c for c in clients if not c.get("hidden")]
        end_iso = _iso(end)
        span_s = max(1.0, (end - start).total_seconds())
        row_limit = max(200000, int(span_s / 30) + 1000)
        stats = []
        for t in tasks:
            nodes = _ping_task_nodes(t, clients)
            if not nodes:
                continue
            for n in nodes:
                # v1.9.4：每个节点用自己的探测数据（agent 上报优先，主控探测回退）
                rows = _ping_rows_for_node(t.get("id"), n.get("uuid"),
                                            _iso(start), end_iso, row_limit)
                total = len(rows)
                oks = [float(r["latency_ms"]) for r in rows
                       if r.get("ok") and r.get("latency_ms") is not None]
                valid = len(oks)
                loss = round((total - valid) / total * 100, 2) if total else 0.0
                if oks:
                    srt = sorted(oks)
                    avg = sum(oks) / valid
                    p50 = _pct(srt, 50)
                    p99 = _pct(srt, 99)
                    var = sum((x - avg) ** 2 for x in oks) / valid
                    entry_stats = {
                        "min": round(srt[0], 2), "max": round(srt[-1], 2),
                        "avg": round(avg, 2), "latest": round(oks[-1], 2),
                        "p50": round(p50, 2), "p99": round(p99, 2),
                        "stddev": round(math.sqrt(var), 2),
                        "p99_p50_ratio": round(p99 / p50, 4) if p50 else None,
                    }
                else:
                    entry_stats = {
                        "min": None, "max": None, "avg": None, "latest": None,
                        "p50": None, "p99": None, "stddev": None,
                        "p99_p50_ratio": None,
                    }
                stats.append({
                    "task_id": t.get("id"),
                    "entity_id": n.get("uuid"),
                    "name": t.get("name"),
                    "type": t.get("type"),
                    "interval": int(t.get("interval_sec") or 60),
                    "total": total,
                    "valid": valid,
                    "loss": loss,
                    **entry_stats,
                })
        return {"start": _iso(start), "end": _iso(end), "stats": stats, "count": len(stats)}

    def rpc_get_ping_records(params):
        return _ping_records_payload(
            uuid=str(params.get("uuid", "") or ""),
            task_id=str(params.get("task_id", "") or ""),
            hours=str(params.get("hours", "4") or "4"),
        )

    def rpc_get_nodes_latest_status(params):
        """common:getNodesLatestStatus — Komari 兼容扁平格式。

        返回 {uuid: record}，record 为 Komari recordLike 扁平结构
        （cpu/ram/net_in 等为数字，而非嵌套对象），第三方 Komari 主题
        （如 Emerald）直接消费；BigCat 自带主题做过 Object.values 兼容。
        另附 ping 字段（各任务延迟统计，供主题三网延迟展示）。
        """
        params = params or {}
        uuids = params.get("uuids") or []
        if uuids:
            clients = [store.get_client(u) for u in uuids]
            clients = [c for c in clients if c]
        else:
            clients = store.list_clients()
        # ping 统计（最近 1 小时）
        try:
            ping_map = store.node_ping_stats(
                _iso(datetime.now(timezone.utc) - timedelta(hours=1)))
        except Exception:
            ping_map = {}
        out = {}
        for c in clients:
            if c.get("hidden"):
                continue
            r = store.latest_record(c["uuid"])
            if not r:
                continue
            # Komari 扁平格式
            out[c["uuid"]] = {
                "client": c["uuid"],
                "time": r.get("time", ""),
                "cpu": r.get("cpu", 0) or 0,
                "gpu": r.get("gpu", 0) or 0,
                "ram": r.get("ram", 0) or 0,
                "ram_total": r.get("ram_total", 0) or 0,
                "swap": r.get("swap", 0) or 0,
                "swap_total": r.get("swap_total", 0) or 0,
                "load": r.get("load", 0) or 0,
                "load5": r.get("load", 0) or 0,
                "load15": r.get("load", 0) or 0,
                "disk": r.get("disk", 0) or 0,
                "disk_total": r.get("disk_total", 0) or 0,
                "net_in": r.get("net_in", 0) or 0,
                "net_out": r.get("net_out", 0) or 0,
                "net_total_up": r.get("net_total_up", 0) or 0,
                "net_total_down": r.get("net_total_down", 0) or 0,
                "process": r.get("process", 0) or 0,
                "connections": r.get("connections", 0) or 0,
                "connections_udp": r.get("connections_udp", 0) or 0,
                "uptime": r.get("uptime", 0) or 0,
                "online": bool(_is_online(c)),
                "ping": ping_map.get(c["uuid"], {}),
            }
        return out

    def rpc_ping(params):
        return "pong"

    def _komari_billing_days(v) -> int:
        """BigCat 计费周期字符串 → Komari 天数（int）。"""
        s = str(v or "").strip().lower()
        mapping = {
            "monthly": 30, "month": 30,
            "quarterly": 90, "quarter": 90,
            "semiannually": 180, "half-year": 180,
            "yearly": 365, "annually": 365, "annual": 365, "year": 365,
            "biennially": 730,
            "long-term": 36500, "lifetime": 36500,  # 长期/买断按 100 年计
        }
        if s in mapping:
            return mapping[s]
        try:
            return max(0, int(float(s)))
        except (ValueError, TypeError):
            return 0

    def _komari_expired_at(v) -> str:
        """到期日统一为 YYYY-MM-DD（Komari 用 new Date() 解析）。"""
        s = str(v or "").strip()
        if not s:
            return ""
        # 兼容 2026.10.18 / 2026/10/18
        m = re.match(r"^(\d{4})[./](\d{1,2})[./](\d{1,2})$", s)
        if m:
            return f"{m.group(1)}-{m.group(2).zfill(2)}-{m.group(3).zfill(2)}"
        return s

    def rpc_common_get_nodes(params):
        """common:getNodes — Komari 兼容格式：返回以 uuid 为键的字典。

        BigCat 自带主题调用后会做 Object.values() 转列表，
        第三方 Komari 主题（如 Emerald）直接按字典消费。
        另做 Komari 兼容归一化：billing_cycle 转天数、expired_at 转 ISO。
        """
        params = params or {}
        uuid = params.get("uuid") or ""
        out = {}
        for c in store.list_clients():
            if c.get("hidden"):
                continue
            node = _public_node(c)
            # Komari 兼容归一化
            node["billing_cycle"] = _komari_billing_days(node.get("billing_cycle"))
            node["expired_at"] = _komari_expired_at(node.get("expired_at"))
            out[node["uuid"]] = node
        if uuid:
            if uuid not in out:
                raise ValueError("Node not found")
            return out[uuid]
        return out

    RPC_METHODS = {
        "public:getNodesInformation": rpc_get_nodes_information,
        "public:getPublicSettings": rpc_get_public_settings,
        "public:getVersion": rpc_get_version,
        "public:getMe": rpc_get_me,
        "public:queryMetrics": rpc_query_metrics,
        "public:getClientRecentRecords": rpc_get_client_recent_records,
        "public:getRecordsByUUID": rpc_get_records_by_uuid,
        "public:listMetricDefinitions": rpc_list_metric_definitions,
        "public:getPublicPingTasks": rpc_get_public_ping_tasks,
        "public:getPingMetricStats": rpc_get_ping_metric_stats,
        "public:getPingRecords": rpc_get_ping_records,
        "common:getNodesLatestStatus": rpc_get_nodes_latest_status,
        # Komari Emerald 等第三方主题使用的命名
        "rpc.ping": rpc_ping,
        "rpc.getVersion": rpc_get_version,
        "common:getNodes": rpc_common_get_nodes,
        "common:getNodeRecentStatus": rpc_get_client_recent_records,
        "common:getPublicInfo": rpc_get_public_settings,
        "common:getBackendVersion": rpc_get_version,
        "common:getRecords": rpc_common_get_records,
        # legacy aliases
        "getNodesInformation": rpc_get_nodes_information,
        "getNodesLatestStatus": rpc_get_nodes_latest_status,
        "queryMetrics": rpc_query_metrics,
    }

    def _dispatch_rpc(body: dict) -> dict:
        """Shared JSON-RPC 2.0 dispatcher used by both HTTP and WebSocket."""
        req_id = body.get("id")
        method = body.get("method", "")
        params = body.get("params") or {}
        handler = RPC_METHODS.get(method)
        if handler is None:
            return {
                "jsonrpc": "2.0", "id": req_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"},
            }
        try:
            result = handler(params)
            return {"jsonrpc": "2.0", "id": req_id, "result": result}
        except ValueError as e:
            return {
                "jsonrpc": "2.0", "id": req_id,
                "error": {"code": -32602, "message": str(e)},
            }
        except Exception as e:  # noqa: BLE001
            return {
                "jsonrpc": "2.0", "id": req_id,
                "error": {"code": -32603, "message": f"Internal error: {e}"},
            }

    @app.route("/api/rpc2", methods=["POST"])
    def rpc2():
        body = request.get_json(force=True, silent=True) or {}
        return jsonify(_dispatch_rpc(body))

    # WebSocket transport for /api/rpc2 (the theme tries WS first,
    # falls back to HTTP POST). Same JSON-RPC methods.
    try:
        from flask_sock import Sock
        _sock = Sock(app)

        @_sock.route("/api/rpc2")
        def rpc2_ws(ws):
            while True:
                msg = ws.receive()
                if msg is None:
                    break
                try:
                    body = json.loads(msg)
                except Exception:
                    continue
                # support batch requests
                if isinstance(body, list):
                    resp = [_dispatch_rpc(b) for b in body]
                else:
                    resp = _dispatch_rpc(body)
                ws.send(json.dumps(resp))
    except ImportError:
        pass

    # ------------------------------------------------------------ legacy REST
    @app.route("/api/nodes")
    def api_nodes():
        return jsonify(rpc_get_nodes_information({}))

    @app.route("/api/public")
    def api_public():
        return jsonify(rpc_get_public_settings({}))

    @app.route("/api/public/last-report")
    def public_last_report():
        nodes = {}
        names = {}
        for c in store.list_clients():
            nodes[c["uuid"]] = c.get("last_report_at")
            names[c["uuid"]] = c.get("name")
        resp = jsonify({"ok": True, "nodes": nodes, "names": names})
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.route("/api/public/server_card_order", methods=["GET"])
    def public_server_card_order():
        """前台服务器卡片手动排序（公开读写，仅视觉顺序）。"""
        try:
            order = json.loads(store.get_setting("server_card_order", "[]"))
        except Exception:
            order = []
        if not isinstance(order, list):
            order = []
        return jsonify({"order": [str(u) for u in order if str(u).strip()]})

    @app.route("/api/public/server_card_order", methods=["POST"])
    def public_server_card_order_save():
        data = request.get_json(force=True, silent=True) or {}
        order = data.get("order") or []
        order = [str(u) for u in order if str(u).strip()]
        # 去重保序
        seen, clean = set(), []
        for u in order:
            if u not in seen:
                seen.add(u)
                clean.append(u)
        store.set_setting("server_card_order", json.dumps(clean))
        return jsonify({"ok": True})

    @app.route("/api/version")
    def api_version():
        return jsonify(rpc_get_version({}))

    @app.route("/api/me")
    def api_me():
        return jsonify(rpc_get_me({}))

    # ------------------------------------------------------------ Komari 兼容补齐
    # 主题可选功能：IP 信息插件（bigcat 未内置 GeoIP，返回未启用，主题会优雅降级）
    @app.route("/api/public/ip-info/v1/status")
    def api_ipinfo_status():
        return jsonify({"ok": True, "data": {
            "available": False,
            "version": "none",
            "schema_version": 1,
            "mainland_china_excluded": False,
            "capabilities": {"geo": False, "network": False, "reputation": False,
                             "media_unlock": False, "ai_unlock": False},
        }})

    @app.route("/api/public/ip-info/v1/lookup")
    def api_ipinfo_lookup():
        return jsonify({"ok": False, "message": "IP 信息功能未启用"}), 503

    @app.route("/api/public/ip-info/v1/latency")
    def api_ipinfo_latency():
        return jsonify({"ok": False, "message": "IP 信息功能未启用"}), 503

    @app.route("/api/recent/<client_uuid>")
    def api_recent(client_uuid):
        return jsonify(rpc_get_client_recent_records({"uuid": client_uuid}))

    @app.route("/api/records/load")
    def api_records_load():
        # Komari 标准包装 {status, data: {records, count}}；
        # 顶层同时附带 count/records，兼容 LuminaPlus 的顶层解析。
        records = rpc_get_records_by_uuid({
            "uuid": request.args.get("uuid", ""),
            "hours": request.args.get("hours", "4"),
        })
        return jsonify({"status": "success",
                        "data": {"records": records, "count": len(records)},
                        "count": len(records), "records": records})

    @app.route("/api/records/ping")
    def api_records_ping():
        return jsonify(_ping_records_payload(
            uuid=request.args.get("uuid", ""),
            task_id=request.args.get("task_id", ""),
            hours=request.args.get("hours", "4"),
        ))

    # ------------------------------------------------------------ agent API
    def _agent_auth():
        token = request.headers.get("Authorization", "")
        if token.startswith("Bearer "):
            token = token[7:]
        if not token:
            token = request.args.get("token", "")
        if not token:
            data = request.get_json(force=True, silent=True) or {}
            token = data.get("token", "")
        if not token:
            return None
        return store.get_client_by_token(token)

    @app.route("/api/agent/register", methods=["POST"])
    def agent_register():
        data = request.get_json(force=True, silent=True) or {}
        client = store.add_client(name=data.get("name", ""))
        _auto_bind_ping_tasks(client["uuid"])
        return jsonify({"uuid": client["uuid"], "token": client["token"]})

    @app.route("/api/agent/basicinfo", methods=["POST"])
    def agent_basicinfo():
        client = _agent_auth()
        if not client:
            return jsonify({"error": "unauthorized"}), 401
        data = request.get_json(force=True, silent=True) or {}
        info = data.get("info", data)
        fields = {}
        mapping = {
            "cpu_name": "cpu_name", "cpuName": "cpu_name",
            "virtualization": "virtualization",
            "arch": "arch",
            "cpu_cores": "cpu_cores", "cpuCores": "cpu_cores",
            "os": "os", "os_name": "os",
            "kernel_version": "kernel_version",
            "gpu_name": "gpu_name",
            "ipv4": "ipv4", "ipv6": "ipv6",
            "region": "region",
            "mem_total": "mem_total", "memTotal": "mem_total",
            "swap_total": "swap_total",
            "disk_total": "disk_total",
            "version": "version",
        }
        for k, col in mapping.items():
            if k in info:
                fields[col] = info[k]
        if "name" in info and not client.get("name"):
            fields["name"] = info["name"]
        store.update_client(client["uuid"], fields)
        return jsonify({"ok": True})

    # ------------------------------------------------------------ GeoIP 地区自动填充
    _GEOIP_TRY_AT = {}  # client_uuid -> 上次尝试时间戳（内存节流，每节点最多 1 小时一次）

    def _request_public_ip() -> str:
        """从请求头/连接信息中取出第一个公网 IP；无则返回空字符串。"""
        candidates = []
        fwd = request.headers.get("X-Forwarded-For", "")
        if fwd:
            candidates.extend(x.strip() for x in fwd.split(","))
        real = request.headers.get("X-Real-IP", "").strip()
        if real:
            candidates.append(real)
        if request.remote_addr:
            candidates.append(request.remote_addr.strip())
        for cand in candidates:
            try:
                ip = ipaddress.ip_address(cand)
            except ValueError:
                continue
            if ip.is_global:
                return cand
        return ""

    def _geoip_lookup(ip: str) -> str:
        """ip-api.com 免费接口查询国家二字码；失败返回空字符串。"""
        try:
            req = urllib.request.Request(
                f"http://ip-api.com/json/{ip}?fields=status,countryCode",
                headers={"User-Agent": "BigCat"},
            )
            with urllib.request.urlopen(req, timeout=10) as r:
                d = json.loads(r.read().decode("utf-8", "ignore"))
            if d.get("status") == "success" and d.get("countryCode"):
                return str(d["countryCode"]).upper()
        except Exception:
            pass
        return ""

    def _maybe_geoip_region(client_uuid: str) -> None:
        now = time.time()
        if now - _GEOIP_TRY_AT.get(client_uuid, 0) < 3600:
            return
        _GEOIP_TRY_AT[client_uuid] = now
        ip = _request_public_ip()
        if not ip:
            return

        def _run():
            try:
                code = _geoip_lookup(ip)
                if not code:
                    return
                c = store.get_client(client_uuid)
                # 再次确认仍为空才写入，避免覆盖用户手动设置
                if c and not (c.get("region") or "").strip():
                    store.update_client(client_uuid, {"region": code})
            except Exception:
                pass

        threading.Thread(target=_run, daemon=True).start()

    @app.route("/api/agent/report", methods=["POST"])
    def agent_report():
        client = _agent_auth()
        if not client:
            return jsonify({"error": "unauthorized"}), 401
        # region 为空时自动 GeoIP 填充国家代码（主题据此显示国旗），手动设置过的不覆盖
        if not (client.get("region") or "").strip():
            _maybe_geoip_region(client["uuid"])
        data = request.get_json(force=True, silent=True) or {}
        rep = data.get("report", data)
        cpu = rep.get("cpu", {})
        ram = rep.get("ram", {})
        swap = rep.get("swap", {})
        load = rep.get("load", {})
        disk = rep.get("disk", {})
        net = rep.get("network", {})
        conn = rep.get("connections", {})
        rec = {
            "time": rep.get("updated_at")
            or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "cpu": cpu.get("usage", 0),
            "gpu": (rep.get("gpu") or {}).get("average_usage", 0),
            "ram": ram.get("used", 0),
            "ram_total": ram.get("total", 0),
            "swap": swap.get("used", 0),
            "swap_total": swap.get("total", 0),
            "load": load.get("load1", 0),
            "disk": disk.get("used", 0),
            "disk_total": disk.get("total", 0),
            "net_in": net.get("down", 0),    # bytes/s down -> in
            "net_out": net.get("up", 0),     # bytes/s up -> out
            "net_total_up": net.get("totalUp", 0),
            "net_total_down": net.get("totalDown", 0),
            "net_month_up": net.get("monthUp", 0),
            "net_month_down": net.get("monthDown", 0),
            "traffic_up": net.get("up", 0),
            "traffic_down": net.get("down", 0),
            "process": rep.get("process", 0),
            "connections": conn.get("tcp", 0),
            "connections_udp": conn.get("udp", 0),
            "uptime": rep.get("uptime", 0),
        }
        # 流量周期基线：累计流量入库时减去周期基线，得到“本周期已用”。
        # 配置了重置日的节点跨入新周期时基线自动重置（用量清零重新累计）；
        # 管理员的流量校准通过调整基线实现（见 /traffic-calibrate）。
        _raw_up = rec["net_total_up"]
        _raw_down = rec["net_total_down"]
        _b_up = client.get("traffic_base_up") or 0
        _b_down = client.get("traffic_base_down") or 0
        _cycle = _traffic_cycle_start(client)
        if _cycle is not None:
            _cid = _cycle.isoformat()
            _saved_cycle = client.get("traffic_base_cycle") or ""
            if _saved_cycle != _cid:
                if _saved_cycle == "":
                    # 功能首次启用：只登记周期，不改动当前显示，下个周期起全程生效
                    store.update_client(client["uuid"],
                                        {"traffic_base_cycle": _cid})
                else:
                    # 跨入新周期：基线重置为当前累计值，本周期用量从 0 起算
                    _b_up, _b_down = _raw_up, _raw_down
                    store.update_client(client["uuid"], {
                        "traffic_base_up": _b_up,
                        "traffic_base_down": _b_down,
                        "traffic_base_cycle": _cid})
            else:
                # 累计计数回退（机器重启/换网卡）：基线跟随回退，该方向重新累计
                _fix = {}
                if _raw_up < _b_up:
                    _b_up = _raw_up
                    _fix["traffic_base_up"] = _b_up
                if _raw_down < _b_down:
                    _b_down = _raw_down
                    _fix["traffic_base_down"] = _b_down
                if _fix:
                    store.update_client(client["uuid"], _fix)
        if _b_up or _b_down:
            rec["net_total_up"] = max(0, _raw_up - _b_up)
            rec["net_total_down"] = max(0, _raw_down - _b_down)
        store.insert_record(client["uuid"], rec)
        store.touch_client(client["uuid"])
        # v1.9.4：节点侧分布式延迟探测结果（agent 自行探测后随上报回传）
        try:
            for pr in rep.get("ping_results") or []:
                if pr.get("task_id") is None:
                    continue
                try:
                    plat = round(float(pr.get("latency_ms", 0) or 0), 2)
                except (TypeError, ValueError):
                    plat = 0.0
                store.insert_ping_result(int(pr["task_id"]), plat,
                                         bool(pr.get("ok")),
                                         client_uuid=client["uuid"])
        except Exception:
            pass
        # 离线/上线通知的状态变化检测 + 过期监控数据清理（无独立调度器，搭上报触发）
        try:
            _check_node_transitions()
        except Exception:
            pass
        try:
            _maybe_prune()
        except Exception:
            pass
        # update totals if agent reports them
        totals = {}
        if ram.get("total"):
            totals["mem_total"] = ram["total"]
        if swap.get("total"):
            totals["swap_total"] = swap["total"]
        if disk.get("total"):
            totals["disk_total"] = disk["total"]
        if cpu.get("cores"):
            totals["cpu_cores"] = cpu["cores"]
        if cpu.get("name"):
            totals["cpu_name"] = cpu["name"]
        if cpu.get("arch"):
            totals["arch"] = cpu["arch"]
        if totals:
            store.update_client(client["uuid"], totals)
        _resp = {"ok": True}
        _mr = _master_redirect()
        if _mr:
            _resp["master"] = _mr
        return jsonify(_resp)

    @app.route("/api/agent/tasks", methods=["GET"])
    def agent_tasks():
        client = _agent_auth()
        if not client:
            return jsonify({"error": "unauthorized"}), 401
        tasks = store.claim_exec_tasks(client["uuid"])
        return jsonify({"tasks": tasks})

    @app.route("/api/agent/ping_tasks", methods=["GET"])
    def agent_ping_tasks():
        """agent 拉取应由本节点执行的延迟探测任务（v1.9.4+ 分布式探测）。

        Komari 语义：任务未绑定 clients 时为全局任务，所有节点各自探测；
        绑定了 clients 时仅被绑定的节点探测。"""
        client = _agent_auth()
        if not client:
            return jsonify({"error": "unauthorized"}), 401
        out = []
        for t in store.list_ping_tasks():
            if not t.get("enabled"):
                continue
            bound = store.get_ping_task_clients(t.get("id"))
            if bound and client["uuid"] not in bound:
                continue
            out.append({
                "id": t.get("id"),
                "name": t.get("name"),
                "target": t.get("target"),
                "type": t.get("type") or "tcp",
                "interval_sec": max(30, int(t.get("interval_sec") or 300)),
            })
        return jsonify({"tasks": out})

    @app.route("/api/agent/task_result", methods=["POST"])
    def agent_task_result():
        client = _agent_auth()
        if not client:
            return jsonify({"error": "unauthorized"}), 401
        data = request.get_json(force=True, silent=True) or {}
        task_id = data.get("task_id")
        if task_id is None:
            return jsonify({"error": "task_id required"}), 400
        store.finish_exec_task(int(task_id), str(data.get("output", ""))[:100000],
                               bool(data.get("ok", True)))
        return jsonify({"ok": True})

    # ------------------------------------------------------------ admin helpers
    def _session_version() -> int:
        try:
            return int(store.get_setting("session_version", "0") or 0)
        except Exception:
            return 0

    def _is_online(c: dict) -> bool:
        return _node_online(c, datetime.now(timezone.utc))

    def _post_webhook(url: str, text: str, timeout: int = 8) -> bool:
        # 保留给旧版测试接口兼容；新逻辑走渠道 _send_channel
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps({"text": text}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return 200 <= resp.status < 300
        except Exception:
            return False

    def _check_node_transitions():
        # v2 兼容入口：agent 上报时顺带触发一次；权威检测由监控线程每 30s 执行
        _offline_check()

    def _maybe_prune():
        """Prune old records at most once per hour (no scheduler in Flask dev server)."""
        try:
            keep = max(1, min(720, int(store.get_setting("record_keep_hours", "24") or 24)))
        except Exception:
            keep = 24
        try:
            last = float(store.get_setting("last_prune_ts", "0") or 0)
        except Exception:
            last = 0
        if time.time() - last < 3600:
            return
        store.set_setting("last_prune_ts", str(time.time()))
        try:
            store.prune_records(keep)
        except Exception:
            pass

    # ------------------------------------------------------------ admin API
    # ------------------------------------------------------------ admin auth (v3, v1.9.8 多账户)
    # 权限页键（与后台导航 PAGES 一一对应）
    PERM_PAGES = ["dashboard", "servers", "themes", "ping", "alerts", "exec",
                  "notify", "events", "database", "sessions", "account",
                  "settings", "domain", "skin", "logs", "migrate"]

    def _create_login_session(username: str, role: str):
        sid = secrets.token_hex(16)
        store.create_session(sid, request.remote_addr or "",
                             request.headers.get("User-Agent", ""),
                             username=username, role=role)
        session["sid"] = sid
        session["v"] = _session_version()
        store.log_event("info", "auth",
                        f"用户 {username} 登录成功（IP {request.remote_addr or '-'}）")
        return sid

    def _login_user():
        """返回当前登录用户身份 dict 或 None。dict: username/role/perms/is_super。"""
        sid = session.get("sid")
        s = store.get_session(sid) if sid else None
        if not s or session.get("v") != _session_version():
            return None
        exp = _parse_time(s.get("expires_at"))
        if not exp or exp < datetime.now(timezone.utc):
            return None
        try:
            last = _parse_time(s.get("last_seen"))
            if not last or (datetime.now(timezone.utc) - last).total_seconds() > 120:
                store.touch_session(sid)
        except Exception:
            pass
        username = s.get("username") or ""
        role = s.get("role") or ""
        # 超级管理员：首次安装时创建的根账户，拥有全部权限
        if role == "superadmin" or (not username and store.get_admin_username()):
            return {"username": store.get_admin_username(), "role": "superadmin",
                    "perms": set(PERM_PAGES), "is_super": True}
        u = store.get_user_by_username(username) if username else None
        if not u or u.get("disabled"):
            return None
        if u.get("role") == "admin":
            perms = set(PERM_PAGES)
        else:
            try:
                perms = set(json.loads(u.get("perms") or "[]"))
            except Exception:
                perms = set()
            perms &= set(PERM_PAGES)
        return {"username": u["username"], "role": u.get("role") or "user",
                "perms": perms, "is_super": False, "user_id": u["id"],
                "phone": u.get("phone") or "", "email": u.get("email") or ""}

    def _admin_logged_in() -> bool:
        return _login_user() is not None

    def _require_login(fn):
        @functools.wraps(fn)
        def wrapper(*a, **kw):
            u = _login_user()
            if not u:
                return jsonify({"error": "login required"}), 401
            g.uinfo = u
            return fn(*a, **kw)
        return wrapper

    def _require_perm(page):
        def deco(fn):
            @functools.wraps(fn)
            def wrapper(*a, **kw):
                u = _login_user()
                if not u:
                    return jsonify({"error": "login required"}), 401
                if page not in u["perms"]:
                    return jsonify({"error": "forbidden"}), 403
                g.uinfo = u
                return fn(*a, **kw)
            return wrapper
        return deco

    def _require_admin(fn):
        """v1.9.8 起含义变更：超级管理员或管理员角色（可管理用户），不再是“任意登录”。"""
        @functools.wraps(fn)
        def wrapper(*a, **kw):
            u = _login_user()
            if not u:
                return jsonify({"error": "login required"}), 401
            if not (u["is_super"] or u["role"] == "admin"):
                return jsonify({"error": "forbidden"}), 403
            g.uinfo = u
            return fn(*a, **kw)
        return wrapper

    def _require_superadmin(fn):
        """仅超级管理员（安装时创建的根账户）。"""
        @functools.wraps(fn)
        def wrapper(*a, **kw):
            u = _login_user()
            if not u:
                return jsonify({"error": "login required"}), 401
            if not u["is_super"]:
                return jsonify({"error": "forbidden"}), 403
            g.uinfo = u
            return fn(*a, **kw)
        return wrapper

    # ------------------------------------------------------------ 一键迁移
    # 将本机 BigCat 全部内容一键迁移到新服务器（对齐 BigCat B 迁移规格）：
    # - 登录方式：密码（sshpass -e，密码走环境变量不进命令行）或 SSH 密钥
    #   （私钥+可选口令；私钥仅在迁移期间写入 /tmp 临时文件 0600，结束即删）
    # - 支持自定义 SSH 用户名（默认 root）；非 root 用户的特权操作统一经
    #   sudo -i 以 root 身份执行（要求目标用户免密 sudo）
    # - 数据原封不动：数据库先做一致性快照，数据目录（主题/皮肤等）整体
    #   rsync 镜像，程序文件同步本机版本，最后核对版本号与关键表行数
    # - 凭据仅保存在进程内存中，不落盘、不记日志
    _MIGRATE_STATE = {
        "running": False, "step": "", "progress": 0, "log": [],
        "done": False, "success": False, "error": "", "target": "",
    }
    _MIGRATE_LOCK = threading.Lock()
    _MIGRATE_AUTH = {}

    def _migrate_log(msg, level="info"):
        with _MIGRATE_LOCK:
            _MIGRATE_STATE["log"].append({
                "time": datetime.now().strftime("%H:%M:%S"),
                "msg": msg, "level": level})
            if len(_MIGRATE_STATE["log"]) > 300:
                _MIGRATE_STATE["log"] = _MIGRATE_STATE["log"][-300:]

    def _migrate_set(step="", progress=None):
        with _MIGRATE_LOCK:
            if step:
                _MIGRATE_STATE["step"] = step
            if progress is not None:
                _MIGRATE_STATE["progress"] = progress

    def _ensure_sshpass(quiet=False):
        if shutil.which("sshpass"):
            return True
        if not quiet:
            _migrate_log("正在安装 sshpass…")
        try:
            subprocess.run(["apt-get", "update", "-qq"],
                           capture_output=True, timeout=120)
            subprocess.run(["apt-get", "install", "-y", "-qq", "sshpass"],
                           capture_output=True, timeout=180)
            return shutil.which("sshpass") is not None
        except Exception as e:
            if not quiet:
                _migrate_log(f"安装 sshpass 失败: {e}", "error")
            return False

    # ---------- 被监控主机切换（迁移后自动上线） ----------
    _AGENT_UPGRADE_CMD = (
        "curl -fsSL https://raw.githubusercontent.com/zhanghaobo1987/BigCat-T/main/agent/agent.py "
        "-o /tmp/bigcat-agent-new.py && install -m 644 /tmp/bigcat-agent-new.py /opt/bigcat/agent.py "
        "&& (nohup sh -c 'sleep 3; systemctl restart bigcat-agent' >/dev/null 2>&1 &) "
        "&& echo agent-upgraded")

    def _master_redirect():
        """当前生效的主控切换指令 URL（随 agent 上报响应下发）；未设置/过期返回 ''。"""
        try:
            obj = json.loads(store.get_setting("agent_master_redirect", "") or "{}")
        except Exception:
            obj = {}
        url = (obj.get("url") or "").strip()
        if url and float(obj.get("until") or 0) > time.time():
            return url
        return ""

    def _issue_agent_switch(new_url):
        """下发主控切换：设置切换指令（新版 agent 下次上报即切换并持久化）+
        给全部节点排队 agent 升级任务（旧版 agent 升级重启后同样执行切换指令）。
        返回 (新排队升级任务数, 节点总数, 当前在线节点 uuid 集合)。"""
        store.set_setting("agent_master_redirect",
                          json.dumps({"url": new_url,
                                      "until": time.time() + 7 * 86400}))
        now = datetime.now(timezone.utc)
        clients = store.list_clients()
        n = 0
        for c in clients:
            try:
                if not store.has_pending_exec(c["uuid"], _AGENT_UPGRADE_CMD):
                    store.add_exec_task(c["uuid"], _AGENT_UPGRADE_CMD)
                    n += 1
            except Exception:
                pass
        online = {c["uuid"] for c in clients if _node_online(c, now)}
        return n, len(clients), online

    def _agents_still_here(uuids):
        """给定集合中近 25 秒内仍在向本机上报的节点（尚未切换走）。
        不用离线阈值（默认 180s 太粗，切换完成会被误判为未切换）。"""
        if not uuids:
            return []
        now = datetime.now(timezone.utc)
        out = []
        for c in store.list_clients():
            if c["uuid"] not in uuids:
                continue
            t = _parse_time(c.get("last_report_at"))
            if t and (now - t).total_seconds() < 25:
                out.append(c)
        return out

    # ---------- 迁移凭据与远程执行 ----------
    def _mig_parse_req(data):
        """解析并校验迁移请求，返回 (auth, 错误信息)；auth 仅驻内存。"""
        host = (data.get("host") or "").strip()
        if not host or not re.fullmatch(r"[A-Za-z0-9._\-]+", host):
            return None, "请输入有效的新服务器 IP / 主机名"
        try:
            port = int(data.get("port") or 22)
        except (ValueError, TypeError):
            port = 22
        if not (1 <= port <= 65535):
            port = 22
        username = (data.get("username") or "root").strip() or "root"
        if not re.fullmatch(r"[A-Za-z0-9._\-]+", username):
            return None, "SSH 用户名不合法"
        auth = {"host": host, "port": port, "username": username,
                "type": "password", "password": "", "private_key": "",
                "passphrase": "", "key_path": None}
        if (data.get("auth_type") or "password") == "key":
            key = data.get("private_key") or ""
            if "PRIVATE KEY" not in key:
                return None, "请粘贴或上传 SSH 私钥（PEM/OpenSSH 格式）"
            auth.update({"type": "key", "private_key": key,
                         "passphrase": data.get("passphrase") or ""})
        else:
            if not data.get("password"):
                return None, "请输入 SSH 密码"
            auth["password"] = data["password"]
        return auth, ""

    def _mig_sudo(auth):
        return "" if auth["username"] == "root" else "sudo -i "

    def _mig_ssh_args(auth):
        args = ["-p", str(auth["port"]),
                "-o", "StrictHostKeyChecking=accept-new",
                "-o", "ConnectTimeout=15"]
        if auth["type"] == "key":
            args += ["-i", auth["key_path"], "-o", "IdentitiesOnly=yes",
                     "-o", "BatchMode=yes", "-o", "PasswordAuthentication=no"]
        else:
            args += ["-o", "PubkeyAuthentication=no",
                     "-o", "NumberOfPasswordPrompts=1"]
        return args

    def _mig_run(cmd, timeout=120, env_extra=None, stdin_text=None):
        env = dict(os.environ)
        if env_extra:
            env.update(env_extra)
        try:
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout, env=env, input=stdin_text)
            return r.returncode == 0, r.stdout.strip(), r.stderr.strip()
        except subprocess.TimeoutExpired:
            return False, "", "命令执行超时"
        except Exception as e:
            return False, "", str(e)

    def _mig_ssh(auth, remote_cmd, timeout=120, stdin_text=None):
        cmd = ["ssh"] + _mig_ssh_args(auth) + \
            [f"{auth['username']}@{auth['host']}", remote_cmd]
        if auth["type"] == "password":
            return _mig_run(["sshpass", "-e"] + cmd, timeout=timeout,
                            env_extra={"SSHPASS": auth["password"]},
                            stdin_text=stdin_text)
        return _mig_run(cmd, timeout=timeout, stdin_text=stdin_text)

    def _mig_rsync(auth, local_src, remote_dest, extra=None, timeout=1200):
        cmd = ["rsync", "-az"] + list(extra or [])
        if auth["username"] != "root":
            cmd += ["--rsync-path=sudo -i rsync"]
        cmd += ["-e", "ssh " + " ".join(_mig_ssh_args(auth)),
                local_src, f"{auth['username']}@{auth['host']}:{remote_dest}"]
        if auth["type"] == "password":
            return _mig_run(["sshpass", "-e"] + cmd, timeout=timeout,
                            env_extra={"SSHPASS": auth["password"]})
        return _mig_run(cmd, timeout=timeout)

    def _mig_prepare_key(auth):
        """把私钥写入 /tmp 临时文件（0600），带口令时先去除口令并校验。"""
        if auth["type"] != "key":
            return
        fd, path = tempfile.mkstemp(prefix="bigcat-migrate-key-")
        auth["key_path"] = path
        try:
            key = auth["private_key"]
            if not key.endswith("\n"):
                key += "\n"
            with os.fdopen(fd, "w") as f:
                f.write(key)
            os.chmod(path, 0o600)
            if auth["passphrase"]:
                ok, _, _ = _mig_run(
                    ["ssh-keygen", "-p", "-P", auth["passphrase"],
                     "-N", "", "-f", path], timeout=30)
                if not ok:
                    raise RuntimeError(
                        "密钥口令不正确，或密钥格式不受支持（需 OpenSSH/PEM 格式）")
            ok, _, _ = _mig_run(["ssh-keygen", "-y", "-f", path], timeout=30)
            if not ok:
                raise RuntimeError(
                    "密钥无效或带有口令：如密钥设有口令，请填写密钥口令后重试")
        except Exception:
            _mig_cleanup_key(auth)
            raise

    def _mig_cleanup_key(auth):
        path = auth.get("key_path")
        auth["key_path"] = None
        if path:
            try:
                os.remove(path)
            except OSError:
                pass

    def _mig_check_conn(auth, timeout=30):
        """测试连接并做基础检查，返回 (ok, message, has_bigcat)。"""
        ok, out, err = _mig_ssh(auth, "echo ok", timeout=timeout)
        if not ok:
            return False, f"SSH 连接失败: {err or out}", False
        if auth["username"] != "root":
            ok, _, _ = _mig_ssh(auth, "sudo -n true", timeout=timeout)
            if not ok:
                return False, ("目标用户无免密 sudo 权限：非 root 用户迁移需要"
                               "免密 sudo（如甲骨文云 ubuntu 用户）"), False
        ok, out, _ = _mig_ssh(
            auth, "test -d /opt/bigcat/server && echo yes || echo no",
            timeout=timeout)
        return True, "连接成功", (out or "").strip() == "yes"

    def _mig_table_counts(db_file):
        counts = {}
        conn = sqlite3.connect(f"file:{db_file}?mode=ro", uri=True)
        try:
            for t in ("clients", "users", "alert_rules", "settings", "records"):
                try:
                    counts[t] = conn.execute(
                        f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                except Exception:
                    counts[t] = None
        finally:
            conn.close()
        return counts

    def _do_migrate(auth):
        S = _mig_sudo(auth)
        snapshot = "/tmp/bigcat-migrate.db"
        install_dir = os.path.dirname(os.path.dirname(os.path.abspath(db_path)))
        data_dir = os.path.join(install_dir, "data")
        try:
            _migrate_set("准备迁移", 5)
            _migrate_log(f"目标服务器: {auth['username']}@{auth['host']}:{auth['port']}"
                         f"（{'密钥' if auth['type'] == 'key' else '密码'}登录）")
            if auth["type"] == "key":
                _mig_prepare_key(auth)
                _migrate_log("SSH 密钥已就绪（临时文件，迁移结束自动删除）")
            else:
                if not _ensure_sshpass():
                    raise RuntimeError("无法安装 sshpass，请手动安装后重试")
            if not shutil.which("rsync"):
                raise RuntimeError("本机缺少 rsync，请先安装后重试")
            _migrate_set("连接新服务器", 10)
            ok, msg, _ = _mig_check_conn(auth)
            if not ok:
                raise RuntimeError(msg)
            _migrate_log("SSH 连接成功"
                         + ("（已确认免密 sudo）" if auth["username"] != "root" else ""))
            _migrate_set("准备目标服务器", 20)
            ok, out, err = _mig_ssh(
                auth, "command -v rsync >/dev/null 2>&1 && echo have || echo missing",
                timeout=30)
            if ok and out.strip() == "missing":
                _migrate_log("目标机未安装 rsync，正在安装…")
                ok, out, err = _mig_ssh(
                    auth, f"{S}apt-get update -qq && {S}apt-get install -y -qq rsync",
                    timeout=600)
                if not ok:
                    raise RuntimeError(f"目标机安装 rsync 失败: {(err or out)[-300:]}")
            _migrate_log("正在目标机安装 BigCat（约需 1-3 分钟）…")
            tmp_pwd = secrets.token_hex(12)
            install_stdin = (
                "export BIGCAT_PORT=25774\n"
                "export BIGCAT_ADMIN_USER=admin\n"
                f"export BIGCAT_ADMIN_PASSWORD='{tmp_pwd}'\n"
                "bash /tmp/bigcat-install.sh server\n"
                "rm -f /tmp/bigcat-install.sh\n")
            ok, out, err = _mig_ssh(
                auth, "curl -fsSL https://raw.githubusercontent.com/zhanghaobo1987/"
                      "bigcat/main/scripts/install.sh -o /tmp/bigcat-install.sh",
                timeout=120)
            if not ok:
                raise RuntimeError(f"目标机下载安装脚本失败: {(err or out)[-300:]}")
            ok, out, err = _mig_ssh(auth, f"{S}bash -s", timeout=900,
                                    stdin_text=install_stdin)
            if not ok:
                raise RuntimeError(f"目标机安装失败: {(err or out)[-500:]}")
            _migrate_log("目标机 BigCat 安装完成")
            _migrate_set("快照数据库", 35)
            db_file = os.path.abspath(db_path)
            if os.path.exists(snapshot):
                os.remove(snapshot)
            src = sqlite3.connect(f"file:{db_file}?mode=ro", uri=True)
            dst = sqlite3.connect(snapshot)
            try:
                src.backup(dst)
            finally:
                dst.close()
                src.close()
            local_counts = _mig_table_counts(snapshot)
            _migrate_log(f"数据库一致性快照完成（节点 {local_counts.get('clients')} 个，"
                         f"监控记录 {local_counts.get('records')} 条）")
            _migrate_set("同步程序文件", 50)
            ok, out, err = _mig_rsync(
                auth, os.path.join(install_dir, "server") + "/",
                "/opt/bigcat/server/",
                extra=["--delete", "--exclude", "__pycache__"], timeout=600)
            if not ok:
                raise RuntimeError(f"程序文件同步失败: {(err or out)[-300:]}")
            _migrate_log("程序文件同步完成（与本机版本一致）")
            _migrate_set("同步数据目录", 62)
            ok, out, err = _mig_ssh(auth, f"{S}systemctl stop bigcat 2>/dev/null; "
                                          f"sleep 2; {S}systemctl is-active bigcat || true",
                                    timeout=60)
            if out.strip().endswith("active"):
                _mig_ssh(auth, f"{S}systemctl stop bigcat; sleep 2", timeout=60)
            has_bak = any(fnmatch.fnmatch(f, "bigcat.db.bak.*")
                          for f in os.listdir(data_dir))
            ok, out, err = _mig_rsync(
                auth, data_dir + "/", "/opt/bigcat/data/",
                extra=["--delete", "--exclude", "bigcat.db",
                       "--exclude", "bigcat.db-wal", "--exclude", "bigcat.db-shm",
                       "--exclude", "bigcat.db.bak.*"], timeout=1800)
            if not ok:
                raise RuntimeError(f"数据目录同步失败: {(err or out)[-300:]}")
            _migrate_log("数据目录同步完成（主题、皮肤等原封不动）"
                         + ("；已跳过大体积历史备份文件 bigcat.db.bak.*（可手动拷贝）"
                            if has_bak else ""))
            _migrate_set("同步数据库", 78)
            ok, out, err = _mig_rsync(auth, snapshot, "/opt/bigcat/data/bigcat.db",
                                      extra=["--ignore-times"], timeout=1800)
            if not ok:
                raise RuntimeError(f"数据库同步失败: {(err or out)[-300:]}")
            ok, out, err = _mig_ssh(
                auth, f"{S}rm -f /opt/bigcat/data/bigcat.db-wal "
                      f"/opt/bigcat/data/bigcat.db-shm && echo cleaned", timeout=60)
            if not ok:
                raise RuntimeError(f"目标机清理 WAL 失败: {(err or out)[-300:]}")
            _migrate_log("数据库同步完成")
            # 启动前预检：直接读目标库文件计数（服务未启动时应与快照完全一致）；
            # 首次安装的初始化写入可能与传输竞态，不一致时自动重传一次快照。
            count_py = (
                "import sqlite3, json\n"
                "conn = sqlite3.connect('file:/opt/bigcat/data/bigcat.db?mode=ro', uri=True)\n"
                "out = {}\n"
                "for t in ('clients', 'users', 'alert_rules', 'settings', 'records'):\n"
                "    try:\n"
                "        out[t] = conn.execute('SELECT COUNT(*) FROM ' + t).fetchone()[0]\n"
                "    except Exception:\n"
                "        out[t] = None\n"
                "print(json.dumps(out))\n")

            def _remote_counts():
                ok2, out2, _ = _mig_ssh(auth, f"{S}python3 -", timeout=60,
                                        stdin_text=count_py)
                if not ok2:
                    return None
                try:
                    return json.loads(out2.strip().splitlines()[-1])
                except Exception:
                    return None

            pre = _remote_counts()
            if pre != local_counts:
                _migrate_log("启动前预检行数不一致，正在重传数据库快照…", "warn")
                ok, out, err = _mig_rsync(auth, snapshot, "/opt/bigcat/data/bigcat.db",
                                          extra=["--ignore-times"], timeout=1800)
                if not ok:
                    raise RuntimeError(f"数据库重传失败: {(err or out)[-300:]}")
                _mig_ssh(auth, f"{S}rm -f /opt/bigcat/data/bigcat.db-wal "
                               f"/opt/bigcat/data/bigcat.db-shm", timeout=60)
                pre = _remote_counts()
                if pre != local_counts:
                    raise RuntimeError(
                        f"目标机数据库预检仍不一致（本机 {local_counts} / 目标 {pre}），"
                        "已中止启动，请手动检查目标机")
            _migrate_log("启动前预检通过：目标库行数与快照一致")
            _migrate_set("启动目标服务", 88)
            ok, out, err = _mig_ssh(
                auth, f"{S}systemctl restart bigcat && sleep 5 && "
                      f"{S}systemctl is-active bigcat", timeout=120)
            if not ok or "active" not in out:
                raise RuntimeError(f"目标机服务启动失败: {(err or out)[-500:]}")
            _migrate_log("目标机服务已启动")
            _migrate_set("验证迁移结果", 95)
            ok, out, err = _mig_ssh(
                auth, "curl -s http://127.0.0.1:25774/api/version", timeout=30)
            remote_ver = ""
            try:
                remote_ver = (json.loads(out) or {}).get("version", "")
            except Exception:
                pass
            if not ok or remote_ver != VERSION:
                raise RuntimeError(
                    f"版本不一致：本机 v{VERSION}，新服务器返回 {out.strip() or err}")
            _migrate_log(f"版本验证通过：v{remote_ver}")
            count_py = (
                "import sqlite3, json\n"
                "conn = sqlite3.connect('file:/opt/bigcat/data/bigcat.db?mode=ro', uri=True)\n"
                "out = {}\n"
                "for t in ('clients', 'users', 'alert_rules', 'settings', 'records'):\n"
                "    try:\n"
                "        out[t] = conn.execute('SELECT COUNT(*) FROM ' + t).fetchone()[0]\n"
                "    except Exception:\n"
                "        out[t] = None\n"
                "print(json.dumps(out))\n")
            ok, out, err = _mig_ssh(auth, f"{S}python3 -", timeout=60,
                                    stdin_text=count_py)
            if not ok:
                raise RuntimeError(f"目标机数据校验失败: {(err or out)[-300:]}")
            remote_counts = json.loads(out.strip().splitlines()[-1])
            diff = [f"{t}: 本机 {local_counts.get(t)} / 目标 {remote_counts.get(t)}"
                    for t in local_counts
                    if local_counts.get(t) != remote_counts.get(t)]
            if diff:
                raise RuntimeError("数据行数不一致：" + "；".join(diff))
            _migrate_log("数据校验通过：节点、用户、告警规则、设置、监控记录行数与本机完全一致")
            # ---- 被监控主机自动切换上线：下发切换指令 + 旧 agent 升级任务，
            # 等待在线节点逐个离开本机（即已切到新服务器），迁移完直接可用 ----
            _migrate_set("被监控主机切换上线", 97)
            new_url = f"http://{auth['host']}:25774"
            issue_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            n_tasks, n_nodes, online_uuids = _issue_agent_switch(new_url)
            _migrate_log(f"已向全部 {n_nodes} 台被监控主机下发切换指令（目标 {new_url}），"
                         f"其中 {n_tasks} 台排队自动升级 agent；"
                         f"当前在线 {len(online_uuids)} 台，等待切换…")
            deadline = time.time() + 150
            while time.time() < deadline:
                still = _agents_still_here(online_uuids)
                if not still:
                    break
                time.sleep(5)
            still = _agents_still_here(online_uuids)
            switched = len(online_uuids) - len(still)
            if online_uuids and not still:
                _migrate_log(f"全部 {len(online_uuids)} 台在线被监控主机已离开本机（正在确认到达新服务器…）")
            elif still:
                names = "、".join((c.get("name") or c["uuid"][:8]) for c in still)
                _migrate_log(f"主机切换：{switched}/{len(online_uuids)} 台已切换；"
                             f"仍在本机的：{names}（可能离线或升级较慢，"
                             f"切换指令 7 天内有效，其下次连上本机时自动切换；"
                             f"请勿立即停止本机服务）", "warn")
            if n_nodes > len(online_uuids):
                _migrate_log(f"另有 {n_nodes - len(online_uuids)} 台离线主机："
                             f"其下次连上本机时将自动切换到新服务器", "warn")
            # 到达确认：离开本机 ≠ 到达新机（目标端口未放行时主机到不了），
            # 经 SSH 读目标库核对切换后已在新服务器上报的主机数
            arrived = None
            if online_uuids:
                arr_py = (
                    "import sqlite3\n"
                    "conn = sqlite3.connect('/opt/bigcat/data/bigcat.db')\n"
                    f"n = conn.execute(\"SELECT COUNT(*) FROM clients "
                    f"WHERE last_report_at > '{issue_iso}'\").fetchone()[0]\n"
                    "print(n)\n")
                for _try in range(3):
                    ok_a, out_a, _err_a = _mig_ssh(auth, f"{S}python3 -", timeout=60,
                                                   stdin_text=arr_py)
                    if ok_a:
                        try:
                            arrived = int(out_a.strip().splitlines()[-1])
                        except (ValueError, IndexError):
                            arrived = None
                    if arrived is not None and arrived >= len(online_uuids):
                        break
                    time.sleep(5)
                if arrived is not None:
                    _migrate_log(f"新服务器到达确认：{arrived} 台主机已在新服务器上报")
                    if arrived < len(online_uuids):
                        _migrate_log(f"⚠️ {len(online_uuids) - arrived} 台主机已离开本机但尚未到达新服务器，"
                                     f"请检查新服务器 25774 端口是否对主机网络放行（云防火墙/安全组）", "warn")
            with _MIGRATE_LOCK:
                _MIGRATE_STATE["done"] = True
                _MIGRATE_STATE["success"] = True
                _MIGRATE_STATE["running"] = False
            _migrate_set("迁移完成", 100)
            _migrate_log(f"✅ 迁移完成！新服务器后台：http://{auth['host']}:25774/admin")
            if still:
                _migrate_log("注意：本机服务仍在运行；仍有主机未切换，请勿停止本机，待其切换后再停", "warn")
            elif online_uuids and arrived is not None and arrived < len(online_uuids):
                _migrate_log("注意：本机服务仍在运行；部分主机尚未到达新服务器，排查端口放行后再停止本机", "warn")
            else:
                _migrate_log("注意：本机服务仍在运行，被监控主机已全部切换，可停止本机服务（systemctl stop bigcat）避免数据分叉", "warn")
        except Exception as e:
            with _MIGRATE_LOCK:
                _MIGRATE_STATE["done"] = True
                _MIGRATE_STATE["success"] = False
                _MIGRATE_STATE["error"] = str(e)
                _MIGRATE_STATE["running"] = False
            _migrate_log(f"迁移失败: {e}", "error")
        finally:
            _mig_cleanup_key(auth)
            with _MIGRATE_LOCK:
                _MIGRATE_AUTH.clear()
            try:
                os.remove(snapshot)
            except OSError:
                pass

    @_require_perm("migrate")
    @app.route("/api/admin/migrate/test", methods=["POST"])
    def api_migrate_test():
        data = request.get_json(force=True, silent=True) or {}
        auth, errmsg = _mig_parse_req(data)
        if errmsg:
            return jsonify({"ok": False, "message": errmsg}), 400
        try:
            if auth["type"] == "key":
                try:
                    _mig_prepare_key(auth)
                except Exception as e:
                    return jsonify({"ok": False, "message": str(e)}), 200
            elif not _ensure_sshpass(quiet=True):
                return jsonify({"ok": False, "message": "sshpass 安装失败"}), 200
            ok, msg, has_bigcat = _mig_check_conn(auth)
            return jsonify({"ok": ok, "message": msg, "has_bigcat": has_bigcat})
        finally:
            _mig_cleanup_key(auth)
            auth["password"] = ""
            auth["private_key"] = ""

    @_require_perm("migrate")
    @app.route("/api/admin/migrate/start", methods=["POST"])
    def api_migrate_start():
        data = request.get_json(force=True, silent=True) or {}
        auth, errmsg = _mig_parse_req(data)
        if errmsg:
            return jsonify({"ok": False, "message": errmsg}), 400
        with _MIGRATE_LOCK:
            if _MIGRATE_STATE["running"]:
                return jsonify({"ok": False, "message": "迁移任务进行中"}), 400
            _MIGRATE_STATE.update({"running": True, "step": "启动中",
                                   "progress": 0, "log": [], "done": False,
                                   "success": False, "error": "",
                                   "target": f"{auth['username']}@{auth['host']}:{auth['port']}"})
            _MIGRATE_AUTH.clear()
            _MIGRATE_AUTH.update(auth)
        t = threading.Thread(target=_do_migrate, args=(_MIGRATE_AUTH,),
                             daemon=True)
        t.start()
        return jsonify({"ok": True, "message": "迁移已启动"})

    @_require_perm("migrate")
    @app.route("/api/admin/migrate/status")
    def api_migrate_status():
        with _MIGRATE_LOCK:
            st = dict(_MIGRATE_STATE)
        url = _master_redirect()
        st["redirect"] = url or None
        clients = store.list_clients()
        here = _agents_still_here({c["uuid"] for c in clients})
        st["agents_total"] = len(clients)
        st["agents_here"] = len(here)
        st["agents_here_names"] = [(c.get("name") or c["uuid"][:8]) for c in here]
        return jsonify({"ok": True, **st})

    @_require_perm("migrate")
    @app.route("/api/admin/migrate/agents-online", methods=["POST"])
    def api_migrate_agents_online():
        data = request.get_json(force=True, silent=True) or {}
        host = (data.get("host") or "").strip()
        if not host:
            with _MIGRATE_LOCK:
                tgt = _MIGRATE_STATE.get("target", "")
            host = tgt.split("@")[-1].split(":")[0] if tgt else ""
        if not host or not re.fullmatch(r"[A-Za-z0-9._\-]+", host):
            return jsonify({"ok": False, "message": "缺少新服务器地址"}), 400
        url = f"http://{host}:25774"
        n_tasks, n_nodes, online = _issue_agent_switch(url)
        return jsonify({"ok": True, "url": url, "upgrade_tasks": n_tasks,
                        "nodes": n_nodes, "online": len(online)})

    @_require_perm("migrate")
    @app.route("/api/admin/migrate/agents-stop", methods=["POST"])
    def api_migrate_agents_stop():
        store.set_setting("agent_master_redirect", "")
        return jsonify({"ok": True, "message": "已停止下发切换指令"})

    @_require_perm("migrate")
    @app.route("/api/admin/migrate/reset", methods=["POST"])
    def api_migrate_reset():
        with _MIGRATE_LOCK:
            if _MIGRATE_STATE["running"]:
                return jsonify({"ok": False, "message": "迁移进行中，不能重置"}), 400
            _mig_cleanup_key(_MIGRATE_AUTH)
            _MIGRATE_AUTH.clear()
            _MIGRATE_STATE.update({"running": False, "step": "", "progress": 0,
                                   "log": [], "done": False, "success": False,
                                   "error": "", "target": ""})
        return jsonify({"ok": True, "message": "已重置，可再次迁移"})

    @app.route("/api/admin/setup", methods=["POST"])
    def admin_setup():
        # 仅在尚未创建管理员时可用（对应 admin 面板的首次初始化）
        if store.has_admin():
            return jsonify({"error": "admin already exists"}), 400
        data = request.get_json(force=True, silent=True) or {}
        username = (data.get("username") or "admin").strip() or "admin"
        password = data.get("password", "")
        if not password:
            return jsonify({"error": "password required"}), 400
        store.set_admin(username, password)
        _create_login_session(username, "superadmin")
        return jsonify({"ok": True, "username": username})

    @app.route("/api/admin/login", methods=["POST"])
    def admin_login():
        data = request.get_json(force=True, silent=True) or {}
        username = (data.get("username") or "").strip()
        password = data.get("password", "")
        # 1) 超级管理员（安装时创建的根账户）
        if store.verify_admin(password, username):
            if (store.get_setting("totp_enabled", "0") or "0") == "1":
                session["pre2fa"] = True
                return jsonify({"ok": False, "need_2fa": True})
            _create_login_session(store.get_admin_username(), "superadmin")
            return jsonify({"ok": True, "username": store.get_admin_username()})
        # 2) 普通账户（users 表）
        u = store.verify_user(username, password) if username else None
        if u:
            _create_login_session(u["username"], u.get("role") or "user")
            return jsonify({"ok": True, "username": u["username"]})
        store.log_event("warn", "auth",
                        f"用户 {username or '-'} 登录失败（IP {request.remote_addr or '-'}）")
        return jsonify({"error": "invalid username or password"}), 401

    @app.route("/api/admin/login/2fa", methods=["POST"])
    def admin_login_2fa():
        if not session.get("pre2fa"):
            return jsonify({"error": "login required"}), 401
        data = request.get_json(force=True, silent=True) or {}
        if _totp_verify(store.get_setting("totp_secret", ""), data.get("code", "")):
            session.pop("pre2fa", None)
            _create_login_session(store.get_admin_username(), "superadmin")
            return jsonify({"ok": True, "username": store.get_admin_username()})
        return jsonify({"error": "验证码错误"}), 401

    @app.route("/api/admin/logout", methods=["POST"])
    def admin_logout():
        sid = session.pop("sid", None)
        if sid:
            try:
                store._conn.execute("DELETE FROM sessions WHERE id = ?", (sid,))
                store._conn.commit()
            except Exception:
                pass
        session.pop("pre2fa", None)
        return jsonify({"ok": True})

    @app.route("/api/admin/status")
    def admin_status():
        u = _login_user()
        return jsonify({
            "has_admin": store.has_admin(),
            "logged_in": bool(u),
            "username": u["username"] if u else "",
            "role": u["role"] if u else "",
            "is_super": bool(u and u["is_super"]),
            "perms": sorted(u["perms"]) if u else [],
            "can_manage_users": bool(u and (u["is_super"] or u["role"] == "admin")),
            "nodes": len(store.list_clients()),
            "need_2fa": bool(session.get("pre2fa")),
        })

    @app.route("/api/admin/clients")
    @_require_perm("servers")
    def admin_clients():
        now = datetime.now(timezone.utc)
        today = now.date()
        out = []
        for c in store.list_clients():
            d = dict(c)
            d["online"] = _is_online(c)
            d["days_to_expiry"] = None
            exp = _parse_expiry_date(c.get("expired_at"))
            if exp is not None:
                d["days_to_expiry"] = (exp - today).days
            out.append(d)
        return jsonify(out)

    @app.route("/api/admin/client/add", methods=["POST"])
    @_require_perm("servers")
    def admin_client_add():
        data = request.get_json(force=True, silent=True) or {}
        client = store.add_client(name=data.get("name", ""))
        _auto_bind_ping_tasks(client["uuid"])
        return jsonify(client)

    @app.route("/api/admin/client/<client_uuid>", methods=["POST"])
    @_require_perm("servers")
    def admin_client_edit(client_uuid):
        data = request.get_json(force=True, silent=True) or {}
        ok = store.update_client(client_uuid, data)
        return jsonify({"ok": ok})

    @app.route("/api/admin/client/<client_uuid>", methods=["DELETE"])
    @_require_perm("servers")
    def admin_client_delete(client_uuid):
        return jsonify({"ok": store.delete_client(client_uuid)})

    def _client_traffic_now(c):
        """节点当前已用流量（与前台卡片同口径：最新记录入库后的累计总量，
        已按周期基线换算为本周期值；按 traffic_limit_type 取总和/出站/入站）。
        返回 (up, down, used)。"""
        r = store.latest_record(c["uuid"]) or {}
        up = r.get("net_total_up", 0) or 0
        down = r.get("net_total_down", 0) or 0
        mode = c.get("traffic_limit_type") or "sum"
        used = up if mode == "up" else down if mode == "down" else up + down
        return up, down, used

    @app.route("/api/admin/client/<client_uuid>/traffic")
    @_require_perm("servers")
    def admin_client_traffic(client_uuid):
        c = store.get_client(client_uuid)
        if not c:
            return jsonify({"ok": False, "message": "节点不存在"}), 404
        up, down, used = _client_traffic_now(c)
        cyc = _traffic_cycle_start(c)
        return jsonify({"ok": True, "up": up, "down": down, "used": used,
                        "mode": c.get("traffic_limit_type") or "sum",
                        "cycle_start": cyc.isoformat() if cyc else None})

    @app.route("/api/admin/client/<client_uuid>/traffic-calibrate", methods=["POST"])
    @_require_perm("servers")
    def admin_client_traffic_calibrate(client_uuid):
        """流量校准：把本周期已用流量校准到管理员给定的值。
        通过下调周期基线实现（显示用量 = 累计总量 − 基线），差值按当前
        出/入比例分摊；基线同时调整最新一条记录使前台立即生效。
        校准只作用于当前周期：跨入新周期时基线自动重置，用量重新累计。"""
        c = store.get_client(client_uuid)
        if not c:
            return jsonify({"ok": False, "message": "节点不存在"}), 404
        data = request.get_json(force=True, silent=True) or {}
        try:
            target = int(data.get("used_bytes"))
        except (TypeError, ValueError):
            return jsonify({"ok": False, "message": "已使用流量数值不合法"}), 400
        if target < 0:
            return jsonify({"ok": False, "message": "已使用流量不能为负"}), 400
        up, down, used = _client_traffic_now(c)
        delta = target - used
        mode = c.get("traffic_limit_type") or "sum"
        if mode == "up":
            d_up, d_down = delta, 0
        elif mode == "down":
            d_up, d_down = 0, delta
        elif up + down > 0:
            d_up = round(delta * up / (up + down))
            d_down = delta - d_up
        else:
            d_up, d_down = delta, 0
        fields = {
            "traffic_base_up": (c.get("traffic_base_up") or 0) - d_up,
            "traffic_base_down": (c.get("traffic_base_down") or 0) - d_down,
        }
        cyc = _traffic_cycle_start(c)
        if cyc is not None:
            fields["traffic_base_cycle"] = cyc.isoformat()
        store.update_client(client_uuid, fields)
        store.adjust_latest_record_totals(client_uuid, d_up, d_down)
        c2 = store.get_client(client_uuid)
        up2, down2, used2 = _client_traffic_now(c2)
        return jsonify({"ok": True, "up": up2, "down": down2, "used": used2})

    @app.route("/api/admin/domain")
    @_require_perm("domain")
    def admin_domain_get():
        domain = _domain_name()
        job = _domain_job_get()
        return jsonify({
            "ok": True, "domain": domain, "job": job,
            "cert_expiry": _domain_cert_expiry(),
            "https_url": f"https://{domain}" if domain else "",
            "http_listening": _domain_servers["http"] is not None,
            "https_listening": _domain_servers["https"] is not None,
        })

    @app.route("/api/admin/domain/deploy", methods=["POST"])
    @_require_perm("domain")
    def admin_domain_deploy():
        data = request.get_json(force=True, silent=True) or {}
        domain = (data.get("domain") or "").strip().lower()
        if not _DOMAIN_RE.match(domain):
            return jsonify({"ok": False, "message": "域名格式不合法（示例：panel.example.com，不要带 http:// 或端口）"}), 400
        job = _domain_job_get()
        if job.get("state") == "running":
            return jsonify({"ok": False, "message": "已有部署任务在进行中"}), 409
        _domain_job_set(state="running", step="排队", message="部署任务已启动…", domain=domain)
        threading.Thread(target=_domain_deploy_job, args=(domain,),
                         daemon=True, name="domain-deploy").start()
        return jsonify({"ok": True})

    @app.route("/api/admin/domain/remove", methods=["POST"])
    @_require_perm("domain")
    def admin_domain_remove():
        _domain_stop_servers()
        store.set_setting("domain_name", "")
        _domain_job_set(state="idle", step="", message="域名已移除，80/443 监听已关闭（证书文件保留在服务器上）。")
        return jsonify({"ok": True})

    @app.route("/api/admin/settings", methods=["GET", "POST"])
    @_require_perm("settings")
    def admin_settings():
        if request.method == "GET":
            out = store.get_public_settings()
            out.update({
                "offline_threshold": store.get_setting("offline_threshold", "180"),
                "record_keep_hours": store.get_setting("record_keep_hours", "24"),
                "ping_record_preserve_time": store.get_setting("ping_record_preserve_time", "4320"),
                "notify_enabled": store.get_setting("notify_enabled", "0"),
                "notify_webhook": store.get_setting("notify_webhook", ""),
                "notify_template": store.get_setting("notify_template", "【{event}】{message}"),
                "expiry_remind_enabled": store.get_setting("expiry_remind_enabled", "1"),
                "expiry_remind_days": store.get_setting("expiry_remind_days", "10"),
            })
            return jsonify(out)
        data = request.get_json(force=True, silent=True) or {}
        for k in ("sitename", "description", "theme"):
            if k in data:
                store.set_setting(k, str(data[k]))
        # 数值型配置做范围钳制
        if "offline_threshold" in data:
            try:
                v = max(30, min(3600, int(data["offline_threshold"])))
            except Exception:
                v = 180
            store.set_setting("offline_threshold", str(v))
        if "record_keep_hours" in data:
            try:
                v = max(1, min(720, int(data["record_keep_hours"])))
            except Exception:
                v = 24
            store.set_setting("record_keep_hours", str(v))
        if "ping_record_preserve_time" in data:
            try:
                v = max(24, min(8760, int(data["ping_record_preserve_time"])))
            except Exception:
                v = 4320
            store.set_setting("ping_record_preserve_time", str(v))
        if "notify_enabled" in data:
            store.set_setting("notify_enabled", "1" if str(data["notify_enabled"]) == "1" else "0")
        if "notify_webhook" in data:
            store.set_setting("notify_webhook", str(data["notify_webhook"]).strip()[:500])
        if "notify_template" in data:
            store.set_setting("notify_template", str(data["notify_template"])[:300])
        if "expiry_remind_enabled" in data:
            store.set_setting("expiry_remind_enabled",
                              "1" if str(data["expiry_remind_enabled"]) == "1" else "0")
        if "expiry_remind_days" in data:
            try:
                v = max(1, min(365, int(data["expiry_remind_days"])))
            except Exception:
                v = 10
            store.set_setting("expiry_remind_days", str(v))
        return jsonify({"ok": True})

    def _expiry_soon_list(within_days: int = 30):
        today = datetime.now(timezone.utc).date()
        out = []
        for c in store.list_clients():
            exp = _parse_expiry_date(c.get("expired_at"))
            if exp is None:
                continue
            exp_s = (c.get("expired_at") or "").strip()
            delta = (exp - today).days
            if 0 <= delta <= within_days:
                out.append({"uuid": c["uuid"], "name": c.get("name") or c["uuid"][:8],
                            "expired_at": exp_s, "days": delta})
        return sorted(out, key=lambda x: x["days"])

    @app.route("/api/admin/dashboard")
    @_require_perm("dashboard")
    def admin_dashboard():
        clients = store.list_clients()
        online = [c for c in clients if _is_online(c)]
        offline = [c for c in clients if not _is_online(c)]
        today = datetime.now(timezone.utc).strftime("%Y-%m-%dT00:00:00Z")
        return jsonify({
            "total": len(clients),
            "online": len(online),
            "offline": len(offline),
            "db_size": store.db_size(),
            "records": store.count_records(),
            "reports_today": store.count_records_since(today),
            "offline_threshold": _online_threshold(),
            "offline_nodes": [
                {"uuid": c["uuid"], "name": c.get("name") or c["uuid"][:8],
                 "last_report_at": c.get("last_report_at")}
                for c in sorted(offline, key=lambda c: c.get("last_report_at") or "")[:10]
            ],
            "expiry_soon": _expiry_soon_list(),
            "nodes": [
                {"uuid": c["uuid"], "name": c.get("name") or c["uuid"][:8],
                 "online": _is_online(c), "last_report_at": c.get("last_report_at")}
                for c in clients
            ],
        })

    @app.route("/api/admin/notify/test", methods=["POST"])
    @_require_perm("notify")
    def admin_notify_test():
        data = request.get_json(force=True, silent=True) or {}
        # 渠道下标优先；否则兼容旧的 webhook 直发
        if "index" in data:
            try:
                ch = _get_channels()[int(data["index"])]
            except Exception:
                return jsonify({"error": "渠道不存在"}), 404
            ok = _send_channel(ch, _render_msg("测试", "BigCat 通知测试：渠道工作正常"))
            return jsonify({"ok": ok} if ok else {"error": "发送失败，请检查渠道配置"}), 200 if ok else 502
        url = (data.get("webhook") or store.get_setting("notify_webhook", "") or "").strip()
        if not url:
            return jsonify({"error": "webhook url required"}), 400
        ok = _post_webhook(url, "✅ BigCat 通知测试：webhook 工作正常", timeout=10)
        return jsonify({"ok": ok} if ok else {"error": "webhook 发送失败，请检查 URL"}), 200 if ok else 502

    # ------------------------------------------------------------ v1.9.8 账户体系
    _USERNAME_RE = re.compile(r"^[A-Za-z0-9_-]{3,32}$")
    _PHONE_RE = re.compile(r"^[+\d][\d\s-]{4,19}$")
    _EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

    def _mask_phone(p):
        p = p or ""
        if len(p) <= 4:
            return "****"
        return p[:3] + "****" + p[-4:]

    def _mask_email(e):
        e = e or ""
        parts = e.split("@")
        if len(parts) != 2:
            return "****"
        name, domain = parts
        return (name[0] + "***" if name else "***") + "@" + domain

    def _account_lookup(username):
        """按用户名查找账户，返回 (kind, obj)：kind 为 'super' 或 'user'。"""
        username = (username or "").strip()
        if not username:
            return None, None
        if username == store.get_admin_username():
            return "super", {
                "username": store.get_admin_username(),
                "phone": store.get_setting("admin_phone", "") or "",
                "email": store.get_setting("admin_email", "") or "",
            }
        u = store.get_user_by_username(username)
        if u:
            return "user", u
        return None, None

    @app.route("/api/admin/profile")
    @_require_login
    def admin_profile():
        u = g.uinfo
        if u["is_super"]:
            phone = store.get_setting("admin_phone", "") or ""
            email = store.get_setting("admin_email", "") or ""
        else:
            phone, email = u.get("phone", ""), u.get("email", "")
        return jsonify({
            "username": u["username"], "role": u["role"], "is_super": u["is_super"],
            "perms": sorted(u["perms"]), "phone": phone, "email": email,
            "can_manage_users": u["is_super"] or u["role"] == "admin",
        })

    @app.route("/api/admin/profile", methods=["PUT"])
    @_require_login
    def admin_profile_update():
        u = g.uinfo
        data = request.get_json(force=True, silent=True) or {}
        # 仅当请求明确携带字段时才更新，避免改密码时清空绑定资料
        phone = (data.get("phone") or "").strip() if "phone" in data else None
        email = (data.get("email") or "").strip() if "email" in data else None
        if phone and not _PHONE_RE.match(phone):
            return jsonify({"error": "手机号格式无效"}), 400
        if email and not _EMAIL_RE.match(email):
            return jsonify({"error": "邮箱格式无效"}), 400
        new_password = data.get("new_password") or ""
        if new_password and len(new_password) < 6:
            return jsonify({"error": "新密码至少 6 位"}), 400
        if u["is_super"]:
            # 超管改密码 / 用户名需验证当前密码
            if new_password or (data.get("username") or "").strip():
                if not store.verify_admin(data.get("current_password", ""), store.get_admin_username()):
                    return jsonify({"error": "当前密码错误"}), 401
            username = (data.get("username") or "").strip()
            if username and username != store.get_admin_username():
                if not _USERNAME_RE.match(username):
                    return jsonify({"error": "用户名需 3-32 位字母/数字/_/-"}), 400
                if not new_password:
                    return jsonify({"error": "修改用户名需同时设置新密码"}), 400
                store.set_admin(username, new_password)
            elif new_password:
                store.set_admin_password(new_password)
            if phone is not None:
                store.set_setting("admin_phone", phone)
            if email is not None:
                store.set_setting("admin_email", email)
        else:
            if new_password:
                full = store.get_user_by_username(u["username"])
                if not full or full.get("password_hash") != store._hash_pw(data.get("current_password", "")):
                    return jsonify({"error": "当前密码错误"}), 401
                store.set_user_password(u["user_id"], new_password)
            contact = {}
            if phone is not None:
                contact["phone"] = phone
            if email is not None:
                contact["email"] = email
            if contact:
                store.update_user(u["user_id"], contact)
        store.log_event("info", "auth", f"用户 {u['username']} 更新了个人资料")
        return jsonify({"ok": True})

    @app.route("/api/admin/users")
    @_require_admin
    def admin_users_list():
        return jsonify(store.list_users())

    @app.route("/api/admin/users", methods=["POST"])
    @_require_admin
    def admin_users_create():
        me = g.uinfo
        data = request.get_json(force=True, silent=True) or {}
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""
        role = data.get("role") if data.get("role") in ("admin", "user") else "user"
        if not _USERNAME_RE.match(username):
            return jsonify({"error": "用户名需 3-32 位字母/数字/_/-"}), 400
        if len(password) < 6:
            return jsonify({"error": "密码至少 6 位"}), 400
        if username == store.get_admin_username() or store.get_user_by_username(username):
            return jsonify({"error": "用户名已存在"}), 400
        if role == "admin" and not me["is_super"]:
            return jsonify({"error": "只有超级管理员可以创建管理员账户"}), 403
        perms = [p for p in (data.get("perms") or []) if p in PERM_PAGES] if role == "user" else list(PERM_PAGES)
        phone = (data.get("phone") or "").strip()
        email = (data.get("email") or "").strip()
        if phone and not _PHONE_RE.match(phone):
            return jsonify({"error": "手机号格式无效"}), 400
        if email and not _EMAIL_RE.match(email):
            return jsonify({"error": "邮箱格式无效"}), 400
        u = store.create_user(username, password, role, perms, phone, email)
        store.log_event("info", "auth", f"用户 {me['username']} 创建了账户 {username}（{role}）")
        return jsonify({"ok": True, "user": u})

    @app.route("/api/admin/users/<int:uid>", methods=["PUT"])
    @_require_admin
    def admin_users_update(uid):
        me = g.uinfo
        u = store.get_user_by_id(uid)
        if not u:
            return jsonify({"error": "用户不存在"}), 404
        if u.get("role") == "admin" and not me["is_super"]:
            return jsonify({"error": "只有超级管理员可以管理管理员账户"}), 403
        data = request.get_json(force=True, silent=True) or {}
        fields = {}
        if "phone" in data:
            phone = (data.get("phone") or "").strip()
            if phone and not _PHONE_RE.match(phone):
                return jsonify({"error": "手机号格式无效"}), 400
            fields["phone"] = phone
        if "email" in data:
            email = (data.get("email") or "").strip()
            if email and not _EMAIL_RE.match(email):
                return jsonify({"error": "邮箱格式无效"}), 400
            fields["email"] = email
        if "role" in data:
            role = data.get("role")
            if role not in ("admin", "user"):
                return jsonify({"error": "角色无效"}), 400
            if role != u.get("role") and not me["is_super"]:
                return jsonify({"error": "只有超级管理员可以变更角色"}), 403
            fields["role"] = role
            fields["perms"] = json.dumps(list(PERM_PAGES) if role == "admin"
                                         else [p for p in (data.get("perms") or []) if p in PERM_PAGES])
        elif "perms" in data and u.get("role") == "user":
            fields["perms"] = json.dumps([p for p in (data.get("perms") or []) if p in PERM_PAGES])
        if "disabled" in data:
            if u["username"] == me["username"]:
                return jsonify({"error": "不能禁用自己的账户"}), 400
            fields["disabled"] = 1 if data.get("disabled") else 0
        if "new_password" in data and data.get("new_password"):
            if len(data.get("new_password")) < 6:
                return jsonify({"error": "密码至少 6 位"}), 400
            fields["password_hash"] = store._hash_pw(data.get("new_password"))
        if not fields:
            return jsonify({"error": "没有要修改的内容"}), 400
        store.update_user(uid, fields)
        store.log_event("info", "auth", f"用户 {me['username']} 更新了账户 {u['username']}")
        return jsonify({"ok": True, "user": store.get_user_by_id(uid)})

    @app.route("/api/admin/users/<int:uid>", methods=["DELETE"])
    @_require_admin
    def admin_users_delete(uid):
        me = g.uinfo
        u = store.get_user_by_id(uid)
        if not u:
            return jsonify({"error": "用户不存在"}), 404
        if u.get("role") == "admin" and not me["is_super"]:
            return jsonify({"error": "只有超级管理员可以删除管理员账户"}), 403
        if u["username"] == me["username"]:
            return jsonify({"error": "不能删除自己的账户"}), 400
        store.delete_user(uid)
        store.log_event("warn", "auth", f"用户 {me['username']} 删除了账户 {u['username']}")
        return jsonify({"ok": True})

    # ---------------- 忘记密码 / 找回密码（无需登录）
    @app.route("/api/admin/recover/request", methods=["POST"])
    def admin_recover_request():
        data = request.get_json(force=True, silent=True) or {}
        kind, obj = _account_lookup(data.get("username"))
        if not obj:
            return jsonify({"error": "账户不存在"}), 404
        phone, email = obj.get("phone") or "", obj.get("email") or ""
        if not phone and not email:
            return jsonify({"error": "该账户未绑定手机号或邮箱，无法自助找回，请联系管理员"}), 400
        return jsonify({"ok": True, "need_phone": bool(phone), "need_email": bool(email),
                        "masked_phone": _mask_phone(phone) if phone else "",
                        "masked_email": _mask_email(email) if email else ""})

    @app.route("/api/admin/recover/verify", methods=["POST"])
    def admin_recover_verify():
        data = request.get_json(force=True, silent=True) or {}
        kind, obj = _account_lookup(data.get("username"))
        if not obj:
            return jsonify({"error": "账户不存在"}), 404
        phone, email = obj.get("phone") or "", obj.get("email") or ""
        if not phone and not email:
            return jsonify({"error": "该账户未绑定手机号或邮箱，无法自助找回，请联系管理员"}), 400
        if phone and (data.get("phone") or "").strip() != phone:
            store.log_event("warn", "auth", f"账户 {obj['username']} 找回密码验证失败（手机）")
            return jsonify({"error": "验证信息不正确"}), 400
        if email and (data.get("email") or "").strip().lower() != email.lower():
            store.log_event("warn", "auth", f"账户 {obj['username']} 找回密码验证失败（邮箱）")
            return jsonify({"error": "验证信息不正确"}), 400
        token = store.create_recovery_token(obj["username"], kind == "super")
        return jsonify({"ok": True, "token": token})

    @app.route("/api/admin/recover/reset", methods=["POST"])
    def admin_recover_reset():
        data = request.get_json(force=True, silent=True) or {}
        new_password = data.get("new_password") or ""
        if len(new_password) < 6:
            return jsonify({"error": "新密码至少 6 位"}), 400
        rec = store.consume_recovery_token(data.get("token") or "")
        if not rec:
            return jsonify({"error": "验证已过期，请重新发起找回"}), 400
        if rec.get("is_super"):
            store.set_admin_password(new_password)
        else:
            u = store.get_user_by_username(rec.get("username") or "")
            if not u:
                return jsonify({"error": "账户不存在"}), 404
            store.set_user_password(u["id"], new_password)
        # 密码重置后强制该账户全部会话失效
        try:
            store._conn.execute("DELETE FROM sessions WHERE username = ?", (rec.get("username"),))
            store._conn.commit()
        except Exception:
            pass
        store.log_event("warn", "auth", f"账户 {rec.get('username')} 通过找回密码重置了密码")
        return jsonify({"ok": True})

    @app.route("/api/admin/sessions")
    @_require_perm("sessions")
    def admin_sessions():
        my_sid = session.get("sid")
        me = g.uinfo
        privileged = me["is_super"] or me["role"] == "admin"
        out = []
        for s in store.list_sessions():
            if not privileged and (s.get("username") or "") != me["username"]:
                continue
            out.append({
                "id": s["id"][:8] + "…",
                "ip": s.get("ip") or "",
                "username": s.get("username") or "",
                "role": s.get("role") or "",
                "user_agent": (s.get("user_agent") or "")[:120],
                "created_at": s.get("created_at"),
                "last_seen": s.get("last_seen"),
                "expires_at": s.get("expires_at"),
                "current": s["id"] == my_sid,
            })
        return jsonify({"sessions": out})

    @app.route("/api/admin/sessions/revoke_all", methods=["POST"])
    @_require_admin
    def admin_sessions_revoke_all():
        # 真正删除全部登录会话（含当前）：后续请求全部 401，当前用户需重新登录
        n = store.delete_all_sessions()
        store.log_event("warn", "auth", f"删除全部登录会话（{n} 个）")
        session.pop("sid", None)
        return jsonify({"ok": True, "deleted": n})

    @app.route("/api/admin/logs")
    @_require_perm("logs")
    def admin_logs():
        try:
            lines = max(50, min(1000, int(request.args.get("lines", 200))))
        except Exception:
            lines = 200
        try:
            out = subprocess.run(
                ["journalctl", "-u", "bigcat", "--no-pager", "-n", str(lines)],
                capture_output=True, text=True, timeout=10,
            )
            if out.returncode == 0 and out.stdout.strip():
                return jsonify({"source": "journalctl -u bigcat", "logs": out.stdout})
        except Exception:
            pass
        return jsonify({"source": "", "logs": "",
                        "hint": "未找到 systemd 日志（journalctl -u bigcat 不可用），请直接在服务器上查看"})

    @app.route("/api/admin/events")
    @_require_perm("events")
    def admin_events():
        try:
            page = max(1, int(request.args.get("page", 1)))
        except Exception:
            page = 1
        try:
            per_page = max(10, min(200, int(request.args.get("per_page", 50))))
        except Exception:
            per_page = 50
        return jsonify({
            "total": store.count_events(),
            "events": store.list_events(per_page, (page - 1) * per_page),
        })

    @app.route("/api/admin/events", methods=["DELETE"])
    @_require_perm("events")
    def admin_events_clear():
        n = store.clear_events()
        return jsonify({"ok": True, "deleted": n})

    @app.route("/api/admin/about")
    @_require_login
    def admin_about():
        try:
            flask_v = _pkg_version("flask")
        except Exception:
            flask_v = "unknown"
        import platform
        return jsonify({
            "bigcat": VERSION,
            "python": platform.python_version(),
            "flask": flask_v,
            "platform": platform.platform(),
            "db_path": str(store.db_path),
            "db_size": store.db_size(),
            "records": store.count_records(),
            "uptime_sec": int(time.time() - STARTED_AT),
            "started_at": datetime.fromtimestamp(STARTED_AT, timezone.utc).isoformat().replace("+00:00", "Z"),
        })

    # ============================================================ v3 API
    # ---------------- 统计 ----------------
    @app.route("/api/admin/stats/traffic")
    @_require_perm("dashboard")
    def admin_stats_traffic():
        try:
            hours = max(1, min(168, int(request.args.get("hours", 24))))
        except Exception:
            hours = 24
        end = datetime.now(timezone.utc)
        start = end - timedelta(hours=hours)
        bucket_sec = max(300, int(hours * 3600 / 48))
        rows = store.traffic_series(_iso(start), _iso(end), bucket_sec)
        return jsonify({
            "labels": [r["time"][11:16] if len(r["time"]) > 16 else r["time"] for r in rows],
            "up": [r["up"] for r in rows],
            "down": [r["down"] for r in rows],
            "bucket_sec": bucket_sec,
        })

    @app.route("/api/admin/stats/rank")
    @_require_perm("dashboard")
    def admin_stats_rank():
        try:
            hours = max(1, min(168, int(request.args.get("hours", 24))))
        except Exception:
            hours = 24
        end = datetime.now(timezone.utc)
        start = _iso(end - timedelta(hours=hours))
        end_s = _iso(end)
        out = []
        for c in store.list_clients():
            t = store.sum_traffic(c["uuid"], start, end_s)
            m = store.avg_metrics(c["uuid"], start)
            p = store.peak_metrics(c["uuid"], start)
            out.append({
                "uuid": c["uuid"],
                "name": c.get("name") or c["uuid"][:8],
                "up": t["up"], "down": t["down"], "total": t["up"] + t["down"],
                "avg_cpu": m["cpu"], "avg_mem": m["mem"],
                "online": _is_online(c),
                "peak_cpu": p["peak_cpu"], "peak_cpu_at": p["peak_cpu_at"],
                "peak_mem": p["peak_mem"], "peak_mem_at": p["peak_mem_at"],
                "peak_up": p["peak_up"], "peak_up_at": p["peak_up_at"],
                "peak_down": p["peak_down"], "peak_down_at": p["peak_down_at"],
            })
        return jsonify(out)

    @app.route("/api/admin/stats/ping-rank")
    @_require_perm("dashboard")
    def admin_stats_ping_rank():
        """延迟排行：每 (任务, 节点) 的平均延迟/抖动/丢包率（近24h）。"""
        try:
            hours = max(1, min(168, int(request.args.get("hours", 24))))
        except Exception:
            hours = 24
        end = datetime.now(timezone.utc)
        start = _iso(end - timedelta(hours=hours))
        tasks = {t["id"]: t.get("name") or t.get("target", "")
                 for t in store.list_ping_tasks()}
        clients = {c["uuid"]: (c.get("name") or c["uuid"][:8])
                   for c in store.list_clients()}
        out = []
        for s in store.ping_rank_stats(start):
            out.append({
                "task_id": s["task_id"],
                "task": tasks.get(s["task_id"], str(s["task_id"])),
                "client_uuid": s["client_uuid"],
                "name": clients.get(s["client_uuid"], s["client_uuid"][:8]),
                "avg_lat": s["avg_lat"], "jitter": s["jitter"],
                "loss": s["loss"], "n": s["n"],
            })
        return jsonify(out)

    @app.route("/api/admin/dashboard_order", methods=["GET"])
    @_require_perm("dashboard")
    def admin_dashboard_order():
        """仪表板卡片排序（仅视觉顺序）。"""
        try:
            order = json.loads(store.get_setting("admin_dashboard_order", "[]"))
        except Exception:
            order = []
        if not isinstance(order, list):
            order = []
        return jsonify({"order": [str(x) for x in order if str(x).strip()]})

    @app.route("/api/admin/dashboard_order", methods=["POST"])
    @_require_perm("dashboard")
    def admin_dashboard_order_save():
        data = request.get_json(force=True, silent=True) or {}
        order = data.get("order") or []
        order = [str(x) for x in order if str(x).strip()]
        seen, clean = set(), []
        for x in order:
            if x not in seen:
                seen.add(x)
                clean.append(x)
        store.set_setting("admin_dashboard_order", json.dumps(clean))
        return jsonify({"ok": True})

    @app.route("/api/admin/nav_order", methods=["GET"])
    def admin_nav_order():
        """左侧菜单排序（仅视觉顺序，按登录用户分别保存）。"""
        me = _login_user()
        key = f"admin_nav_order_{me['username']}" if me else "admin_nav_order"
        try:
            order = json.loads(store.get_setting(key, "[]"))
        except Exception:
            order = []
        if not isinstance(order, list):
            order = []
        return jsonify({"order": [str(x) for x in order if str(x).strip()]})

    @app.route("/api/admin/nav_order", methods=["POST"])
    def admin_nav_order_save():
        me = _login_user()
        if not me:
            return jsonify({"error": "unauthorized"}), 401
        key = f"admin_nav_order_{me['username']}"
        data = request.get_json(force=True, silent=True) or {}
        order = data.get("order") or []
        order = [str(x) for x in order if str(x).strip()]
        seen, clean = set(), []
        for x in order:
            if x not in seen:
                seen.add(x)
                clean.append(x)
        store.set_setting(key, json.dumps(clean))
        return jsonify({"ok": True})

    @app.route("/api/admin/stats/ping")
    @_require_perm("dashboard")
    def admin_stats_ping():
        try:
            hours = max(1, min(720, int(request.args.get("hours", 24))))
        except Exception:
            hours = 24
        since = _iso(datetime.now(timezone.utc) - timedelta(hours=hours))
        return jsonify(store.ping_stats(since))

    # ---------------- 延迟监测任务 ----------------
    @app.route("/api/admin/ping/tasks", methods=["GET"])
    @_require_perm("ping")
    def admin_ping_tasks():
        return jsonify([_public_ping_task(t) for t in store.list_ping_tasks()])

    @app.route("/api/admin/ping/tasks", methods=["POST"])
    @_require_perm("ping")
    def admin_ping_task_add():
        data = request.get_json(force=True, silent=True) or {}
        name = (data.get("name") or "").strip()
        target = (data.get("target") or "").strip()
        if not name or not target:
            return jsonify({"error": "name 和 target 必填"}), 400
        typ = (data.get("type") or "tcp").strip().lower()
        if typ not in ("tcp", "http", "icmp"):
            typ = "tcp"
        try:
            interval = max(30, min(86400, int(data.get("interval_sec", 300))))
        except Exception:
            interval = 300
        task = store.add_ping_task(name, target, typ, interval)
        if "clients" in data:
            store.set_ping_task_clients(task["id"], data.get("clients") or [])
        store.log_event("info", "ping", f"新增延迟任务「{name}」（{typ} {target}）")
        return jsonify(_public_ping_task(task))

    @app.route("/api/admin/ping/tasks/<int:task_id>", methods=["PUT"])
    @_require_perm("ping")
    def admin_ping_task_update(task_id):
        data = request.get_json(force=True, silent=True) or {}
        fields = {}
        if "name" in data:
            fields["name"] = str(data["name"]).strip()
        if "target" in data:
            fields["target"] = str(data["target"]).strip()
        if "type" in data and str(data["type"]).lower() in ("tcp", "http", "icmp"):
            fields["type"] = str(data["type"]).lower()
        if "interval_sec" in data:
            try:
                fields["interval_sec"] = max(30, min(86400, int(data["interval_sec"])))
            except Exception:
                pass
        if "enabled" in data:
            fields["enabled"] = 1 if str(data["enabled"]) == "1" else 0
        store.update_ping_task(task_id, fields)
        if "clients" in data:
            store.set_ping_task_clients(task_id, data.get("clients") or [])
        return jsonify({"ok": True})

    @app.route("/api/admin/ping/tasks/<int:task_id>", methods=["DELETE"])
    @_require_perm("ping")
    def admin_ping_task_delete(task_id):
        store.delete_ping_task(task_id)
        store.log_event("info", "ping", f"删除延迟任务 {task_id}")
        return jsonify({"ok": True})

    @app.route("/api/admin/ping/results")
    @_require_perm("ping")
    def admin_ping_results():
        try:
            hours = max(1, min(720, int(request.args.get("hours", 24))))
        except Exception:
            hours = 24
        since = _iso(datetime.now(timezone.utc) - timedelta(hours=hours))
        task_id = request.args.get("task_id")
        try:
            task_id = int(task_id) if task_id else None
        except Exception:
            task_id = None
        return jsonify(store.ping_results(task_id, since, limit=2000))

    # ---------------- 负载告警规则 ----------------
    @app.route("/api/admin/alerts", methods=["GET"])
    @_require_perm("alerts")
    def admin_alerts():
        return jsonify(store.list_alert_rules())

    @app.route("/api/admin/alerts", methods=["POST"])
    @_require_perm("alerts")
    def admin_alert_add():
        data = request.get_json(force=True, silent=True) or {}
        name = (data.get("name") or "").strip() or "未命名规则"
        metric = str(data.get("metric", "cpu")).lower()
        if metric not in ("cpu", "ram", "disk"):
            metric = "cpu"
        try:
            threshold = max(1, min(100, float(data.get("threshold", 90))))
        except Exception:
            threshold = 90
        try:
            ratio = max(0.1, min(1.0, float(data.get("ratio", 0.8))))
        except Exception:
            ratio = 0.8
        try:
            interval = max(1, min(1440, int(data.get("interval_min", 2))))
        except Exception:
            interval = 2
        clients = data.get("clients") or []
        if not isinstance(clients, list):
            clients = []
        rule = store.add_alert_rule(name, metric, threshold, ratio, interval,
                                    json.dumps([str(x) for x in clients]))
        store.log_event("info", "alert", f"新增告警规则「{name}」")
        return jsonify(rule)

    @app.route("/api/admin/alerts/<int:rule_id>", methods=["PUT"])
    @_require_perm("alerts")
    def admin_alert_update(rule_id):
        data = request.get_json(force=True, silent=True) or {}
        fields = {}
        if "name" in data:
            fields["name"] = str(data["name"]).strip()
        if "metric" in data and str(data["metric"]).lower() in ("cpu", "ram", "disk"):
            fields["metric"] = str(data["metric"]).lower()
        for k in ("threshold", "ratio", "interval_min", "enabled"):
            if k in data:
                fields[k] = data[k]
        if "clients" in data:
            clients = data.get("clients") or []
            if not isinstance(clients, list):
                clients = []
            fields["clients"] = json.dumps([str(x) for x in clients])
        store.update_alert_rule(rule_id, fields)
        return jsonify({"ok": True})

    @app.route("/api/admin/alerts/<int:rule_id>", methods=["DELETE"])
    @_require_perm("alerts")
    def admin_alert_delete(rule_id):
        store.delete_alert_rule(rule_id)
        return jsonify({"ok": True})

    # ---------------- 通知 ----------------
    @app.route("/api/admin/notify/channels", methods=["GET"])
    @_require_perm("notify")
    def admin_notify_channels():
        return jsonify(_get_channels())

    @app.route("/api/admin/notify/channels", methods=["POST"])
    @_require_perm("notify")
    def admin_notify_channel_add():
        data = request.get_json(force=True, silent=True) or {}
        typ = str(data.get("type", "webhook")).lower()
        if typ not in ("webhook", "telegram", "bark"):
            return jsonify({"error": "未知渠道类型"}), 400
        ch = _get_channels()
        ch.append({
            "name": (data.get("name") or typ).strip()[:50],
            "type": typ,
            "enabled": bool(data.get("enabled", True)),
            "config": data.get("config") or {},
        })
        _save_channels(ch)
        return jsonify({"ok": True, "index": len(ch) - 1})

    @app.route("/api/admin/notify/channels/<int:index>", methods=["PUT"])
    @_require_perm("notify")
    def admin_notify_channel_update(index):
        data = request.get_json(force=True, silent=True) or {}
        ch = _get_channels()
        if not (0 <= index < len(ch)):
            return jsonify({"error": "渠道不存在"}), 404
        c = ch[index]
        if "name" in data:
            c["name"] = str(data["name"]).strip()[:50]
        if "enabled" in data:
            c["enabled"] = bool(data["enabled"])
        if "config" in data:
            c["config"] = data["config"] or {}
        _save_channels(ch)
        return jsonify({"ok": True})

    @app.route("/api/admin/notify/channels/<int:index>", methods=["DELETE"])
    @_require_perm("notify")
    def admin_notify_channel_delete(index):
        ch = _get_channels()
        if not (0 <= index < len(ch)):
            return jsonify({"error": "渠道不存在"}), 404
        ch.pop(index)
        _save_channels(ch)
        return jsonify({"ok": True})

    @app.route("/api/admin/notify/offline")
    @_require_perm("notify")
    def admin_notify_offline():
        return jsonify([{
            "uuid": c["uuid"],
            "name": c.get("name") or c["uuid"][:8],
            "online": _is_online(c),
            "notify_offline": c.get("notify_offline", 1),
            "offline_grace": c.get("offline_grace") or _online_threshold(),
        } for c in store.list_clients()])

    @app.route("/api/admin/notify/offline/<client_uuid>", methods=["PUT"])
    @_require_perm("notify")
    def admin_notify_offline_update(client_uuid):
        data = request.get_json(force=True, silent=True) or {}
        fields = {}
        if "notify_offline" in data:
            fields["notify_offline"] = 1 if str(data["notify_offline"]) == "1" else 0
        if "offline_grace" in data:
            try:
                fields["offline_grace"] = max(30, min(86400, int(data["offline_grace"])))
            except Exception:
                pass
        if not store.get_client(client_uuid):
            return jsonify({"error": "node not found"}), 404
        store.update_client(client_uuid, fields)
        return jsonify({"ok": True})

    @app.route("/api/admin/notify/traffic", methods=["GET"])
    @_require_perm("notify")
    def admin_notify_traffic_get():
        return jsonify([{
            "uuid": c["uuid"],
            "name": c.get("name") or c["uuid"][:8],
            "report_enabled": c.get("report_enabled", 0),
            "report_types": c.get("report_types") or "",
        } for c in store.list_clients()])

    @app.route("/api/admin/notify/traffic", methods=["PUT"])
    @_require_perm("notify")
    def admin_notify_traffic_put():
        data = request.get_json(force=True, silent=True) or {}
        if not isinstance(data, dict):
            return jsonify({"error": "invalid body"}), 400
        for uuid, cfg in data.items():
            if not store.get_client(uuid):
                continue
            fields = {}
            if isinstance(cfg, dict):
                if "report_enabled" in cfg:
                    fields["report_enabled"] = 1 if str(cfg["report_enabled"]) == "1" else 0
                if "report_types" in cfg:
                    types = [t for t in str(cfg["report_types"]).split(",") if t in ("daily", "weekly", "monthly")]
                    fields["report_types"] = ",".join(types)
                store.update_client(uuid, fields)
        return jsonify({"ok": True})

    # ---------------- 2FA ----------------
    @app.route("/api/admin/2fa")
    @_require_superadmin
    def admin_2fa_status():
        return jsonify({"enabled": (store.get_setting("totp_enabled", "0") or "0") == "1"})

    @app.route("/api/admin/2fa/setup", methods=["POST"])
    @_require_superadmin
    def admin_2fa_setup():
        secret = _new_totp_secret()
        session["totp_pending"] = secret
        user = store.get_admin_username()
        uri = (f"otpauth://totp/BigCat:{user}?secret={secret}"
               f"&issuer=BigCat&algorithm=SHA1&digits=6&period=30")
        return jsonify({"secret": secret, "uri": uri})

    @app.route("/api/admin/2fa/enable", methods=["POST"])
    @_require_superadmin
    def admin_2fa_enable():
        data = request.get_json(force=True, silent=True) or {}
        secret = session.get("totp_pending")
        if not secret:
            return jsonify({"error": "请先生成密钥"}), 400
        if _totp_verify(secret, data.get("code", "")):
            store.set_setting("totp_secret", secret)
            store.set_setting("totp_enabled", "1")
            session.pop("totp_pending", None)
            store.log_event("info", "auth", "管理员启用了双重认证")
            return jsonify({"ok": True})
        return jsonify({"error": "验证码错误"}), 400

    @app.route("/api/admin/2fa/disable", methods=["POST"])
    @_require_superadmin
    def admin_2fa_disable():
        data = request.get_json(force=True, silent=True) or {}
        if not store.verify_admin(data.get("password", ""), store.get_admin_username()):
            return jsonify({"error": "密码错误"}), 401
        store.set_setting("totp_enabled", "0")
        store.log_event("warn", "auth", "管理员关闭了双重认证")
        return jsonify({"ok": True})

    # ---------------- 远程执行 ----------------
    @app.route("/api/admin/exec", methods=["POST"])
    @_require_perm("exec")
    def admin_exec():
        data = request.get_json(force=True, silent=True) or {}
        command = (data.get("command") or "").strip()
        uuids = data.get("client_uuids") or []
        if not command or not uuids:
            return jsonify({"error": "command 和 client_uuids 必填"}), 400
        created = [store.add_exec_task(u, command[:2000])["id"]
                   for u in uuids if store.get_client(u)]
        store.log_event("warn", "exec",
                        f"管理员下发远程执行命令（{len(created)} 个节点）: {command[:120]}")
        return jsonify({"ok": True, "task_ids": created})

    @app.route("/api/admin/exec/tasks")
    @_require_perm("exec")
    def admin_exec_tasks():
        try:
            limit = max(10, min(500, int(request.args.get("limit", 50))))
        except Exception:
            limit = 50
        rows = store.list_exec_tasks(limit)
        names = {c["uuid"]: (c.get("name") or c["uuid"][:8]) for c in store.list_clients()}
        for r in rows:
            r["client_name"] = names.get(r["client_uuid"], r["client_uuid"][:8])
        return jsonify(rows)

    # ---------------- 数据库维护 ----------------
    @app.route("/api/admin/db/info")
    @_require_perm("database")
    def admin_db_info():
        cur = store._conn.cursor()
        ping_n = cur.execute("SELECT COUNT(*) FROM ping_results").fetchone()[0]
        sess_n = cur.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        return jsonify({
            "db_size": store.db_size(),
            "records": store.count_records(),
            "events": store.count_events(),
            "ping_results": ping_n,
            "sessions": sess_n,
            "record_keep_hours": store.get_setting("record_keep_hours", "24"),
            "ping_record_preserve_time": store.get_setting("ping_record_preserve_time", "4320"),
        })

    @app.route("/api/admin/db/vacuum", methods=["POST"])
    @_require_perm("database")
    def admin_db_vacuum():
        res = store.vacuum()
        store.log_event("info", "db",
                        f"数据库压缩完成：{res['before']} → {res['after']} 字节")
        return jsonify({"ok": True, **res})

    # ============================================================ theme & skin
    def _theme_info(short, manifest=None):
        m = manifest or _theme_manifest(short) or {}
        return {
            "name": m.get("name", short),
            "short": short,
            "description": m.get("description", ""),
            "version": m.get("version", ""),
            "author": m.get("author", ""),
            "url": m.get("url", ""),
            "preview": m.get("preview", ""),
        }

    def _install_theme_zip(data: bytes):
        """校验并解压主题 zip，返回主题信息；失败 raise ValueError(msg)。"""
        import io as _io
        try:
            zf = _zipfile.ZipFile(_io.BytesIO(data))
        except Exception:
            raise ValueError("不是有效的 ZIP 文件")
        names = zf.namelist()
        if len(names) > _MAX_THEME_FILES:
            raise ValueError("主题文件数量超限")
        total = 0
        for info in zf.infolist():
            if info.is_dir():
                continue
            if info.file_size > _MAX_THEME_FILE_SIZE:
                raise ValueError(f"主题文件 {info.filename} 超过大小限制")
            total += info.file_size
            if total > _MAX_THEME_TOTAL_SIZE:
                raise ValueError("主题解压后总大小超限")
        if "komari-theme.json" not in names:
            raise ValueError("缺少 komari-theme.json（需放在压缩包根目录）")
        try:
            manifest = json.loads(zf.read("komari-theme.json").decode("utf-8"))
        except Exception:
            raise ValueError("komari-theme.json 不是有效的 JSON")
        name = str(manifest.get("name") or "").strip()
        short = str(manifest.get("short") or "").strip()
        if not name or not short:
            raise ValueError("komari-theme.json 缺少必填字段 name / short")
        if short == "default" or not _THEME_SHORT_RE.match(short):
            raise ValueError("short 无效（仅允许字母、数字、下划线、连字符，且不能为 default）")
        if "dist/index.html" not in names:
            raise ValueError("主题包内缺少 dist/index.html")
        dest = os.path.join(THEMES_DIR, short)
        base = os.path.realpath(dest)
        if os.path.isdir(dest):
            _shutil.rmtree(dest)
        os.makedirs(dest, exist_ok=True)
        try:
            for info in zf.infolist():
                rel = info.filename.replace("\\", "/")
                target = os.path.realpath(os.path.join(dest, rel))
                if target != base and not target.startswith(base + os.sep):
                    continue  # 路径穿越，跳过
                if info.is_dir():
                    os.makedirs(target, exist_ok=True)
                    continue
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with zf.open(info) as src, open(target, "wb") as out:
                    _shutil.copyfileobj(src, out)
        except Exception as e:
            _shutil.rmtree(dest, ignore_errors=True)
            raise ValueError(f"解压主题失败: {e}")
        return _theme_info(short, manifest)

    def _download_theme(url: str) -> bytes:
        m = re.match(r"https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$", url)
        if m:
            owner, repo = m.group(1), m.group(2)
            req = urllib.request.Request(
                f"https://api.github.com/repos/{owner}/{repo}/releases/latest",
                headers={"User-Agent": "BigCat", "Accept": "application/vnd.github+json"})
            try:
                with urllib.request.urlopen(req, timeout=20) as r:
                    rel = json.loads(r.read().decode("utf-8"))
            except Exception as e:
                raise ValueError(f"获取 GitHub release 失败: {e}")
            zip_url = next((a.get("browser_download_url") for a in (rel.get("assets") or [])
                            if str(a.get("name") or "").lower().endswith(".zip")), None)
            if not zip_url:
                raise ValueError("该仓库最新 release 中没有 zip 资源")
            url = zip_url
        req = urllib.request.Request(url, headers={"User-Agent": "BigCat"})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                data = r.read(_MAX_THEME_TOTAL_SIZE + 1)
        except Exception as e:
            raise ValueError(f"下载主题失败: {e}")
        if len(data) > _MAX_THEME_TOTAL_SIZE:
            raise ValueError("主题文件过大")
        return data

    @app.route("/api/admin/theme/list")
    @_require_perm("themes")
    def admin_theme_list():
        active = _active_theme_short()
        themes = [{
            "name": "默认主题（内置 LuminaPlus）", "short": "default",
            "description": "BigCat 内置前台主题", "version": VERSION,
            "author": "BigCat", "url": "", "preview": "",
            "active": active == "default",
        }]
        try:
            entries = sorted(os.listdir(THEMES_DIR))
        except Exception:
            entries = []
        for e in entries:
            m = _theme_manifest(e)
            if not m:
                continue
            info = _theme_info(e, m)
            info["active"] = (e == active)
            themes.append(info)
        return jsonify({"themes": themes, "active": active})

    @app.route("/api/admin/theme/upload", methods=["POST"])
    @_require_perm("themes")
    def admin_theme_upload():
        f = request.files.get("file")
        if not f:
            return jsonify({"error": "请选择主题 zip 文件"}), 400
        data = f.read()
        if len(data) > _MAX_THEME_TOTAL_SIZE:
            return jsonify({"error": "文件过大"}), 400
        try:
            info = _install_theme_zip(data)
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        return jsonify({"ok": True, "theme": info})

    @app.route("/api/admin/theme/import", methods=["POST"])
    @_require_perm("themes")
    def admin_theme_import():
        body = request.get_json(force=True, silent=True) or {}
        url = (body.get("url") or "").strip()
        if not url.startswith(("http://", "https://")):
            return jsonify({"error": "请输入 http(s) 链接"}), 400
        try:
            data = _download_theme(url)
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        try:
            info = _install_theme_zip(data)
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        return jsonify({"ok": True, "theme": info})

    @app.route("/api/admin/theme/set")
    @_require_perm("themes")
    def admin_theme_set():
        short = (request.args.get("theme") or "").strip()
        if short != "default" and not _theme_manifest(short):
            return jsonify({"error": "主题不存在"}), 404
        store.set_setting("active_theme", short)
        return jsonify({"ok": True, "theme": short})

    @app.route("/api/admin/theme/delete", methods=["POST"])
    @_require_perm("themes")
    def admin_theme_delete():
        body = request.get_json(force=True, silent=True) or {}
        short = (body.get("short") or "").strip()
        if short == "default" or not _THEME_SHORT_RE.match(short):
            return jsonify({"error": "不能删除该主题"}), 400
        if _active_theme_short() == short:
            return jsonify({"error": "该主题正在使用中，请先切换到其他主题"}), 400
        d = os.path.join(THEMES_DIR, short)
        if not os.path.isdir(d) or not _theme_manifest(short):
            return jsonify({"error": "主题不存在"}), 404
        _shutil.rmtree(d, ignore_errors=True)
        return jsonify({"ok": True})

    @app.route("/api/admin/theme/settings", methods=["GET", "POST"])
    @_require_perm("themes")
    def admin_theme_settings():
        body = request.get_json(force=True, silent=True) if request.method == "POST" else {}
        short = ((request.args.get("theme") or (body or {}).get("theme")
                  or _active_theme_short()) or "").strip()
        if request.method == "GET":
            return jsonify({"theme": short, "settings": store.get_theme_settings(short)})
        if not isinstance(body, dict):
            return jsonify({"error": "设置必须为 JSON 对象"}), 400
        body = {k: v for k, v in body.items() if k != "theme"}
        store.set_theme_settings(short, body)
        return jsonify({"ok": True})

    @app.route("/api/admin/theme/preview/<short>")
    @_require_perm("themes")
    def admin_theme_preview(short):
        m = _theme_manifest(short)
        if not m:
            return jsonify({"error": "主题不存在"}), 404
        rel = str(m.get("preview") or "").replace("\\", "/").lstrip("/")
        if not rel or ".." in rel:
            return jsonify({"error": "无预览图"}), 404
        return send_from_directory(os.path.join(THEMES_DIR, short), rel)

    # ------------------------------------------------------------ admin skin
    @app.route("/api/admin/ip-info/v1/refresh", methods=["POST"])
    @_require_perm("servers")
    def api_ipinfo_refresh():
        return jsonify({"ok": False, "message": "IP 信息功能未启用"}), 503

    @app.route("/api/admin/ping")
    @_require_perm("ping")
    def api_admin_ping():
        # 主题期望裸数组 [{id, interval, name, loss, clients, type, target, weight}]
        tasks = store.list_ping_tasks() if hasattr(store, "list_ping_tasks") else []
        return jsonify([{
            "id": t.get("id"), "interval": t.get("interval_sec") or 60,
            "name": t.get("name") or "", "loss": 0, "clients": [],
            "type": t.get("type") or "icmp", "target": t.get("target") or "",
            "weight": 0,
        } for t in tasks])

    @app.route("/api/admin/client/list")
    @_require_perm("servers")
    def api_admin_client_list():
        # 主题期望裸数组 [{uuid, name, group, region, weight}]
        return jsonify([{
            "uuid": c.get("uuid"), "name": c.get("name") or "",
            "group": c.get("group") or "", "region": c.get("region") or "",
            "weight": c.get("weight") or 0,
        } for c in store.list_clients()])

    _SKIN_ACCENT_RE = re.compile(r"^#[0-9a-fA-F]{6}$")
    _SKIN_BG_MAX_SIZE = 5 << 20  # 背景图上限 5MB
    _SKIN_BG_EXTS = {
        ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
        ".gif": "image/gif", ".webp": "image/webp",
    }
    SKIN_DIR = os.path.join(os.path.dirname(os.path.abspath(db_path)), "skin")
    os.makedirs(SKIN_DIR, exist_ok=True)

    def _skin_bg_file():
        """返回已上传的背景图路径（任意允许的扩展名），没有则返回 None。"""
        for ext in _SKIN_BG_EXTS:
            p = os.path.join(SKIN_DIR, "background" + ext)
            if os.path.isfile(p):
                return p
        return None

    def _get_skin():
        try:
            skin = json.loads(store.get_setting("admin_skin", "") or "")
        except Exception:
            skin = {}
        mode = skin.get("mode") if skin.get("mode") in ("dark", "light") else "dark"
        accent = skin.get("accent")
        if not _SKIN_ACCENT_RE.match(str(accent or "")):
            accent = "#2f81f7"
        try:
            bg_dim = float(skin.get("bg_dim", 0.55))
        except (TypeError, ValueError):
            bg_dim = 0.55
        bg_dim = max(0.0, min(0.85, bg_dim))
        bg_version = skin.get("bg_version", 0) or 0
        background = ""
        if _skin_bg_file():
            background = f"/api/admin/skin/background?v={bg_version}"
        return {"mode": mode, "accent": accent, "bg_dim": bg_dim,
                "background": background}

    @app.route("/api/admin/skin", methods=["GET", "PUT"])
    @_require_perm("skin")
    def admin_skin():
        if request.method == "GET":
            return jsonify(_get_skin())
        body = request.get_json(force=True, silent=True) or {}
        mode = body.get("mode") if body.get("mode") in ("dark", "light") else "dark"
        accent = str(body.get("accent") or "")
        if not _SKIN_ACCENT_RE.match(accent):
            return jsonify({"error": "强调色格式无效（需 #rrggbb）"}), 400
        try:
            raw = json.loads(store.get_setting("admin_skin", "") or "") or {}
        except Exception:
            raw = {}
        try:
            bg_dim = max(0.0, min(0.85, float(body.get("bg_dim", raw.get("bg_dim", 0.55)))))
        except (TypeError, ValueError):
            bg_dim = 0.55
        skin = {"mode": mode, "accent": accent, "bg_dim": bg_dim,
                "bg_version": raw.get("bg_version", 0) or 0}
        store.set_setting("admin_skin", json.dumps(skin))
        return jsonify({"ok": True, "skin": _get_skin()})

    def _valid_skin_bg(data: bytes, filename: str):
        """校验上传的背景图：扩展名白名单 + 文件头魔数 + 大小。"""
        if not data or len(data) > _SKIN_BG_MAX_SIZE:
            return None
        ext = os.path.splitext(filename or "")[1].lower()
        if ext not in _SKIN_BG_EXTS:
            return None
        sig_ok = (
            data.startswith(b"\x89PNG\r\n\x1a\n") or
            data.startswith(b"\xff\xd8\xff") or
            data.startswith(b"GIF87a") or data.startswith(b"GIF89a") or
            (data.startswith(b"RIFF") and data[8:12] == b"WEBP")
        )
        return ext if sig_ok else None

    @app.route("/api/admin/skin/background", methods=["GET", "POST", "DELETE"])
    @_require_perm("skin")
    def admin_skin_background():
        if request.method == "GET":
            p = _skin_bg_file()
            if not p:
                return jsonify({"error": "未上传背景图"}), 404
            ext = os.path.splitext(p)[1].lower()
            return app.response_class(
                open(p, "rb").read(), mimetype=_SKIN_BG_EXTS.get(ext, "image/png"))
        if request.method == "DELETE":
            p = _skin_bg_file()
            if p:
                try:
                    os.remove(p)
                except OSError:
                    pass
            return jsonify({"ok": True, "skin": _get_skin()})
        # POST: multipart 上传
        f = request.files.get("file")
        if not f:
            return jsonify({"error": "请选择图片文件"}), 400
        data = f.read()
        ext = _valid_skin_bg(data, f.filename or "")
        if not ext:
            return jsonify({"error": "仅支持 PNG/JPG/GIF/WebP，且不超过 5MB"}), 400
        for e in _SKIN_BG_EXTS:  # 清理旧扩展名的残留
            old = os.path.join(SKIN_DIR, "background" + e)
            if os.path.isfile(old):
                try:
                    os.remove(old)
                except OSError:
                    pass
        with open(os.path.join(SKIN_DIR, "background" + ext), "wb") as fh:
            fh.write(data)
        try:
            raw = json.loads(store.get_setting("admin_skin", "") or "") or {}
        except Exception:
            raw = {}
        raw["bg_version"] = int(raw.get("bg_version", 0) or 0) + 1
        store.set_setting("admin_skin", json.dumps(raw))
        return jsonify({"ok": True, "skin": _get_skin()})

    # ------------------------------------------------------------ 配置备份与恢复
    @app.route("/api/admin/backup", methods=["GET"])
    @_require_perm("settings")
    def admin_backup_download():
        payload = {
            "format": "bigcat-backup",
            "version": 1,
            "app_version": VERSION,
            "exported_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "data": store.export_config(),
        }
        body = json.dumps(payload, ensure_ascii=False)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        resp = app.response_class(body, mimetype="application/json")
        resp.headers["Content-Disposition"] = f"attachment; filename=bigcat-backup-{stamp}.json"
        return resp

    @app.route("/api/admin/backup/restore", methods=["POST"])
    @_require_perm("settings")
    def admin_backup_restore():
        f = request.files.get("backup")
        if f is None:
            return jsonify({"error": "请上传备份文件（字段名 backup）"}), 400
        raw = f.read(64 * 1024 * 1024 + 1)
        if len(raw) > 64 * 1024 * 1024:
            return jsonify({"error": "备份文件过大（上限 64MB）"}), 400
        try:
            payload = json.loads(raw.decode("utf-8"))
        except Exception:
            return jsonify({"error": "备份文件不是有效的 JSON"}), 400
        if not isinstance(payload, dict) or payload.get("format") != "bigcat-backup":
            return jsonify({"error": "不是有效的 BigCat 备份文件"}), 400
        try:
            store.import_config(payload.get("data") or {})
        except ValueError as e:
            return jsonify({"error": f"备份数据无效：{e}"}), 400
        except Exception as e:
            return jsonify({"error": f"恢复失败：{e}"}), 500
        return jsonify({"ok": True})

    # ============================================================ v3 API end

    # ------------------------------------------------------------ SPA fallback
    # 必须注册在所有路由之后：/traffic、/instance/xxx 等前端路由刷新或直连时
    # 返回 index.html 交给前端路由接管；未知 API 路径返回 JSON 404
    @app.route("/<path:p>")
    def spa_fallback(p):
        if p.startswith("api/"):
            return jsonify({"error": "not found"}), 404
        return send_from_directory(_active_theme_dist(), "index.html")

    # 后台监控线程：离线检测 / 告警 / 延迟监测 / 到期提醒 / 流量报告。
    # enable_monitor=False 时（单元测试）不启动。
    if enable_monitor and not app.config.get("monitor_started"):
        app.config["monitor_started"] = True
        threading.Thread(target=_monitor_loop, daemon=True, name="bigcat-monitor").start()
        print(f"[BigCat] monitor thread started (interval 30s)")

    # 域名监听恢复：已配置域名时在服务启动后拉起 80/443（失败不影响主服务）
    try:
        _domain_ensure_servers()
    except Exception:
        pass

    return app


def main():
    import argparse

    ap = argparse.ArgumentParser(description="BigCat server")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=25774)
    ap.add_argument("--db", default="data/bigcat.db")
    ap.add_argument("--set-admin", metavar="USER:PASS",
                    help="set (or reset) the admin account and exit; "
                         "format 'username:password', or plain 'password' "
                         "(username keeps existing value, default admin)")
    args = ap.parse_args()

    app = create_app(db_path=args.db)
    store: Storage = app.config["store"]
    if args.set_admin:
        if ":" in args.set_admin:
            username, password = args.set_admin.split(":", 1)
            store.set_admin(username.strip() or "admin", password)
        else:
            store.set_admin_password(args.set_admin)
        print(f"admin account updated (username: {store.get_admin_username()})")
        return
    if not store.has_admin():
        print("NOTE: no admin account set. Run with --set-admin <user:pass> first.")
    print(f"BigCat T server v{VERSION} listening on http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, threaded=True)


if __name__ == "__main__":
    main()
