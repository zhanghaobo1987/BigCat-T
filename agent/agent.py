#!/usr/bin/env python3
"""
BigCat agent.

Collects host metrics with psutil and reports them to a BigCat server,
using the Komari v2 report shape (protocol/v2) over plain HTTPS POST.

Usage:
    python3 agent.py --server http://MASTER:25774 --token <node-token> [--interval 2]

Register a node first (on the master):
    curl -X POST http://MASTER:25774/api/agent/register -d '{"name":"hk-1"}'
"""
import argparse
import datetime
import fnmatch
import json
import os
import platform
import re
import socket
import ssl
import subprocess
import time
import urllib.request
import urllib.error


# Commands an admin may run remotely. Keep this intentionally narrow:
# single non-interactive shell commands, no redirections to system paths.
EXEC_MAX_OUTPUT = 64 * 1024
EXEC_TIMEOUT = 120


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


_insecure_ctx = None


def _ssl_context(insecure: bool):
    """SSL context for talking to the master. Unverified only when --insecure."""
    global _insecure_ctx
    if not insecure:
        return None
    if _insecure_ctx is None:
        _insecure_ctx = ssl._create_unverified_context()
    return _insecure_ctx


# ------------------------------------------------------------ 主控切换（迁移）
# 主控迁移后在上报响应中下发 {"master": "http://新地址:25774"}，agent 收到即
# 切换上报目标并持久化到 agent.py 同目录 master.json，重启后继续用新主控，
# 免去逐台修改 agent 配置。指令只来自当前主控的鉴权响应。
_MASTER_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "master.json")


def _load_master_override() -> str:
    try:
        with open(_MASTER_FILE, "r", encoding="utf-8") as f:
            url = (json.load(f) or {}).get("server", "")
        if isinstance(url, str) and url.startswith(("http://", "https://")):
            return url.rstrip("/")
    except Exception:  # noqa: BLE001
        pass
    return ""


def _save_master_override(url: str):
    try:
        with open(_MASTER_FILE, "w", encoding="utf-8") as f:
            json.dump({"server": url}, f)
    except Exception as e:  # noqa: BLE001
        print(f"[agent] save master override failed: {e}")


def _post(url: str, payload: dict, token: str = "", timeout: int = 10,
          insecure: bool = False) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}
    )
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=timeout,
                                    context=_ssl_context(insecure)) as resp:
            return json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        print(f"[agent] HTTP {e.code}: {e.read().decode()[:200]}")
    except Exception as e:  # noqa: BLE001
        print(f"[agent] request failed: {e}")
    return {}


def collect_basic_info(args=None):
    import psutil

    vm = psutil.virtual_memory()
    sm = psutil.swap_memory()
    disk_mount = (args.disk_mount if args else None) or _default_disk_mount()
    try:
        du = psutil.disk_usage(disk_mount)
    except Exception:
        du = psutil.disk_usage(_default_disk_mount())
    uname = platform.uname()
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith("model name"):
                    cpu_name = line.split(":", 1)[1].strip()
                    break
            else:
                cpu_name = uname.processor or uname.machine
    except Exception:
        cpu_name = uname.processor or uname.machine
    info = {
        "cpu_name": cpu_name,
        "arch": uname.machine,
        "cpu_cores": psutil.cpu_count(logical=True) or 0,
        "os": f"{uname.system} {uname.release}",
        "kernel_version": uname.version,
        "mem_total": vm.total,
        "swap_total": sm.total,
        "disk_total": du.total,
        "version": "BigCat-agent/1.1.0",
        "name": socket.gethostname(),
    }
    if args is not None:
        if args.gpu:
            g = collect_gpu()
            if g and g.get("name"):
                info["gpu_name"] = g["name"]
        if args.nic_ip:
            ip = detect_nic_ip()
            if ip:
                info["ipv4"] = ip
    return info


def collect_report(prev_net, args):
    """Build a Komari v2 Report dict. Returns (report, new_prev_net)."""
    import psutil

    cpu_usage = psutil.cpu_percent(interval=None)
    vm = psutil.virtual_memory()
    sm = psutil.swap_memory()
    try:
        load1, load5, load15 = psutil.getloadavg()
    except Exception:
        load1 = load5 = load15 = 0.0
    disk_mount = (args.disk_mount if args else None) or _default_disk_mount()
    try:
        du = psutil.disk_usage(disk_mount)
    except Exception:
        disk_mount = _default_disk_mount()
        du = psutil.disk_usage(disk_mount)

    include = _parse_nic_list(args.include_nics if args else "")
    exclude = _parse_nic_list(args.exclude_nics if args else "")
    sent_total, recv_total = net_totals_filtered(include, exclude)
    now = time.time()

    up = down = 0
    if prev_net is not None:
        dt = max(now - prev_net["t"], 0.001)
        up = max(int((sent_total - prev_net["sent"]) / dt), 0)
        down = max(int((recv_total - prev_net["recv"]) / dt), 0)
    new_prev = {"t": now, "sent": sent_total, "recv": recv_total}

    reset_day = args.traffic_reset_day if args else 0
    month_up, month_down = monthly_traffic(sent_total, recv_total, reset_day)

    gpu_info = collect_gpu() if (args and args.gpu) else None

    conns = psutil.net_connections(kind="inet")
    tcp = sum(1 for c in conns if c.type == socket.SOCK_STREAM)
    udp = sum(1 for c in conns if c.type == socket.SOCK_DGRAM)

    report = {
        "cpu": {"usage": round(cpu_usage, 2)},
        "ram": {"total": vm.total, "used": vm.total - vm.available},
        "swap": {"total": sm.total, "used": sm.used},
        "load": {"load1": round(load1, 2), "load5": round(load5, 2),
                 "load15": round(load15, 2)},
        "disk": {"total": du.total, "used": du.used, "mount": disk_mount},
        "network": {
            "up": up, "down": down,
            "totalUp": sent_total, "totalDown": recv_total,
            "monthUp": month_up, "monthDown": month_down,
        },
        "gpu": gpu_info or {},
        "connections": {"tcp": tcp, "udp": udp},
        "uptime": int(time.time() - psutil.boot_time()),
        "process": len(psutil.pids()),
        "message": "",
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    return report, new_prev


def run_exec_task(task: dict) -> dict:
    """Run one remote-execution task. Returns {ok, output}."""
    command = str(task.get("command", ""))[:2000]
    try:
        out = subprocess.run(
            command, shell=True, capture_output=True, text=True,
            timeout=EXEC_TIMEOUT,
        )
        output = (out.stdout or "") + (out.stderr or "")
        if len(output) > EXEC_MAX_OUTPUT:
            output = output[:EXEC_MAX_OUTPUT] + "\n…[输出已截断]"
        return {"ok": out.returncode == 0,
                "output": output or f"[exit {out.returncode}]"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "output": f"[超时：命令执行超过 {EXEC_TIMEOUT}s]"}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "output": f"[执行失败] {e}"}


def poll_exec_tasks(server: str, token: str, insecure: bool = False):
    """Fetch pending exec tasks from master, run them, report results back."""
    resp = _get(f"{server}/api/agent/tasks", token=token, insecure=insecure)
    tasks = resp.get("tasks") or []
    for task in tasks:
        print(f"[agent] exec task #{task.get('id')}: {str(task.get('command'))[:80]}")
        result = run_exec_task(task)
        _post(f"{server}/api/agent/task_result",
              {"task_id": task.get("id"), "output": result["output"],
               "ok": result["ok"]}, token=token, insecure=insecure)


# ------------------------------------------------------------------ 分布式延迟探测
# v1.9.4：agent 自行探测主控下发的 ping 任务（三网延迟等），结果随上报回传，
# 主控按节点分别存储展示；未升级的 agent 由主控侧探测数据回退展示。
PING_TASK_REFRESH_SEC = 60


def _do_ping(task: dict):
    """本地执行一次延迟探测，与主控侧 _do_ping 同语义：tcp/http/icmp。"""
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


class PingProber:
    """延迟探测调度器：定期从主控拉取任务，按各自间隔本地探测，结果排队随上报回传。"""

    def __init__(self):
        self.tasks = []
        self.next_run = {}
        self.last_fetch = 0.0
        self.pending = []

    def maybe_refresh(self, server: str, token: str, insecure: bool = False):
        now = time.time()
        if now - self.last_fetch < PING_TASK_REFRESH_SEC:
            return
        self.last_fetch = now
        try:
            resp = _get(f"{server}/api/agent/ping_tasks", token=token,
                        insecure=insecure)
            tasks = resp.get("tasks") or []
            self.tasks = tasks
            # 任务变更时清掉已删除任务的调度
            alive = {t.get("id") for t in tasks}
            self.next_run = {tid: ts for tid, ts in self.next_run.items()
                             if tid in alive}
        except Exception as e:  # noqa: BLE001
            print(f"[agent] ping tasks refresh failed: {e}")

    def tick(self):
        now = time.time()
        for task in self.tasks:
            tid = task.get("id")
            if tid is None:
                continue
            if now < self.next_run.get(tid, 0):
                continue
            latency, ok = _do_ping(task)
            self.pending.append({"task_id": tid,
                                 "latency_ms": round(latency, 2),
                                 "ok": bool(ok)})
            interval = max(30, int(task.get("interval_sec") or 300))
            self.next_run[tid] = now + interval

    def drain(self):
        out = self.pending
        self.pending = []
        return out


def _get(url: str, token: str = "", timeout: int = 10,
         insecure: bool = False) -> dict:
    req = urllib.request.Request(url, headers={"Content-Type": "application/json"})
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=timeout,
                                    context=_ssl_context(insecure)) as resp:
            return json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        print(f"[agent] HTTP {e.code}: {e.read().decode()[:200]}")
    except Exception as e:  # noqa: BLE001
        print(f"[agent] request failed: {e}")
    return {}


# ------------------------------------------------------------------ 网卡过滤
def _parse_nic_list(s: str):
    return [p.strip() for p in str(s or "").split(",") if p.strip()]


def _nic_allowed(name: str, include, exclude) -> bool:
    if include and not any(fnmatch.fnmatch(name, pat) for pat in include):
        return False
    if any(fnmatch.fnmatch(name, pat) for pat in exclude):
        return False
    return True


def net_totals_filtered(include, exclude):
    """(bytes_sent, bytes_recv) summed over NICs passing the include/exclude filters."""
    import psutil
    pernic = psutil.net_io_counters(pernic=True) or {}
    sent = recv = 0
    for name, counters in pernic.items():
        if _nic_allowed(name, include, exclude):
            sent += counters.bytes_sent
            recv += counters.bytes_recv
    return sent, recv


# ------------------------------------------------------------------ 月流量统计
TRAFFIC_STATE_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), ".traffic_state.json")


def billing_month_key(now: datetime.datetime, reset_day: int):
    """Billing month containing `now` when traffic resets on `reset_day` each month."""
    if not reset_day or not 1 <= reset_day <= 28:
        return None
    if now.day >= reset_day:
        return now.strftime("%Y-%m")
    prev = (now.replace(day=1) - datetime.timedelta(days=1))
    return prev.strftime("%Y-%m")


def _load_traffic_state():
    try:
        with open(TRAFFIC_STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_traffic_state(state):
    try:
        with open(TRAFFIC_STATE_FILE, "w") as f:
            json.dump(state, f)
    except Exception as e:  # noqa: BLE001
        print(f"[agent] traffic state save failed: {e}")


def monthly_traffic(sent: int, recv: int, reset_day: int, now=None):
    """(month_up, month_down) bytes used in the current billing cycle.

    Returns (0, 0) when disabled. Re-bases on billing-month rollover or when
    the kernel counters wrapped (reboot).
    """
    if not reset_day or not 1 <= reset_day <= 28:
        return 0, 0
    now = now or datetime.datetime.now()
    key = billing_month_key(now, reset_day)
    st = _load_traffic_state()
    base_sent = st.get("base_sent", 0)
    base_recv = st.get("base_recv", 0)
    if st.get("key") != key or sent < base_sent or recv < base_recv:
        st = {"key": key, "base_sent": sent, "base_recv": recv}
        _save_traffic_state(st)
        return 0, 0
    return sent - base_sent, recv - base_recv


# ------------------------------------------------------------------ GPU
def _default_disk_mount() -> str:
    """Platform-appropriate default mount point for disk usage."""
    if os.name == "nt":
        return os.environ.get("SystemDrive", "C:") + "\\"
    return "/"
def collect_gpu():
    """Detailed GPU stats via nvidia-smi, or None when unavailable."""
    try:
        out = subprocess.run(
            ["nvidia-smi",
             "--query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu",
             "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=15,
        )
        line = (out.stdout or "").strip().split("\n")[0]
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 5 or not parts[0]:
            return None
        name, util, mem_used, mem_total, temp = parts[:5]
        return {
            "name": name,
            "average_usage": float(util),
            "memory_used": int(float(mem_used) * 1024 * 1024),
            "memory_total": int(float(mem_total) * 1024 * 1024),
            "temperature": float(temp),
        }
    except Exception:  # noqa: BLE001 - no GPU / no nvidia-smi
        return None


def detect_nic_ip() -> str:
    """Local IP as seen on the default route's NIC (no traffic is actually sent)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip or ""
    except Exception:  # noqa: BLE001
        return ""


def main():
    ap = argparse.ArgumentParser(description="BigCat agent")
    ap.add_argument("--server", required=True, help="master URL, e.g. http://1.2.3.4:25774")
    ap.add_argument("--token", required=True, help="node token from /api/agent/register")
    ap.add_argument("--interval", type=float, default=2.0, help="report interval seconds")
    ap.add_argument("--traffic-reset-day", type=int,
                    default=int(os.environ.get("BIGCAT_TRAFFIC_RESET_DAY", "0") or 0),
                    help="monthly traffic reset day 1-28, 0 = disabled")
    ap.add_argument("--gpu", action="store_true", default=_env_flag("BIGCAT_GPU"),
                    help="enable detailed GPU monitoring via nvidia-smi")
    ap.add_argument("--disable-remote-exec", action="store_true",
                    default=_env_flag("BIGCAT_DISABLE_REMOTE_EXEC"),
                    help="do not poll/execute remote commands from the master")
    ap.add_argument("--insecure", action="store_true", default=_env_flag("BIGCAT_INSECURE"),
                    help="skip TLS certificate verification (self-signed master cert)")
    ap.add_argument("--include-nics", default=os.environ.get("BIGCAT_INCLUDE_NICS", ""),
                    help="only count these NICs in network stats, comma-separated, * wildcards")
    ap.add_argument("--exclude-nics", default=os.environ.get("BIGCAT_EXCLUDE_NICS", ""),
                    help="exclude these NICs from network stats, comma-separated, * wildcards")
    ap.add_argument("--disk-mount", default=os.environ.get("BIGCAT_DISK_MOUNT", "") or "",
                    help="mount point reported as disk usage (default: / on Unix, system drive on Windows)")
    ap.add_argument("--nic-ip", action="store_true", default=_env_flag("BIGCAT_NIC_IP"),
                    help="report local IP detected from the default NIC in basic info")
    args = ap.parse_args()

    server = args.server.rstrip("/")
    _override = _load_master_override()
    if _override and _override != server:
        print(f"[agent] master override active: {_override} (configured: {server})")
        server = _override
    print(f"[agent] reporting to {server} every {args.interval}s")

    # send static info once
    try:
        info = collect_basic_info(args)
        _post(f"{server}/api/agent/basicinfo", {"info": info}, token=args.token,
              insecure=args.insecure)
        print(f"[agent] basic info sent: {info['os']} / {info['cpu_cores']} cores")
    except Exception as e:  # noqa: BLE001
        print(f"[agent] basicinfo failed: {e}")

    prev_net = None
    # warm up cpu_percent
    try:
        import psutil
        psutil.cpu_percent(interval=None)
    except Exception:
        pass

    prober = PingProber()

    while True:
        try:
            # 分布式延迟探测：拉取任务 -> 本地探测 -> 结果随上报回传（v1.9.4）
            try:
                prober.maybe_refresh(server, args.token, insecure=args.insecure)
                prober.tick()
            except Exception as e:  # noqa: BLE001
                print(f"[agent] ping probe failed: {e}")
            report, prev_net = collect_report(prev_net, args)
            ping_results = prober.drain()
            if ping_results:
                report["ping_results"] = ping_results
            resp = _post(f"{server}/api/agent/report", {"report": report}, token=args.token,
                         insecure=args.insecure)
            # 主控切换指令（服务器迁移）：换目标、持久化、向新主控补发静态信息
            _new_master = resp.get("master") if isinstance(resp, dict) else None
            if isinstance(_new_master, str):
                _new_master = _new_master.rstrip("/")
                if _new_master.startswith(("http://", "https://")) and _new_master != server:
                    print(f"[agent] master redirect: {server} -> {_new_master}")
                    _save_master_override(_new_master)
                    server = _new_master
                    try:
                        _info = collect_basic_info(args)
                        _post(f"{server}/api/agent/basicinfo", {"info": _info},
                              token=args.token, insecure=args.insecure)
                    except Exception as e:  # noqa: BLE001
                        print(f"[agent] basicinfo to new master failed: {e}")
        except Exception as e:  # noqa: BLE001
            print(f"[agent] report failed: {e}")
        # 每轮顺带轮询远程执行任务（低频操作，失败不影响上报；可被 --disable-remote-exec 关闭）
        if not args.disable_remote_exec:
            try:
                poll_exec_tasks(server, args.token, insecure=args.insecure)
            except Exception as e:  # noqa: BLE001
                print(f"[agent] exec poll failed: {e}")
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
