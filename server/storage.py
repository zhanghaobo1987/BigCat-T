"""
bigcat storage layer.

SQLite-backed persistence for nodes (clients) and their metric history.
Mirrors the Komari data model (database/models) in a simplified form.
"""
import json
import sqlite3
import threading
import time
import uuid as uuid_lib
from datetime import datetime, timezone
from pathlib import Path


class Storage:
    def __init__(self, db_path: str):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    # ------------------------------------------------------------------ schema
    def _init_schema(self):
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS clients (
                    uuid            TEXT PRIMARY KEY,
                    token           TEXT UNIQUE NOT NULL,
                    name            TEXT DEFAULT '',
                    cpu_name        TEXT DEFAULT '',
                    virtualization  TEXT DEFAULT '',
                    arch            TEXT DEFAULT '',
                    cpu_cores       INTEGER DEFAULT 0,
                    os              TEXT DEFAULT '',
                    kernel_version  TEXT DEFAULT '',
                    gpu_name        TEXT DEFAULT '',
                    ipv4            TEXT DEFAULT '',
                    ipv6            TEXT DEFAULT '',
                    region          TEXT DEFAULT '',
                    remark          TEXT DEFAULT '',
                    public_remark   TEXT DEFAULT '',
                    mem_total       INTEGER DEFAULT 0,
                    swap_total      INTEGER DEFAULT 0,
                    disk_total      INTEGER DEFAULT 0,
                    version         TEXT DEFAULT '',
                    weight          INTEGER DEFAULT 0,
                    price           REAL DEFAULT 0,
                    billing_cycle   INTEGER DEFAULT 0,
                    auto_renewal    INTEGER DEFAULT 0,
                    currency        TEXT DEFAULT '$',
                    expired_at      TEXT,
                    group_name      TEXT DEFAULT '',
                    tags            TEXT DEFAULT '',
                    hidden          INTEGER DEFAULT 0,
                    traffic_limit   INTEGER DEFAULT 0,
                    traffic_limit_type TEXT DEFAULT '',
                    traffic_reset_day INTEGER DEFAULT 0,
                    created_at      TEXT NOT NULL,
                    updated_at      TEXT NOT NULL,
                    last_report_at  TEXT
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS records (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    client          TEXT NOT NULL,
                    time            TEXT NOT NULL,
                    cpu             REAL DEFAULT 0,
                    gpu             REAL DEFAULT 0,
                    ram             INTEGER DEFAULT 0,
                    ram_total       INTEGER DEFAULT 0,
                    swap            INTEGER DEFAULT 0,
                    swap_total      INTEGER DEFAULT 0,
                    load            REAL DEFAULT 0,
                    disk            INTEGER DEFAULT 0,
                    disk_total      INTEGER DEFAULT 0,
                    net_in          INTEGER DEFAULT 0,
                    net_out         INTEGER DEFAULT 0,
                    net_total_up    INTEGER DEFAULT 0,
                    net_total_down  INTEGER DEFAULT 0,
                    net_month_up    INTEGER DEFAULT 0,
                    net_month_down  INTEGER DEFAULT 0,
                    traffic_up      INTEGER DEFAULT 0,
                    traffic_down    INTEGER DEFAULT 0,
                    process         INTEGER DEFAULT 0,
                    connections     INTEGER DEFAULT 0,
                    connections_udp INTEGER DEFAULT 0,
                    uptime          INTEGER DEFAULT 0
                )
                """
            )
            cur.execute("CREATE INDEX IF NOT EXISTS idx_records_client ON records(client)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_records_time ON records(time)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_records_client_time ON records(client, time)")
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS settings (
                    key   TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
            self._conn.commit()
            # default settings
            defaults = {
                "sitename": "BigCat Monitor",
                "description": "A lightweight VPS monitor, Komari-compatible.",
                "theme": "LuminaPlus",
                "admin_password": "",  # set on first run via CLI
                "notify_template": "【{event}】{message}",
                "expiry_remind_enabled": "1",
                "expiry_remind_days": "10",
                "active_theme": "default",
                "admin_skin": '{"mode": "dark", "accent": "#2f81f7"}',
            }
            for k, v in self._default_settings().items():
                cur.execute("INSERT OR IGNORE INTO settings(key, value) VALUES(?, ?)", (k, v))
            self._conn.commit()
            # ---- v3 tables (Komari-parity admin) ----
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS ping_tasks (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    name         TEXT NOT NULL,
                    target       TEXT NOT NULL,
                    type         TEXT DEFAULT 'tcp',
                    interval_sec INTEGER DEFAULT 300,
                    enabled      INTEGER DEFAULT 1,
                    created_at   TEXT NOT NULL
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS ping_results (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id     INTEGER NOT NULL,
                    time        TEXT NOT NULL,
                    latency_ms  REAL DEFAULT 0,
                    ok          INTEGER DEFAULT 0,
                    client_uuid TEXT NOT NULL DEFAULT ''
                )
                """
            )
            # v1.9.4 迁移：老库 ping_results 补 client_uuid 列（节点侧分布式探测结果归属）
            cols = {r[1] for r in cur.execute("PRAGMA table_info(ping_results)").fetchall()}
            if "client_uuid" not in cols:
                cur.execute("ALTER TABLE ping_results ADD COLUMN client_uuid TEXT NOT NULL DEFAULT ''")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_pingres_task_time ON ping_results(task_id, time)")
            # v1.11.10：按 (任务, 节点, 时间) 查询的复合索引，供 ping_results_for_client 用
            cur.execute("CREATE INDEX IF NOT EXISTS idx_pingres_task_client_time ON ping_results(task_id, client_uuid, time)")
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS ping_task_clients (
                    task_id     INTEGER NOT NULL,
                    client_uuid TEXT NOT NULL,
                    PRIMARY KEY (task_id, client_uuid)
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS alert_rules (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    name         TEXT NOT NULL,
                    metric       TEXT NOT NULL,
                    threshold    REAL DEFAULT 90,
                    ratio        REAL DEFAULT 0.8,
                    interval_min INTEGER DEFAULT 2,
                    enabled      INTEGER DEFAULT 1,
                    clients      TEXT DEFAULT '[]',
                    last_fired_at TEXT
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    id         TEXT PRIMARY KEY,
                    ip         TEXT DEFAULT '',
                    ua         TEXT DEFAULT '',
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    last_seen  TEXT NOT NULL
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id      INTEGER PRIMARY KEY AUTOINCREMENT,
                    time    TEXT NOT NULL,
                    level   TEXT DEFAULT 'info',
                    type    TEXT DEFAULT '',
                    message TEXT DEFAULT ''
                )
                """
            )
            cur.execute("CREATE INDEX IF NOT EXISTS idx_events_time ON events(time)")
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS exec_tasks (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_uuid TEXT NOT NULL,
                    command     TEXT NOT NULL,
                    status      TEXT DEFAULT 'pending',
                    output      TEXT DEFAULT '',
                    created_at  TEXT NOT NULL,
                    finished_at TEXT
                )
                """
            )
            cur.execute("CREATE INDEX IF NOT EXISTS idx_exec_client ON exec_tasks(client_uuid)")
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS theme_settings (
                    short      TEXT PRIMARY KEY,
                    data       TEXT NOT NULL DEFAULT '{}',
                    updated_at TEXT NOT NULL
                )
                """
            )
            self._conn.commit()
        self._migrate()

    def _migrate(self):
        """Additive migrations for the clients table (v3 fields) and records table."""
        with self._lock:
            cols = {r["name"] for r in self._conn.execute("PRAGMA table_info(clients)").fetchall()}
            for col, ddl in {
                "offline_grace": "INTEGER DEFAULT 0",
                "notify_offline": "INTEGER DEFAULT 1",
                "report_enabled": "INTEGER DEFAULT 0",
                "report_types": "TEXT DEFAULT 'daily,weekly,monthly'",
                "traffic_limit_type": "TEXT DEFAULT ''",
                "traffic_reset_day": "INTEGER DEFAULT 0",
                "traffic_base_up": "INTEGER DEFAULT 0",
                "traffic_base_down": "INTEGER DEFAULT 0",
                "traffic_base_cycle": "TEXT DEFAULT ''",
            }.items():
                if col not in cols:
                    self._conn.execute(f"ALTER TABLE clients ADD COLUMN {col} {ddl}")
            rcols = {r["name"] for r in self._conn.execute("PRAGMA table_info(records)").fetchall()}
            for col, ddl in {
                "net_month_up": "INTEGER DEFAULT 0",
                "net_month_down": "INTEGER DEFAULT 0",
            }.items():
                if col not in rcols:
                    self._conn.execute(f"ALTER TABLE records ADD COLUMN {col} {ddl}")
            # v1.13.1: 前台按节点查时间范围（图表/流量）高频，加复合索引
            idxs = {r["name"] for r in self._conn.execute(
                "SELECT name FROM sqlite_master WHERE tbl_name='records' AND type='index'").fetchall()}
            if "idx_records_client_time" not in idxs:
                self._conn.execute(
                    "CREATE INDEX idx_records_client_time ON records(client, time)")
            # v1.9.8: sessions 记录登录用户身份
            scols = {r["name"] for r in self._conn.execute("PRAGMA table_info(sessions)").fetchall()}
            for col, ddl in {
                "username": "TEXT DEFAULT ''",
                "role": "TEXT DEFAULT ''",
            }.items():
                if col not in scols:
                    self._conn.execute(f"ALTER TABLE sessions ADD COLUMN {col} {ddl}")
            # v1.9.8: 多账户体系
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    username      TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    role          TEXT NOT NULL DEFAULT 'user',
                    perms         TEXT NOT NULL DEFAULT '[]',
                    phone         TEXT DEFAULT '',
                    email         TEXT DEFAULT '',
                    disabled      INTEGER NOT NULL DEFAULT 0,
                    created_at    TEXT NOT NULL
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS recovery_tokens (
                    token      TEXT PRIMARY KEY,
                    username   TEXT NOT NULL,
                    is_super   INTEGER NOT NULL DEFAULT 0,
                    expires_at TEXT NOT NULL
                )
                """
            )
            self._conn.commit()

    # ------------------------------------------------------------------ clients
    def _row_to_client(self, row) -> dict:
        d = dict(row)
        # map internal column names back to komari json names
        d["group"] = d.pop("group_name", "")
        return d

    def add_client(self, name: str = "", token: str = "") -> dict:
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        client_uuid = str(uuid_lib.uuid4())
        if not token:
            token = uuid_lib.uuid4().hex + uuid_lib.uuid4().hex[:16]
        with self._lock:
            self._conn.execute(
                """INSERT INTO clients(uuid, token, name, created_at, updated_at)
                   VALUES(?, ?, ?, ?, ?)""",
                (client_uuid, token, name, now, now),
            )
            self._conn.commit()
        return self.get_client(client_uuid)

    def get_client(self, client_uuid: str):
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM clients WHERE uuid = ?", (client_uuid,)
            ).fetchone()
        return self._row_to_client(row) if row else None

    def get_client_by_token(self, token: str):
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM clients WHERE token = ?", (token,)
            ).fetchone()
        return self._row_to_client(row) if row else None

    def list_clients(self):
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM clients ORDER BY weight DESC, created_at ASC"
            ).fetchall()
        return [self._row_to_client(r) for r in rows]

    def update_client(self, client_uuid: str, fields: dict) -> bool:
        allowed = {
            "name", "cpu_name", "virtualization", "arch", "cpu_cores", "os",
            "kernel_version", "gpu_name", "ipv4", "ipv6", "region", "remark",
            "public_remark", "mem_total", "swap_total", "disk_total", "version",
            "weight", "price", "billing_cycle", "auto_renewal", "currency",
            "expired_at", "group", "tags", "hidden", "traffic_limit",
            "traffic_limit_type", "traffic_reset_day",
            "traffic_base_up", "traffic_base_down", "traffic_base_cycle",
            "offline_grace", "notify_offline", "report_enabled", "report_types",
        }
        sets, vals = [], []
        for k, v in fields.items():
            col = "group_name" if k == "group" else k
            if k not in allowed:
                continue
            sets.append(f"{col} = ?")
            vals.append(v)
        if not sets:
            return False
        sets.append("updated_at = ?")
        vals.append(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        vals.append(client_uuid)
        with self._lock:
            cur = self._conn.execute(
                f"UPDATE clients SET {', '.join(sets)} WHERE uuid = ?", vals
            )
            self._conn.commit()
        return cur.rowcount > 0

    def touch_client(self, client_uuid: str):
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self._lock:
            self._conn.execute(
                "UPDATE clients SET last_report_at = ?, updated_at = ? WHERE uuid = ?",
                (now, now, client_uuid),
            )
            self._conn.commit()

    def delete_client(self, client_uuid: str) -> bool:
        with self._lock:
            cur = self._conn.execute("DELETE FROM clients WHERE uuid = ?", (client_uuid,))
            self._conn.execute("DELETE FROM records WHERE client = ?", (client_uuid,))
            self._conn.commit()
        return cur.rowcount > 0

    # ------------------------------------------------------------------ records
    def insert_record(self, client_uuid: str, rec: dict):
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        cols = (
            "client", "time", "cpu", "gpu", "ram", "ram_total", "swap",
            "swap_total", "load", "disk", "disk_total", "net_in", "net_out",
            "net_total_up", "net_total_down", "net_month_up", "net_month_down",
            "traffic_up", "traffic_down",
            "process", "connections", "connections_udp", "uptime",
        )
        vals = [client_uuid, rec.get("time", now)] + [rec.get(c, 0) for c in cols[2:]]
        with self._lock:
            self._conn.execute(
                f"INSERT INTO records({', '.join(cols)}) VALUES({', '.join('?' * len(cols))})",
                vals,
            )
            self._conn.commit()

    def query_records(self, client_uuid: str, since: str, until: str, limit: int = 500):
        with self._lock:
            rows = self._conn.execute(
                """SELECT * FROM records
                   WHERE client = ? AND time >= ? AND time <= ?
                   ORDER BY time ASC LIMIT ?""",
                (client_uuid, since, until, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    # records 表可聚合的数值列白名单（query_records_bucketed 的 col 参数校验用）
    RECORD_NUMERIC_COLS = (
        "cpu", "gpu", "ram", "ram_total", "swap", "swap_total", "load",
        "disk", "disk_total", "net_in", "net_out", "net_total_up",
        "net_total_down", "traffic_up", "traffic_down", "process",
        "connections", "connections_udp", "uptime",
    )

    def query_records_bucketed(self, client_uuid: str, since: str, until: str,
                               col: str, start_ts: float, bucket_s: float,
                               max_points: int = 500):
        """按时间分桶聚合取 records，覆盖整个请求窗口。

        旧的 query_records(ORDER BY time ASC LIMIT)在长窗口下只拿到最旧一段
        数据，导致 7 天以上图表曲线挤在开头一小段。这里在 SQL 侧按
        bucket_s 秒分桶，对 col 取均值，保证点数铺满整个窗口。
        返回时间升序 [{"time","value","count"}]，time 为桶起点。
        """
        if col not in self.RECORD_NUMERIC_COLS:
            raise ValueError(f"bad column: {col}")
        bucket_s = max(1.0, float(bucket_s))
        start_int = int(start_ts)
        with self._lock:
            rows = self._conn.execute(
                f"""SELECT CAST((strftime('%s', time) - ?) / ? AS INTEGER) AS bkt,
                           AVG({col}), COUNT(*)
                    FROM records
                    WHERE client = ? AND time >= ? AND time <= ?
                    GROUP BY bkt ORDER BY bkt LIMIT ?""",
                (start_int, bucket_s, client_uuid, since, until, int(max_points)),
            ).fetchall()
        out = []
        for bkt, avg, cnt in rows:
            if bkt is None:
                continue
            t = datetime.fromtimestamp(start_int + bkt * bucket_s, tz=timezone.utc)
            out.append({
                "time": t.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "value": float(avg or 0),
                "count": int(cnt),
            })
        return out

    def latest_record(self, client_uuid: str):
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM records WHERE client = ? ORDER BY time DESC LIMIT 1",
                (client_uuid,),
            ).fetchone()
        return dict(row) if row else None

    def adjust_latest_record_totals(self, client_uuid: str, d_up: int, d_down: int):
        """流量校准即时生效：给最新一条记录的累计流量叠加偏移（与入库偏移一致，
        避免下一条上报前前台仍显示旧值）。"""
        with self._lock:
            self._conn.execute(
                """UPDATE records
                   SET net_total_up = MAX(0, net_total_up + ?),
                       net_total_down = MAX(0, net_total_down + ?)
                   WHERE id = (SELECT id FROM records WHERE client = ?
                               ORDER BY time DESC LIMIT 1)""",
                (int(d_up), int(d_down), client_uuid))
            self._conn.commit()

    def prune_records(self, keep_hours: int = 24):
        """Drop records older than keep_hours to bound DB size."""
        cutoff = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - keep_hours * 3600)
        )
        with self._lock:
            self._conn.execute("DELETE FROM records WHERE time < ?", (cutoff,))
            self._conn.commit()

    def count_records(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS n FROM records").fetchone()
        return int(row["n"]) if row else 0

    def count_records_since(self, since_iso: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS n FROM records WHERE time >= ?", (since_iso,)
            ).fetchone()
        return int(row["n"]) if row else 0

    def db_size(self) -> int:
        try:
            return self.db_path.stat().st_size
        except Exception:
            return 0

    # ------------------------------------------------------------------ settings
    def get_setting(self, key: str, default: str = "") -> str:
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM settings WHERE key = ?", (key,)
            ).fetchone()
        return row["value"] if row else default

    def set_setting(self, key: str, value: str):
        with self._lock:
            self._conn.execute(
                "INSERT INTO settings(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )
            self._conn.commit()

    def get_public_settings(self) -> dict:
        def _hours(key: str, default: int) -> int:
            try:
                return int(self.get_setting(key, str(default)) or default)
            except Exception:
                return default

        return {
            "sitename": self.get_setting("sitename"),
            "description": self.get_setting("description"),
            "theme": self.get_setting("theme"),
            "private_site": False,
            "allow_register": False,
            # Komari 兼容：监控记录 / ping 记录保留时长（小时），主题据此过滤图表时间选项
            "record_preserve_time": _hours("record_keep_hours", 24),
            "ping_record_preserve_time": _hours("ping_record_preserve_time", 4320),
        }

    # ------------------------------------------------------- theme settings
    def get_theme_settings(self, short: str) -> dict:
        import json as _json
        from datetime import datetime as _dt

        cur = self._conn.cursor()
        cur.execute("SELECT data FROM theme_settings WHERE short=?", (short,))
        row = cur.fetchone()
        if not row:
            return {}
        try:
            return _json.loads(row[0]) or {}
        except Exception:
            return {}

    def set_theme_settings(self, short: str, data: dict):
        import json as _json
        from datetime import datetime as _dt

        now = _dt.now().isoformat(timespec="seconds")
        self._conn.execute(
            "INSERT INTO theme_settings(short, data, updated_at) VALUES(?, ?, ?) "
            "ON CONFLICT(short) DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at",
            (short, _json.dumps(data, ensure_ascii=False), now),
        )
        self._conn.commit()

    @staticmethod
    def _default_settings() -> dict:
        return {
            "sitename": "BIGCat",
            "description": "A lightweight VPS monitor, Komari-compatible.",
            "theme": "LuminaPlus",
            "admin_password": "",  # set on first run via CLI
            "notify_template": "【{event}】{message}",
            "expiry_remind_enabled": "1",
            "expiry_remind_days": "10",
            "active_theme": "default",
            "admin_skin": '{"mode": "dark", "accent": "#2f81f7"}',
        }

    # ------------------------------------------------------- config backup
    def export_config(self) -> dict:
        """导出全部配置数据（不含监控历史、事件日志、会话）。"""
        with self._lock:
            settings = {r["key"]: r["value"]
                        for r in self._conn.execute("SELECT key, value FROM settings")}
            theme_settings = {r["short"]: r["data"]
                              for r in self._conn.execute("SELECT short, data FROM theme_settings")}
            ping_tasks = [dict(r) for r in
                          self._conn.execute("SELECT * FROM ping_tasks ORDER BY id ASC")]
            ping_task_clients = [dict(r) for r in
                                 self._conn.execute(
                                     "SELECT task_id, client_uuid FROM ping_task_clients ORDER BY task_id, client_uuid")]
            alert_rules = [dict(r) for r in
                           self._conn.execute("SELECT * FROM alert_rules ORDER BY id ASC")]
            clients = [self._row_to_client(r) for r in
                       self._conn.execute("SELECT * FROM clients ORDER BY created_at ASC")]
        for c in clients:
            c.pop("last_report_at", None)
        return {"settings": settings, "theme_settings": theme_settings,
                "ping_tasks": ping_tasks, "ping_task_clients": ping_task_clients,
                "alert_rules": alert_rules, "clients": clients}

    def import_config(self, data: dict):
        """用备份数据整体替换配置（事务）。缺失的设置键用默认值补齐。"""
        if not isinstance(data, dict):
            raise ValueError("backup must be an object")
        settings = data.get("settings") or {}
        theme_settings = data.get("theme_settings") or {}
        ping_tasks = data.get("ping_tasks") or []
        ping_task_clients = data.get("ping_task_clients") or []
        alert_rules = data.get("alert_rules") or []
        clients = data.get("clients") or []
        if not isinstance(settings, dict) or not isinstance(theme_settings, dict):
            raise ValueError("bad settings section")
        if not isinstance(ping_tasks, list) or not isinstance(alert_rules, list) \
                or not isinstance(clients, list) or not isinstance(ping_task_clients, list):
            raise ValueError("bad list section")
        import time as _time
        now = _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime())
        client_cols = ("uuid", "token", "name", "cpu_name", "virtualization", "arch",
                       "cpu_cores", "os", "kernel_version", "gpu_name", "ipv4", "ipv6",
                       "region", "remark", "public_remark", "mem_total", "swap_total",
                       "disk_total", "version", "weight", "price", "billing_cycle",
                       "auto_renewal", "currency", "expired_at", "group_name", "tags",
                       "hidden", "traffic_limit", "traffic_reset_day", "created_at", "updated_at")
        with self._lock:
            cur = self._conn
            cur.execute("BEGIN")
            try:
                cur.execute("DELETE FROM settings")
                cur.executemany("INSERT INTO settings(key, value) VALUES(?, ?)",
                                [(str(k), str(v)) for k, v in settings.items()])
                for k, v in self._default_settings().items():
                    cur.execute("INSERT OR IGNORE INTO settings(key, value) VALUES(?, ?)", (k, v))
                cur.execute("DELETE FROM theme_settings")
                cur.executemany(
                    "INSERT INTO theme_settings(short, data, updated_at) VALUES(?, ?, ?)",
                    [(str(s), str(d), now) for s, d in theme_settings.items()])
                cur.execute("DELETE FROM ping_tasks")
                for t in ping_tasks:
                    cur.execute(
                        """INSERT INTO ping_tasks(id, name, target, type, interval_sec, enabled, created_at)
                           VALUES(?, ?, ?, ?, ?, ?, ?)""",
                        (t.get("id"), str(t.get("name") or ""), str(t.get("target") or ""),
                         str(t.get("type") or "tcp"), int(t.get("interval_sec") or 300),
                         int(t.get("enabled", 1)), str(t.get("created_at") or now)))
                cur.execute("DELETE FROM ping_task_clients")
                for b in ping_task_clients:
                    if not isinstance(b, dict) or not b.get("task_id") or not b.get("client_uuid"):
                        continue
                    cur.execute(
                        "INSERT OR IGNORE INTO ping_task_clients(task_id, client_uuid) VALUES(?, ?)",
                        (int(b["task_id"]), str(b["client_uuid"])))
                cur.execute("DELETE FROM alert_rules")
                for r in alert_rules:
                    cur.execute(
                        """INSERT INTO alert_rules(id, name, metric, threshold, ratio, interval_min,
                                                  enabled, clients, last_fired_at)
                           VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (r.get("id"), str(r.get("name") or ""), str(r.get("metric") or ""),
                         float(r.get("threshold") or 0), float(r.get("ratio") or 0),
                         int(r.get("interval_min") or 2), int(r.get("enabled", 1)),
                         str(r.get("clients") or "[]"), r.get("last_fired_at")))
                keep = [str(c.get("uuid")) for c in clients if c.get("uuid")]
                if keep:
                    cur.execute(
                        f"DELETE FROM clients WHERE uuid NOT IN ({','.join('?' * len(keep))})", keep)
                else:
                    cur.execute("DELETE FROM clients")
                for c in clients:
                    if not c.get("uuid"):
                        continue
                    row = dict(c)
                    row["group_name"] = row.pop("group", "")
                    cur.execute(
                        f"INSERT OR REPLACE INTO clients({','.join(client_cols)}) "
                        f"VALUES({','.join('?' * len(client_cols))})",
                        [row.get(col) for col in client_cols])
                cur.execute("COMMIT")
            except Exception:
                cur.execute("ROLLBACK")
                raise

    # ------------------------------------------------------------------ auth
    def verify_admin(self, password: str, username: str = "") -> bool:
        import hashlib

        stored = self.get_setting("admin_password")
        if not stored:
            return False
        if stored != hashlib.sha256(password.encode()).hexdigest():
            return False
        # 用户名校验：未设置用户名时只校验密码，保持向后兼容
        stored_user = self.get_setting("admin_username") or "admin"
        if username:
            return username == stored_user
        return True

    def set_admin(self, username: str, password: str):
        import hashlib

        self.set_setting("admin_username", username or "admin")
        self.set_setting("admin_password", hashlib.sha256(password.encode()).hexdigest())

    def set_admin_password(self, password: str):
        """向后兼容：只改密码，保留已有用户名（默认为 admin）"""
        import hashlib

        if not self.get_setting("admin_username"):
            self.set_setting("admin_username", "admin")
        self.set_setting("admin_password", hashlib.sha256(password.encode()).hexdigest())

    def get_admin_username(self) -> str:
        return self.get_setting("admin_username") or "admin"

    def has_admin(self) -> bool:
        return bool(self.get_setting("admin_password"))

    # ------------------------------------------------------- v1.9.8: 多账户
    @staticmethod
    def _hash_pw(password: str) -> str:
        import hashlib

        return hashlib.sha256(password.encode()).hexdigest()

    def create_user(self, username: str, password: str, role: str = "user",
                    perms: list = None, phone: str = "", email: str = "") -> dict:
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self._lock:
            cur = self._conn.execute(
                """INSERT INTO users(username, password_hash, role, perms, phone, email, disabled, created_at)
                   VALUES(?, ?, ?, ?, ?, ?, 0, ?)""",
                (username, self._hash_pw(password), role,
                 json.dumps(perms or []), phone or "", email or "", now),
            )
            self._conn.commit()
            return self.get_user_by_id(cur.lastrowid)

    def list_users(self) -> list:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM users ORDER BY id").fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d.pop("password_hash", None)
            out.append(d)
        return out

    def get_user_by_id(self, uid: int):
        with self._lock:
            row = self._conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d.pop("password_hash", None)
        return d

    def get_user_by_username(self, username: str):
        with self._lock:
            row = self._conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        return dict(row) if row else None

    def verify_user(self, username: str, password: str):
        """校验普通账户，返回完整行（含 password_hash）或 None。"""
        u = self.get_user_by_username(username)
        if not u or u.get("disabled"):
            return None
        if u.get("password_hash") != self._hash_pw(password or ""):
            return None
        return u

    def update_user(self, uid: int, fields: dict) -> bool:
        allowed = {"password_hash", "role", "perms", "phone", "email", "disabled", "username"}
        sets, vals = [], []
        for k, v in (fields or {}).items():
            if k in allowed:
                sets.append(f"{k} = ?")
                vals.append(v)
        if not sets:
            return False
        vals.append(uid)
        with self._lock:
            cur = self._conn.execute(f"UPDATE users SET {', '.join(sets)} WHERE id = ?", vals)
            self._conn.commit()
        return cur.rowcount > 0

    def delete_user(self, uid: int) -> bool:
        with self._lock:
            cur = self._conn.execute("DELETE FROM users WHERE id = ?", (uid,))
            self._conn.commit()
        return cur.rowcount > 0

    def set_user_password(self, uid: int, password: str) -> bool:
        return self.update_user(uid, {"password_hash": self._hash_pw(password)})

    # ------------------------------------------------------- v1.9.8: 找回密码 token
    def create_recovery_token(self, username: str, is_super: bool, ttl_sec: int = 900) -> str:
        import secrets

        token = secrets.token_hex(24)
        exp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + ttl_sec))
        with self._lock:
            self._conn.execute("DELETE FROM recovery_tokens WHERE username = ?", (username,))
            self._conn.execute(
                "INSERT INTO recovery_tokens(token, username, is_super, expires_at) VALUES(?, ?, ?, ?)",
                (token, username, 1 if is_super else 0, exp),
            )
            self._conn.commit()
        return token

    def consume_recovery_token(self, token: str):
        """校验并一次性消费 token，返回行或 None。"""
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM recovery_tokens WHERE token = ? AND expires_at > ?", (token, now)
            ).fetchone()
            if row:
                self._conn.execute("DELETE FROM recovery_tokens WHERE token = ?", (token,))
                self._conn.commit()
        return dict(row) if row else None

    # ------------------------------------------------------- v3: ping tasks
    def add_ping_task(self, name, target, type="tcp", interval_sec=300, enabled=1) -> dict:
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self._lock:
            cur = self._conn.execute(
                """INSERT INTO ping_tasks(name, target, type, interval_sec, enabled, created_at)
                   VALUES(?, ?, ?, ?, ?, ?)""",
                (name, target, type, interval_sec, enabled, now),
            )
            self._conn.commit()
            row = self._conn.execute(
                "SELECT * FROM ping_tasks WHERE id = ?", (cur.lastrowid,)).fetchone()
        return dict(row) if row else {}

    def list_ping_tasks(self):
        with self._lock:
            rows = self._conn.execute("SELECT * FROM ping_tasks ORDER BY id ASC").fetchall()
        return [dict(r) for r in rows]

    def update_ping_task(self, task_id: int, fields: dict) -> bool:
        allowed = {"name", "target", "type", "interval_sec", "enabled"}
        sets, vals = [], []
        for k, v in fields.items():
            if k in allowed:
                sets.append(f"{k} = ?")
                vals.append(v)
        if not sets:
            return False
        vals.append(task_id)
        with self._lock:
            cur = self._conn.execute(
                f"UPDATE ping_tasks SET {', '.join(sets)} WHERE id = ?", vals)
            self._conn.commit()
        return cur.rowcount > 0

    def delete_ping_task(self, task_id: int) -> bool:
        with self._lock:
            cur = self._conn.execute("DELETE FROM ping_tasks WHERE id = ?", (task_id,))
            self._conn.execute("DELETE FROM ping_results WHERE task_id = ?", (task_id,))
            self._conn.execute("DELETE FROM ping_task_clients WHERE task_id = ?", (task_id,))
            self._conn.commit()
        return cur.rowcount > 0

    def get_ping_task_clients(self, task_id: int) -> list:
        """任务绑定的节点 uuid 列表（Komari 语义：为空表示全局默认，适用所有节点）。"""
        with self._lock:
            rows = self._conn.execute(
                "SELECT client_uuid FROM ping_task_clients WHERE task_id = ? ORDER BY client_uuid",
                (task_id,)).fetchall()
        return [r["client_uuid"] for r in rows]

    def set_ping_task_clients(self, task_id: int, uuids) -> None:
        uuids = [str(u) for u in (uuids or []) if str(u).strip()]
        with self._lock:
            self._conn.execute("DELETE FROM ping_task_clients WHERE task_id = ?", (task_id,))
            self._conn.executemany(
                "INSERT OR IGNORE INTO ping_task_clients(task_id, client_uuid) VALUES(?, ?)",
                [(task_id, u) for u in uuids])
            self._conn.commit()

    def insert_ping_result(self, task_id: int, latency_ms: float, ok: bool,
                           client_uuid: str = ""):
        """写入一条延迟探测结果。

        client_uuid 为空表示主控侧探测；非空表示该节点 agent 自行探测的结果。
        """
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self._lock:
            self._conn.execute(
                "INSERT INTO ping_results(task_id, time, latency_ms, ok, client_uuid)"
                " VALUES(?, ?, ?, ?, ?)",
                (task_id, now, latency_ms, 1 if ok else 0, client_uuid or ""),
            )
            self._conn.commit()

    def prune_ping_results(self, keep_hours: int = 72):
        cutoff = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - keep_hours * 3600))
        with self._lock:
            self._conn.execute("DELETE FROM ping_results WHERE time < ?", (cutoff,))
            self._conn.commit()

    def ping_results(self, task_id: int, since_iso: str, limit: int = 500,
                     desc: bool = False):
        """延迟探测记录。desc=True 时取最新的 limit 条（图表/长窗口用，
        避免数据量超过 limit 时只拿到最旧的一段）；默认 ASC 保持历史行为。"""
        order = "DESC" if desc else "ASC"
        with self._lock:
            rows = self._conn.execute(
                f"""SELECT * FROM ping_results WHERE task_id = ? AND time >= ?
                   ORDER BY time {order} LIMIT ?""", (task_id, since_iso, limit)).fetchall()
        return [dict(r) for r in rows]

    def ping_results_for_client(self, task_id: int, client_uuid: str, since_iso: str,
                                until_iso: str = None, limit: int = 2000):
        """某任务下指定节点（client_uuid）的探测记录，按时间升序返回。

        v1.11.10 新增：SQL 侧直接按 client_uuid 过滤。数据量超过 limit 时
        在 SQL 侧做均匀抽样（ROW_NUMBER 窗口函数），保证返回的点覆盖整个
        [since, until] 窗口，而不是只取最新的一段。
        修复旧逻辑"先按 task LIMIT 再在 Python 按节点过滤"导致的 bug：
        多节点/主控混合写入时 limit 在混合数据上生效，长窗口只剩最近约 1.5 天。
        client_uuid="" 时查询主控侧探测数据（兼容未上报的 agent）。
        """
        cli = client_uuid or ""
        where = "task_id = ? AND client_uuid = ? AND time >= ?"
        params = [task_id, cli, since_iso]
        if until_iso:
            where += " AND time <= ?"
            params.append(until_iso)
        # 均匀抽样：(rn*L)//cnt 递增的 L 个位置，恰好取 L 行且等距
        with self._lock:
            rows = self._conn.execute(
                f"""SELECT id, task_id, time, latency_ms, ok, client_uuid FROM (
                        SELECT *, ROW_NUMBER() OVER (ORDER BY time ASC, id ASC) AS rn,
                               COUNT(*) OVER () AS cnt
                        FROM ping_results WHERE {where}
                    )
                    WHERE cnt <= ? OR ((rn * ?) / cnt) != (((rn - 1) * ?) / cnt)
                    ORDER BY time ASC, id ASC""",
                params + [limit, limit, limit]).fetchall()
        return [dict(r) for r in rows]

    def ping_stats(self, since_iso: str):
        """Per-task stats over a window: avg/min/max latency, loss ratio, last sample."""
        out = []
        for t in self.list_ping_tasks():
            with self._lock:
                rows = self._conn.execute(
                    """SELECT latency_ms, ok, time FROM ping_results
                       WHERE task_id = ? AND time >= ? ORDER BY time ASC""",
                    (t["id"], since_iso)).fetchall()
            oks = [r["latency_ms"] for r in rows if r["ok"]]
            total = len(rows)
            out.append({
                "task": t,
                "samples": total,
                "loss": round(1 - len(oks) / total, 4) if total else 0,
                "avg": round(sum(oks) / len(oks), 2) if oks else 0,
                "min": round(min(oks), 2) if oks else 0,
                "max": round(max(oks), 2) if oks else 0,
                "last_ms": round(oks[-1], 2) if oks else 0,
                "last_ok": bool(rows and rows[-1]["ok"]),
                "last_time": rows[-1]["time"] if rows else "",
            })
        return out

    # ------------------------------------------------------- v3: alert rules
    def add_alert_rule(self, name, metric, threshold, ratio=0.8, interval_min=2,
                       enabled=1, clients="[]") -> dict:
        with self._lock:
            cur = self._conn.execute(
                """INSERT INTO alert_rules(name, metric, threshold, ratio, interval_min,
                                          enabled, clients)
                   VALUES(?, ?, ?, ?, ?, ?, ?)""",
                (name, metric, threshold, ratio, interval_min, enabled, clients),
            )
            self._conn.commit()
            row = self._conn.execute(
                "SELECT * FROM alert_rules WHERE id = ?", (cur.lastrowid,)).fetchone()
        return dict(row) if row else {}

    def list_alert_rules(self):
        with self._lock:
            rows = self._conn.execute("SELECT * FROM alert_rules ORDER BY id ASC").fetchall()
        return [dict(r) for r in rows]

    def update_alert_rule(self, rule_id: int, fields: dict) -> bool:
        allowed = {"name", "metric", "threshold", "ratio", "interval_min", "enabled", "clients"}
        sets, vals = [], []
        for k, v in fields.items():
            if k in allowed:
                sets.append(f"{k} = ?")
                vals.append(v)
        if not sets:
            return False
        vals.append(rule_id)
        with self._lock:
            cur = self._conn.execute(
                f"UPDATE alert_rules SET {', '.join(sets)} WHERE id = ?", vals)
            self._conn.commit()
        return cur.rowcount > 0

    def delete_alert_rule(self, rule_id: int) -> bool:
        with self._lock:
            cur = self._conn.execute("DELETE FROM alert_rules WHERE id = ?", (rule_id,))
            self._conn.commit()
        return cur.rowcount > 0

    def set_rule_fired(self, rule_id: int):
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self._lock:
            self._conn.execute(
                "UPDATE alert_rules SET last_fired_at = ? WHERE id = ?", (now, rule_id))
            self._conn.commit()

    # ------------------------------------------------------- v3: sessions
    def create_session(self, sid: str, ip: str, ua: str, ttl_sec: int = 30 * 86400,
                       username: str = "", role: str = "") -> dict:
        now = time.time()
        fmt = lambda t: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))
        with self._lock:
            self._conn.execute(
                """INSERT INTO sessions(id, ip, ua, created_at, expires_at, last_seen, username, role)
                   VALUES(?, ?, ?, ?, ?, ?, ?, ?)""",
                (sid, ip, ua[:200], fmt(now), fmt(now + ttl_sec), fmt(now), username or "", role or ""),
            )
            self._conn.commit()
            row = self._conn.execute("SELECT * FROM sessions WHERE id = ?", (sid,)).fetchone()
        return dict(row) if row else {}

    def get_session(self, sid: str):
        with self._lock:
            row = self._conn.execute("SELECT * FROM sessions WHERE id = ?", (sid,)).fetchone()
        return dict(row) if row else None

    def touch_session(self, sid: str):
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self._lock:
            self._conn.execute("UPDATE sessions SET last_seen = ? WHERE id = ?", (now, sid))
            self._conn.commit()

    def list_sessions(self):
        with self._lock:
            rows = self._conn.execute("SELECT * FROM sessions ORDER BY last_seen DESC").fetchall()
        return [dict(r) for r in rows]

    def delete_all_sessions(self) -> int:
        with self._lock:
            cur = self._conn.execute("DELETE FROM sessions")
            self._conn.commit()
            return cur.rowcount

    def prune_expired_sessions(self):
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self._lock:
            self._conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
            self._conn.commit()

    # ------------------------------------------------------- v3: events
    def log_event(self, level: str, type: str, message: str):
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self._lock:
            self._conn.execute(
                "INSERT INTO events(time, level, type, message) VALUES(?, ?, ?, ?)",
                (now, level, type, message[:1000]),
            )
            self._conn.commit()

    def list_events(self, limit: int = 100, offset: int = 0):
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM events ORDER BY id DESC LIMIT ? OFFSET ?",
                (limit, offset)).fetchall()
        return [dict(r) for r in rows]

    def count_events(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()
        return int(row["n"]) if row else 0

    def clear_events(self):
        with self._lock:
            self._conn.execute("DELETE FROM events")
            self._conn.commit()

    # ------------------------------------------------------- v3: exec tasks
    def add_exec_task(self, client_uuid: str, command: str) -> dict:
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self._lock:
            cur = self._conn.execute(
                """INSERT INTO exec_tasks(client_uuid, command, status, created_at)
                   VALUES(?, ?, 'pending', ?)""",
                (client_uuid, command[:2000], now),
            )
            self._conn.commit()
            row = self._conn.execute(
                "SELECT * FROM exec_tasks WHERE id = ?", (cur.lastrowid,)).fetchone()
        return dict(row) if row else {}

    def has_pending_exec(self, client_uuid: str, command: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                """SELECT COUNT(*) AS n FROM exec_tasks
                   WHERE client_uuid = ? AND command = ? AND status = 'pending'""",
                (client_uuid, command[:2000])).fetchone()
        return bool(row and row["n"])

    def claim_exec_tasks(self, client_uuid: str, limit: int = 5):
        """Agent picks up pending tasks; marked running to avoid double execution."""
        with self._lock:
            rows = self._conn.execute(
                """SELECT * FROM exec_tasks WHERE client_uuid = ? AND status = 'pending'
                   ORDER BY id ASC LIMIT ?""", (client_uuid, limit)).fetchall()
            tasks = [dict(r) for r in rows]
            for t in tasks:
                self._conn.execute(
                    "UPDATE exec_tasks SET status = 'running' WHERE id = ?", (t["id"],))
            self._conn.commit()
        return tasks

    def finish_exec_task(self, task_id: int, output: str, ok: bool):
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self._lock:
            self._conn.execute(
                """UPDATE exec_tasks SET status = ?, output = ?, finished_at = ?
                   WHERE id = ?""",
                ("done" if ok else "error", output[:20000], now, task_id),
            )
            self._conn.commit()

    def list_exec_tasks(self, limit: int = 50):
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM exec_tasks ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------- v3: analytics
    def sum_traffic(self, client_uuid: str, since_iso: str, until_iso: str):
        with self._lock:
            row = self._conn.execute(
                """SELECT COALESCE(SUM(traffic_up),0) AS up,
                          COALESCE(SUM(traffic_down),0) AS down,
                          COUNT(*) AS n
                   FROM records WHERE client = ? AND time >= ? AND time <= ?""",
                (client_uuid, since_iso, until_iso)).fetchone()
        return {"up": int(row["up"]), "down": int(row["down"]), "samples": int(row["n"])}

    def avg_metrics(self, client_uuid: str, since_iso: str):
        with self._lock:
            row = self._conn.execute(
                """SELECT AVG(cpu) AS cpu,
                          AVG(CASE WHEN ram_total > 0 THEN ram*100.0/ram_total END) AS mem,
                          MAX(time) AS last
                   FROM records WHERE client = ? AND time >= ?""",
                (client_uuid, since_iso)).fetchone()
        return {"cpu": round(row["cpu"] or 0, 2), "mem": round(row["mem"] or 0, 2),
                "last": row["last"] or ""}

    def peak_metrics(self, client_uuid: str, since_iso: str):
        """各指标峰值及出现时间（供仪表板排行展示）。"""
        out = {}
        with self._lock:
            q = ("SELECT {col}, time FROM records WHERE client = ? AND time >= ? "
                 "ORDER BY {col} DESC LIMIT 1")
            r = self._conn.execute(q.format(col="cpu"),
                                   (client_uuid, since_iso)).fetchone()
            out["peak_cpu"] = round(r[0] or 0, 1)
            out["peak_cpu_at"] = r[1] or ""
            r = self._conn.execute(
                q.format(col="CASE WHEN ram_total > 0 THEN ram*100.0/ram_total ELSE 0 END"),
                (client_uuid, since_iso)).fetchone()
            out["peak_mem"] = round(r[0] or 0, 1)
            out["peak_mem_at"] = r[1] or ""
            r = self._conn.execute(q.format(col="net_out"),
                                   (client_uuid, since_iso)).fetchone()
            out["peak_up"] = round(r[0] or 0, 1)
            out["peak_up_at"] = r[1] or ""
            r = self._conn.execute(q.format(col="net_in"),
                                   (client_uuid, since_iso)).fetchone()
            out["peak_down"] = round(r[0] or 0, 1)
            out["peak_down_at"] = r[1] or ""
        return out

    def ping_rank_stats(self, since_iso: str):
        """各 (任务, 节点) 的平均延迟、抖动(标准差)、丢包率，供延迟排行。"""
        with self._lock:
            rows = self._conn.execute(
                """SELECT task_id, client_uuid,
                          AVG(latency_ms) AS avg_lat,
                          AVG(latency_ms*latency_ms) AS avg_sq,
                          SUM(ok) AS ok_n, COUNT(*) AS n
                   FROM ping_results WHERE time >= ?
                   GROUP BY task_id, client_uuid""",
                (since_iso,)).fetchall()
        out = []
        for r in rows:
            n = r["n"] or 0
            avg = r["avg_lat"] or 0
            var = max(0, (r["avg_sq"] or 0) - avg * avg)
            out.append({
                "task_id": r["task_id"],
                "client_uuid": r["client_uuid"],
                "avg_lat": round(avg, 1),
                "jitter": round(var ** 0.5, 2),
                "loss": round((1 - (r["ok_n"] or 0) / n) * 100, 1) if n else 0,
                "n": n,
            })
        return out

    def query_ping_records(self, since_iso: str, until_iso: str,
                           client_uuid: str = "", task_id: int = -1,
                           limit: int = 4000):
        """查询 ping 结果，供 Komari common:getRecords(type=ping)。

        返回 [(client_uuid, task_id, time, value)]，value>=0 为延迟 ms，
        value=-1 表示探测失败（丢包）。
        """
        q = ("SELECT client_uuid, task_id, time, latency_ms, ok "
             "FROM ping_results WHERE time >= ? AND time <= ? "
             "AND client_uuid != ''")
        args = [since_iso, until_iso]
        if client_uuid:
            q += " AND client_uuid = ?"
            args.append(client_uuid)
        if task_id and task_id != -1:
            q += " AND task_id = ?"
            args.append(task_id)
        q += " ORDER BY time DESC LIMIT ?"
        args.append(limit)
        with self._lock:
            rows = self._conn.execute(q, args).fetchall()
        return [(r["client_uuid"], r["task_id"], r["time"],
                 int(r["latency_ms"]) if r["ok"] else -1) for r in rows]

    def node_ping_stats(self, since_iso: str):
        """各节点最近 ping 统计，供 Komari 主题状态接口。

        返回 {client_uuid: {task_name: {name, latest, avg, min, max, loss}}}。
        """
        with self._lock:
            tasks = {r["id"]: r["name"] for r in self._conn.execute(
                "SELECT id, name FROM ping_tasks WHERE enabled=1").fetchall()}
            if not tasks:
                return {}
            rows = self._conn.execute(
                """SELECT client_uuid, task_id,
                          AVG(CASE WHEN ok=1 THEN latency_ms END) AS avg_lat,
                          MIN(CASE WHEN ok=1 THEN latency_ms END) AS min_lat,
                          MAX(CASE WHEN ok=1 THEN latency_ms END) AS max_lat,
                          SUM(ok) AS ok_n, COUNT(*) AS n
                   FROM ping_results
                   WHERE time >= ? AND client_uuid != ''
                   GROUP BY client_uuid, task_id""",
                (since_iso,)).fetchall()
            # 取各 (节点,任务) 最新一条延迟
            latest = {}
            for r in self._conn.execute(
                """SELECT client_uuid, task_id, latency_ms, ok
                   FROM ping_results
                   WHERE time >= ? AND client_uuid != ''
                   ORDER BY time DESC""",
                (since_iso,)).fetchall():
                key = (r["client_uuid"], r["task_id"])
                if key not in latest:
                    latest[key] = r
        out = {}
        for r in rows:
            uuid, tid = r["client_uuid"], r["task_id"]
            if tid not in tasks:
                continue
            n = r["n"] or 0
            name = tasks[tid]
            lt = latest.get((uuid, tid))
            stat = {
                "name": name,
                "latest": int(lt["latency_ms"]) if lt and lt["ok"] else 0,
                "avg": int(r["avg_lat"] or 0),
                "min": int(r["min_lat"] or 0),
                "max": int(r["max_lat"] or 0),
                "loss": round((1 - (r["ok_n"] or 0) / n) * 100, 1) if n else 0,
                "tail": 0,
            }
            out.setdefault(uuid, {})[name] = stat
        return out

    def traffic_series(self, since_iso: str, until_iso: str, bucket_sec: int = 900):
        """Aggregate up/down rates into time buckets across all clients."""
        with self._lock:
            rows = self._conn.execute(
                """SELECT time, AVG(net_out) AS up, AVG(net_in) AS down
                   FROM records WHERE time >= ? AND time <= ?
                   GROUP BY CAST(strftime('%s', time) / ? AS INTEGER)
                   ORDER BY time ASC""",
                (since_iso, until_iso, bucket_sec)).fetchall()
        return [{"time": r["time"], "up": round(r["up"] or 0, 1),
                 "down": round(r["down"] or 0, 1)} for r in rows]

    def vacuum(self) -> dict:
        before = self.db_size()
        with self._lock:
            self._conn.execute("VACUUM")
            self._conn.commit()
        after = self.db_size()
        return {"before": before, "after": after,
                "reclaimed": max(0, before - after)}
