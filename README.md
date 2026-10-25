# BigCat T

<img src="icon.png" alt="BigCat T" width="96">

BigCat T 是一个轻量、开箱即用的 VPS 实时监控方案，API 与 [Komari](https://github.com/komari-monitor/komari) 兼容，前端直接使用 LuminaPlus 主题（Komari-Theme-LuminaPlus v1.3.4）的构建产物，界面与 Komari 一致。

- **服务端**：Python + Flask，SQLite 存储，无需编译 Go。
- **Agent**：Python + psutil，单文件，可在被监控的 VPS 上运行，定时上报 CPU / 内存 / 磁盘 / 网络 / 负载等指标。
- **前端**：LuminaPlus 主题静态文件，通过 `/api/rpc2` JSON-RPC 获取数据。

## 目录结构

```
bigcat/
├── server/
│   ├── app.py          # Flask 服务端：静态主题 + Komari 兼容 API
│   ├── storage.py      # SQLite 存储（节点 / 历史指标 / 设置）
│   └── static/         # LuminaPlus 主题构建产物（index.html + assets）
├── agent/
│   └── agent.py        # 被控端采集脚本（psutil）
├── scripts/
│   ├── install.sh          # Debian/Ubuntu 一键安装（server/agent）
│   ├── uninstall.sh        # Debian/Ubuntu 卸载
│   ├── install-macos.sh    # macOS 一键安装（server/agent，launchd）
│   ├── uninstall-macos.sh  # macOS 卸载
│   ├── install.ps1         # Windows 一键安装（server/agent，计划任务）
│   ├── uninstall.ps1       # Windows 卸载
│   ├── install-router.sh   # 路由器一键安装（ASUSWRT-Merlin，Entware + U 盘）
│   └── bigcat.service      # systemd 服务单元（服务端，供参考）
├── requirements.txt
├── Dockerfile
└── README.md
```

## 安装与卸载

> 一键脚本会自动：安装 Python 依赖 → 创建虚拟环境 → 复制程序文件 →
> 注册开机自启服务 → 放行防火墙端口。
>
> **一键粘贴安装**：下面每条 `curl … | bash` 命令粘贴后，安装过程中会
> **交互式询问**监听端口、管理员用户名/密码（主控端）或主控地址/token
> （被控端），直接回车可用默认值。也可以用 `--port` / `--admin-user` /
> `--admin-password` 参数或 `BIGCAT_*` 环境变量预设答案，实现全自动安装。

### Debian / Ubuntu

**安装主控端（服务端）：**

```bash
curl -fsSL https://raw.githubusercontent.com/zhanghaobo1987/BigCat-T/main/scripts/install.sh | sudo bash -s -- server
```

指定端口：

```bash
curl -fsSL https://raw.githubusercontent.com/zhanghaobo1987/BigCat-T/main/scripts/install.sh | sudo bash -s -- server --port 8080
```

预设管理密码：

```bash
BIGCAT_ADMIN_PASSWORD=xxx curl -fsSL https://raw.githubusercontent.com/zhanghaobo1987/BigCat-T/main/scripts/install.sh | sudo bash -s -- server
```

全自动示例：

```bash
curl -fsSL https://raw.githubusercontent.com/zhanghaobo1987/BigCat-T/main/scripts/install.sh | sudo bash -s -- server --port 8080 --admin-user admin --admin-password "xxx"
```

**安装被控端（Agent，需先在主控注册拿到 token）：**

```bash
curl -fsSL https://raw.githubusercontent.com/zhanghaobo1987/BigCat-T/main/scripts/install.sh | sudo bash -s -- agent http://主控IP:25774 <token>
```

**卸载：**

```bash
curl -fsSL https://raw.githubusercontent.com/zhanghaobo1987/BigCat-T/main/scripts/uninstall.sh | sudo bash -s -- all
```

上面命令卸载全部（保留监控数据）。卸载全部并删除数据：

```bash
curl -fsSL https://raw.githubusercontent.com/zhanghaobo1987/BigCat-T/main/scripts/uninstall.sh | sudo bash -s -- all --purge
```

只卸载主控端把末尾 `all` 换成 `server`，只卸载被控端换成 `agent`。

### macOS

**安装主控端：**

```bash
curl -fsSL https://raw.githubusercontent.com/zhanghaobo1987/BigCat-T/main/scripts/install-macos.sh | sudo bash -s -- server
```

指定端口：

```bash
curl -fsSL https://raw.githubusercontent.com/zhanghaobo1987/BigCat-T/main/scripts/install-macos.sh | sudo bash -s -- server --port 8080
```

**安装被控端：**

```bash
curl -fsSL https://raw.githubusercontent.com/zhanghaobo1987/BigCat-T/main/scripts/install-macos.sh | sudo bash -s -- agent http://主控IP:25774 <token>
```

服务通过 launchd 注册（`com.bigcat.server` / `com.bigcat.agent`），开机自启。

**卸载：**

```bash
curl -fsSL https://raw.githubusercontent.com/zhanghaobo1987/BigCat-T/main/scripts/uninstall-macos.sh | sudo bash -s -- all
```

彻底删除数据：在末尾加 `--purge` 参数。

### Windows

请以**管理员身份**打开 PowerShell，粘贴一键安装（会先让你选 server/agent，再交互式询问端口 / 用户名 / 密码等）：

```powershell
irm https://raw.githubusercontent.com/zhanghaobo1987/BigCat-T/main/scripts/install.ps1 | iex
```

或先下载再传参（适合自动化）：

**安装主控端：**

```powershell
Invoke-WebRequest -Uri https://raw.githubusercontent.com/zhanghaobo1987/BigCat-T/main/scripts/install.ps1 -OutFile $env:TEMP\install.ps1
powershell -ExecutionPolicy Bypass -File $env:TEMP\install.ps1 -Mode server
```

指定端口 / 预设密码：

```powershell
powershell -ExecutionPolicy Bypass -File $env:TEMP\install.ps1 -Mode server -Port 8080 -AdminUser admin -AdminPassword "你的强密码"
```

**安装被控端：**

```powershell
Invoke-WebRequest -Uri https://raw.githubusercontent.com/zhanghaobo1987/BigCat-T/main/scripts/install.ps1 -OutFile $env:TEMP\install.ps1
powershell -ExecutionPolicy Bypass -File $env:TEMP\install.ps1 -Mode agent -ServerUrl http://主控IP:25774 -Token <token>
```

服务注册为 Windows 计划任务（`bigcat-server` / `bigcat-agent`），系统启动时自动运行（无窗口，后台运行）。

**卸载：**

```powershell
Invoke-WebRequest -Uri https://raw.githubusercontent.com/zhanghaobo1987/BigCat-T/main/scripts/uninstall.ps1 -OutFile $env:TEMP\uninstall.ps1
powershell -ExecutionPolicy Bypass -File $env:TEMP\uninstall.ps1 -Mode all
```

彻底删除数据：在末尾加 `-Purge` 参数。

### 路由器（ASUSWRT-Merlin）

适用于 ASUSWRT-Merlin 固件的路由器（已验证 GT-AX6000，aarch64）。
要求：路由器已开启 SSH、插有 ext2/3/4 格式的 U 盘。
脚本会自动：检测 U 盘 → 安装 Entware（已有则跳过）→ 安装 Python3 + psutil →
下载 agent → 写入开机自启（post-mount / services-start）→ 启动上报。
重复运行即升级（更新 agent 并重启，不重复写自启配置）。

在路由器 SSH 里执行（已是 root，不用 sudo；路由器没有 bash，用 sh）：

```sh
curl -fsSL https://raw.githubusercontent.com/zhanghaobo1987/BigCat-T/main/scripts/install-router.sh | sh -s -- http://主控IP:25774 <token>
```

可选参数：`--interval 秒数`（上报间隔，默认 2）、`--disk-mount 路径`
（磁盘用量监控点，默认 U 盘挂载点）、`--usb 路径`（手动指定 U 盘挂载点）、
`--raw-base 地址`（agent 下载基地址，国内可用代理前缀）。

也可以在后台管理页「节点管理」→「一键部署指令」→「路由器」分类里
直接复制带 token 的一键命令。

### 注册被控节点（拿 token）

在主控端上为每台被监控的机器注册一个节点：

```bash
curl -X POST http://主控IP:25774/api/agent/register \
  -H "Content-Type: application/json" \
  -d '{"name":"hk-1"}'
```

返回 `{"uuid": "...", "token": "..."}`，把 token 填给对应机器的安装命令。

也可以直接打开后台管理页 **http://主控IP:25774/admin**，登录后在「节点管理」里
点几下完成添加，页面会直接给出被控机的**一键安装命令**（含 token）。

## 后台管理

浏览器打开 **http://主控IP:25774/admin**：

- 首次打开会引导创建管理员账号（用户名 + 密码）
- **仪表板**：节点在线/离线统计、30 天内到期提醒、全网流量曲线、流量排行、离线节点列表
- **服务器**：添加 / 编辑（名称/分组/备注/价格/计费周期/到期日/流量限额/离线宽限/隐藏）/ 删除节点，复制 token，一键生成被控端安装命令
- **延迟监测**：TCP / HTTP / ICMP 探测任务（由主控定时执行），延迟统计与可用率，探测记录查询
- **告警规则**：CPU / 内存 / 磁盘使用率告警（阈值 + 触发比例 + 检查间隔，可按节点）
- **远程执行**：向选中节点下发 shell 命令并查看回传输出（agent 自动轮询领取）
- **通知**：多渠道（Webhook / Telegram Bot / Bark）+ 消息模板；离线通知可按节点开关与宽限；到期提醒；按节点定时流量日报/周报/月报
- **事件日志**：节点上下线、告警、通知、登录、远程执行等关键事件
- **主题管理**：上传 Komari 主题包（.zip，根目录含 komari-theme.json），或从链接 / GitHub 仓库导入；启用 / 删除 / 在线编辑主题设置（JSON），启用后前台即时切换
- **外观皮肤**：后台管理页深色 / 浅色模式 + 强调色自定义，即时生效
- **数据库**：占用信息、数据保留时长、VACUUM 压缩；**配置备份与恢复**：一键下载全部配置（站点设置、主题设置、延迟探测任务、告警规则、主机配置含 Agent Token），上传备份文件即可整体恢复
- **会话管理**：查看全部登录会话，一键删除所有会话（含本机，立即全部失效）
- **账户**：修改管理员用户名 / 密码，双重认证（2FA）
- **设置**：站点名称、站点描述、离线判定阈值
- **系统日志**：查看服务端 systemd 日志
- **关于**：版本与运行环境信息

> 说明：Webhook 渠道发送通用 JSON `{"text":"..."}`；Bark / Server 酱 / 企业微信机器人等服务若接受该格式即可直接对接，不再逐一宣称官方兼容。
> 终端、文件管理、插件系统暂未实现。

> 前端主题右上角的「后台登录 / 管理」按钮链向的正是 `/admin`。
> 直接访问 `/traffic`、`/instance/xxx` 等前端路由，或刷新页面，也能正常加载
> （服务端已做 SPA 兜底，不会再报 404）。

## 手动运行（不装服务）

### 1. 启动服务端（主控端）

```bash
pip install -r requirements.txt
cd server
python3 app.py --port 25774 --db data/bigcat.db
```

首次启动后设置管理员账号（用户名:密码）：

```bash
cd server
python3 app.py --db data/bigcat.db --set-admin "admin:你的强密码"
```

只改密码（保留原用户名）：

```bash
cd server
python3 app.py --db data/bigcat.db --set-admin "你的强密码"
```

然后浏览器打开 `http://服务器IP:25774`。

### 2. 在被控机器上手动运行 Agent

```bash
pip install psutil requests
python3 agent/agent.py --server http://主控IP:25774 --token <token> --interval 2
```

Agent 可选参数（也可用 `BIGCAT_` 前缀环境变量）：

| 参数 | 说明 |
|---|---|
| `--traffic-reset-day 1` | 月流量重置日 1-28，`0`=关闭（默认 0） |
| `--gpu` | 详细 GPU 监控（需 nvidia-smi） |
| `--disable-remote-exec` | 禁用远程命令执行 |
| `--insecure` | 忽略主控 TLS 证书校验（自签证书） |
| `--nic-ip` | 从网卡获取本机 IP 上报 |
| `--disk-mount /data` | 磁盘用量监控的挂载点（默认 `/`） |
| `--include-nics eth0,eth1` | 只统计这些网卡（逗号分隔，支持 `*` 通配） |
| `--exclude-nics 'docker*,veth*'` | 排除这些网卡 |

## API 兼容性

服务端实现了 Komari 的公开 JSON-RPC 接口（`POST /api/rpc2`，`{"jsonrpc":"2.0","method":"public:xxx"}`）：

| 方法 | 说明 |
|---|---|
| `public:getVersion` | 服务端版本 |
| `public:getMe` | 当前登录态（访客返回 Guest） |
| `public:getNodesInformation` | 节点基本信息列表 |
| `public:getPublicSettings` | 公开站点设置 |
| `public:getClientRecentRecords` | 某节点的最近上报记录 |
| `public:getRecordsByUUID` | 某节点的历史记录（legacy 形状） |
| `public:queryMetrics` | 按 metric key 查询指标序列（图表用） |
| `public:listMetricDefinitions` | 可用指标定义列表 |

Agent 上报接口：

| 接口 | 说明 |
|---|---|
| `POST /api/agent/register` | 注册节点，返回 uuid + token |
| `POST /api/agent/report` | 上报基础信息（首次） |
| `POST /api/agent/metrics` | 上报实时指标 |

## 指标

Agent 每 2 秒采集并上报：CPU 使用率、内存、Swap、磁盘、网络上下行速率与总量、TCP/UDP 连接数、进程数、系统负载、开机时长。服务端保留最近记录，`queryMetrics` 支持 `cpu.usage`、`memory.used`、`disk.used`、`net.in.rate`、`net.out.rate`、`load.average` 等 key，前端图表直接可用。

## 安全建议

- 生产环境务必设置强管理密码，关闭公网直接暴露时建议前面加反向代理（Nginx/Caddy）并启用 HTTPS。
- 每个节点的 token 妥善保管，泄露后可在管理端重新生成。
- 默认管理接口仅监听时请注意防火墙规则。

## 版本

当前版本见 `server/VERSION`（同时通过 `/api/version` 接口和 `/admin` 页面页脚展示，
服务端启动时也会打印）。每次修改代码后按 semver 递增一位：

- 修 bug → 递增 patch 位（如 `1.0.0` → `1.0.1`）
- 加功能 → 递增 minor 位（如 `1.0.0` → `1.1.0`）
- 不兼容变更 → 递增 major 位

## 许可证与致谢

- 本项目服务端与 Agent 代码为原创实现。
- 前端主题 `server/static/` 来自 [Komari-Theme-LuminaPlus](https://github.com/shanyang242/Komari-Theme-LuminaPlus)（作者 shark & shanyang），请遵守其原仓库的许可证与署名要求。
- API 设计兼容 [Komari](https://github.com/komari-monitor/komari)，感谢 Komari 团队的开源工作。
