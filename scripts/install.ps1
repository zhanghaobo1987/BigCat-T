#Requires -RunAsAdministrator
<#
.SYNOPSIS
  BigCat 一键安装脚本（Windows）

.DESCRIPTION
  首次安装会交互式询问端口 / 管理员用户名 / 密码等，
  请以管理员身份打开 PowerShell 后粘贴：

    irm https://raw.githubusercontent.com/zhanghaobo1987/BigCat-T/main/scripts/install.ps1 | iex
    # 按提示选择 server 或 agent，并输入端口 / 用户名 / 密码等

  重复运行即升级：检测到已安装后自动复用原有配置（端口/账号/密码/主控地址/token），
  直接更新程序并重启，不再重复提问。如需改端口可加 -Port 参数；如需重置管理员密码可加 -AdminPassword 参数。

  或先下载再传参（适合自动化）：

    Invoke-WebRequest -Uri https://raw.githubusercontent.com/zhanghaobo1987/BigCat-T/main/scripts/install.ps1 -OutFile $env:TEMP\install.ps1
    powershell -ExecutionPolicy Bypass -File $env:TEMP\install.ps1 -Mode server -Port 8080 -AdminUser admin -AdminPassword "xxx"
    powershell -ExecutionPolicy Bypass -File $env:TEMP\install.ps1 -Mode agent -ServerUrl http://主控IP:25774 -Token <token>

  agent 可调选项（参数或 BIGCAT_ 前缀环境变量）:
    -IntervalSec 5                  上报间隔秒数（默认 2）
    -InstallDir "D:\bigcat"         安装目录（默认 C:\Program Files\bigcat）
    -ServiceName my-agent           计划任务名（默认 bigcat-agent）
    -RepoUrl <地址>                 源码仓库地址，用于 GitHub 访问困难时走代理
    -TrafficResetDay 1              月流量重置日 1-28，0=关闭（默认 0）
    -Gpu                            启用详细 GPU 监控（nvidia-smi）
    -DisableRemoteExec              禁用远程命令执行
    -Insecure                       忽略主控 TLS 证书校验（自签证书）
    -NicIp                          从网卡获取本机 IP 上报
    -DiskMount "D:\"               磁盘用量监控的挂载点（默认 / 或 C:\）
    -IncludeNics "eth0,eth1"        只统计这些网卡（逗号分隔，支持 * 通配）
    -ExcludeNics "docker*,veth*"    排除这些网卡（逗号分隔，支持 * 通配）

  也支持 git clone 后本地运行。
#>
param(
  [ValidateSet("server", "agent")]
  [string]$Mode,
  [int]$Port = 25774,
  [string]$AdminUser = "",
  [string]$ServerUrl = "",
  [string]$Token = "",
  [string]$AdminPassword = "",
  # agent 可调选项（也可用 BIGCAT_ 前缀环境变量）
  [int]$IntervalSec = 0,
  [string]$InstallDir = "",
  [string]$ServiceName = "",
  [string]$RepoUrl = "",
  [int]$TrafficResetDay = 0,
  [switch]$Gpu,
  [switch]$DisableRemoteExec,
  [switch]$Insecure,
  [switch]$NicIp,
  [string]$DiskMount = "",
  [string]$IncludeNics = "",
  [string]$ExcludeNics = ""
)

$ErrorActionPreference = "Stop"
# 环境变量兜底（参数优先）
if ($IntervalSec -le 0 -and $env:BIGCAT_INTERVAL) { $IntervalSec = [int]$env:BIGCAT_INTERVAL }
if ($IntervalSec -le 0) { $IntervalSec = 2 }
if (-not $InstallDir -and $env:BIGCAT_INSTALL_DIR) { $InstallDir = $env:BIGCAT_INSTALL_DIR }
if (-not $InstallDir) { $InstallDir = "C:\Program Files\bigcat" }
if (-not $ServiceName -and $env:BIGCAT_SERVICE_NAME) { $ServiceName = $env:BIGCAT_SERVICE_NAME }
if (-not $ServiceName) { $ServiceName = "bigcat-agent" }
if (-not $RepoUrl -and $env:BIGCAT_REPO_URL) { $RepoUrl = $env:BIGCAT_REPO_URL }
if (-not $RepoUrl) { $RepoUrl = "https://github.com/zhanghaobo1987/BigCat-T" }
if ($TrafficResetDay -le 0 -and $env:BIGCAT_TRAFFIC_RESET_DAY) { $TrafficResetDay = [int]$env:BIGCAT_TRAFFIC_RESET_DAY }
if (-not $Gpu -and $env:BIGCAT_GPU -match '^(1|true|yes|on)$') { $Gpu = $true }
if (-not $DisableRemoteExec -and $env:BIGCAT_DISABLE_REMOTE_EXEC -match '^(1|true|yes|on)$') { $DisableRemoteExec = $true }
if (-not $Insecure -and $env:BIGCAT_INSECURE -match '^(1|true|yes|on)$') { $Insecure = $true }
if (-not $NicIp -and $env:BIGCAT_NIC_IP -match '^(1|true|yes|on)$') { $NicIp = $true }
if (-not $DiskMount -and $env:BIGCAT_DISK_MOUNT) { $DiskMount = $env:BIGCAT_DISK_MOUNT }
if (-not $IncludeNics -and $env:BIGCAT_INCLUDE_NICS) { $IncludeNics = $env:BIGCAT_INCLUDE_NICS }
if (-not $ExcludeNics -and $env:BIGCAT_EXCLUDE_NICS) { $ExcludeNics = $env:BIGCAT_EXCLUDE_NICS }
$ZipUrl = $RepoUrl.TrimEnd('/') + "/archive/refs/heads/main.zip"
$VenvPythonw = Join-Path $InstallDir "venv\Scripts\pythonw.exe"
$VenvPython  = Join-Path $InstallDir "venv\Scripts\python.exe"

function Log([string]$msg) { Write-Host "[BigCat T] $msg" }
function Die([string]$msg) { Write-Host "[BigCat T] 错误: $msg" -ForegroundColor Red; exit 1 }

function Read-Secret([string]$prompt, [switch]$Required) {
  # 交互式读取密码（带确认）；Required 时不允许为空
  while ($true) {
    $s1 = Read-Host $prompt -AsSecureString
    $p1 = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
      [Runtime.InteropServices.Marshal]::SecureStringToBSTR($s1))
    if (-not $p1) {
      if ($Required) { Write-Host "  不能为空，请重新输入"; continue }
      return ""
    }
    $s2 = Read-Host "再输入一次确认" -AsSecureString
    $p2 = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
      [Runtime.InteropServices.Marshal]::SecureStringToBSTR($s2))
    if ($p1 -eq $p2) { return $p1 }
    Write-Host "  两次输入不一致，请重新输入"
  }
}

function Read-Required([string]$prompt) {
  $v = ""
  while (-not $v) {
    $v = (Read-Host $prompt).Trim()
    if (-not $v) { Write-Host "  不能为空，请重新输入" }
  }
  return $v
}

function Ensure-Sources {
  # 返回包含 server/ 和 agent/ 的源码目录
  $scriptDir = $PSScriptRoot
  if ($scriptDir -and (Test-Path (Join-Path $scriptDir "..\server\app.py")) -and (Test-Path (Join-Path $scriptDir "..\agent\agent.py"))) {
    return (Resolve-Path (Join-Path $scriptDir "..")).Path
  }
  Log "未检测到本地仓库源码，正在从 GitHub 下载..."
  $tmp = Join-Path ([IO.Path]::GetTempPath()) "bigcat-src"
  if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }
  New-Item -ItemType Directory -Path $tmp | Out-Null
  $zip = Join-Path $tmp "bigcat.zip"
  Invoke-WebRequest -Uri $ZipUrl -OutFile $zip
  Expand-Archive -Path $zip -DestinationPath $tmp
  return (Join-Path $tmp "bigcat-main")
}

function Ensure-Python {
  $candidates = @(
    @{ Exe = "py";      Args = @("-3") },
    @{ Exe = "python";  Args = @() },
    @{ Exe = "python3"; Args = @() }
  )
  foreach ($c in $candidates) {
    try {
      $v = & $c.Exe @($c.Args + "--version") 2>$null
      if ($LASTEXITCODE -eq 0) { Log "检测到 Python: $v"; return $c }
    } catch {}
  }
  Log "未找到 Python，尝试通过 winget 安装..."
  try {
    winget install -e --id Python.Python.3.12 --silent --accept-package-agreements --accept-source-agreements
  } catch { Die "winget 安装 Python 失败，请手动从 https://www.python.org/downloads/ 安装 Python 3.10+" }
  $env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [Environment]::GetEnvironmentVariable("Path", "User")
  return Ensure-Python
}

function Setup-Venv {
  if (-not (Test-Path $VenvPython)) {
    Log "创建虚拟环境 $InstallDir\venv ..."
    $py = Ensure-Python
    & $py.Exe @($py.Args + "-m", "venv", (Join-Path $InstallDir "venv"))
  }
  Log "安装 Python 依赖..."
  & $VenvPython -m pip install -q --upgrade pip
  & $VenvPython -m pip install -q Flask flask-cors flask-sock psutil requests
}

function Install-Server {
  # ---- 升级检测：已安装则复用原有配置，跳过端口/账号/密码提问 ----
  $upgrade = $false
  $oldTask = Get-ScheduledTask -TaskName "bigcat-server" -ErrorAction SilentlyContinue
  if ($oldTask) {
    $upgrade = $true
    if (-not $PSBoundParameters.ContainsKey("Port")) {
      $args0 = $oldTask.Actions[0].Arguments
      if ($args0 -match '--port\s+(\d+)') { $Port = [int]$Matches[1] }
    }
  } elseif (Test-Path (Join-Path $InstallDir "server\app.py")) {
    $upgrade = $true
  }
  if ($upgrade) {
    Log "检测到已安装 BigCat T，进入升级模式：保留原有配置（端口=$Port、管理员账号与数据不动），仅更新程序并重启"
  } else {
    # ---- 交互式收集配置（参数优先）----
    if (-not $PSBoundParameters.ContainsKey("Port")) {
      $p = (Read-Host "服务端监听端口 [25774]").Trim()
      if ($p) {
        if ($p -notmatch '^\d+$') { Die "端口必须是数字" }
        $Port = [int]$p
      }
    }
    if (-not $AdminUser) {
      $u = (Read-Host "管理员用户名 [admin]").Trim()
      $AdminUser = if ($u) { $u } else { "admin" }
    }
    if (-not $PSBoundParameters.ContainsKey("AdminPassword")) {
      $AdminPassword = Read-Secret "管理员密码（留空则跳过，可稍后设置）"
    }
    Log "配置: 端口=$Port, 管理员=$AdminUser"
  }

  $src = Ensure-Sources
  Log "安装服务端..."
  New-Item -ItemType Directory -Force -Path (Join-Path $InstallDir "data") | Out-Null
  Copy-Item -Recurse -Force (Join-Path $src "server") $InstallDir
  Setup-Venv

  if ($PSBoundParameters.ContainsKey("AdminPassword") -and $AdminPassword) {
    Push-Location (Join-Path $InstallDir "server")
    & $VenvPython app.py --db (Join-Path $InstallDir "data\bigcat.db") --set-admin "$($AdminUser):$($AdminPassword)" | Out-Null
    Pop-Location
    Log "管理员账号已设置（用户名: $AdminUser）"
  } elseif ($upgrade) {
    Log "升级模式：保留原有管理员账号（如需重置，重新运行时加 -AdminPassword 参数）"
  } else {
    Log "未设置管理员账号，稍后可用以下命令设置："
    Log "  `"$VenvPython`" `"$InstallDir\server\app.py`" --db `"$InstallDir\data\bigcat.db`" --set-admin `"用户名:密码`""
  }

  $taskName = "bigcat-server"
  Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
  $action = New-ScheduledTaskAction -Execute $VenvPythonw `
    -Argument "`"$InstallDir\server\app.py`" --port $Port --db `"$InstallDir\data\bigcat.db`"" `
    -WorkingDirectory "$InstallDir\server"
  $trigger = New-ScheduledTaskTrigger -AtStartup
  $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
  $settings = New-ScheduledTaskSettingsSet -RestartCount 9999 -RestartInterval (New-TimeSpan -Minutes 1) `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
  Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Force `
    -Principal $principal -Settings $settings -Description "BigCat monitoring server" | Out-Null
  Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
  Start-ScheduledTask -TaskName $taskName
  Log "计划任务 $taskName 已创建并启动（开机自启）"

  if (-not (Get-NetFirewallRule -DisplayName "bigcat-server" -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName "bigcat-server" -Direction Inbound `
      -LocalPort $Port -Protocol TCP -Action Allow | Out-Null
    Log "防火墙已放行 TCP 端口 $Port"
  }
  Log "服务端已启动: http://本机IP:$Port"
}

function Install-Agent {
  # ---- 升级检测：已安装则复用原主控地址与 token，跳过提问 ----
  $upgrade = $false
  $oldTask = Get-ScheduledTask -TaskName $ServiceName -ErrorAction SilentlyContinue
  if (-not $oldTask -and $ServiceName -ne "bigcat-agent") {
    $oldTask = Get-ScheduledTask -TaskName "bigcat-agent" -ErrorAction SilentlyContinue
  }
  if ($oldTask) {
    $upgrade = $true
    $args0 = $oldTask.Actions[0].Arguments
    if (-not $ServerUrl -and $args0 -match '--server\s+(\S+)') { $ServerUrl = $Matches[1] }
    if (-not $Token -and $args0 -match '--token\s+(\S+)') { $Token = $Matches[1] }
  } elseif (Test-Path (Join-Path $InstallDir "agent.py")) {
    $upgrade = $true
  }
  if ($upgrade) { Log "检测到已安装 agent，进入升级模式：保留原有主控地址与 token，仅更新程序并重启" }
  # ---- 交互式收集配置（参数优先）----
  if (-not $ServerUrl) { $ServerUrl = Read-Required "主控地址（例如 http://主控IP:25774）" }
  if (-not $Token)     { $Token = Read-Secret "Agent token（在主控执行 /api/agent/register 获取）" -Required }
  $src = Ensure-Sources
  Log "安装 agent，上报目标 $ServerUrl ..."
  New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
  Copy-Item -Force (Join-Path $src "agent\agent.py") $InstallDir
  Setup-Venv

  $taskName = $ServiceName
  if ($taskName -ne "bigcat-agent") {
    # 服务改名时卸载旧任务，避免重复上报
    Unregister-ScheduledTask -TaskName "bigcat-agent" -Confirm:$false -ErrorAction SilentlyContinue
  }
  Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
  # 组装 agent 启动参数（只附加用户实际启用的选项）
  $agentArgs = "--server $ServerUrl --token $Token --interval $IntervalSec"
  if ($TrafficResetDay -gt 0) { $agentArgs += " --traffic-reset-day $TrafficResetDay" }
  if ($Gpu) { $agentArgs += " --gpu" }
  if ($DisableRemoteExec) { $agentArgs += " --disable-remote-exec" }
  if ($Insecure) { $agentArgs += " --insecure" }
  if ($NicIp) { $agentArgs += " --nic-ip" }
  if ($DiskMount -and $DiskMount -ne "/") { $agentArgs += " --disk-mount `"$DiskMount`"" }
  if ($IncludeNics) { $agentArgs += " --include-nics $($IncludeNics -replace '\s','')" }
  if ($ExcludeNics) { $agentArgs += " --exclude-nics $($ExcludeNics -replace '\s','')" }
  $action = New-ScheduledTaskAction -Execute $VenvPythonw `
    -Argument "`"$InstallDir\agent.py`" $agentArgs" `
    -WorkingDirectory $InstallDir
  $trigger = New-ScheduledTaskTrigger -AtStartup
  $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
  $settings = New-ScheduledTaskSettingsSet -RestartCount 9999 -RestartInterval (New-TimeSpan -Minutes 1) `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
  Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Force `
    -Principal $principal -Settings $settings -Description "BigCat monitoring agent" | Out-Null
  Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
  Start-ScheduledTask -TaskName $taskName
  Log "计划任务 $taskName 已创建并启动（开机自启）"
  Log "agent 正在向 $ServerUrl 上报"
}

if (-not $Mode) {
  # 通过 irm ... | iex 一键运行时无法传参，改为交互式选择
  if ($Host.Name -eq "ConsoleHost") {
    Write-Host ""
    Write-Host "  BigCat 一键安装"
    Write-Host "  [1] server  主控端（监控服务端）"
    Write-Host "  [2] agent   被控端（上报本机指标）"
    Write-Host ""
    $c = (Read-Host "请选择 [1/2]").Trim()
    switch ($c) {
      "1" { $Mode = "server" }
      "2" { $Mode = "agent" }
      default { Die "无效选择" }
    }
  } else {
    Write-Host @"
用法（请以管理员身份运行 PowerShell）:
  一键安装（交互式）: irm https://raw.githubusercontent.com/zhanghaobo1987/BigCat-T/main/scripts/install.ps1 | iex
  非交互式:
    powershell -ExecutionPolicy Bypass -File install.ps1 -Mode server [-Port 端口] [-AdminUser 用户名] [-AdminPassword 密码]
    powershell -ExecutionPolicy Bypass -File install.ps1 -Mode agent -ServerUrl http://主控IP:25774 -Token <token>
"@
    exit 1
  }
}

switch ($Mode) {
  "server" { Install-Server }
  "agent"  { Install-Agent }
}
