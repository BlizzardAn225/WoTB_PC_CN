# 坦克世界闪击战 PC 版登录国服桥接

> **免责声明 / Disclaimer**
> 本项目仅供个人学习与研究。使用本项目即表示你理解并接受：
> 连接方式可能违反 Wargaming / 网易的服务条款，由此产生的账号处罚、封禁与法律责任**由使用者自行承担**。
> 请使用**自己的**账号，项目不包含任何作弊逻辑，不修改游戏对局数据。
>
> For personal study/research only. May violate the game's EULA — use at your own risk, with your own account. No cheating logic included.

基于 Steam 版客户端 11.20 适配；游戏版本更新后需按"游戏更新"一节重新适配。

---

## 原理

```
Steam 启动 PC 客户端（国际服 exe 无需改动游戏文件*）
 ├─ HTTP  :80 ──► regions_http_server.py
 │                （hosts 劫持 cdn.static.wotb.app 等，下发仅含国服 CN1 的 regions 配置）
 ├─ HTTPS :443 ─► wgni_proxy.py
 │                （hosts 劫持 cn1.plt.ms1shanghai.cn；自签证书做 TLS 中间人）
 │                ├─ Steam oauth 请求 → 替换为"模拟器登录收割的真实国服令牌"
 │                ├─ 令牌刷新/注册请求 → 透传真实 CN1（剥离 CN 不认的国际服 scope）
 │                └─ 收割：透传时自动缓存真实会话令牌
 ├─ TCP 20016 ──► 直连真实国服登录服（用透传拿到的凭证）
 └─ 进入国服大厅对战

（*） 可选的 exe NOP 补丁见下文"补丁说明"，非必需。

真实国服会话令牌的来源：在一台 **已 root 的安卓模拟器**（如 MuMu6）中运行国服
客户端登录自己的网易账号，其流量经代理时令牌被自动收割缓存（约 10 小时有效）。
```

## 文件说明

| 文件 | 用途 |
|---|---|
| `wgni_proxy.py` | WGNI 代理（:443）。令牌注入/scope 改写/注册伪造/透传/收割，核心组件 |
| `regions_http_server.py` | regions 配置服务器（:80）。向客户端下发含国服 CN1 的 regions 配置 |
| `merge_cn_common.py` | 游戏更新后重跑：把 APK 反编译产物中的国服配置键合并进下发的 regions yaml |
| `SingleEXE/main.go` | 上述两个服务 + exe 补丁检查的 **Go 一体化单文件版**（可选，编译见下） |
| `SingleEXE/go.mod` | Go 模块定义 |

## 环境要求

- Python 3.8+（仅标准库，无第三方依赖）
- Windows（客户端平台）；模拟器任选（需 root，下文以 MuMu6 为例）
- [Git Bash](https://git-scm.com/) 自带的 `openssl`（生成证书用）或任意 openssl
- 可选：Go 1.20+（编译一体化版）

## 部署步骤（一次性）

### 1. hosts 劫持（管理员编辑 `C:\Windows\System32\drivers\etc\hosts`）

```
127.0.0.1 cdn.static.wotb.app
127.0.0.1 dl-wotblitz-gc.wargaming.net
127.0.0.1 cn1.plt.ms1shanghai.cn
```

### 2. 生成 TLS 证书（脚本目录下，Git Bash 执行）

```bash
mkdir -p proxy_certs
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -keyout proxy_certs/srv.key -out proxy_certs/srv_chain.pem \
  -subj "/CN=cn1.plt.ms1shanghai.cn" \
  -addext "subjectAltName=DNS:cn1.plt.ms1shanghai.cn，DNS:cdn.static.wotb.app，DNS:dl-wotblitz-gc.wargaming.net，IP:127.0.0.1"
```

`proxy_certs/srv_chain.pem` 同时就是给模拟器安装的 CA 证书。

### 3. Windows 防火墙放行入站 80/443/20016（LAN 内模拟器访问需要 443）

## 模拟器收割配置（一次性，需 root）

1. **hosts**：模拟器 root shell 执行
   `echo <电脑IP> cn1.plt.ms1shanghai.cn >> /etc/hosts`
   （同一台电脑的 NAT 模拟器用 `10.0.2.2`；局域网另一台设备用电脑局域网 IP）
2. **系统证书**：把 `proxy_certs/srv_chain.pem` 安装为模拟器的**系统级** CA
   （Android 7+ 应用只信任系统证书；安装方法随模拟器/安卓版本而异，root 后均可完成）
3. 模拟器里运行国服客户端，登录自己的网易账号 → 代理日志出现 `[harvest]` 即收割成功

## 日常使用

1. 启动 `regions_http_server.py`（窗口 1）；
2. 启动 `wgni_proxy.py inject`（窗口 2）；
3. 首次使用Steam 启动游戏 → 登录页点「立即畅玩」→ 进入国服大厅。
   > 首次登录后，再次使用时，只需启动上述两个脚本，打开WoTB PC客户端即可自动登录。令牌理论上约 10 小时过期，但是目前暂未见过期，若PC端WoTB无法自动登录，或者进入后卡在“同步数据”，则先完成上面“模拟器收割”再启动游戏。

或者下载Release中的 `WoTB_PC_CN.exe` 按以下步骤运行：
1. 前置条件：MUMU模拟器+开启Root权限；
2. 初次使用：运行exe，弹出的窗口中选择N，此时将会拉起MUMU模拟器，用户需要手动启动游戏、登录，直到进入车库；
3. 首次登录：Steam启动WoTB PC端，点“立即畅玩”即可登录；
4. 后续使用：运行exe，Steam启动WoTB PC端，若令牌未失效，则会自动登录，弹出的窗口中选择Y无影响，若令牌失效/卡同步数据等，重新执行步骤2.

## 游戏更新后

游戏版本升级会使 regions 配置与部分适配失效：

1. 让游戏跑一次（即使失败），它会从代理拉取新版本号的 regions 请求
2. 用 jadx 反编译新版 APK，取 `assets/Data/regions_publish.yaml`
3. 重跑 `python merge_cn_common.py --apk <新版 regions_publish.yaml>`

## 可选：Go 一体化单文件版

```bash
cd SingleEXE
go build -o WoTB_PC_CN.exe .
```

`WoTB_PC_CN.exe` 等价于两个 Python 服务 + 补丁检查，数据文件跟随 exe 目录，首次运行自动生成证书并打印模拟器配置指引。参数 `-tls/-http/-ip/-game`，子命令 `check`/`revert`（检查是否补丁/还原文件）。

**内置自动收割**：启动时若令牌缺失/过期，会自动拉起已 root 的 MuMu 模拟器——自动配置模拟器 hosts 与系统 CA、启动国服客户端、等待登录收割，全程约 2-4 分钟（模拟器内弹出账号选择窗口时手动点一下登录）。相关参数：`-harvest`（强制收割）、`-no-auto-harvest`、`-mumu <MuMu安装目录>`（默认自动探测注册表）、`-adb-serial`（默认 127.0.0.1:16384）。自动收割失败时会打印手动配置指引。

## 已知限制

- **游戏内商店/活动/公告不可用**；请在手机端/模拟器查看
- 令牌理论上约 10 小时过期，但是目前暂未见过期；
- PC 端登录的账号 = 模拟器中登录成功的坦克世界闪击战国服账号；
- 仅适配 11.20，新版本需重新适配。

## 许可证

[MIT](LICENSE)——附加条款见 LICENSE 文件末尾。
