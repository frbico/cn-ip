# cn-ip / cnip

在 **1Panel 社区版 / 专业版的 OpenResty** 上为**指定域名**启用「仅允许中国大陆 IP 访问」，不需要 Cloudflare 橙云代理。

安装后运行 `cnip` 即可进入 **中文数字菜单**。同时支持命令行调用，适合脚本和定时任务。

> ⚠️ 本工具会修改 OpenResty 网站配置文件，并重载 Nginx。请先在测试站验证。IP 归属地不等于真实地理位置；VPN、代理和 IP 数据库误差都可能影响结果。

## 功能

- 通过 Docker 挂载自动查找 1Panel OpenResty 容器、`/www` 目录和 `conf.d`，无需手填安装路径
- **精确匹配域名**：多个域名共用同一个 `server` 时，只有已加入规则的 Host 被限制
- 中国大陆 **IPv4 + IPv6** 白名单，使用 IPdeny 数据库，下载数据格式校验、失败不部署
- 设置境外固定办公 IP / 监控 IP **额外放行**（IPv4、IPv6、CIDR；对所有受 cnip 保护的域名同时生效）
- 默认放行 `/.well-known/acme-challenge/` 路径，以减少 HTTP-01 证书续期冲突，可开关
- 通过 systemd timer 每日自动更新 IP 地址库（需自行启用）
- 查看域名状态、配置检测、修复 1Panel 重写后丢失的 include、保存所有变更的备份、恢复
- 交易式写入：`nginx -t` 与配置加载检测通过才重载；失败尝试回滚
- 运行 `cnip uninstall` 取消 cnip 管理的规则并卸载命令，不删除备份

## 环境要求

- Linux，root 权限，Python 3.8+、Docker CLI、curl
- 1Panel 已安装并运行 OpenResty，网站流量实际经过此 OpenResty
- OpenResty 容器需把网站目录挂载到 `/www`、把网站配置目录挂载到 `/usr/local/openresty/nginx/conf/conf.d`
- 网站 `server_name` 在上述配置目录的 `*.conf` 文件内存在，使用**精确域名**（不支持将通配符视为精确域名）
- OpenResty Nginx 构建包含标准 `geo`、`map` 模块
- IPdeny 可被服务器访问；只对相关 IP 数据进行本地生成及存储

如果 1Panel 使用不同的容器布局或在 OpenResty 前还有一层代理，需要自行核实真实客户端 IP 与兼容性。发现多个候选容器时可使用 `CNIP_CONTAINER=容器名 cnip` 选择。

## 安装

**方法 A：克隆仓库后安装（建议首次使用）**

```bash
git clone https://github.com/frbico/cn-ip.git
cd cn-ip
sudo bash install.sh
sudo cnip
```

**方法 B：一行下载安装**

```bash
curl -fsSL https://raw.githubusercontent.com/frbico/cn-ip/main/install.sh -o /tmp/cnip-install.sh && sudo bash /tmp/cnip-install.sh
sudo cnip
```

安装器会检查 Python 版本及 Docker 等依赖；缺少依赖时明确报错，不会自动安装系统软件。单独下载安装脚本时，会从仓库下载 `cnip.py`，不会使用 `/tmp` 中零散的同名文件。

安装器只负责将 `cnip.py` 安装为 `/usr/local/bin/cnip`；安装时**不会自动修改网站配置**。如果想让 `cnip` 不需要 `sudo`，可以先进入 `sudo -i` 的 root 终端。

> 安全提示：执行下载的安装脚本前，请审查仓库代码；生产环境建议固定版本 / 提交哈希下载并核对文件。

## 升级与交互排障

升级前在所有旧版菜单输入 `0` 退出，再重新执行上面的安装命令；不会重置现有域名规则或备份。运行 `cnip --version` 确认版本为 `1.0.4`，然后重新打开菜单。已经运行的旧进程不会因覆盖脚本而自动更新。

- 恢复备份时可以输入列表中的序号，也可以输入完整备份名称；CLI 的 `restore` 子命令仍使用完整名称。
- 诊断、自动更新状态、备份列表及完成结果使用统一分区，长路径单独显示。
- 菜单输入数字后会显示识别、下载、备份及重载阶段。完成、失败、取消或输入无效后，都会停留显示结果，只有直接按 Enter（回车）才返回主菜单；输入其他内容不会自动返回。
- Docker 的列表及 inspect 调用各最多等待 15 秒；其他系统命令默认 30 秒；IPv4、IPv6 每次下载各最多等待 110 秒。超时会报错，不会无限静默等待。
- 菜单空闲及结果停留时不占用操作锁；另一项操作执行中会立即提示繁忙。若旧版菜单仍打开，先输入 `0` 退出旧菜单，不要删除锁文件。
- 第 3 项读取当前受保护域名和 IP 库状态；未初始化会明确显示 0 条及“尚未更新”。
- 第 4 项即使尚未启用任何域名，也会下载并校验 IPv4/IPv6 数据库，但不会自动开启域名限制。定时任务在没有受保护域名时仍跳过更新。
- 所有输入处，包括主菜单、域名/IP 输入、确认提示、自动更新子菜单及结果停留页，按 Ctrl+C 都会退出整个工具。下载阶段按 Ctrl+C 也会退出；配置写入、验证或重载阶段按 Ctrl+C 时，会先尝试从变更前备份回滚，再退出。不要直接终止进程或关闭服务器。

若仍有异常，可以分别执行下面的命令，查看卡在哪个阶段（Docker 命令超时也会明确报错）：

```bash
sudo cnip list
sudo cnip update
sudo cnip doctor
```

## 交互式管理

```bash
sudo cnip
```

```text
cnip · 1Panel 中国大陆 IP 访问管理
v1.0.4

域名与 IP 库
  1. 开启指定域名限制
  2. 关闭指定域名限制
  3. 查看域名 / IP 库状态
  4. 更新中国 IP 地址库

访问例外
  5. 新增 IP / 网段放行
  6. 删除自定义放行
  7. 设置证书验证路径例外

维护与备份
  8. 自动更新管理
  9. 检查 OpenResty 配置
 10. 修复网站规则
 11. 查看配置备份
 12. 恢复配置备份

退出与卸载
  0. 退出工具
 13. 卸载工具并撤销全部限制

Enter 返回主菜单 · Ctrl+C 随时退出
```

## 命令行示例

```bash
sudo cnip add example.com                # 仅允许中国大陆 IP 访问 example.com
sudo cnip add www.example.com            # www 域名需要单独启用
sudo cnip list                           # 状态
sudo cnip remove example.com             # 取消限制
sudo cnip update                         # 更新 IPv4 / IPv6 库
sudo cnip allow add 203.0.113.10         # 示例保留地址；实际使用请替换
sudo cnip allow add 2001:db8::/48       # IPv6 CIDR 示例（文档地址不可实际访问）
sudo cnip allow list
sudo cnip allow remove 203.0.113.10
sudo cnip acme on                        # 允许 HTTP-01 路径绕过地区限制（默认）
sudo cnip acme off
sudo cnip auto-update enable             # 开启每日自动更新
sudo cnip auto-update status
sudo cnip auto-update disable
sudo cnip doctor                         # 检查 Nginx 配置与站点标记
sudo cnip repair                         # 重新插入缺失的站点 include
sudo cnip backups                        # 列出备份
sudo cnip restore 20261016-120000-000000-add   # 从实际备份名称恢复
sudo cnip uninstall                      # 有确认提示，撤销规则并卸载
```

## 工作原理

不依赖 Cloudflare 的 WAF。通过 OpenResty `geo` 读取来自 IPdeny 的 IPv4/IPv6 地址段，`map` 匹配 **Host + 访客地址是否允许 + ACME 路径**，仅在目标站点的 `server` 中加入带标记的 `include` 指令，命中时返回 **HTTP 403**。一个 `server_name` 配置了多个域名时，仅精确匹配加入规则的那个域名；如果 `www` 也要限制，需单独 `add www.example.com`。

文件位置根据 Docker 实际挂载动态识别：

| 文件 | 用途 |
| --- | --- |
| `[宿主机 /www 挂载源]/.cnip/state.json` | 域名、放行网段、IP 库更新记录 |
| `[宿主机 /www 挂载源]/.cnip/china.geo` | 中国大陆 IPv4/IPv6 地址段 |
| `[宿主机 /www 挂载源]/.cnip/extra.geo` | 自定义放行 IP |
| `[宿主机 /www 挂载源]/.cnip/domains.map` | 按域名拦截的 map |
| `[宿主机 conf.d 挂载源]/00-cnip-managed.conf` | Nginx `geo` / `map` 全局定义 |
| `/var/backups/cnip/` | 每次修改前保存的配置快照 |

## 旧版脚本迁移

如果你曾使用旧的一键命令，网站配置里可能有：

```nginx
include /www/cn-allow.conf;
```

或者 V2 的：

```nginx
include /www/.cn-only-v2/guard.conf;
```

**默认仍会阻止新旧规则混用。** 在中文菜单选择 `1` 并输入域名后，若检测到上述旧 include，会先显示迁移范围并要求确认；确认后自动备份网站配置，移除该目标 `server` 的旧引用并写入新规则，检测或重载失败会回滚。CLI 的 `cnip add` 仍会拒绝旧规则，需通过菜单明确确认迁移。

- 只处理目标域名对应 `server` 中的已知旧 include；**不会删除共享旧规则文件或修改其他网站的引用**。
- 同一 `server` 若还包含未被 cnip 选择的其他域名，会停止迁移，避免取消其他域名原有的限制。请先在 1Panel 将目标域名分离到独立网站配置，不要直接删除共享 include。
- 嵌套在 `location` 等块中的旧规则需人工检查，不自动迁移。
- 旧文件中的自定义放行 IP、特殊规则不会自动转换；迁移前请确认，并在菜单 `5` 重新添加必要的放行地址。
- 注释及字符串中的旧路径不会被当作实际生效的 include。
- 迁移后卸载只会撤销 cnip 的限制，不会重新启用旧 include；要恢复旧规则，请使用迁移前的 `migrate-legacy` 备份。

## 重要限制

1. **Nginx 收到的客户端 IP 必须真实可靠**。Cloudflare 灰云 + 用户直连通常满足；如果在 OpenResty 前有 CDN / 负载均衡 / 反向代理，必须先安全配置真实 IP 还原，否则会按代理 IP 判断。
2. **域名限制不是源站防火墙**。访问者通过另一个未限制的 Host、默认站点、IP 直连等，仍可能绕过某些 Web 应用的保护；请按实际情况配置默认站点及所有域名别名。
3. **证书**：默认只对 `/.well-known/acme-challenge/` 路径放行，减少 HTTP-01 验证失败，但证书验证程序需要原站点提供有效 token，不能保证所有证书自动续期方式都兼容。
4. **IPv6**：如果启用了 AAAA 记录，IPv6 也会使用中国大陆 IP 段匹配。IP 归属地可能误判，建议定时更新。
5. **1Panel 更新网站配置**可能覆盖 include：运行 `cnip doctor` 检查，必要时运行 `cnip repair`。
6. **服务器脚本运行成功不代表全球测试通过**：请使用中国大陆和境外网络分别访问域名验证返回的 HTTP 状态码。
7. 自动更新会记录启用时选择的 OpenResty 容器；容器改名后需重新启用定时器。自动更新需要服务器 systemd；安装时不会默认启动定时器。更新异常不会覆盖当前有效的 IP 数据。
8. 本工具适用于一般的 Nginx/OpenResty 站点，遇到自定义 Lua、复杂重写、外部代理或特殊服务配置，请先在测试环境中验证。

## 本地测试

```bash
python3 -m unittest discover -s tests -v
bash -n install.sh
```

GitHub Actions 包含 Python 3.8 / 3.10 / 3.12 / 3.13 的单元测试。欢迎提交问题与改进。

## 许可证

[MIT](LICENSE)
