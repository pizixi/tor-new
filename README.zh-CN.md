# Tor 国家路由器

[English](README.md) | [简体中文](README.zh-CN.md)

此 Tor 分支会把每个通过身份认证的 SOCKS5 明网请求，路由到用户名所指定国家的出口中继。一个 Tor 进程和一个 SOCKS 端口即可同时服务多个国家，无需修改 `ExitNodes` 或重启 Tor。

国家路由功能默认启用，共享密码默认为 `123456`。如果 SOCKS 端口不只监听本机，请务必先修改默认密码。

## 快速开始

Release 压缩包包含 Tor 二进制文件、`geoip`、`geoip6`、自动生成的严格映射 `exit-countries`、映射更新脚本和 `torrc.country.example`。请在解压目录中启动 Tor：

```sh
./tor -f torrc.country.example
```

Windows：

```powershell
.\tor.exe -f .\torrc.country.example
```

然后将 ISO 3166-1 alpha-2 两位国家代码作为 SOCKS5 用户名：

```powershell
curl.exe -x socks5h://us:123456@127.0.0.1:9050 https://myip.ipip.net
curl.exe -x socks5h://de:123456@127.0.0.1:9050 https://myip.ipip.net
curl.exe -x socks5h://jp:123456@127.0.0.1:9050 https://myip.ipip.net
curl.exe -x socks5h://ca:123456@127.0.0.1:9050 https://myip.ipip.net
```

国家代码不区分大小写。必须使用 `socks5h`，这样 DNS 解析会在 Tor 网络内完成。如果指定国家没有可访问目标端口的出口，Tor 会让该请求失败，不会改用其他国家。

Release 示例配置默认启用严格模式。严格模式根据 Tor Project 出口扫描器观测到的实际出站 IP 判断国家，而不是只信任中继公开的 OR 地址；随后还要求 Tor 自带的 IPFire 数据库与第二个公共 GeoIP 查询结果一致。缺少观测、国家未知或数据源冲突的中继都会被排除。这可以显著减少与 IP 查询网站之间的结果差异，但独立 GeoIP 数据源无法保证在任何时刻都完全一致。

## 配置

本项目新增以下配置项：

```text
SocksCountryRouting 1
SocksCountryPassword 123456
SocksCountryStrict 1
SocksCountryExitMapFile exit-countries
```

启用 `SocksCountryRouting` 后，SOCKS 监听端口将强制使用 RFC1929 用户名/密码认证。用户名必须正好是两个 ASCII 字母。Tor 标准的 `IsolateSOCKSAuth` 行为会让不同凭据使用相互隔离的线路。

除非所有客户端到 SOCKS 端口之间的网络都可信，否则应始终让 `SocksPort` 只监听本机地址。SOCKS5 用户名和密码本身并不加密。

为提高准确性，建议使用 `SocksCountryStrict 1`。设置为 `0` 可恢复兼容模式：按照中继公开 OR 地址的 GeoIP 国家选择出口。兼容模式通常能为冷门国家提供更多出口，但第三方 GeoIP 服务可能把最终出口 IP 判断为另一个国家。严格模式绝不会自动回退到兼容模式。

映射更新脚本需要访问 Onionoo 和国家共识查询 API。在 Release 解压目录中可使用 Python 3 更新映射：

```sh
python3 update_exit_country_map.py --geoip geoip --geoip6 geoip6 \
  --output exit-countries
```

脚本会自动读取 `HTTP_PROXY`、`HTTPS_PROXY` 和 `ALL_PROXY`，并原生支持
`socks5://` 与 `socks5h://`，无需安装额外 Python 包。也可以显式指定代理：

```sh
python3 update_exit_country_map.py --geoip geoip --geoip6 geoip6 \
  --output exit-countries --proxy socks5h://127.0.0.1:7789
```

如需忽略环境和系统代理，请添加 `--no-proxy`。

更新完成后请重启 Tor；在支持 SIGHUP 的平台也可以发送 SIGHUP 重新加载配置。如果更新失败，脚本会保留原来的映射文件，不会用不完整文件覆盖。

`torrc.country.example` 支持 Tor 自带的上游代理配置。取消示例中下面一行的
注释，即可让 Tor 的 OR 连接经过该 SOCKS5 代理：

```text
Socks5Proxy 127.0.0.1:7789
```

这与面向应用程序的 `SocksPort 127.0.0.1:9050` 作用相反，不能把
`Socks5Proxy` 指向 Tor 自己的 `SocksPort`，否则会形成代理循环。如果上游代理
需要认证，必须同时配置 `Socks5ProxyUsername` 和 `Socks5ProxyPassword`。

## 构建和测试

Debian 或 Ubuntu：

```sh
sudo apt-get install build-essential pkg-config libevent-dev libssl-dev \
  zlib1g-dev liblzma-dev libzstd-dev
./configure --disable-asciidoc --disable-manpage --disable-html-manual
make -j"$(nproc)"
make check
```

## 自动发布

`.github/workflows/build-release.yml` 会构建并测试 Linux x86-64，构建 macOS x86-64、macOS arm64 和 Windows x86-64。工作流会根据当前 Tor Project 观测生成一份严格映射，排除 GeoIP 数据源不一致的中继，并把完全相同的映射打入所有平台的压缩包。

每次构建都会上传可移植压缩包作为 workflow artifact。推送匹配 `v*` 的标签时，还会自动创建 GitHub Release，并上传所有平台压缩包和 `SHA256SUMS`。

本项目基于 Tor 0.4.9.11。许可证条款请参阅 `LICENSE`，Tor 常规使用方式请参阅 `doc/` 目录中的上游文档。
