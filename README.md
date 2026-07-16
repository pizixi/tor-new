# Tor Country Router

[English](README.md) | [简体中文](README.zh-CN.md)

This fork routes each authenticated SOCKS5 clearnet stream through an exit
relay in the country named by its username. One Tor process and one SOCKS port
can serve multiple countries concurrently without changing `ExitNodes` or
restarting.

Country routing is enabled by default. The default shared password is
`123456`; change it before exposing the SOCKS port beyond localhost.

## Quick start

Release archives include the Tor binary, `geoip`, `geoip6`, the generated
`exit-countries` strict map, its updater, and `torrc.country.example`. Start
Tor from the extracted directory:

```sh
./tor -f torrc.country.example
```

On Windows:

```powershell
.\tor.exe -f .\torrc.country.example
```

Then use an ISO 3166-1 alpha-2 country code as the SOCKS5 username:

```powershell
curl.exe -x socks5h://us:123456@127.0.0.1:9050 https://myip.ipip.net
curl.exe -x socks5h://de:123456@127.0.0.1:9050 https://myip.ipip.net
curl.exe -x socks5h://jp:123456@127.0.0.1:9050 https://myip.ipip.net
curl.exe -x socks5h://ca:123456@127.0.0.1:9050 https://myip.ipip.net
```

Country codes are case-insensitive. `socks5h` is important because it keeps
DNS resolution inside Tor. If no relay in the requested country can reach the
destination port, Tor fails the stream instead of using a different country.
The release configuration enables strict mode. It uses Tor Project exit
scanner observations to classify the address that a relay actually exits
from, rather than trusting only the relay's published OR address. It then
requires Tor's IPFire database and a second public GeoIP lookup to agree.
Relays with missing, unknown, or conflicting results are rejected. This
substantially reduces disagreement with IP-check sites, though no independent
provider can guarantee identical data at every moment.

## Configuration

The new options are:

```text
SocksCountryRouting 1
SocksCountryPassword 123456
SocksCountryStrict 1
SocksCountryExitMapFile exit-countries
```

When `SocksCountryRouting` is enabled, the SOCKS listener requires RFC1929
username/password authentication. The username must be exactly two ASCII
letters. Different credentials remain isolated on different circuits by Tor's
standard `IsolateSOCKSAuth` behavior.

Keep `SocksPort` bound to localhost unless the network path to every client is
trusted: SOCKS5 credentials are transmitted without encryption.

`SocksCountryStrict 1` is recommended for accuracy. Set it to `0` to restore
the original behavior based on each relay's published OR-address country;
that mode usually has more exits for small countries but can return an exit IP
that external GeoIP services place elsewhere. Strict mode never falls back to
the original classification. The updater needs access to Onionoo and the
country-consensus API. Refresh the map from the extracted release directory
with Python 3:

```sh
python3 update_exit_country_map.py --geoip geoip --geoip6 geoip6 \
  --output exit-countries
```

The script automatically honors `HTTP_PROXY`, `HTTPS_PROXY`, and `ALL_PROXY`.
It supports `socks5://` and `socks5h://` without an extra Python package. A
proxy can also be selected explicitly:

```sh
python3 update_exit_country_map.py --geoip geoip --geoip6 geoip6 \
  --output exit-countries --proxy socks5h://127.0.0.1:7789
```

Pass `--no-proxy` to ignore environment and system proxy settings.

Restart Tor after updating the map, or send SIGHUP on platforms that support
it. If the update fails, the script leaves the previous map unchanged.

`torrc.country.example` also supports Tor's built-in upstream proxy option.
Uncomment this example to send Tor's OR connections through a SOCKS5 proxy:

```text
Socks5Proxy 127.0.0.1:7789
```

This is the opposite side of the application-facing
`SocksPort 127.0.0.1:9050`. Do not point `Socks5Proxy` at Tor's own
`SocksPort`, since that creates a proxy loop. If the upstream proxy requires
authentication, set both `Socks5ProxyUsername` and `Socks5ProxyPassword`.

## Build and test

On Debian or Ubuntu:

```sh
sudo apt-get install build-essential pkg-config libevent-dev libssl-dev \
  zlib1g-dev liblzma-dev libzstd-dev
./configure --disable-asciidoc --disable-manpage --disable-html-manual
make -j"$(nproc)"
make check
```

## Automated releases

`.github/workflows/build-release.yml` builds and tests Linux x86-64, builds
macOS x86-64 and arm64, and builds Windows x86-64. It generates one strict map
from current Tor Project observations, rejects GeoIP-provider disagreements,
and packages the identical map on every platform. Every build uploads a
portable archive as a workflow artifact.
Pushing a tag matching `v*` also creates a GitHub Release containing all
archives and `SHA256SUMS`.

This project is based on Tor 0.4.9.11. See `LICENSE` for licensing terms and
the upstream Tor documentation under `doc/` for general Tor operation.
