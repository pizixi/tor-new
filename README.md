# Tor Country Router

This fork routes each authenticated SOCKS5 clearnet stream through an exit
relay in the country named by its username. One Tor process and one SOCKS port
can serve multiple countries concurrently without changing `ExitNodes` or
restarting.

Country routing is enabled by default. The default shared password is
`123456`; change it before exposing the SOCKS port beyond localhost.

## Quick start

Release archives include the Tor binary, `geoip`, `geoip6`, and
`torrc.country.example`. Start Tor from the extracted directory:

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
The country decision uses the bundled Tor GeoIP database and the exit relay's
published IPv4 address.

## Configuration

The new options are:

```text
SocksCountryRouting 1
SocksCountryPassword 123456
```

When `SocksCountryRouting` is enabled, the SOCKS listener requires RFC1929
username/password authentication. The username must be exactly two ASCII
letters. Different credentials remain isolated on different circuits by Tor's
standard `IsolateSOCKSAuth` behavior.

Keep `SocksPort` bound to localhost unless the network path to every client is
trusted: SOCKS5 credentials are transmitted without encryption.

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
macOS x86-64 and arm64, and builds Windows x86-64. Every build uploads a
portable archive as a workflow artifact. Pushing a tag matching `v*` also
creates a GitHub Release containing all archives and `SHA256SUMS`.

This project is based on Tor 0.4.9.11. See `LICENSE` for licensing terms and
the upstream Tor documentation under `doc/` for general Tor operation.
