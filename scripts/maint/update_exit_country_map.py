#!/usr/bin/env python3
"""Build a strict relay-fingerprint country map from observed exit IPs.

Tor's consensus publishes a relay's OR address, which is not always the
source address used for exit traffic. Onionoo's ``exit_addresses`` field is
derived from Tor Project exit scanners and records the latter. This script
maps those observed addresses through Tor's bundled GeoIP databases and emits
only relays whose observed addresses all resolve to one ISO country.
"""

import argparse
import bisect
import datetime
import functools
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import struct
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request


DEFAULT_URL = (
    "https://onionoo.torproject.org/details?flag=Exit&running=true&"
    "fields=fingerprint%2Cexit_addresses"
)
DEFAULT_COUNTRY_API = "http://ip-api.com/batch"
FINGERPRINT_RE = re.compile(r"^[0-9A-Fa-f]{40}$")


def _receive_exact(sock, size):
    """Receive exactly size bytes or report a closed SOCKS connection."""
    chunks = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise OSError("SOCKS5 proxy closed the connection")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _destination_bytes(host, remote_dns):
    """Encode a SOCKS5 destination, optionally resolving it locally."""
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if remote_dns:
            encoded = host.encode("idna")
            if not encoded or len(encoded) > 255:
                raise ValueError("SOCKS5 destination hostname is too long")
            return b"\x03" + bytes([len(encoded)]) + encoded
        address_info = socket.getaddrinfo(
            host, None, type=socket.SOCK_STREAM
        )
        if not address_info:
            raise OSError("unable to resolve SOCKS5 destination " + host)
        address = ipaddress.ip_address(address_info[0][4][0])
    if address.version == 4:
        return b"\x01" + address.packed
    return b"\x04" + address.packed


def _socks5_connect(sock, host, port, remote_dns, username, password):
    """Perform a SOCKS5 CONNECT handshake on an already connected socket."""
    methods = b"\x00"
    if username is not None:
        methods += b"\x02"
    sock.sendall(b"\x05" + bytes([len(methods)]) + methods)
    version, method = _receive_exact(sock, 2)
    if version != 5:
        raise OSError("invalid response from SOCKS5 proxy")
    if method == 2:
        if username is None:
            raise OSError("SOCKS5 proxy requires username/password")
        sock.sendall(
            b"\x01" + bytes([len(username)]) + username +
            bytes([len(password)]) + password
        )
        auth_version, auth_status = _receive_exact(sock, 2)
        if auth_version != 1 or auth_status != 0:
            raise OSError("SOCKS5 proxy authentication failed")
    elif method != 0:
        if method == 255:
            raise OSError("SOCKS5 proxy rejected all authentication methods")
        raise OSError("SOCKS5 proxy selected an unsupported auth method")

    destination = _destination_bytes(host, remote_dns)
    sock.sendall(b"\x05\x01\x00" + destination + struct.pack("!H", port))
    reply_version, reply_code, _, address_type = _receive_exact(sock, 4)
    if reply_version != 5:
        raise OSError("invalid CONNECT response from SOCKS5 proxy")
    if reply_code != 0:
        messages = {
            1: "general failure",
            2: "connection not allowed",
            3: "network unreachable",
            4: "host unreachable",
            5: "connection refused",
            6: "TTL expired",
            7: "command not supported",
            8: "address type not supported",
        }
        raise OSError(
            "SOCKS5 CONNECT failed: " +
            messages.get(reply_code, "error %d" % reply_code)
        )
    if address_type == 1:
        _receive_exact(sock, 4)
    elif address_type == 4:
        _receive_exact(sock, 16)
    elif address_type == 3:
        _receive_exact(sock, _receive_exact(sock, 1)[0])
    else:
        raise OSError("invalid address type in SOCKS5 response")
    _receive_exact(sock, 2)


def _parse_socks5_proxy(proxy_url):
    """Return connection settings from a socks5:// or socks5h:// URL."""
    parsed = urllib.parse.urlsplit(proxy_url)
    if parsed.scheme.lower() not in ("socks5", "socks5h"):
        raise ValueError("proxy must use socks5:// or socks5h://")
    if not parsed.hostname:
        raise ValueError("SOCKS5 proxy URL is missing a hostname")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError("SOCKS5 proxy URL must not contain a path or query")
    try:
        port = parsed.port or 1080
    except ValueError as exc:
        raise ValueError("SOCKS5 proxy URL has an invalid port") from exc
    username = parsed.username
    password = parsed.password
    if (username is None) != (password is None):
        raise ValueError(
            "SOCKS5 proxy URL must include both username and password"
        )
    if username is not None:
        username = urllib.parse.unquote_to_bytes(username)
        password = urllib.parse.unquote_to_bytes(password)
        if not (1 <= len(username) <= 255 and 1 <= len(password) <= 255):
            raise ValueError(
                "SOCKS5 username and password must be 1 to 255 bytes"
            )
    return {
        "proxy_host": parsed.hostname,
        "proxy_port": port,
        "remote_dns": parsed.scheme.lower() == "socks5h",
        "username": username,
        "password": password,
    }


class _Socks5HTTPConnection(http.client.HTTPConnection):
    """HTTP connection whose TCP stream is opened through SOCKS5."""

    def __init__(self, *args, proxy_settings, **kwargs):
        self.proxy_settings = proxy_settings
        super().__init__(*args, **kwargs)

    def connect(self):
        settings = self.proxy_settings
        self.sock = socket.create_connection(
            (settings["proxy_host"], settings["proxy_port"]),
            self.timeout,
            self.source_address,
        )
        try:
            _socks5_connect(
                self.sock, self.host, self.port,
                settings["remote_dns"], settings["username"],
                settings["password"],
            )
        except Exception:
            self.sock.close()
            self.sock = None
            raise


class _Socks5HTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection whose TCP stream is opened through SOCKS5."""

    def __init__(self, *args, proxy_settings, **kwargs):
        self.proxy_settings = proxy_settings
        super().__init__(*args, **kwargs)

    def connect(self):
        settings = self.proxy_settings
        self.sock = socket.create_connection(
            (settings["proxy_host"], settings["proxy_port"]),
            self.timeout,
            self.source_address,
        )
        try:
            _socks5_connect(
                self.sock, self.host, self.port,
                settings["remote_dns"], settings["username"],
                settings["password"],
            )
            self.sock = self._context.wrap_socket(
                self.sock, server_hostname=self.host
            )
        except Exception:
            self.sock.close()
            self.sock = None
            raise


class _Socks5HTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, settings):
        super().__init__()
        self.settings = settings

    def http_open(self, request):
        connection = functools.partial(
            _Socks5HTTPConnection, proxy_settings=self.settings
        )
        return self.do_open(connection, request)


class _Socks5HTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, settings):
        super().__init__()
        self.settings = settings

    def https_open(self, request):
        connection = functools.partial(
            _Socks5HTTPSConnection, proxy_settings=self.settings
        )
        arguments = {"context": self._context}
        if hasattr(self, "_check_hostname"):
            arguments["check_hostname"] = self._check_hostname
        return self.do_open(connection, request, **arguments)


def _proxy_for_url(url, proxy):
    """Select an explicit proxy or one from the standard environment."""
    if proxy is False:
        return None
    target = urllib.parse.urlsplit(url)
    if proxy is None:
        if target.hostname and urllib.request.proxy_bypass(target.hostname):
            return None
        proxies = urllib.request.getproxies()
        proxy = proxies.get(target.scheme.lower()) or proxies.get("all")
    if not proxy:
        return None
    if "://" not in proxy:
        proxy = "http://" + proxy
    return proxy


def build_url_opener(url, proxy=None):
    """Build an opener with HTTP(S), SOCKS5, or no proxy as appropriate."""
    proxy_url = _proxy_for_url(url, proxy)
    if proxy_url is None:
        return urllib.request.build_opener(urllib.request.ProxyHandler({}))
    scheme = urllib.parse.urlsplit(proxy_url).scheme.lower()
    if scheme in ("socks5", "socks5h"):
        settings = _parse_socks5_proxy(proxy_url)
        return urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _Socks5HTTPHandler(settings),
            _Socks5HTTPSHandler(settings),
        )
    if scheme in ("http", "https"):
        return urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
        )
    raise ValueError(
        "unsupported proxy scheme %r; use http, https, socks5, or socks5h"
        % scheme
    )


class GeoIPIndex:
    """Small binary-search index for Tor's geoip/geoip6 text format."""

    def __init__(self, path, version):
        self.version = version
        ranges = []
        with Path(path).open("r", encoding="ascii") as geoip_file:
            for raw_line in geoip_file:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                start_text, end_text, country = line.split(",", 2)
                if version == 4:
                    start = int(start_text)
                    end = int(end_text)
                else:
                    start = int(ipaddress.IPv6Address(start_text))
                    end = int(ipaddress.IPv6Address(end_text))
                ranges.append((start, end, country.lower()))
        ranges.sort()
        self.starts = [item[0] for item in ranges]
        self.ranges = ranges

    def country(self, address):
        ip = ipaddress.ip_address(address)
        if ip.version != self.version:
            return None
        value = int(ip)
        pos = bisect.bisect_right(self.starts, value) - 1
        if pos < 0:
            return None
        start, end, country = self.ranges[pos]
        if start <= value <= end and len(country) == 2 and country.isalpha():
            return country
        return None


def download_json(url, attempts=5, proxy=None):
    """Download JSON with bounded retries and an explicit user agent."""
    opener = build_url_opener(url, proxy)
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "tor-country-exit-map/1.0",
        },
    )
    last_error = None
    for attempt in range(attempts):
        try:
            with opener.open(request, timeout=90) as response:
                return json.load(response)
        except Exception as exc:  # Network failures vary by Python platform.
            last_error = exc
            if attempt + 1 < attempts:
                time.sleep(2 ** attempt)
    raise RuntimeError("unable to download Onionoo exit details") from last_error


def collect_addresses(document):
    """Return normalized, unique exit addresses from an Onionoo document."""
    addresses = set()
    for relay in document.get("relays", []):
        for address in relay.get("exit_addresses") or []:
            try:
                addresses.add(str(ipaddress.ip_address(address)))
            except ValueError:
                pass
    return sorted(
        addresses,
        key=lambda item: (
            ipaddress.ip_address(item).version,
            ipaddress.ip_address(item),
        ),
    )


def query_country_api(addresses, url=DEFAULT_COUNTRY_API, proxy=None):
    """Look up countries in batches, respecting the service rate headers.

    Results are used only as a consensus filter: they can exclude a relay but
    never change the country assigned by Tor's bundled GeoIP data.
    """
    opener = build_url_opener(url, proxy)
    results = {}
    batches = [
        addresses[pos:pos + 100]
        for pos in range(0, len(addresses), 100)
    ]
    for batch_number, batch in enumerate(batches):
        payload = json.dumps([
            {"query": address, "fields": "status,countryCode,query"}
            for address in batch
        ]).encode("ascii")
        last_error = None
        for attempt in range(5):
            request = urllib.request.Request(
                url,
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "tor-country-exit-map/1.0",
                },
                method="POST",
            )
            try:
                with opener.open(request, timeout=90) as response:
                    response_items = json.load(response)
                    remaining = int(response.headers.get("X-Rl", "1"))
                    reset_after = int(response.headers.get("X-Ttl", "0"))
                for item in response_items:
                    country = (item.get("countryCode") or "").lower()
                    address = item.get("query")
                    if (
                        item.get("status") == "success" and address and
                        len(country) == 2 and country.isalpha()
                    ):
                        try:
                            normalized = str(ipaddress.ip_address(address))
                        except ValueError:
                            continue
                        results[normalized] = country
                if remaining <= 0 and batch_number + 1 < len(batches):
                    time.sleep(max(reset_after, 1) + 1)
                break
            except urllib.error.HTTPError as exc:
                last_error = exc
                if exc.code != 429:
                    raise
                reset_after = int(exc.headers.get("X-Ttl", "60"))
                time.sleep(max(reset_after, 1) + 1)
            except Exception as exc:
                last_error = exc
                if attempt + 1 < 5:
                    time.sleep(2 ** attempt)
        else:
            raise RuntimeError("country consensus lookup failed") from last_error
    return results


def build_entries(document, geoip4, geoip6, consensus_countries=None):
    """Return strict map entries and counters explaining excluded relays."""
    entries = []
    counters = {
        "relays": 0,
        "included": 0,
        "no_observation": 0,
        "unknown_country": 0,
        "conflicting_country": 0,
        "provider_missing": 0,
        "provider_conflict": 0,
        "invalid": 0,
    }
    for relay in document.get("relays", []):
        counters["relays"] += 1
        fingerprint = relay.get("fingerprint", "")
        if not FINGERPRINT_RE.fullmatch(fingerprint):
            counters["invalid"] += 1
            continue
        addresses = sorted(set(relay.get("exit_addresses") or []))
        if not addresses:
            counters["no_observation"] += 1
            continue
        countries = set()
        reliable = True
        provider_missing = False
        provider_conflict = False
        for address in addresses:
            try:
                ip = ipaddress.ip_address(address)
                index = geoip4 if ip.version == 4 else geoip6
                country = index.country(address)
            except ValueError:
                country = None
            if country is None:
                reliable = False
                break
            countries.add(country)
            if consensus_countries is not None:
                normalized = str(ipaddress.ip_address(address))
                provider_country = consensus_countries.get(normalized)
                if provider_country is None:
                    provider_missing = True
                elif provider_country != country:
                    provider_conflict = True
        if not reliable:
            counters["unknown_country"] += 1
            continue
        if provider_missing:
            counters["provider_missing"] += 1
            continue
        if provider_conflict:
            counters["provider_conflict"] += 1
            continue
        if len(countries) != 1:
            counters["conflicting_country"] += 1
            continue
        country = countries.pop()
        entries.append((fingerprint.upper(), country, ",".join(addresses)))
    entries.sort()
    counters["included"] = len(entries)
    return entries, counters


def render(entries, source, country_source=None, generated_at=None):
    """Render the map format consumed by Tor."""
    if generated_at is None:
        generated_at = datetime.datetime.now(datetime.timezone.utc)
    stamp = generated_at.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    lines = [
        "# Strict Tor exit-country map.",
        "# Generated: " + stamp,
        "# Source: " + source,
        "# Country consensus: " + (country_source or "disabled"),
        "# fingerprint country observed-exit-addresses",
    ]
    lines.extend("%s %s %s" % entry for entry in entries)
    return "\n".join(lines) + "\n"


def atomic_write(path, contents):
    """Replace the output only after a complete map has been generated."""
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=output.name + ".", dir=output.parent)
    try:
        with os.fdopen(fd, "w", encoding="ascii", newline="\n") as target:
            target.write(contents)
        os.replace(temporary, output)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--geoip", required=True, help="Tor IPv4 geoip file")
    parser.add_argument("--geoip6", required=True, help="Tor IPv6 geoip6 file")
    parser.add_argument("--output", required=True, help="map file to replace")
    parser.add_argument("--url", default=DEFAULT_URL, help="Onionoo details URL")
    parser.add_argument(
        "--country-api",
        default=DEFAULT_COUNTRY_API,
        help="batch API used to reject GeoIP disagreements",
    )
    parser.add_argument("--input-json", help="use saved Onionoo JSON instead")
    proxy_group = parser.add_mutually_exclusive_group()
    proxy_group.add_argument(
        "--proxy",
        help=(
            "proxy URL (http, https, socks5, or socks5h); by default use "
            "HTTP_PROXY/HTTPS_PROXY/ALL_PROXY"
        ),
    )
    proxy_group.add_argument(
        "--no-proxy",
        action="store_true",
        help="ignore all system and environment proxy settings",
    )
    parser.add_argument(
        "--minimum-entries",
        type=int,
        default=100,
        help="refuse suspiciously small maps (default: 100)",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    proxy = False if args.no_proxy else args.proxy
    if args.input_json:
        with Path(args.input_json).open("r", encoding="utf-8") as source_file:
            document = json.load(source_file)
        source = str(args.input_json)
    else:
        document = download_json(args.url, proxy=proxy)
        source = args.url
    consensus_countries = query_country_api(
        collect_addresses(document), args.country_api, proxy=proxy
    )
    entries, counters = build_entries(
        document,
        GeoIPIndex(args.geoip, 4),
        GeoIPIndex(args.geoip6, 6),
        consensus_countries,
    )
    if len(entries) < args.minimum_entries:
        raise RuntimeError(
            "refusing to publish only %d mappings (minimum %d)"
            % (len(entries), args.minimum_entries)
        )
    atomic_write(args.output, render(entries, source, args.country_api))
    print(json.dumps(counters, sort_keys=True))


if __name__ == "__main__":
    main()
