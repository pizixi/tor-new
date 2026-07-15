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
import ipaddress
import json
import os
from pathlib import Path
import re
import tempfile
import time
import urllib.error
import urllib.request


DEFAULT_URL = (
    "https://onionoo.torproject.org/details?flag=Exit&running=true&"
    "fields=fingerprint%2Cexit_addresses"
)
DEFAULT_COUNTRY_API = "http://ip-api.com/batch"
FINGERPRINT_RE = re.compile(r"^[0-9A-Fa-f]{40}$")


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


def download_json(url, attempts=5):
    """Download JSON with bounded retries and an explicit user agent."""
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
            with urllib.request.urlopen(request, timeout=90) as response:
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


def query_country_api(addresses, url=DEFAULT_COUNTRY_API):
    """Look up countries in batches, respecting the service rate headers.

    Results are used only as a consensus filter: they can exclude a relay but
    never change the country assigned by Tor's bundled GeoIP data.
    """
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
                with urllib.request.urlopen(request, timeout=90) as response:
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
    parser.add_argument(
        "--minimum-entries",
        type=int,
        default=100,
        help="refuse suspiciously small maps (default: 100)",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    if args.input_json:
        with Path(args.input_json).open("r", encoding="utf-8") as source_file:
            document = json.load(source_file)
        source = str(args.input_json)
    else:
        document = download_json(args.url)
        source = args.url
    consensus_countries = query_country_api(
        collect_addresses(document), args.country_api
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
