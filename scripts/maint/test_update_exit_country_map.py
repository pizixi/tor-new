#!/usr/bin/env python3
"""Tests for update_exit_country_map.py."""

import datetime
import ipaddress
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from update_exit_country_map import (GeoIPIndex, build_entries,
                                     _parse_socks5_proxy, _proxy_for_url,
                                     _socks5_connect, collect_addresses,
                                     render)


class FakeSocket:
    """Minimal scripted socket for SOCKS5 handshake tests."""

    def __init__(self, responses):
        self.responses = bytearray(responses)
        self.sent = []

    def recv(self, size):
        chunk = self.responses[:size]
        del self.responses[:size]
        return bytes(chunk)

    def sendall(self, data):
        self.sent.append(data)


class ExitCountryMapTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        geoip = root / "geoip"
        geoip6 = root / "geoip6"
        us_start = int(ipaddress.IPv4Address("8.8.8.0"))
        us_end = int(ipaddress.IPv4Address("8.8.8.255"))
        de_start = int(ipaddress.IPv4Address("9.9.9.0"))
        de_end = int(ipaddress.IPv4Address("9.9.9.255"))
        geoip.write_text(
            f"{us_start},{us_end},US\n{de_start},{de_end},DE\n",
            encoding="ascii",
        )
        geoip6.write_text(
            "2001:4860::,2001:4860:ffff:ffff:ffff:ffff:ffff:ffff,US\n",
            encoding="ascii",
        )
        self.geoip4 = GeoIPIndex(geoip, 4)
        self.geoip6 = GeoIPIndex(geoip6, 6)

    def tearDown(self):
        self.temporary.cleanup()

    def test_only_unambiguous_observed_countries_are_included(self):
        document = {
            "relays": [
                {"fingerprint": "A" * 40, "exit_addresses": ["8.8.8.8"]},
                {
                    "fingerprint": "B" * 40,
                    "exit_addresses": ["8.8.8.9", "2001:4860::1"],
                },
                {
                    "fingerprint": "C" * 40,
                    "exit_addresses": ["8.8.8.8", "9.9.9.9"],
                },
                {"fingerprint": "D" * 40, "exit_addresses": ["10.0.0.1"]},
                {"fingerprint": "E" * 40, "exit_addresses": []},
                {"fingerprint": "F" * 40, "exit_addresses": ["8.8.8.10"]},
                {"fingerprint": "0" * 40, "exit_addresses": ["8.8.8.11"]},
                {"fingerprint": "invalid", "exit_addresses": ["8.8.8.8"]},
            ]
        }
        consensus = {
            "8.8.8.8": "us",
            "8.8.8.9": "us",
            "2001:4860::1": "us",
            "9.9.9.9": "de",
            "8.8.8.10": "de",
        }
        entries, counters = build_entries(
            document, self.geoip4, self.geoip6, consensus
        )
        self.assertEqual([entry[0] for entry in entries], ["A" * 40, "B" * 40])
        self.assertTrue(all(entry[1] == "us" for entry in entries))
        self.assertEqual(counters["included"], 2)
        self.assertEqual(counters["conflicting_country"], 1)
        self.assertEqual(counters["unknown_country"], 1)
        self.assertEqual(counters["no_observation"], 1)
        self.assertEqual(counters["provider_conflict"], 1)
        self.assertEqual(counters["provider_missing"], 1)
        self.assertEqual(counters["invalid"], 1)

    def test_collect_addresses_normalizes_and_deduplicates(self):
        document = {"relays": [{"exit_addresses": [
            "2001:4860:0:0:0:0:0:1", "2001:4860::1", "8.8.8.8", "bad"
        ]}]}
        self.assertEqual(
            collect_addresses(document), ["8.8.8.8", "2001:4860::1"]
        )

    def test_render_is_stable_and_diagnostic(self):
        stamp = datetime.datetime(2026, 7, 15, tzinfo=datetime.timezone.utc)
        output = render(
            [("A" * 40, "us", "8.8.8.8")],
            "fixture.json",
            country_source="country-api",
            generated_at=stamp,
        )
        self.assertIn("# Generated: 2026-07-15T00:00:00Z", output)
        self.assertIn("# Country consensus: country-api", output)
        self.assertIn("A" * 40 + " us 8.8.8.8\n", output)

    def test_socks5h_connect_sends_hostname_to_proxy(self):
        sock = FakeSocket(
            b"\x05\x00" +
            b"\x05\x00\x00\x01\x7f\x00\x00\x01\x1e\x65"
        )
        _socks5_connect(
            sock, "onionoo.torproject.org", 443, True, None, None
        )
        hostname = b"onionoo.torproject.org"
        self.assertEqual(sock.sent[0], b"\x05\x01\x00")
        self.assertEqual(
            sock.sent[1],
            b"\x05\x01\x00\x03" + bytes([len(hostname)]) + hostname +
            b"\x01\xbb",
        )

    def test_socks5_proxy_credentials_are_decoded(self):
        settings = _parse_socks5_proxy(
            "socks5://user%40name:p%40ss@127.0.0.1:7789"
        )
        self.assertEqual(settings["proxy_host"], "127.0.0.1")
        self.assertEqual(settings["proxy_port"], 7789)
        self.assertEqual(settings["username"], b"user@name")
        self.assertEqual(settings["password"], b"p@ss")
        self.assertFalse(settings["remote_dns"])

    @mock.patch("urllib.request.proxy_bypass", return_value=False)
    @mock.patch("urllib.request.getproxies")
    def test_all_proxy_is_used_for_https(self, getproxies, _proxy_bypass):
        getproxies.return_value = {"all": "socks5h://127.0.0.1:7789"}
        self.assertEqual(
            _proxy_for_url("https://example.com", None),
            "socks5h://127.0.0.1:7789",
        )

    @mock.patch("urllib.request.getproxies")
    def test_proxy_can_be_disabled(self, getproxies):
        self.assertIsNone(_proxy_for_url("https://example.com", False))
        getproxies.assert_not_called()


if __name__ == "__main__":
    unittest.main()
