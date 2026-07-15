#!/usr/bin/env python3
"""Tests for update_exit_country_map.py."""

import datetime
import ipaddress
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from update_exit_country_map import GeoIPIndex, build_entries, render


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
                {"fingerprint": "invalid", "exit_addresses": ["8.8.8.8"]},
            ]
        }
        entries, counters = build_entries(document, self.geoip4, self.geoip6)
        self.assertEqual([entry[0] for entry in entries], ["A" * 40, "B" * 40])
        self.assertTrue(all(entry[1] == "us" for entry in entries))
        self.assertEqual(counters["included"], 2)
        self.assertEqual(counters["conflicting_country"], 1)
        self.assertEqual(counters["unknown_country"], 1)
        self.assertEqual(counters["no_observation"], 1)
        self.assertEqual(counters["invalid"], 1)

    def test_render_is_stable_and_diagnostic(self):
        stamp = datetime.datetime(2026, 7, 15, tzinfo=datetime.timezone.utc)
        output = render(
            [("A" * 40, "us", "8.8.8.8")],
            "fixture.json",
            generated_at=stamp,
        )
        self.assertIn("# Generated: 2026-07-15T00:00:00Z", output)
        self.assertIn("A" * 40 + " us 8.8.8.8\n", output)


if __name__ == "__main__":
    unittest.main()
