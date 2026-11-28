"""Checks for the offline country database and its monthly download."""
import gzip
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "home-assistant" / "connector")]
from aiohttp import web
from aiohttp.test_utils import make_mocked_request
import countrydb
import service

SAMPLE = """0.0.0.0,0.255.255.255,ZZ
1.0.0.0,1.0.0.255,AU
8.8.8.0,8.8.8.255,US
185.100.0.0,185.100.255.255,PT
203.0.113.0,203.0.113.255,ZZ
2001:4860::,2001:4860:ffff:ffff:ffff:ffff:ffff:ffff,US
2a01:4f8::,2a01:4f8:ffff:ffff:ffff:ffff:ffff:ffff,DE
"""


def packed(text):
    return gzip.compress(text.encode("ascii"))


class CountryDatabaseTests(unittest.TestCase):
    def setUp(self):
        patcher = patch.object(countrydb, "MIN_RANGES", 1)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_lookups_cover_ipv4_ipv6_and_mapped_addresses(self):
        db = countrydb.CountryDB.parse(packed(SAMPLE))
        self.assertEqual(db.ranges, 7)
        expected = {"185.100.0.1": "PT", "8.8.8.8": "US", "1.0.0.1": "AU", "::ffff:185.100.0.1": "PT",
                    "2001:4860:4860::8888": "US", "2a01:4f8:1:2::3": "DE",
                    "9.9.9.9": "", "10.0.0.1": "", "2001:db8::1": "", "not an ip": "", None: ""}
        for ip, code in expected.items():
            with self.subTest(ip=ip):
                self.assertEqual(db.country(ip), code)

    def test_bad_files_are_refused(self):
        for raw in (b"not gzip", packed("1.0.0.0,1.0.0.255,AUS\n"), packed("1.0.0.0,1.0.0.255\n"),
                    packed("2.0.0.0,2.0.0.255,FR\n1.0.0.0,1.0.0.255,AU\n"), packed("1.0.0.9,1.0.0.1,AU\n"),
                    packed("1.0.0.0,banana,AU\n")):
            with self.subTest(raw=raw[:20]), self.assertRaises(ValueError):
                countrydb.CountryDB.parse(raw)
        with patch.object(countrydb, "MIN_RANGES", 100), self.assertRaises(ValueError):
            countrydb.CountryDB.parse(packed(SAMPLE))

    def test_months_to_try(self):
        from datetime import datetime, timezone
        self.assertEqual(countrydb.months_to_try(datetime(2026, 11, 27, tzinfo=timezone.utc)), ["2026-11", "2026-10"])
        self.assertEqual(countrydb.months_to_try(datetime(2027, 1, 1, tzinfo=timezone.utc)), ["2027-01", "2026-12"])


class CountryDatabaseServiceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        state = Path(self.directory.name)
        self.state = state
        self.files = {}
        self.seen = []

        async def handler(request):
            month = request.match_info["month"]
            self.seen.append(month)
            if month not in self.files:
                return web.Response(status=404)
            return web.Response(body=self.files[month])
        app = web.Application()
        app.router.add_get("/free/dbip-country-lite-{month}.csv.gz", handler)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        self.addAsyncCleanup(runner.cleanup)
        port = site._server.sockets[0].getsockname()[1]
        patches = [patch.object(countrydb, "URL", f"http://127.0.0.1:{port}/free/dbip-country-lite-{{month}}.csv.gz"),
                   patch.object(countrydb, "MIN_RANGES", 1),
                   patch.object(service, "STATE", state), patch.object(service, "COUNTRY_DB_FILE", state / "db.csv.gz"),
                   patch.object(service, "COUNTRY_DB_META", state / "db.json"), patch.object(service, "COUNTRY_DB", None),
                   patch.object(service, "SETTINGS", state / "settings.json"),
                   patch.object(service, "COUNTRY_DB_STATUS", {"available": False, "month": None, "downloaded_at": None,
                                                               "ranges": 0, "error": None, "checked_at": None})]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)

    async def test_download_falls_back_to_last_month_and_survives_restart(self):
        self.files["2026-10"] = packed(SAMPLE)
        self.assertTrue(await service.download_country_db(["2026-11", "2026-10"]))
        self.assertEqual(self.seen, ["2026-11", "2026-10"])
        self.assertEqual(service.local_country("185.100.0.1"), "PT")
        self.assertEqual(service.COUNTRY_DB_STATUS["month"], "2026-10")
        service.COUNTRY_DB = None
        self.assertTrue(await service.load_country_db())
        self.assertEqual(service.local_country("8.8.8.8"), "US")

    async def test_a_bad_download_keeps_the_current_database(self):
        self.files["2026-10"] = packed(SAMPLE)
        await service.download_country_db(["2026-10"])
        self.files["2026-11"] = b"broken"
        self.assertFalse(await service.download_country_db(["2026-11"]))
        self.assertEqual(service.local_country("185.100.0.1"), "PT")
        self.assertEqual(service.COUNTRY_DB_STATUS["error"], "download_failed")
        self.assertEqual(gzip.decompress((self.state / "db.csv.gz").read_bytes()).decode(), SAMPLE)

    async def test_countries_are_returned_even_with_city_names_off(self):
        self.files["2026-10"] = packed(SAMPLE)
        await service.download_country_db(["2026-10"])
        (self.state / "settings.json").write_text(json.dumps({"geolocation_enabled": False}))
        response = await service.geolocation(make_mocked_request("GET", "/api/geolocation?ips=185.100.0.1&ips=8.8.8.8&ips=10.0.0.1"))
        data = json.loads(response.text)
        self.assertEqual(data["countries"], {"185.100.0.1": "PT", "8.8.8.8": "US"})
        self.assertEqual((data["enabled"], data["locations"]), (False, {}))

    async def test_country_rules_use_the_local_database(self):
        self.files["2026-10"] = packed(SAMPLE)
        await service.download_country_db(["2026-10"])
        found = {ip: ("", code) for ip in ["185.100.0.1", "8.8.8.8"] if (code := service.local_country(ip))}
        added = service.apply_country_rules(found, [], {"mode": "allow", "codes": ["PT"], "minutes": 60}, now=1000)
        self.assertEqual([row["cidr"] for row in added], ["8.8.8.8"])
        self.assertIn("Country: US", added[0]["reason"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
