"""Offline IP-to-country lookups from DB-IP's free country database.

The data is "IP to Country Lite" by DB-IP (https://db-ip.com), licensed CC BY 4.0. The app
downloads it once a month; addresses are looked up here and never sent anywhere.
"""
from array import array
from bisect import bisect_right
from datetime import datetime, timezone
import gzip
import io
import ipaddress
import socket

URL = "https://download.db-ip.com/free/dbip-country-lite-{month}.csv.gz"
MAX_DOWNLOAD = 64 * 1024 * 1024
MIN_RANGES = 100_000


class CountryDB:
    """Sorted, non-overlapping ranges kept in compact arrays (about 15 MB in memory)."""

    def __init__(self):
        self.v4_starts, self.v4_ends, self.v4_codes = array("I"), array("I"), bytearray()
        self.v6_starts, self.v6_ends, self.v6_codes = bytearray(), bytearray(), bytearray()
        if self.v4_starts.itemsize < 4:
            raise RuntimeError("platform array type too small")
        self._last4, self._last6 = -1, b""

    @property
    def ranges(self):
        return len(self.v4_starts) + len(self.v6_codes) // 2

    @classmethod
    def parse(cls, raw):
        """Build from the gzip-compressed CSV (start,end,country). Raises ValueError if it looks wrong."""
        db = cls()
        # Stream line by line: the decompressed file is about 40 MB; the arrays need far less.
        lines = io.TextIOWrapper(gzip.GzipFile(fileobj=io.BytesIO(raw)), encoding="ascii")
        try:
            for line in lines:
                line = line.strip()
                if line:
                    db._add(line)
        except (OSError, EOFError, UnicodeDecodeError) as error:
            raise ValueError("not a DB-IP country file") from error
        if db.ranges < MIN_RANGES:
            raise ValueError("country file is too small")
        return db

    def _add(self, line):
        parts = line.split(",")
        if len(parts) != 3 or len(parts[2]) != 2 or not parts[2].isalpha():
            raise ValueError("unexpected line in country file")
        start, end, code = parts[0], parts[1], parts[2].upper().encode("ascii")
        try:
            if ":" in start:
                first, last = socket.inet_pton(socket.AF_INET6, start), socket.inet_pton(socket.AF_INET6, end)
                if first <= self._last6 or last < first:
                    raise ValueError("IPv6 ranges are not sorted")
                self.v6_starts += first
                self.v6_ends += last
                self.v6_codes += code
                self._last6 = last
            else:
                first = int.from_bytes(socket.inet_pton(socket.AF_INET, start), "big")
                last = int.from_bytes(socket.inet_pton(socket.AF_INET, end), "big")
                if first <= self._last4 or last < first:
                    raise ValueError("IPv4 ranges are not sorted")
                self.v4_starts.append(first)
                self.v4_ends.append(last)
                self.v4_codes += code
                self._last4 = last
        except OSError as error:
            raise ValueError("bad address in country file") from error

    def country(self, ip):
        """Two-letter country code, or "" when unknown, private or not an address."""
        try:
            address = ipaddress.ip_address(ip)
        except (ValueError, TypeError):
            return ""
        if address.version == 6 and address.ipv4_mapped:
            address = address.ipv4_mapped
        if not address.is_global:
            return ""
        if address.version == 4:
            value = int(address)
            index = bisect_right(self.v4_starts, value) - 1
            if index < 0 or value > self.v4_ends[index]:
                return ""
            code = self.v4_codes[2 * index:2 * index + 2]
        else:
            packed = address.packed
            low, high = 0, len(self.v6_codes) // 2
            while low < high:  # find the last range starting at or before the address
                middle = (low + high) // 2
                if self.v6_starts[16 * middle:16 * middle + 16] <= packed:
                    low = middle + 1
                else:
                    high = middle
            index = low - 1
            if index < 0 or packed > self.v6_ends[16 * index:16 * index + 16]:
                return ""
            code = self.v6_codes[2 * index:2 * index + 2]
        code = code.decode("ascii")
        return "" if code == "ZZ" else code


def months_to_try(now=None):
    """This month's edition first, then last month's (DB-IP publishes early in the month)."""
    now = now or datetime.now(timezone.utc)
    previous = (now.year - 1, 12) if now.month == 1 else (now.year, now.month - 1)
    return [f"{now.year:04d}-{now.month:02d}", f"{previous[0]:04d}-{previous[1]:02d}"]
