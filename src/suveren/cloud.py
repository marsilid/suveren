"""Address ranges of public clouds, from the lists the clouds publish themselves.

A server deleted in a cloud gives its public address back to the pool, and the next
customer may get it. A DNS record still pointing there then shows that customer's
server on the company's subdomain (a "dangling" A record). The lists say which
addresses are such pool addresses; they are downloaded once a week and cached.

Azure is not here: its list moves to a new address every week. Russian clouds
(Yandex Cloud, VK Cloud, Selectel) publish no machine-readable list.
"""

from __future__ import annotations

import asyncio
import csv
import io
import ipaddress
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx

from suveren.cache import fetch_cached
from suveren.checks import copy_of
from suveren.errors import ModuleError

TTL = 7 * 24 * 3600
Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def parse_aws(text: str) -> list[str]:
    """EC2 is where elastic and instance addresses live; CloudFront and the like are
    shared front ends, not addresses a customer holds."""
    data: dict[str, Any] = json.loads(text)
    v4 = [p["ip_prefix"] for p in data.get("prefixes", []) if p.get("service") == "EC2"]
    v6 = [p["ipv6_prefix"] for p in data.get("ipv6_prefixes", []) if p.get("service") == "EC2"]
    return v4 + v6


def parse_gcp(text: str) -> list[str]:
    """cloud.json lists the external addresses Google Cloud customers get."""
    data: dict[str, Any] = json.loads(text)
    return [
        p.get("ipv4Prefix") or p.get("ipv6Prefix") or ""
        for p in data.get("prefixes", [])
        if p.get("ipv4Prefix") or p.get("ipv6Prefix")
    ]


def parse_oracle(text: str) -> list[str]:
    data: dict[str, Any] = json.loads(text)
    return [c["cidr"] for r in data.get("regions", []) for c in r.get("cidrs", []) if "cidr" in c]


def parse_digitalocean(text: str) -> list[str]:
    """A geofeed (RFC 8805): the prefix is the first column."""
    return [row[0] for row in csv.reader(io.StringIO(text)) if row and "/" in row[0]]


@dataclass(frozen=True, slots=True)
class CloudSource:
    name: str
    url: str
    filename: str
    parse: Callable[[str], list[str]]


SOURCES = (
    CloudSource(
        "AWS", "https://ip-ranges.amazonaws.com/ip-ranges.json", "cloud/aws.json", parse_aws
    ),
    CloudSource(
        "Google Cloud", "https://www.gstatic.com/ipranges/cloud.json", "cloud/gcp.json", parse_gcp
    ),
    CloudSource(
        "Oracle Cloud",
        "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json",
        "cloud/oracle.json",
        parse_oracle,
    ),
    CloudSource(
        "DigitalOcean",
        "https://digitalocean.com/geo/google.csv",
        "cloud/digitalocean.csv",
        parse_digitalocean,
    ),
)


@dataclass(slots=True)
class CloudRanges:
    # prefix length -> network -> cloud; a lookup is one set probe per length.
    by_length: dict[int, dict[Network, str]] = field(default_factory=dict)
    sources: list[str] = field(default_factory=list)  # "AWS, список от 30.10.2026"
    missing: list[str] = field(default_factory=list)  # clouds whose list did not load

    def add(self, cloud: str, prefixes: list[str]) -> None:
        for prefix in prefixes:
            try:
                net = ipaddress.ip_network(prefix, strict=False)
            except ValueError:
                continue
            self.by_length.setdefault(net.prefixlen, {})[net] = cloud

    def cloud_of(self, address: str) -> str | None:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return None
        for length, nets in self.by_length.items():
            if length > ip.max_prefixlen:
                continue
            net = ipaddress.ip_network(f"{ip}/{length}", strict=False)
            if net in nets:
                return nets[net]
        return None

    def overlaps(self, network: str) -> list[tuple[Network, str]]:
        """The parts of ``network`` that are pool addresses: (the shared part, its cloud).

        A cloud prefix holding the whole network gives the network itself; a smaller cloud
        prefix inside it gives that prefix."""
        try:
            net = ipaddress.ip_network(network, strict=False)
        except ValueError:
            return []
        found: list[tuple[Network, str]] = []
        low, high = int(net.network_address), int(net.broadcast_address)
        for length, nets in self.by_length.items():
            if length > net.max_prefixlen:
                continue
            if length <= net.prefixlen:
                outer = net.supernet(new_prefix=length) if length < net.prefixlen else net
                if outer in nets:
                    found.append((net, nets[outer]))
                continue
            # A longer prefix starting inside the network lies wholly inside it.
            found += [
                (n, cloud)
                for n, cloud in nets.items()
                if n.version == net.version and low <= int(n.network_address) <= high
            ]
        return found

    @property
    def empty(self) -> bool:
        return not self.by_length


async def load_ranges(client: httpx.AsyncClient, *, refresh: bool = False) -> CloudRanges:
    """Every list that loads; the clouds whose list did not are named in ``missing``."""

    async def one(src: CloudSource) -> tuple[CloudSource, list[str] | None, str]:
        try:
            path, _ = await fetch_cached(client, src.url, src.filename, ttl=TTL, refresh=refresh)
            prefixes = src.parse(path.read_text("utf-8", "replace"))
        except (ModuleError, ValueError, KeyError, TypeError, AttributeError):
            return src, None, ""
        return src, prefixes, copy_of(f"{src.name}, {src.url}", path, "список")

    ranges = CloudRanges()
    for src, prefixes, origin in await asyncio.gather(*(one(s) for s in SOURCES)):
        if prefixes:
            ranges.add(src.name, prefixes)
            ranges.sources.append(origin)
        else:
            ranges.missing.append(src.name)
    return ranges
