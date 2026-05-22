from __future__ import annotations

import asyncio
import socket

from loguru import logger

from threatrecon.app.core.models import Finding


class DnsEnricher:
    async def resolve(self, hostnames: set[str]) -> list[Finding]:
        tasks = [self._resolve_one(hostname) for hostname in sorted(hostnames)]
        results = await asyncio.gather(*tasks)
        findings: dict[str, Finding] = {}
        for hostname, ips in results:
            for ip in ips:
                findings[f"{hostname}:{ip}"] = Finding(
                    type="ip",
                    value=ip,
                    source=hostname,
                    severity="info",
                    evidence="Resolved via local DNS lookup",
                    metadata={"hostname": hostname},
                )
        return list(findings.values())

    async def _resolve_one(self, hostname: str) -> tuple[str, set[str]]:
        try:
            records = await asyncio.to_thread(socket.getaddrinfo, hostname, None, proto=socket.IPPROTO_TCP)
            ips = {record[4][0] for record in records}
            return hostname, ips
        except socket.gaierror as exc:
            logger.debug("DNS lookup failed for {}: {}", hostname, exc)
            return hostname, set()
