"""DNS-over-HTTPS resolver. Same approach as the `rockblack.pro/ip-address` page."""
from __future__ import annotations

import json
import sys
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

DEFAULT_RESOLVERS: tuple[str, ...] = (
    "https://dns.google/resolve",
    "https://cloudflare-dns.com/dns-query",
)


def resolve_a(domain: str, resolvers: tuple[str, ...] = DEFAULT_RESOLVERS, timeout: int = 8) -> set[str]:
    """Resolve A records for one domain through all listed resolvers.

    Returns the union of IPs reported. Resolvers that fail are silently
    skipped (logged to stderr).
    """
    ips: set[str] = set()
    for base in resolvers:
        url = f"{base}?{urllib.parse.urlencode({'name': domain, 'type': 'A'})}"
        req = urllib.request.Request(url, headers={"Accept": "application/dns-json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                data = json.loads(r.read())
        except Exception as e:
            print(f"  ! {domain} via {base}: {e}", file=sys.stderr)
            continue
        for ans in data.get("Answer") or []:
            if ans.get("type") == 1:
                ips.add(ans["data"])
    return ips


def resolve_many(
    domains: list[str],
    resolvers: tuple[str, ...] = DEFAULT_RESOLVERS,
    workers: int = 16,
    progress: bool = True,
) -> dict[str, set[str]]:
    """Resolve many domains in parallel. Returns {domain: {ip, ...}}."""
    result: dict[str, set[str]] = {}
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(resolve_a, d, resolvers): d for d in domains}
        for i, fut in enumerate(as_completed(futs), 1):
            d = futs[fut]
            ips = fut.result()
            result[d] = ips
            if progress:
                print(f"  [{i}/{len(domains)}] {d}: {len(ips)} IP")
    return result


def load_domains(path) -> list[str]:
    """Read newline-separated domains from a file. `#` starts a comment."""
    from pathlib import Path

    out: list[str] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        out.append(s)
    return out
