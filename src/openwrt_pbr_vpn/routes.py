"""Main update flow: resolve domains → filter → append → push to router."""

from __future__ import annotations

from . import doh, nft
from .config import Config
from .output import get_logger
from .router import Router

log = get_logger("routes")


def update(
    cfg: Config,
    *,
    upload: bool = True,
    resolvers: tuple[str, ...] = doh.DEFAULT_RESOLVERS,
) -> dict:
    """Run the full update cycle.

    Returns a small summary dict (counts, new entries) so callers/tests can
    inspect what happened without scraping stdout.
    """
    if not cfg.local_routes.exists():
        raise FileNotFoundError(f"Local routes file not found: {cfg.local_routes}")
    if not cfg.domains.exists():
        raise FileNotFoundError(f"Domains file not found: {cfg.domains}")

    log.info(f"→ Parsing {cfg.local_routes.name}…")
    existing = nft.parse_networks(cfg.local_routes)
    log.info(f"  already covered: {len(existing)} networks/IPs")

    domains = doh.load_domains(cfg.domains)
    log.info(f"→ Resolving {len(domains)} domains via DoH…")
    resolved = doh.resolve_many(domains, resolvers=resolvers)

    all_ips: set[str] = set()
    for ips in resolved.values():
        all_ips.update(ips)
    log.info(f"\n→ Unique IPs resolved: {len(all_ips)}")

    new_ips = sorted(
        (ip for ip in all_ips if not nft.is_covered(ip, existing)),
        key=lambda x: tuple(int(o) for o in x.split(".")),
    )
    log.info(f"→ New (not yet covered): {len(new_ips)}")

    summary = {
        "domains": len(domains),
        "total_resolved": len(all_ips),
        "new_ips": new_ips,
        "uploaded": False,
    }

    if not new_ips:
        log.info("\nNothing to add. Routes file unchanged.")
        if upload:
            _upload_only(cfg)
            summary["uploaded"] = True
        return summary

    if cfg.auto_aggregate_24:
        cidrs, singles = nft.aggregate_into_24(new_ips, existing)
        items = sorted(set(cidrs)) + singles
        log.info(f"  aggregation: {len(cidrs)} new /24 + {len(singles)} singles")
    else:
        items = new_ips

    log.info("\nNew entries:")
    for x in items:
        log.info(f"  + {x}")

    block = nft.render_append_block(items, batch_size=cfg.batch_size)
    nft.append_to_file(cfg.local_routes, block)
    log.info(f"\n✓ Wrote to {cfg.local_routes}")

    if upload:
        _upload_only(cfg)
        summary["uploaded"] = True

    return summary


def _upload_only(cfg: Config) -> None:
    """Push local vpn-routes.sh to router and restart PBR."""
    log.info(f"\n→ SSH {cfg.user}@{cfg.host}:{cfg.port}")
    with Router(cfg) as r:
        size = r.upload_file(cfg.local_routes, cfg.remote_routes, mode=0o755)
        log.info(f"  ✓ uploaded {size} bytes → {cfg.remote_routes}")
        # Belt-and-braces CRLF strip
        r.run(f"sed -i 's/\\r//' {cfg.remote_routes}")
        if cfg.restart_pbr:
            res = r.run("service pbr restart", timeout=120)
            for line in res.stdout.splitlines():
                log.info(f"    {line}")
            count = r.run(f"nft list set inet fw4 {cfg.nft_set} 2>/dev/null | grep -c '\\.'")
            log.info(f"  ✓ pbr restarted, set lines with dots: {count.stdout.strip()}")


def upload_only(cfg: Config) -> None:
    """Public wrapper for --upload-only mode."""
    if not cfg.local_routes.exists():
        raise FileNotFoundError(f"Local routes file not found: {cfg.local_routes}")
    _upload_only(cfg)


def routes_show(cfg: Config) -> str:
    """Dump the nft set from the router."""
    with Router(cfg) as r:
        return r.run(f"nft list set inet fw4 {cfg.nft_set}").stdout


def routes_add(cfg: Config, entries: list[str]) -> None:
    """Append entries (IPs/CIDRs) to local file and push."""
    block = nft.render_append_block(entries, batch_size=cfg.batch_size)
    nft.append_to_file(cfg.local_routes, block)
    log.info(f"✓ Appended {len(entries)} entries to {cfg.local_routes}")
    _upload_only(cfg)


def routes_remove(cfg: Config, entries: list[str]) -> int:
    """Remove entries from local file. Returns count removed."""
    if not cfg.local_routes.exists():
        return 0
    text = cfg.local_routes.read_text(encoding="utf-8")
    removed = 0
    for e in entries:
        # Strip "1.2.3.4, " or ", 1.2.3.4" or "{ 1.2.3.4 }" cases
        for pattern in (f", {e}", f"{e}, ", e):
            if pattern in text:
                text = text.replace(pattern, "", 1)
                removed += 1
                break
    cfg.local_routes.write_text(text, encoding="utf-8", newline="\n")
    log.info(f"✓ Removed {removed}/{len(entries)} entries")
    _upload_only(cfg)
    return removed
