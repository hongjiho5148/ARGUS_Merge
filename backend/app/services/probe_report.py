"""Collapse multi-pass probe rows (guest + accounts) into endpoint-level views."""

from __future__ import annotations

from typing import Any

_STATUS_RANK: dict[str, int] = {
    "confirmed": 0,
    "skipped_unsafe": 0,
    "params_issue": 1,
    "server_error": 2,
    "unknown": 3,
    "error": 4,
    "not_found": 5,
    "method_not_allowed": 6,
    "unreachable": 7,
}


def group_probe_results(results: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in results:
        grouped.setdefault(str(row.get("endpoint_id", "")), []).append(row)
    return grouped


def pick_best_probe_row(rows: list[dict[str, Any]]) -> dict[str, Any]:
    if not rows:
        return {}
    if len(rows) == 1:
        return rows[0]

    def sort_key(row: dict[str, Any]) -> tuple[Any, ...]:
        include_rank = 0 if row.get("include_in_final") else 1
        status_rank = _STATUS_RANK.get(str(row.get("status", "")), 50)
        code = row.get("http_status")
        if code is None:
            code_rank = 3
        elif 200 <= int(code) < 400:
            code_rank = 0
        elif int(code) in (401, 403):
            code_rank = 1
        else:
            code_rank = 2
        return (include_rank, status_rank, code_rank, int(code or 999))

    return sorted(rows, key=sort_key)[0]


def dedupe_probe_results(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped = group_probe_results(results)
    return [pick_best_probe_row(rows) for rows in grouped.values()]


def endpoint_passes_final(rows: list[dict[str, Any]]) -> bool:
    return any(r.get("include_in_final") and not r.get("discovered") for r in rows)


def endpoint_passes_discovered(rows: list[dict[str, Any]]) -> bool:
    return any(r.get("discovered") for r in rows)


def endpoint_passes_rejected(rows: list[dict[str, Any]]) -> bool:
    return not any(r.get("include_in_final") for r in rows)


PROBE_INPUT_SOURCES = frozenset({"probe", "zap_probe", "zap_traffic"})


def endpoint_keeps_in_inventory(ep: Any, rows: list[dict[str, Any]]) -> bool:
    """Keep endpoint in Verified inventory if probe passed OR params/headers were collected."""
    if any(r.get("include_in_final") for r in rows):
        return True
    if any(int(r.get("params_enriched") or 0) > 0 for r in rows):
        return True
    if PROBE_INPUT_SOURCES.intersection(getattr(ep, "sources", []) or []):
        return True
    header_sources = {
        source
        for hdr in getattr(ep, "request_headers", []) + getattr(ep, "response_headers", [])
        for source in getattr(hdr, "sources", [])
    }
    if PROBE_INPUT_SOURCES.intersection(header_sources):
        return True
    return False


def filter_deduped_by_outcome(
    results: list[dict[str, Any]],
    outcome: str | None,
) -> list[dict[str, Any]]:
    grouped = group_probe_results(results)
    deduped = dedupe_probe_results(results)
    if outcome == "final":
        return [row for row in deduped if endpoint_passes_final(grouped.get(str(row["endpoint_id"]), []))]
    if outcome == "discovered":
        return [row for row in deduped if endpoint_passes_discovered(grouped.get(str(row["endpoint_id"]), []))]
    if outcome == "rejected":
        return [row for row in deduped if endpoint_passes_rejected(grouped.get(str(row["endpoint_id"]), []))]
    if outcome == "verified":
        return [
            row
            for row in deduped
            if any(r.get("include_in_final") for r in grouped.get(str(row["endpoint_id"]), []))
        ]
    return deduped


def summarize_probe_results(results: list[dict[str, Any]]) -> dict[str, int]:
    grouped = group_probe_results(results)
    deduped = [pick_best_probe_row(rows) for rows in grouped.values()]

    return {
        "probe_runs": len(results),
        "endpoints_probed": len(grouped),
        "confirmed": sum(1 for row in deduped if row.get("status") == "confirmed"),
        "params_issues": sum(1 for row in deduped if row.get("status") == "params_issue"),
        "skipped_unsafe": sum(1 for row in deduped if row.get("status") == "skipped_unsafe"),
        "rejected": sum(1 for rows in grouped.values() if endpoint_passes_rejected(rows)),
        "final_count": sum(1 for rows in grouped.values() if endpoint_passes_final(rows)),
        "discovered_count": sum(1 for rows in grouped.values() if endpoint_passes_discovered(rows)),
        "verified_count": sum(1 for rows in grouped.values() if endpoint_passes_final(rows)),
    }
