"""Discover classifies base URLs by the kind saved in the Base URLs panel, not by port."""

import pytest

from app.services import discover_service as ds


def _saved(monkeypatch, entries):
    monkeypatch.setattr(
        "app.services.base_urls_service.load_base_urls",
        lambda: {"urls": [{"url": url, "kind": kind} for url, kind in entries]},
    )


def test_registered_frontend_is_found_on_any_port(monkeypatch):
    _saved(monkeypatch, [("http://localhost:3000", "frontend"), ("http://localhost:9000", "api")])
    bases = ["http://localhost:3000", "http://localhost:9000"]
    assert ds._frontend_base(bases) == "http://localhost:3000"
    assert ds._api_bases(bases) == ["http://localhost:9000"]


def test_runtime_alias_matches_the_saved_localhost_entry(monkeypatch):
    _saved(monkeypatch, [("http://localhost:4200", "frontend"), ("http://localhost:7000", "api")])
    bases = ["http://host.docker.internal:4200", "http://host.docker.internal:7000"]
    assert ds._frontend_base(bases) == "http://host.docker.internal:4200"
    assert ds._api_bases(bases) == ["http://host.docker.internal:7000"]


def test_api_and_frontend_counts_as_both(monkeypatch):
    _saved(monkeypatch, [("http://localhost:8000", "api-and-frontend")])
    assert ds._frontend_base(["http://localhost:8000"]) == "http://localhost:8000"
    assert ds._api_bases(["http://localhost:8000"]) == ["http://localhost:8000"]


def test_legacy_setup_without_a_frontend_kind_falls_back_to_ports(monkeypatch):
    _saved(monkeypatch, [("http://localhost:5173", "api"), ("http://localhost:8080", "api")])
    bases = ["http://localhost:5173", "http://localhost:8080"]
    assert ds._frontend_base(bases) == "http://localhost:5173"
    assert ds._api_bases(bases) == ["http://localhost:8080"]


def test_discovered_urls_are_not_filtered_by_a_site_route_list():
    eps = ds._urls_to_new_endpoints(
        {"http://localhost:8080/anything/at/all", "http://localhost:8080/flight"},
        set(),
        ["http://localhost:8080"],
    )
    assert {e.path for e in eps} == {"/anything/at/all", "/flight"}
    assert all(e.kind == "api" for e in eps)
