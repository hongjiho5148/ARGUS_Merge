"""1-1 role helpers: privilege tiers are configurable, not tied to one site's role names."""

import importlib.util
import sys
from pathlib import Path

import pytest

_DIR = Path(__file__).resolve().parents[1] / "diagnosis" / "modules" / "1-1"


@pytest.fixture()
def rh():
    spec = importlib.util.spec_from_file_location("diag_g11_role_helpers_test", _DIR / "role_helpers.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    module.configure_role_tiers(None)
    return module


def acct(role="", **extra):
    return {"role": role, **extra}


def test_default_ranking_puts_privileged_roles_first(rh):
    ranks = [rh.account_role_rank(acct(r)) for r in ("SUPER_ADMIN", "ROLE_SELLER", "ROLE_USER", "mystery")]
    assert ranks == sorted(ranks) and len(set(ranks)) == 4


def test_roles_are_also_read_from_token_claims(rh):
    assert rh.account_role_rank({"role": "x", "claims": {"auth": "ROLE_ADMIN"}}) == rh.account_role_rank(acct("admin"))


def test_custom_tiers_replace_the_defaults(rh):
    rh.configure_role_tiers([["director", "chief"], ["clerk"]])
    assert rh.account_role_rank(acct("Director")) == 0
    assert rh.account_role_rank(acct("clerk")) == 1
    assert rh.account_role_rank(acct("ROLE_ADMIN")) > 1  # no longer privileged
    assert rh.is_admin_account({"role": "chief", "token": "t"})


def test_endpoint_priority_prefers_paths_matching_the_accounts_tier(rh):
    admin = acct("admin", token="t")
    user = acct("user", token="t")
    assert rh.endpoint_role_priority("/api/admin/users", admin)[0] == 0
    assert rh.endpoint_role_priority("/api/admin/users", user)[0] == 3
    assert rh.endpoint_role_priority("/api/items", user)[0] == 1


def test_endpoint_priority_follows_custom_tiers(rh):
    rh.configure_role_tiers([["director"], ["clerk"]])
    clerk = acct("clerk", token="t")
    assert rh.endpoint_role_priority("/api/clerks/tasks", clerk)[0] == 0
    assert rh.endpoint_role_priority("/api/director/reports", clerk)[0] == 3


def test_role_words_are_not_resource_tokens(rh):
    rh.configure_role_tiers([["director"], ["clerk"]])
    assert "director" not in rh.resource_tokens_from_path("/api/director/reports")
    assert "reports" in rh.resource_tokens_from_path("/api/director/reports")
