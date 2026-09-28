"""Smoke test over canned Graph responses. Run: python test_server.py (or pytest)."""

import os
from datetime import datetime, timezone

import m365_evidence_mcp as server

RECENT = datetime.now(timezone.utc).isoformat()

CANNED = {
    "secureScores": {"value": [{
        "currentScore": 52.0, "maxScore": 100.0,
        "createdDateTime": "2026-09-27T00:00:00Z",
        "controlScores": [
            {"controlName": "SigninRiskPolicy", "score": 1.0},
            {"controlName": "AdminMFAV2", "score": 0.0},
        ],
    }]},
    "userRegistrationDetails": {"value": [
        {"userPrincipalName": "a@demo.example", "isMfaRegistered": True},
        {"userPrincipalName": "b@demo.example", "isMfaRegistered": False},
    ]},
    "/users?": {"value": [
        {"userPrincipalName": "old@demo.example", "accountEnabled": True,
         "signInActivity": {"lastSuccessfulSignInDateTime": "2020-01-01T00:00:00Z"}},
        {"userPrincipalName": "never@demo.example", "accountEnabled": True},
        {"userPrincipalName": "fresh@demo.example", "accountEnabled": True,
         "signInActivity": {"lastSuccessfulSignInDateTime": RECENT}},
        {"userPrincipalName": "gone@demo.example", "accountEnabled": False},
    ]},
    "directoryRoles": {"value": [
        {"displayName": "Global Administrator",
         "members": [{"userPrincipalName": "a@demo.example"}]},
        {"displayName": "Empty Role", "members": []},
    ]},
}


def _fake_get(path):
    for key, resp in CANNED.items():
        if key in path:
            return resp
    raise AssertionError(f"unexpected path {path}")


def test_token_required():
    os.environ.pop("GRAPH_TOKEN", None)
    try:
        server._get("/anything")
        assert False, "should have raised"
    except RuntimeError as e:
        assert "GRAPH_TOKEN" in str(e)


def test_tools():
    server._get = _fake_get

    score = server.secure_score()
    assert "52 of 100 (52%)" in score
    assert score.index("AdminMFAV2") < score.index("SigninRiskPolicy")

    mfa = server.mfa_coverage()
    assert "1 of 2 users (50%)" in mfa
    assert "- b@demo.example" in mfa

    stale = server.stale_accounts(90)
    assert "2 enabled account(s)" in stale
    assert "old@demo.example (last 2020-01-01)" in stale
    assert "never@demo.example (never)" in stale
    assert "fresh@" not in stale and "gone@" not in stale

    roles = server.privileged_roles()
    assert "Global Administrator (1):" in roles
    assert "  - a@demo.example" in roles
    assert "Empty Role" not in roles


if __name__ == "__main__":
    test_token_required()
    test_tools()
    print("ok")
