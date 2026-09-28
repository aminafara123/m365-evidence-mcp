#!/usr/bin/env python3
"""m365-evidence-mcp: read-only Microsoft 365 audit evidence as MCP tools.

The four Graph reads an IT auditor keeps repeating, exposed as tools any
MCP-capable model can call: secure score, MFA coverage, stale accounts,
privileged role membership. Every tool is a GET, nothing writes.

Run (stdio):  GRAPH_TOKEN=<token> python server.py
Wire into Claude Code:
  claude mcp add m365evidence -- /path/to/.venv/bin/python /path/to/server.py
"""

import json
import os
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

GRAPH = "https://graph.microsoft.com/v1.0"

server = MCPServer(
    "m365evidence",
    instructions=(
        "Read-only audit evidence from a Microsoft 365 tenant: secure "
        "score, MFA coverage, stale accounts and privileged roles. Needs "
        "a Graph token with read scopes in the GRAPH_TOKEN env var."
    ),
)

# Network reads against Graph: read-only and idempotent, but open world.
READ_ONLY = ToolAnnotations(
    read_only_hint=True,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=True,
)


def _get(path: str) -> dict:
    token = os.environ.get("GRAPH_TOKEN")
    if not token:
        raise RuntimeError(
            "GRAPH_TOKEN is not set. Grab one from Graph Explorer, or: "
            "az account get-access-token "
            "--resource https://graph.microsoft.com --query accessToken -o tsv")
    url = path if path.startswith("http") else GRAPH + path
    req = urllib.request.Request(
        url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        raise RuntimeError(
            f"Graph returned {e.code} for {url.split('?')[0]}. "
            "Check token expiry and scopes.") from e


def _get_all(path: str, max_pages: int = 10) -> list:
    # nextLink pagination capped at 10 pages of 999, raise for huge tenants
    items, url = [], path
    for _ in range(max_pages):
        data = _get(url)
        items.extend(data.get("value", []))
        url = data.get("@odata.nextLink")
        if not url:
            break
    return items


@server.tool(annotations=READ_ONLY)
def secure_score() -> str:
    """Current Microsoft Secure Score with the five weakest controls.
    Needs SecurityEvents.Read.All."""
    scores = _get("/security/secureScores?$top=1").get("value", [])
    if not scores:
        return "No secure score available for this tenant."
    s = scores[0]
    pct = round(100 * s["currentScore"] / s["maxScore"]) if s.get("maxScore") else 0
    weakest = sorted(
        (c for c in s.get("controlScores", [])
         if isinstance(c.get("score"), (int, float))),
        key=lambda c: c["score"])[:5]
    lines = [f"Secure score: {s['currentScore']:g} of {s['maxScore']:g} ({pct}%)",
             f"As of: {s.get('createdDateTime', 'unknown')}",
             "", "Weakest controls:"]
    lines += [f"- {c.get('controlName', '?')} (score {c['score']:g})"
              for c in weakest]
    return "\n".join(lines)


@server.tool(annotations=READ_ONLY)
def mfa_coverage() -> str:
    """Share of users registered for MFA, with up to ten who are not.
    Needs Reports.Read.All."""
    users = _get_all(
        "/reports/authenticationMethods/userRegistrationDetails?$top=999")
    if not users:
        return "No registration data returned."
    missing = [u["userPrincipalName"] for u in users
               if not u.get("isMfaRegistered")]
    covered = len(users) - len(missing)
    out = [f"MFA registered: {covered} of {len(users)} users "
           f"({round(100 * covered / len(users))}%)"]
    if missing:
        out.append("Not registered (first 10):")
        out += [f"- {u}" for u in missing[:10]]
        if len(missing) > 10:
            out.append(f"...and {len(missing) - 10} more")
    return "\n".join(out)


@server.tool(annotations=READ_ONLY)
def stale_accounts(days: int = 90) -> str:
    """Enabled accounts with no successful sign-in in the last N days,
    never-signed-in included. Needs User.Read.All and AuditLog.Read.All."""
    users = _get_all(
        "/users?$select=userPrincipalName,accountEnabled,signInActivity"
        "&$top=999")
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    stale = []
    for u in users:
        if not u.get("accountEnabled"):
            continue
        last = (u.get("signInActivity") or {}).get(
            "lastSuccessfulSignInDateTime")
        if not last:
            stale.append(f"{u['userPrincipalName']} (never)")
        elif datetime.fromisoformat(last.replace("Z", "+00:00")) < cutoff:
            stale.append(f"{u['userPrincipalName']} (last {last[:10]})")
    if not stale:
        return f"No enabled account is stale past {days} days."
    return (f"{len(stale)} enabled account(s) with no sign-in in {days} days:\n"
            + "\n".join(f"- {s}" for s in stale[:25])
            + (f"\n...and {len(stale) - 25} more" if len(stale) > 25 else ""))


@server.tool(annotations=READ_ONLY)
def privileged_roles() -> str:
    """Activated directory roles and who holds them, ten members shown per
    role. The access review starting point. Needs Directory.Read.All."""
    roles = _get_all("/directoryRoles?$expand=members")
    out = []
    for r in sorted(roles, key=lambda r: r.get("displayName", "")):
        members = r.get("members", [])
        if not members:
            continue
        out.append(f"{r['displayName']} ({len(members)}):")
        out += [f"  - {m.get('userPrincipalName') or m.get('displayName', '?')}"
                for m in members[:10]]
        if len(members) > 10:
            out.append(f"  ...and {len(members) - 10} more")
    return "\n".join(out) or "No activated role has members."


def main():
    server.run()


if __name__ == "__main__":
    main()
