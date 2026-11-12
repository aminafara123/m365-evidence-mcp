# m365-evidence-mcp

<!-- mcp-name: io.github.aminafara123/m365-evidence-mcp -->

An MCP server that turns the Microsoft Graph reads an IT auditor keeps repeating into tools any MCP-capable AI client can call. Point it at a tenant with a read-only token and ask for the evidence in plain language instead of clicking through four admin portals.

The four tools cover ITGC classics: security posture, MFA coverage, dormant accounts and privileged access. The model fetches, the auditor concludes.

## Tools

| Tool | What it does |
|---|---|
| `secure_score()` | Current Secure Score plus the five weakest controls |
| `mfa_coverage()` | How many users are MFA registered, and who is not |
| `stale_accounts(days)` | Enabled accounts with no sign-in in the last N days |
| `privileged_roles()` | Activated directory roles and who holds them |

## Setup

```bash
pipx install m365-evidence-mcp
```

`uvx m365-evidence-mcp` works too if you prefer no install. Hacking on a clone instead:

```bash
python3 -m venv .venv
.venv/bin/pip install mcp
```

Get a Graph token. The Azure CLI is the quickest way:

```bash
export GRAPH_TOKEN=$(az account get-access-token --resource https://graph.microsoft.com --query accessToken -o tsv)
```

The Access token tab in Graph Explorer works too. Scopes: SecurityEvents.Read.All for the score, Reports.Read.All for MFA coverage, User.Read.All plus AuditLog.Read.All for stale accounts, Directory.Read.All for roles. All of them are read scopes and most need admin consent.

Wire it into Claude Code:

```bash
claude mcp add m365evidence -- m365-evidence-mcp
```

Running from a clone, point it at the venv instead:

```bash
claude mcp add m365evidence -- /path/to/m365-evidence-mcp/.venv/bin/python /path/to/m365-evidence-mcp/m365_evidence_mcp.py
```

## Demo

What it looks like from Claude Code:

```
> pull the access review evidence for the quarter

⏺ m365evidence · privileged_roles()

  Global Administrator (2):
    - amir.admin@demo.example
    - breakglass@demo.example
  Helpdesk Administrator (1):
    - sara.support@demo.example

⏺ Two global admins and one of them is the break glass account.
  Helpdesk Administrator has a single holder. MFA coverage next?
```

The accounts above are demo data. The format is exactly what the server returns.

## Design notes

- **Read-only by construction.** Every tool is a single Graph GET, the annotations declare it, and a token with read scopes could not write anyway. Two layers, both structural.
- **Evidence, not judgement.** Tools return counts with capped name lists, the kind of thing that goes straight into a workpaper. The conclusion stays with whoever reads it.
- **Nothing touches disk.** The token lives in an environment variable and reports are never cached or logged.

## Honest notes

- Sign-in activity needs Entra ID P1 or better, so `stale_accounts` comes back empty on a bare Business Standard tenant.
- Pagination is capped at ten pages of 999 objects. Fine for a small or midsize tenant, raise the cap in `_get_all` for bigger ones.
- The logic is tested against canned Graph responses in `test_server.py`. Run `python test_server.py`.

## About

Al Amin Bashir Afara, Dubai · [github.com/aminafara123](https://github.com/aminafara123) · [linkedin.com/in/aminafara](https://www.linkedin.com/in/aminafara)
