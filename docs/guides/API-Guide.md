# ExaBGP Route Manager — User Guide

## Authentication

### Web GUI

Open `https://<host>` and login with your username and password.

| Role | GUI | API read | API write |
|------|-----|----------|-----------|
| `admin` | full access | ✓ | ✓ |
| `readonly` | view only | ✓ | ✗ 403 |

### REST API

All API endpoints require a Bearer token:

```
Authorization: Bearer <token>
```

Use `-k` with curl to accept the self-signed certificate:

```bash
curl -k https://<host>/api/status -H "Authorization: Bearer <token>"
```

Write endpoints (`announce`, `withdraw`, `import`, admin operations) require an **admin** token. Read endpoints accept any valid token.

---

## Interactive API Docs — Swagger UI

Every endpoint below can also be explored from the browser at:

```
https://<host>/apidocs
```

The Swagger UI lets you:
- Browse all endpoints grouped by tag (Status, Routes, Simple Routes, RBTH, Flowspec, History, Export/Import, Admin)
- Authorize once and call any endpoint without writing curl
- Inspect request/response schemas with examples
- Edit request bodies directly in the browser and execute live calls

**Authorize:** click the **Authorize** button at the top, paste your token (with or without the `Bearer ` prefix), close the dialog. All subsequent calls automatically include your token.

The raw OpenAPI 2.0 spec is at `/apispec.json` if you need to import it into Postman, Insomnia or another client.

---

## BGP Status

```bash
curl -k https://<host>/api/status -H "Authorization: Bearer <token>"
```

```json
{"established": true, "socket_available": true, "checked_at": "2026-04-28 10:00:00"}
```

---

## Named Next-Hops

Named next-hops are configured in `.env` and shared across all route types. Each has an auto-assigned path-information value based on alphabetical order.

```bash
curl -k https://<host>/api/nexthops -H "Authorization: Bearer <token>"
```

```json
{
  "route_community": "65201:100",
  "nexthops": [
    {"name": "ddos1", "ip": "10.11.7.2", "ipv4": "10.11.7.2", "ipv6": "2001:668::1", "path_info": 1},
    {"name": "ddos2", "ip": "10.11.8.2", "ipv4": "10.11.8.2", "ipv6": null, "path_info": 2}
  ]
}
```

IPv6 prefixes automatically use the IPv6 address from dual-stack next-hops. Next-hops without an IPv6 address are hidden in the GUI when an IPv6 prefix is entered.

---

## Simple Routes

Single-prefix announce with full BGP attribute control (local-preference, community, as-path, MED, origin).

### GUI

1. Click **+ announce simple route**
2. Enter prefix (`10.0.0.0/24` or `2001:db8::/32`)
3. Set **next-hop** — check **use self** or enter an IP directly
4. Optionally set local-preference, MED, origin, community, as-path
5. The command preview shows the exact ExaBGP command including the default community from `.env`
6. Click **announce**

To edit, click the ✎ button — the old route is withdrawn and re-announced with the new attributes.

### API

```bash
# Minimal
curl -k -X POST https://<host>/api/announce/simple \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"prefix": "10.50.0.0/24", "nexthop": "self"}'

# Full attributes
curl -k -X POST https://<host>/api/announce/simple \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "prefix": "10.50.0.0/24",
    "nexthop": "self",
    "local_pref": 200,
    "community": "64000:400",
    "as_path": "65001 65002",
    "med": 50,
    "origin": "IGP",
    "comment": "upstream prepend"
  }'

# IPv6 with self — uses IPV6_SELF from .env automatically
curl -k -X POST https://<host>/api/announce/simple \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"prefix": "2001:db8::1/32", "nexthop": "self", "local_pref": 100, "origin": "IGP"}'

# Edit existing
curl -k -X POST https://<host>/api/announce/simple \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"prefix": "10.50.0.0/24", "nexthop": "self", "local_pref": 300, "edit": true}'

# Withdraw
curl -k -X POST https://<host>/api/withdraw/simple \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"prefix": "10.50.0.0/24", "comment": "no longer needed"}'

# List
curl -k https://<host>/api/simple-routes -H "Authorization: Bearer <token>"
```

**Field reference:**

| Field | Type | Notes |
|-------|------|-------|
| `prefix` | string CIDR | Required. Host bits auto-zeroed. |
| `nexthop` | string | Required. IP address or `"self"`. |
| `local_pref` | integer | Optional. |
| `community` | string | Optional. `"65001:100"` or `"65001:100 65002:200"`. Merged with `SIMPLE_COMMUNITY` from `.env`. |
| `as_path` | string | Optional. Space-separated ASNs, e.g. `"65001 65002"`. |
| `med` | integer | Optional. |
| `origin` | string | Optional. Must be uppercase: `IGP`, `EGP`, `INCOMPLETE`. |
| `comment` | string | Optional. |
| `edit` | boolean | Set `true` to update an existing prefix. |

---

## Multi-Nexthop Routes

Announce the same prefix via multiple next-hops using BGP add-path path-information. All next-hops for a prefix are announced independently and can be withdrawn one at a time.

### GUI

1. Click **+ announce route**
2. Enter prefix
3. Select named next-hops from the grid, or enter a manual next-hop + path-information
4. Optionally set community — merged with `ROUTE_COMMUNITY` from `.env`
5. Click **announce**

To add a next-hop to an existing prefix, click the **+** button on that prefix row.

### API

```bash
# Announce via named next-hops
curl -k -X POST https://<host>/api/announce \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "prefix": "10.0.0.0/24",
    "entries": [
      {"nexthop": "10.11.7.2", "path_info": 1, "nexthop_name": "ddos1"},
      {"nexthop": "10.11.8.2", "path_info": 2, "nexthop_name": "ddos2"}
    ],
    "comment": "DDoS mitigation"
  }'

# With per-entry community (merged with ROUTE_COMMUNITY)
curl -k -X POST https://<host>/api/announce \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "prefix": "192.168.1.0/24",
    "entries": [{"nexthop": "10.11.7.2", "path_info": 1, "community": "64000:400"}]
  }'

# IPv6 prefix — use nexthop_name; IPv6 address resolved automatically
curl -k -X POST https://<host>/api/announce \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "prefix": "2001:db8::1/32",
    "entries": [{"nexthop_name": "ddos1", "path_info": 1}]
  }'

# Withdraw single next-hop
curl -k -X POST https://<host>/api/withdraw \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"prefix": "10.0.0.0/24", "nexthop": "10.11.8.2"}'

# Withdraw all next-hops for prefix
curl -k -X POST https://<host>/api/withdraw/all \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"prefix": "10.0.0.0/24", "comment": "attack over"}'

# List
curl -k https://<host>/api/routes -H "Authorization: Bearer <token>"
```

---

## RBTH — Remote Triggered Black Hole

Announces a /32 (IPv4) or /128 (IPv6) with `next-hop self` and the configured RBTH community. The suffix is added automatically if omitted.

### GUI

Click **+ blackhole**, enter the IP, optionally add a comment, click **blackhole**.

### API

```bash
# List available ISP blackhole communities (from .env BLACKHOLE_* vars)
curl -k https://<host>/api/blackhole-communities -H "Authorization: Bearer <token>"
# → {"communities": {"cogent": "65001:100", "gtt": "65001:200"}, "default_community": "65000:666"}

# Announce with default community (no ISP selected)
curl -k -X POST https://<host>/api/rbth/announce \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"ip": "10.30.1.1", "comment": "attack source"}'

# Announce with ISP communities (cogent + gtt)
curl -k -X POST https://<host>/api/rbth/announce \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"ip": "10.30.1.1", "communities": ["cogent", "gtt"], "comment": "attack source"}'

# Update ISP communities — re-announce with new community set (removes gtt)
curl -k -X POST https://<host>/api/rbth/announce \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"ip": "10.30.1.1", "communities": ["cogent"]}'

# Revert to default community (remove all ISPs)
curl -k -X POST https://<host>/api/rbth/announce \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"ip": "10.30.1.1", "communities": []}'

# Announce IPv6 blackhole (/128 added automatically, uses IPV6_SELF)
curl -k -X POST https://<host>/api/rbth/announce \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"ip": "2001:db8::bad:1", "communities": ["cogent"], "comment": "IPv6 attacker"}'

# Withdraw
curl -k -X POST https://<host>/api/rbth/withdraw \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"ip": "10.30.1.1", "comment": "attack over"}'

# List
curl -k https://<host>/api/rbth -H "Authorization: Bearer <token>"
```

**ISP community logic:**
- `BLACKHOLE_<name>` value can be standard (`X:Y`) or large (`X:Y:Z`) format
- No `communities` or empty `[]` → uses default `RBTH_COMMUNITY`: `community [X:Y]`
- All-standard ISPs → `community [a b c]`
- All-large ISPs → `large-community [a b c]`
- Mixed (standard + large) → `community [a] large-community [b]` — both blocks are emitted
- Re-announcing same IP updates the community — no withdraw needed

**Example .env:**
```
RBTH_COMMUNITY=65001:666
BLACKHOLE_cogent=65001:174:666
BLACKHOLE_gtt=65001:3257:666
BLACKHOLE_legacy=3257:666
```

**Example commands:**
- `communities: []` → `announce route 10.0.0.1/32 next-hop self community [65001:666]`
- `communities: ["cogent"]` → `announce route 10.0.0.1/32 next-hop self large-community [65001:174:666]`
- `communities: ["legacy"]` → `announce route 10.0.0.1/32 next-hop self community [3257:666]`
- `communities: ["cogent","gtt"]` → `announce route 10.0.0.1/32 next-hop self large-community [65001:174:666 65001:3257:666]`
- `communities: ["cogent","legacy"]` → `announce route 10.0.0.1/32 next-hop self community [3257:666] large-community [65001:174:666]`

---

## Flowspec

RFC 5575 flow rules with discard or rate-limit actions.

> **Restriction:** `source_ip` and `destination_ip` cannot both be `0.0.0.0/0` or `::/0` at the same time. At least one must be a specific subnet.

### GUI

Click **+ flowspec rule**, fill in source/destination, protocol, ports, action. Click **add rule**.

### API

```bash
# Discard by source
curl -k -X POST https://<host>/api/flowspec/announce \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"source_ip": "10.10.10.0/24", "action": "discard", "comment": "DDoS source"}'

# Discard by destination
curl -k -X POST https://<host>/api/flowspec/announce \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"destination_ip": "10.20.20.0/24", "action": "discard"}'

# Rate-limit UDP DNS — 100 Mbps
curl -k -X POST https://<host>/api/flowspec/announce \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "destination_ip": "10.20.20.0/24",
    "protocol": "udp",
    "destination_port": "53",
    "action": "rate-limit",
    "rate_limit_mbps": 100,
    "comment": "DNS amplification"
  }'

# Rate-limit TCP with source + destination
curl -k -X POST https://<host>/api/flowspec/announce \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "source_ip": "10.10.10.0/24",
    "destination_ip": "10.20.20.0/24",
    "protocol": "tcp",
    "source_port": "80",
    "action": "rate-limit",
    "rate_limit_mbps": 50
  }'

# Withdraw (use rule id from GET /api/flowspec)
curl -k -X POST https://<host>/api/flowspec/withdraw \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"id": 1, "comment": "attack over"}'

# List
curl -k https://<host>/api/flowspec -H "Authorization: Bearer <token>"
```

**Flowspec field reference:**

| Field | Type | Notes |
|-------|------|-------|
| `source_ip` | string CIDR | Optional. Cannot be `0.0.0.0/0` if destination is also `0.0.0.0/0`. |
| `destination_ip` | string CIDR | Optional. Same restriction as above. |
| `protocol` | string | Optional. `tcp` or `udp`. Required for port fields. |
| `source_port` | string | Optional. Port number. Requires `protocol`. |
| `destination_port` | string | Optional. Port number. Requires `protocol`. |
| `action` | string | Required. `discard` or `rate-limit`. |
| `rate_limit_mbps` | number | Required if `action` is `rate-limit`. |
| `comment` | string | Optional. |

---

## Export / Import

Backup and restore all route types (multi-nexthop routes, simple routes, RBTH, flowspec) in a single JSON file. Duplicate entries are skipped on import — safe to re-run.

```bash
# Export
curl -k https://<host>/api/routes/export \
  -H "Authorization: Bearer <token>" \
  -o exabgp-backup-$(date +%Y%m%d).json

# Import
curl -k -X POST https://<host>/api/routes/import \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d @exabgp-backup-20260428.json
```

---

## Re-Announce

Re-announces all active routes from the database to ExaBGP. Useful after an ExaBGP restart.

```bash
curl -k -X POST https://<host>/api/reannounce \
  -H "Authorization: Bearer <admin-token>"
```

```json
{"status": "ok", "routes": 4, "rbths": 2, "flowspecs": 1, "simples": 3}
```

---

## History

Full operation log with filtering by type, operation, and date. Available at `/history` in the GUI.

```bash
# All history
curl -k https://<host>/api/history -H "Authorization: Bearer <token>"

# Filter by type
curl -k "https://<host>/api/history?type=flowspec" -H "Authorization: Bearer <token>"

# Filter by operation and date range
curl -k "https://<host>/api/history?operation=withdraw&from=2026-04-01&to=2026-04-30" \
  -H "Authorization: Bearer <token>"
```

| Param | Values |
|-------|--------|
| `type` | `route`, `rbth`, `flowspec`, `simple_route` |
| `operation` | `announce`, `withdraw`, `edit` |
| `from` | `YYYY-MM-DD` |
| `to` | `YYYY-MM-DD` |
| `limit` | integer (default 500) |

Each record includes a `performed_by` field showing the GUI username or API token name that triggered the operation.

---

## User & Token Management

Managed at `/admin` in the GUI (admin only) or via API.

```bash
# Create user
curl -k -X POST https://<host>/api/admin/users \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"username": "noc1", "password": "securepass", "role": "readonly"}'

# Create token (value shown once — store immediately)
curl -k -X POST https://<host>/api/admin/tokens \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"name": "automation-script", "role": "admin"}'

# Revoke token
curl -k -X DELETE https://<host>/api/admin/tokens/1 -H "Authorization: Bearer <admin-token>"

# Export users and tokens
curl -k https://<host>/api/admin/export -H "Authorization: Bearer <admin-token>" -o users.json

# Import on new instance
curl -k -X POST https://<host>/api/admin/import \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d @users.json
```

---

## Endpoint Summary

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/status` | GET | any | BGP session status |
| `/api/me` | GET | any | Current token identity |
| `/api/nexthops` | GET | any | Named next-hops |
| `/api/routes` | GET | any | Multi-nexthop route table |
| `/api/routes/export` | GET | any | Export all routes as JSON |
| `/api/routes/import` | POST | admin | Import routes from JSON |
| `/api/announce` | POST | admin | Announce multi-nexthop route |
| `/api/withdraw` | POST | admin | Withdraw single next-hop |
| `/api/withdraw/all` | POST | admin | Withdraw all next-hops for prefix |
| `/api/simple-routes` | GET | any | Simple route table |
| `/api/announce/simple` | POST | admin | Announce simple route |
| `/api/withdraw/simple` | POST | admin | Withdraw simple route |
| `/api/blackhole-communities` | GET | any | ISP blackhole communities from .env |
| `/api/rbth` | GET | any | RBTH routes |
| `/api/rbth/announce` | POST | admin | Add RBTH blackhole |
| `/api/rbth/withdraw` | POST | admin | Remove RBTH blackhole |
| `/api/flowspec` | GET | any | Flowspec rules |
| `/api/flowspec/announce` | POST | admin | Add flowspec rule |
| `/api/flowspec/withdraw` | POST | admin | Remove flowspec rule |
| `/api/history` | GET | any | Operation history |
| `/api/reannounce` | POST | admin | Re-announce all from DB |
| `/api/admin/users` | GET, POST | admin | List / create users |
| `/api/admin/users/<id>` | PUT, DELETE | admin | Update / delete user |
| `/api/admin/tokens` | GET, POST | admin | List / create tokens |
| `/api/admin/tokens/<id>` | DELETE | admin | Revoke token |
| `/api/admin/export` | GET | admin | Export accounts JSON |
| `/api/admin/import` | POST | admin | Import accounts JSON |
