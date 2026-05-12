# Arista cEOS Containerlab Example

A four-node Arista cEOS lab driven by [containerlab](https://containerlab.dev),
alongside the ExaBGP Route Manager stack (ExaBGP + Flask API + HAProxy). The lab
models a small customer-edge / upstream-provider environment where two customer
routers peer with two upstream ISPs and an ExaBGP speaker injects routes into the
customer routers. The customer routers then propagate selected routes to the
ISPs through outbound route-maps that translate large-community signals into
standard BGP communities and AS-path prepends.

## Topology

```
            ┌─────────────────────────────────────┐
            │   Host (Linux native, or            │
            │          Debian VM via OrbStack)    │
            │                                     │
            │   Docker Compose stack:             │
            │     ExaBGP   AS 65000   10.100.0.1  │
            │     Flask API                       │
            │     HAProxy  :80  :443              │
            └─────────────────┬───────────────────┘
                              │
              ext-lan host bridge  10.100.0.0/24
                              │
              ┌───────────────┴───────────────┐
              │                               │
       eth3 10.100.0.2                 eth3 10.100.0.3
         ┌────┴────┐    iBGP eth4         ┌────┴────┐
         │ router1 ├──────────────────────┤ router2 │
         │ AS65001 │   192.168.100.0/30   │ AS65001 │
         └─┬─────┬─┘                      └─┬─────┬─┘
        eth1   eth2                       eth1   eth2
           │     │                          │     │
           │     └───────────┐  ┌───────────┘     │
           │                 │  │                 │
        ┌──┴──────┐       ┌──┴──┴───┐
        │  isp1   │       │  isp2   │
        │ AS 123  ├───────┤ AS 456  │
        │         │ eBGP  │         │
        └─────────┘ eth3↔eth3 └─────┘
                192.168.100.0/30
```

### BGP peerings

| Side A          | Side B          | Type | Subnet              |
|-----------------|-----------------|------|---------------------|
| ExaBGP (65000)  | router1 (65001) | eBGP | 10.100.0.0/24       |
| ExaBGP (65000)  | router2 (65001) | eBGP | 10.100.0.0/24       |
| router1 (65001) | router2 (65001) | iBGP | 192.168.100.0/30    |
| router1 (65001) | isp1 (123)      | eBGP | 192.168.1.0/30      |
| router1 (65001) | isp2 (456)      | eBGP | 192.168.2.0/30      |
| router2 (65001) | isp1 (123)      | eBGP | 192.168.21.0/30     |
| router2 (65001) | isp2 (456)      | eBGP | 192.168.22.0/30     |
| isp1 (123)      | isp2 (456)      | eBGP | 192.168.100.0/30    |

Both customer routers run `redistribute connected` and `redistribute static`
into BGP, so the customer-to-ISP /30s are visible in ISP tables out of the box.

### Community semantics

The customer routers carry route-maps that translate large-community signals
on routes received from ExaBGP into actions toward the ISPs:

| Large community on inbound route | Effect on outbound to ISP |
|----------------------------------|---------------------------|
| `65001:123:666`                  | rewrite to standard `community 123:666` → isp1 blackholes locally |
| `65001:456:666`                  | rewrite to standard `community 456:666` → isp2 blackholes locally |
| `65001:123:1` / `:2` / `:3`      | AS-path prepend 1x / 2x / 3x toward isp1 |
| `65001:456:1` / `:2` / `:3`      | AS-path prepend 1x / 2x / 3x toward isp2 |

Routes tagged with the local-RBTH community `65001:666` resolve to a static
`Null0` route on each customer router via the inbound `rbth-in` route-map,
but are not propagated to the ISPs.

---

## Prerequisites

- Docker Engine 20.10+ and Docker Compose v2
- containerlab v0.50+
- An Arista cEOS-lab image (free Arista account required)
- Linux host **or** macOS with OrbStack and a Debian VM
- About 4–6 GB of free RAM and 2 vCPU for the lab nodes plus the Compose stack

---

## Host Setup

Pick the path that matches your machine.

### Option 1 — Linux (native)

```bash
# Install containerlab
bash -c "$(curl -sL https://get.containerlab.dev)"

containerlab version
docker --version
```

Then download cEOS-lab from Arista:

1. Register at `https://www.arista.com/en/users/registration`
2. Navigate to **Support → Software Download → cEOS-lab**
3. Download the `.tar.xz` matching the tag in `isp-topology.yml` (default
   `4.36.1F`, filename example: `cEOS-lab-4.36.1F.tar.xz`)

Import it into Docker:

```bash
xz -dc cEOS-lab-4.36.1F.tar.xz | docker import - ceosimage:4.36.1F
docker images | grep ceosimage
```

Skip ahead to **Configuring the Stack**.

### Option 2 — macOS via OrbStack

cEOS-lab needs a Linux kernel and tooling that Docker Desktop / OrbStack
containers on macOS do not expose directly. The supported pattern on Apple
Silicon and Intel Macs is to run a full Debian VM and execute Docker plus
containerlab inside it.

#### Step 1 — Install OrbStack on macOS

1. Download from `https://orbstack.dev`
2. Install the `.dmg` and launch OrbStack
3. Accept the kernel extension prompt on first launch

OrbStack automatically mounts your macOS home directory inside every Linux VM
at the same path. A file at `/Users/<your-mac-username>/Downloads/foo.tar` on
macOS is reachable at exactly `/Users/<your-mac-username>/Downloads/foo.tar`
from within the VM. This is how the cEOS image is shared with the VM in the
next steps — no copy, no `scp`.

#### Step 2 — Download the cEOS-lab image from Arista

Do this on macOS (no VM yet needed):

1. Register at `https://www.arista.com/en/users/registration`
2. Navigate to **Support → Software Download → cEOS-lab**
3. Download the `.tar.xz` matching the tag in `isp-topology.yml` (default
   `4.36.1F`, filename example: `cEOS-lab-4.36.1F.tar.xz`)

Save it under `~/Downloads/` (or any location inside your macOS home).

#### Step 3 — Create the Debian VM and install Docker + containerlab

From macOS Terminal:

```bash
orb create debian labvm
orb shell labvm
```

Inside the VM:

```bash
sudo apt update
sudo apt install -y ca-certificates curl gnupg lsb-release

# Docker CE
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg \
  | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/debian $(lsb_release -cs) stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io \
                    docker-buildx-plugin docker-compose-plugin

# containerlab
bash -c "$(curl -sL https://get.containerlab.dev)"

docker --version
containerlab version
```

#### Step 4 — Import the cEOS image into the VM's Docker

The image you downloaded on macOS in Step 2 is already visible from inside the
VM at the same path. Import it directly — no copy required:

```bash
# inside the VM
MAC_USER=<your-mac-username>
xz -dc /Users/$MAC_USER/Downloads/cEOS-lab-4.36.1F.tar.xz \
  | docker import - ceosimage:4.36.1F

docker images | grep ceosimage
```

If you saved the image somewhere other than `~/Downloads/`, adjust the path
accordingly. The Docker daemon inside the VM runs as root, which OrbStack maps
to your macOS user, so it has the same read access as you do on macOS.

---

## Accessing the Lab from macOS

The Compose stack exposes HAProxy on `:80` and `:443`. From inside the Debian
VM those bind to `127.0.0.1`. To reach them from macOS, pick one of:

### Method A — OrbStack hostname (simplest)

OrbStack resolves `<vm-name>.orb.local` from macOS automatically. Once the
stack is running:

```
https://labvm.orb.local
```

This gets you to HAProxy on the VM. It does **not** give macOS access to the
cEOS routers' management IPs.

### Method B — Static route to the clab subnet (reach cEOS directly)

To SSH the cEOS nodes from macOS, route their management subnet through the
VM. By default containerlab uses `172.20.20.0/24` for its management bridge.

```bash
# 1. Inside the VM — enable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" | sudo tee /etc/sysctl.d/99-forward.conf

# 2. On macOS — find the VM IP and add a route
orb info labvm                                # note the IP
sudo route -n add -net 172.20.20.0/24 <vm-ip>
```

The route is not persistent across macOS reboots. To make it permanent,
create a LaunchDaemon plist that runs `route add` at boot.

You can use both methods at the same time — A for the web UI, B for cEOS SSH.

---

## Configuring the Stack

The example directory ships with a working `.env` file containing
lab-suitable defaults — you can use it as-is for a quick start:

```bash
cd docs/examples/arista_eos
cat .env
```

Keys you may want to review before starting:

| Variable                                          | Purpose                                          |
|---------------------------------------------------|--------------------------------------------------|
| `ADMIN_USERNAME` / `ADMIN_PASSWORD`               | GUI login                                        |
| `ADMIN_TOKEN`                                     | REST API Bearer token                            |
| `FLASK_SECRET_KEY`                                | Flask session signing                            |
| `NEXTHOP_self`                                    | Named next-hop offered in the UI (`10.100.0.1`)  |
| `RBTH_COMMUNITY`                                  | Local-RBTH community (`65001:666`)               |
| `BLACKHOLE_isp1` / `BLACKHOLE_isp2`               | Large communities the routers translate per ISP  |
| `TLS_CN` / `TLS_ORG` / `TLS_COUNTRY` / `TLS_DAYS` | Self-signed HAProxy cert subject                 |

Take note of `ADMIN_PASSWORD` and `ADMIN_TOKEN` — they are needed for GUI and
API access. For anything beyond local lab use, rotate them to fresh random
values, e.g. with `openssl rand -hex 24`.

If any value contains a literal `$`, escape it as `$$` in `.env`
(Docker Compose substitution).

### `exabgp.conf`

ExaBGP must peer with both customer routers. The shipped config:

```
neighbor 10.100.0.2 {
    router-id 10.100.0.1;
    local-address 10.100.0.1;
    local-as 65000;
    peer-as 65001;
    capability { add-path send/receive; }
    family { ipv4 unicast; ipv4 flow; }
}

neighbor 10.100.0.3 {
    router-id 10.100.0.1;
    local-address 10.100.0.1;
    local-as 65000;
    peer-as 65001;
    capability { add-path send/receive; }
    family { ipv4 unicast; ipv4 flow; }
}
```

No edits should be needed for the default lab.

### Runtime directories

The Compose stack expects named pipes and a state directory before ExaBGP
starts:

```bash
mkdir -p exabgp-run    && chmod 777 exabgp-run
mkdir -p haproxy-certs && chmod 700 haproxy-certs
mkfifo exabgp-run/exabgp.in exabgp-run/exabgp.out
chmod 666 exabgp-run/exabgp.in exabgp-run/exabgp.out
```

---

## Bringing the Lab Up

The `clab-up.sh` helper destroys any previous deploy, creates the `ext-lan`
host bridge at `10.100.0.1/24`, and deploys the topology in one shot:

```bash
cd docs/examples/arista_eos
chmod +x clab-up.sh
sudo ./clab-up.sh
```

Then start the Compose stack:

```bash
docker compose up -d --build
docker compose logs -f api
```

ExaBGP runs in the host network namespace so it can bind to `10.100.0.1`
directly on the `ext-lan` bridge. HAProxy publishes ports `:80` and `:443` to
the host (the Debian VM, in the macOS case).

**Verify the lab is up:**

```bash
sudo containerlab inspect -t isp-topology.yml
docker compose ps

docker exec -t clab-ceos-router1 Cli -c "show ip bgp summary"
```

All BGP peers should reach `Established`: ExaBGP, the iBGP partner, and both
ISP eBGP peers.

---

## Connecting to cEOS Devices

Two ways to reach the network OS — both work.

### Method A — `docker exec` into the EOS CLI (no password)

The fastest path. Bypasses SSH entirely.

```bash
docker exec -it clab-ceos-router1 Cli
docker exec -it clab-ceos-router2 Cli
docker exec -it clab-ceos-isp1    Cli
docker exec -it clab-ceos-isp2    Cli
```

You drop straight into EOS exec mode. `enable` for privileged (no password
required), `configure` for config mode.

One-shot commands:

```bash
docker exec -t clab-ceos-router1 Cli -c "show ip bgp summary"
docker exec -t clab-ceos-isp1    Cli -c "show ip route bgp"
```

### Method B — SSH (operator workflow)

containerlab assigns each node a management IP on the default `172.20.20.0/24`
clab network. Find the IPs with:

```bash
sudo containerlab inspect -t isp-topology.yml
```

Then SSH with the cleartext admin password that corresponds to the SHA-512
hash baked into the startup-configs:

```bash
ssh admin@172.20.20.X            # X from inspect output
```

If you do not know the password, reset it from inside the node (via
**Method A**) and `write memory`:

```bash
docker exec -it clab-ceos-router1 Cli
enable
configure
username admin secret <new-password>
write memory
```

From macOS, SSH to clab IPs requires the static route from **Method B** in
**Accessing the Lab from macOS**.

---

## Walkthrough: Happy Path

Four scenarios end to end. Run them after the lab is up and you have the
`ADMIN_TOKEN` from `.env`. The examples use `curl` against the REST API; the
same actions are available in the GUI.

```bash
HOST=https://labvm.orb.local            # or your VM/host IP
TOKEN=<your ADMIN_TOKEN from .env>
```

### Step 1 — Confirm BGP sessions are up

```bash
docker exec -t clab-ceos-router1 Cli -c "show ip bgp summary"
```

Expect four established peers on each customer router: ExaBGP (`10.100.0.1`),
the iBGP partner, and both ISPs.

### Step 2 — Announce a simple route

Inject `172.31.100.0/24` from ExaBGP with `next-hop self`, local-preference
200, and a tracking community.

```bash
curl -sk -X POST "$HOST/api/announce/simple" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "prefix": "172.31.100.0/24",
    "next_hop": "self",
    "local_preference": 200,
    "community": "65001:100",
    "origin": "IGP"
  }'
```

Check on router1:

```bash
docker exec -t clab-ceos-router1 Cli -c "show ip bgp 172.31.100.0/24"
```

router1 should see two paths — directly from ExaBGP (weight 300, local-pref
200) and via iBGP from router2 (because both customer routers also peer with
ExaBGP).

Check on isp1:

```bash
docker exec -t clab-ceos-isp1 Cli -c "show ip bgp 172.31.100.0/24"
```

isp1 sees the prefix from both router1 and router2 (`AS path 65001`) and
from isp2 (`AS path 456 65001`).

### Step 3 — Local RBTH (drop on the customer routers only)

Announce with the local RBTH community `65001:666`. The customer routers'
inbound `rbth-in` route-map rewrites next-hop to `192.168.12.12`, which is a
static route to `Null0`.

```bash
curl -sk -X POST "$HOST/api/announce/simple" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "prefix": "172.31.42.1/32",
    "next_hop": "self",
    "community": "65001:666",
    "origin": "IGP"
  }'
```

Check the resolution on router1:

```bash
docker exec -t clab-ceos-router1 Cli -c "show ip route 172.31.42.1"
docker exec -t clab-ceos-router1 Cli -c "show ip bgp 172.31.42.1/32 detail"
```

The route resolves via `192.168.12.12 → Null0`. The customer routers do not
rewrite this community on egress, so the ISPs do **not** see the prefix as a
blackhole — they may not see it at all, depending on best-path selection.

### Step 4 — RBTH propagated to ISP1

Use the RBTH endpoint and target isp1. The API attaches the large community
`65001:123:666` (from `BLACKHOLE_isp1`).

```bash
curl -sk -X POST "$HOST/api/announce/rbth" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "prefix": "172.31.42.2/32",
    "isps": ["isp1"]
  }'
```

On router1 the outbound `isp1-ipv4-out-rm` route-map matches
`large-community 65001:123:666` and rewrites it to `community 123:666` toward
isp1. isp1's `customer-in` then sets next-hop to `192.168.12.12` (its local
`Null0` static).

Verify on isp1:

```bash
docker exec -t clab-ceos-isp1 Cli -c "show ip bgp 172.31.42.2/32 detail"
docker exec -t clab-ceos-isp1 Cli -c "show ip route 172.31.42.2"
```

The BGP entry should carry community `123:666`; the route resolves via
`192.168.12.12 → Null0`. isp2 sees the original prefix but without the
blackhole semantics.

### Step 5 — AS-path prepend toward isp2

The outbound route-maps recognize prepend signals through large communities
`65001:456:1` (1×), `65001:456:2` (2×), `65001:456:3` (3×).

```bash
curl -sk -X POST "$HOST/api/announce/simple" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "prefix": "172.31.50.0/24",
    "next_hop": "self",
    "community": "65001:456:2",
    "origin": "IGP"
  }'
```

Verify on isp2:

```bash
docker exec -t clab-ceos-isp2 Cli -c "show ip bgp 172.31.50.0/24"
```

The path direct from router1/router2 shows AS path `65001 65001 65001`
(original ASN plus two prepends). isp2 may now prefer the path learned via
isp1 (`123 65001`) because of the shorter AS path.

### Step 6 — Withdraw

```bash
curl -sk -X POST "$HOST/api/withdraw/simple" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"prefix": "172.31.100.0/24"}'
```

`show ip bgp 172.31.100.0/24` on any node should no longer find the prefix.

The GUI's **History** page lists every announce / withdraw with timestamp and
the token or user that issued it.

---

## Tearing Down

```bash
# stop the Compose stack
docker compose down

# destroy the clab topology AND remove its state directory
sudo containerlab destroy -t isp-topology.yml --cleanup

# optional: remove the host bridge
sudo ip link del ext-lan
```

The `--cleanup` flag is important. Without it containerlab keeps the
`clab-ceos/` directory with the rendered configs from the previous deploy, so
edits to files under `configs/` are silently ignored on the next deploy.
`clab-up.sh` always destroys with `--cleanup` before re-deploying.

---

## Troubleshooting

**`containerlab deploy` fails with "image not found"**
The cEOS image tag must match exactly. Compare:
```bash
docker images | grep ceosimage
grep image: isp-topology.yml
```

**ExaBGP says peer is connecting but never establishes**
Check that the customer routers can reach `10.100.0.1`:
```bash
docker exec -t clab-ceos-router1 Cli -c "ping 10.100.0.1 source 10.100.0.2"
```
If ping fails, the `ext-lan` bridge is not wired correctly or its IP was not
assigned. Re-run `clab-up.sh`.

**Config edits in `configs/*.cfg` have no effect**
containerlab cached the rendered configs in `clab-ceos/`. Destroy with
`--cleanup` (or just rerun `clab-up.sh`):
```bash
sudo containerlab destroy -t isp-topology.yml --cleanup
```

**HAProxy cert warning in the browser**
The cert is self-signed and is regenerated on first start. Pass `-k` to
`curl` and accept the warning in the browser, or replace
`haproxy-certs/haproxy.pem` with a real cert.

**Routes not auto re-announced after `docker compose restart exabgp`**
Check `docker compose logs api` for `ExaBGP pipe reachable again`. If it does
not appear, trigger manually:
```bash
curl -sk -X POST "$HOST/api/reannounce" -H "Authorization: Bearer $TOKEN"
```

**`mkfifo: cannot create fifo: File exists`**
Safe to ignore — the pipes already exist. If they were created with the wrong
permissions, remove and recreate:
```bash
rm -f exabgp-run/exabgp.in exabgp-run/exabgp.out
mkfifo exabgp-run/exabgp.in exabgp-run/exabgp.out
chmod 666 exabgp-run/exabgp.in exabgp-run/exabgp.out
```

---

## File Layout

```
arista_eos/
├── api/                        Flask API build context (mirrors top-level api/)
├── haproxy/                    HAProxy build context
├── configs/                    cEOS startup-configs, one per node
│   ├── isp1-startup-config.cfg
│   ├── isp2-startup-config.cfg
│   ├── router1-startup-config.cfg
│   └── router2-startup-config.cfg
├── clab-up.sh                  Bridge + lab bring-up helper
├── isp-topology.yml            containerlab topology
├── docker-compose.yml          ExaBGP + API + HAProxy
├── exabgp.conf                 ExaBGP peer config
└── .env                        API credentials and lab settings
```
