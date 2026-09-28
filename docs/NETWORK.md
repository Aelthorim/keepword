# Starting a Witness network

This guide sets up a real, public Witness network: independent witnesses on
the internet that audit each other's logs, agree on who captures which
page, and give verdicts that hold up because the witnesses are genuinely
independent.

For installing a single node, see [INSTALL.md](INSTALL.md). For why things
work the way they do, see [DESIGN.md](DESIGN.md) §6.

## 1. What makes a network trustworthy

A verdict says "witnesses in N independent networks saw this". The software
counts **autonomous systems (ASNs)**, the networks of internet providers,
not machines or keys, because keys and machines are free and networks are
not. It learns a witness's ASN by watching where the witness's connections
come from; what a node says about itself is ignored.

So a real network needs:

| Requirement | Why |
|---|---|
| **At least 3 witnesses, each in a different ASN** | "Agreed" needs 3 ASNs (`quorum.min_asns`), and each witness's location has to be confirmed by 2 others (`quorum.min_observers`). |
| **At least 2 countries** | Assignment takes at most 2 witnesses per country (`network.max_per_country`). With the default 5 witnesses per request, 3 or more countries fill every slot. |
| **Different operators** | The software can only check networks. Witnesses run by one person agree because one person runs them. For evidence others trust, each witness should be run by a different person or organization. |
| **A public HTTPS endpoint on every witness** | Peers audit a witness's log and fetch its attestations through its endpoint. A witness without one is never assigned requests and doesn't count toward verdicts. |
| **An accurate clock** | Messages more than 5 minutes off are rejected. |

Different providers usually means different ASNs: for example Hetzner
(AS24940), OVH (AS16276), Scaleway (AS12876), DigitalOcean (AS14061), Vultr
(AS20473), or a home connection such as Deutsche Telekom (AS3320). Two
servers at the same provider are the same ASN, even in different data
centers. A witness's location is where its traffic leaves: behind a VPN or
proxy, it is the VPN's network.

A good first network is **5 witnesses, run by 3 or more people, at 5
different providers, in 3 countries.** Three witnesses is the minimum that
works at all.

## 2. Before you start (every witness)

- A Linux server (1 vCPU, 1 GB RAM and 20 GB disk are plenty to start).
- A domain name pointing at it (an `A`, and `AAAA` if it has IPv6),
  e.g. `w1.example.org`. Use a name you can keep: it's how peers find the
  witness.
- Ports **80 and 443** open to everyone (Caddy gets a TLS certificate
  through port 80). Nothing else needs to be public.
- Time sync on: `timedatectl` should say `System clock synchronized: yes`.
- Outbound HTTPS allowed to drand (`api.drand.sh`), the OpenTimestamps
  calendars and `iptoasn.com`.

## 3. Launch

### Step 1: the first witness

```sh
git clone https://github.com/aelthorim/witness.git
cd witness
sudo sh scripts/install.sh --domain w1.example.org --caddy
```

Check it answers from outside:

```sh
curl https://w1.example.org/v1/descriptor
```

This first witness is the **bootstrap peer**: the address the others dial
first. There is nothing special about it afterwards. Every witness learns
every other one through gossip, and any witness's address works as a
bootstrap peer.

### Step 2: the other founding witnesses

On each, with its own domain, pointing at the first:

```sh
sudo sh scripts/install.sh --domain w2.example.net --caddy \
    --peer https://w1.example.org
```

Giving two bootstrap peers (repeat `--peer`) means a new witness still
joins when one of them is down.

### Step 3: check that the network formed

After two or three minutes (a few sync rounds), on any witness:

```sh
witness net peers        # as root or with sudo
witness net status
```

`witness net peers` should list every other witness with a log size, a
recent `last sync`, no error, and a location like
`AS16276 FR (2 observers)`. `witness net status` should show:

- `location` with an ASN and observers, not `not corroborated`;
- `candidates` equal to the number of witnesses;
- `epoch ... (drand)`;
- **no warnings** at the end. The warnings name anything that keeps the
  node out of the network, such as a missing endpoint, no ASN table, test
  settings or failing peers.

### Step 4: a first real verdict

On any witness, ask the network to watch a page that doesn't change often:

```sh
witness request https://www.example.org/ --every 10m --for 1day
```

Within a sync round, the assigned witnesses show it in
`witness watch list`. After about ten minutes they have all captured it,
and on any witness:

```sh
witness verdict https://www.example.org/
# AGREED by 3 witnesses in 3 independent networks: ...
```

Then check that the evidence stands on its own. Export a bundle and verify
it on a different machine:

```sh
witness export https://www.example.org/ > bundle.json   # on a witness that captured it
witness verify --bundle bundle.json                           # anywhere
```

Withdraw the test request when you're done:
`witness request https://www.example.org/ --cancel`.

### Step 5: publish how to join

Publish the endpoints of two or three bootstrap witnesses run by different
people, for example in your project's README. A newcomer joins with:

```sh
sudo sh scripts/install.sh --domain their.domain --caddy \
    --peer https://w1.example.org --peer https://w2.example.net
```

There is no registration and no central server. A new witness counts in
verdicts once two others have observed it, and is assigned requests from
then on.

## 4. Settings the whole network must share

Every witness computes the assignment itself, so these must be **the same
on every witness**, or witnesses disagree about who captures what:

| Setting | Default |
|---|---|
| `network.replication` | 5 |
| `network.max_per_country` | 2 |
| `network.audit_logs` | 16 |
| `beacon.drand_url` | `https://api.drand.sh` (quicknet) |

These only change how *your* witness judges verdicts, but keep the
defaults so all witnesses report the same thing: `quorum.min_asns = 3`,
`quorum.min_dissent_asns = 2`, `quorum.window_secs = 600`,
`quorum.min_observers = 2`.

**Never enable these on a public witness.** They exist for test networks,
and `witness net status` warns about them: `quorum.trust_self_reported`,
`beacon.allow_insecure_seed`, `network.allow_private_peers`.

## 5. Each operator's own choices

| Setting | What it does |
|---|---|
| `network.decline_hosts` | Hosts your witness never captures for others' requests, e.g. for legal reasons. Requests are still relayed. |
| `network.max_request_watches` | Most URLs your witness captures for the network at once (default 200). |
| `network.render_requests` | Render requests in Chromium. Off by default: the browser fetches sub-resources past the node's address checks, so only enable it with the browser sandboxed away from your LAN. |
| `network.serve_content_hosts` | Hosts whose captured content your API serves to anyone. Empty by default: peers get hashes and signatures, never page content. |
| `content.retain` | `full`, `normalized` or `none`. See DESIGN.md §7 before storing third-party content. |

Change settings with `witness config set KEY VALUE`, then
`sudo systemctl restart witness`.

## 6. Resources

Each witness talks to a random sample of 16 peers a minute, audits about 16
logs an hour with a consistency proof, and fetches other witnesses'
attestations only for the URLs it follows. So its costs barely depend on
how big the network is:

| | Per witness |
|---|---|
| Network data (peers, observations, audit state, fetched attestations) | roughly 25–50 GB a year, bounded by pruning |
| Own captures, `content.retain = normalized` | about 10 MB a day for 100 URLs checked hourly |
| Own captures, `content.retain = full` | 0.1–0.5 GB a day for the same, depending on the pages |
| Traffic | a few hundred requests a minute |

`network.max_peers` (2000) bounds the peer table; raise it for a larger
network.

## 7. Running it

- **Upgrades:** `git pull` and re-run the installer with the same options.
  Keys and data are kept. Nodes skip message types they don't know, so
  witnesses can upgrade one at a time, but upgrade within days.
- **Backups:** `/var/lib/witness/witness.key` is the witness's identity. A
  lost key means a new witness, and the old log can never be extended.
- **Monitoring:** `witness net status` (warnings), `witness alerts`,
  `journalctl -u witness`. A peer that keeps failing shows its error in
  `witness net peers`.
- **Automatic:** syncing every minute, Bitcoin anchoring every hour, the
  IP-to-ASN table refresh every week.
- **Retiring a witness:** export the bundles that matter first
  (`witness export`); bundles verify on their own, but nobody else keeps a
  full copy of a witness's log. Keep the key. Peers retry it every ten minutes, stop
  assigning it requests after a week, and drop it first when their peer
  table fills up. `witness net remove-peer KEY` drops it at once.

## 8. Moving on from a test cluster

Test witnesses have signed attestations with test settings (fake ASNs, a
predictable seed) into their permanent logs. For the public network, start
the witnesses over with new keys:

```sh
sudo sh scripts/install.sh --uninstall --purge     # deletes key and log
sudo sh scripts/install.sh --domain wN.example.org --caddy --peer https://w1.example.org
```

To keep a test witness's key instead, undo every test setting
(`witness config unset quorum.trust_self_reported`, and likewise
`network.max_per_country`, `quorum.min_asns`, `quorum.min_dissent_asns`,
`network.allow_private_peers`, `vantage.asn`), set its public endpoint and
peers, remove the old LAN peers with `witness net remove-peer`, and
restart it.

## 9. Troubleshooting

| Symptom | Likely cause |
|---|---|
| `witness net peers` is empty | No `network.peers`, or the bootstrap peer isn't reachable: `curl https://PEER/v1/descriptor` from this server. |
| A peer shows `error: ... not a public address` | Its endpoint is a private IP. Public witnesses need public endpoints. |
| `location not corroborated` | Fewer than 2 other witnesses have received pushes from this one yet. Wait a few rounds, and check that its peers can reach it. |
| Every location is `unknown` | No IP-to-ASN table: `witness config get quorum.asn_db`, and check the `witness-asn-update` timer. |
| Peers all show the same ASN | They're at the same provider, or observations come from a proxy or CDN in front of the API. The API must be reached directly or through your own reverse proxy (INSTALL.md). |
| `no seed: no drand beacon` | Nobody can reach drand yet. Assignment waits for the day's beacon. |
| Verdicts stay `INSUFFICIENT` | Fewer than 3 ASNs among the witnesses assigned to the URL, or their captures fall outside one 10-minute window. |
| Messages rejected, heads look wrong | Clock skew: check `timedatectl`. |
| A bundle has no cosignatures | The capture is newer than the log's last checkpoint. Checkpoints are hourly; auditors cosign within the following hour. |
