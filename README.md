# plugin-platform-googlecloud

Google Cloud for Liminal's platform: a project's servers, disks, addresses, VPC firewall rules, Cloud DNS zones and
project-wide SSH keys through Google's own APIs; the free changes, each confirmed; and Dynamic DNS through Cloud DNS.

The user's words (2026-11-11): "lets roll plugins for EC2, vultr, azure and google cloud", choosing "Free changes
only"; and "each plugin should reflect the the API its attached to, and present links that provide documentation".

## What it shows

A machine plugin of the platform (`liminal_libs.machines.MachinePlugin`, plugin API 2.2, its icon Google Cloud's
cloud), read every quarter of an hour while it is attached to the platform app (Refresh reads it at once):

- **The project**: its ID, the service account acting on it, its billing (on or off, the billing account, whether
  that account is open). Google's APIs give no balance and no spend: the console's Billing pages do.
- **Servers**: every zone's instances (aggregatedList): state, zone, machine type with its vCPUs and memory, external
  IPv4 (a static one marked) and IPv6, internal address, disks, when made. Compute Engine's API gives no prices: the
  pricing pages are linked on its API card.
- **Disks**, **Addresses** (reserved static ones, regional and global, and what uses them), **Firewall rules** (every
  VPC rule, with the servers each one reaches), **Project-wide SSH keys** (the project metadata's `ssh-keys`, each with
  its user, type, fingerprint and expiry), **DNS zones** and each zone's **records**, the **Regions in use** with the
  quotas they use, and **In the project**: a count of every other kind it holds (snapshots, networks, images...) as its
  quotas count them, from the one read of the project.
- **A stopped server still bills**: Compute Engine stops billing its vCPUs and memory, but its disks and static
  addresses keep billing while they exist. The page says so beside the servers, and the stop's confirmation names them.

## What it changes, and only once you confirm

Only what costs nothing (the user: "Free changes only"), each through a form on the platform's page that names the
change before it is sent:

- **Start…** a stopped server. Starting one restarts its charges (its vCPUs and memory, any GPU, a premium image's
  licence), so it is asked twice: the second confirmation names the machine type, its shape and its GPUs.
- **Stop…** a running server: Google sends its guest an ACPI shutdown and gives it up to 120 seconds (30 for a Spot
  VM). The confirmation names what keeps billing (its disks, its static addresses) and the ephemeral address it lets
  go (started again, a server gets another: a DNS record holding it is then wrong). A server with a Local SSD is
  stopped in the console instead, where you choose what happens to that data.
- **Reset…** a running server: a hard reset, with no shutdown of its guest (unsaved data is lost, file systems may be
  corrupted), so it is asked twice.
- **Set a record…** and a record's **Remove** in each Cloud DNS zone: one change through `changes.create`, the name's
  record set of the type deleted exactly as it was read and added back changed. Every other record is kept, and a
  change made meanwhile makes Google refuse it, so nothing is overwritten. An A, AAAA or CNAME replaces the name's
  values of its type; a TXT, MX, CAA, SRV or NS value is added beside the others. The zone's own SOA, NS and DNSSEC
  records, record sets with a routing policy and forwarding or peering zones are not written here.
- **Add a rule…** and a rule's **Remove** among the VPC firewall rules (rules cost nothing; their logging, which
  would, stays off). Asked twice: a rule denying SSH (it may lock you out), a rule letting anything but the web's ports
  80 and 443 in from the whole internet (0.0.0.0/0 or ::/0: SSH, RDP, Docker's 2375, SSH moved to 2222, every port,
  ping), removing the rule that lets SSH or RDP in to a server it reaches, and removing a rule that denies ingress to
  one.
- **Add a key…** and a key's **Remove** among the project-wide SSH keys, safely (below). The confirmation says what a
  key gives: Google's guest agent adds the accounts it makes from metadata keys to `google-sudoers`, whose members get
  sudo on the server.
- **Dynamic DNS**: hosts of a public Cloud DNS zone kept at this network's public IPv4 address, only those that are its
  own (below); **Update DNS now** sets them now, after its confirmation, and a host holding another address
  offers **Take over…**.

A second confirmation counts only when it is exactly true (the page sends JSON true): a program of its own sending
"yes" or 1 is refused like a missing one.

### The SSH keys, with the metadata's fingerprint

The project-wide keys are one item (`ssh-keys`) of the project's common metadata, which Google writes whole
(`setCommonInstanceMetadata`). So a key is added or removed by reading the metadata afresh, changing that one item
(every other key line and every other item, startup scripts too, sent back exactly as read) and writing it with the
fingerprint it was read with. Google refuses the write (412 conditionNotMet) when the metadata changed since, so a
change made meanwhile is never overwritten; the plugin then reads the metadata back and says whether it holds what
was written. Servers with OS Login on, or blocking project-wide keys, ignore these keys: the page says which.

## Setting it up

1. **Enable the APIs** in the project: Compute Engine, Cloud DNS (if you use it) and Cloud Billing.
2. **Make a service account** for Liminal and give it the reads, and the free changes alone (the commands below).
3. **Make a JSON key** for it (IAM & Admin > Service accounts > the account > Keys > Add key > Create new key >
   JSON). Google downloads it once. An organization made on or after May 3, 2024 refuses keys by default (the
   `iam.disableServiceAccountKeyCreation` policy): its administrator can exempt the project.
4. **Enter the settings**: on the platform's page, the plugin's **Settings…** asks for each one below, the key typed
   hidden. Paste the key file's contents whole into `GOOGLECLOUD_KEY` (the field drops its line breaks; it is still
   the same JSON), then delete the downloaded file: the key is kept in the login (your user environment variables
   today, the login app once it holds them), never in a file of the plugin's, and never shown back.

```
gcloud services enable compute.googleapis.com dns.googleapis.com cloudbilling.googleapis.com --project=PROJECT_ID
gcloud iam service-accounts create liminal --display-name="Liminal" --project=PROJECT_ID

SA="serviceAccount:liminal@PROJECT_ID.iam.gserviceaccount.com"
# the reads
gcloud projects add-iam-policy-binding PROJECT_ID --member="$SA" --role="roles/compute.viewer"
gcloud projects add-iam-policy-binding PROJECT_ID --member="$SA" --role="roles/dns.reader"
# the free changes alone (and the billing info's read), in a role of your own
gcloud iam roles create liminalFreeChanges --project=PROJECT_ID --title="Liminal free changes" \
    --description="Start, stop and reset servers; Cloud DNS records; VPC firewall rules" --stage=GA \
    --permissions="compute.instances.start,compute.instances.stop,compute.instances.reset,compute.firewalls.create,compute.firewalls.delete,compute.networks.updatePolicy,dns.changes.create,dns.resourceRecordSets.create,dns.resourceRecordSets.update,dns.resourceRecordSets.delete,resourcemanager.projects.get"
gcloud projects add-iam-policy-binding PROJECT_ID --member="$SA" --role="projects/PROJECT_ID/roles/liminalFreeChanges"

gcloud iam service-accounts keys create key.json --iam-account=liminal@PROJECT_ID.iam.gserviceaccount.com
```

Without the custom role the plugin reads everything and every change is refused by Google in its own words. The
SSH keys need two more permissions, which Google's guide names for project metadata:
`compute.projects.setCommonInstanceMetadata` and `iam.serviceAccounts.actAs` on the project. Add them only if you
want the keys changed from here: whoever may change the project's metadata may let anyone in to its servers, and
`actAs` lets the account act as the project's service accounts. The billing account's name needs Billing Account
Viewer on that billing account (optional: without it the page shows the account's ID).

| Variable | | |
|---|---|---|
| `GOOGLECLOUD_KEY` | secret | the service account's JSON key itself, pasted whole |
| `GOOGLECLOUD_PROJECT` | optional | the ID of the project acted on (the key's own `project_id` unless set) |
| `GOOGLECLOUD_DDNS_HOSTS` | Dynamic DNS | the hosts kept at this network's address, comma separated, each in a public Cloud DNS zone of the project: `home.example.com`, `@.example.com` (the zone's own name) |
| `GOOGLECLOUD_DDNS_MINUTES` | optional | minutes between Dynamic DNS checks, 1 to 1440 (5 unless set) |

The plugin keeps no settings file and never shows a value: its status names the settings that are set (and the
service account's address, which you grant the roles to). The token it asks with the key lasts an hour and is held in
memory alone.

## Dynamic DNS

This network's public IPv4 address is asked of DNS (`myip.opendns.com` of OpenDNS's resolver, else Google's
`o-o.myaddr.l.google.com`, each asked by its IPv4 address, as the hw-stats plugin asks it), and each host's A record of
Cloud DNS's API, through the library's Keeper (liminal-libs 1.49.2). It changes only what is its own: a host with no A
record (it is made), one already pointing at this network, one holding the address it set last (after the network's
address changed, after a restart too: what is its own is kept in `googlecloud/ddns.json` under the platform's folder,
`LIMINAL_PLATFORM_DIR`, else the data folder's `platform/`), and one you took over. Any other record, another address
or several, is left as it is and said so, with **Take over…** on its row: confirmed, the host is pointed here on the
next pass and kept there. Several addresses are never cut to one unasked. Just before a write the address is asked
again, and the record read again: changed meanwhile to what is not its own, it is left as it is. Only hosts of the
project's public zones are kept (a private zone answers inside its VPC networks alone); a host holding a CNAME is never
written over; a host taken out of the settings is let go.

## Its API

It attaches to four of Google's APIs, each drawn on its page with its parts (every part of each reference, the ones
it uses first), its calls (those it makes, and the others worth knowing, those that change something or cost money
marked so), its limits and costs, and what it learned of them while it ran (the requests made, the last answer):

- **Compute Engine API** v1, `https://compute.googleapis.com/compute/v1`: the
  [reference](https://docs.cloud.google.com/compute/docs/reference/rest/v1),
  [rate quotas](https://docs.cloud.google.com/compute/api-quota),
  [stopping and starting](https://docs.cloud.google.com/compute/docs/instances/stop-start-instance),
  [what each state bills](https://docs.cloud.google.com/compute/docs/instances/instance-lifecycle),
  [VM pricing](https://cloud.google.com/products/compute/pricing),
  [disk pricing](https://cloud.google.com/compute/disks-image-pricing),
  [network pricing](https://cloud.google.com/vpc/network-pricing).
- **Cloud DNS API** v1, `https://dns.googleapis.com/dns/v1`: the
  [reference](https://docs.cloud.google.com/dns/docs/reference/rest),
  [records](https://docs.cloud.google.com/dns/docs/records), [quotas](https://docs.cloud.google.com/dns/quotas),
  [pricing](https://cloud.google.com/dns/pricing).
- **Cloud Billing API** v1, `https://cloudbilling.googleapis.com/v1`: the
  [reference](https://docs.cloud.google.com/billing/docs/reference/rest),
  [projects.getBillingInfo](https://docs.cloud.google.com/billing/docs/reference/rest/v1/projects/getBillingInfo).
- **Google OAuth 2.0**, `https://oauth2.googleapis.com/token`: a service account's signed JWT (RS256) exchanged for an
  hour's access token, as [Google's guide](https://developers.google.com/identity/protocols/oauth2/service-account)
  gives it.

Google Cloud's status: [Service Health](https://status.cloud.google.com/).

## What it never does

No server, disk, snapshot, image, machine image, reservation, commitment, reserved address or Cloud DNS zone is made;
nothing is resized, restored, suspended or resumed; nothing is deleted but a firewall rule you remove; no billing
account is linked or unlinked; no firewall rule logging is turned on. The client (`api.py`) holds none of those calls'
paths (its tests check it), only the free changes above, and refuses any other change before anything is sent.

## Valid, and the platform

Its background reading starts only when the platform attaches it (the charts app run alone attaches every plugin it
finds, and starts none of this). Detached (the platform ending, the plugin disabled), the reading ends: a request under
way is the last thing it does, its settings are not read again (not from the process's environment either) and nothing
more is written.

The plugin is valid while a part of it works or has not been tried yet (Compute Engine, Cloud DNS): the platform
disables a plugin that is not valid, which would stop Dynamic DNS, so a key that may read Cloud DNS alone keeps it
working. A part that failed is taken as untried a quarter of an hour later (the platform attaches it again), or at
once when its settings change. With nothing set, or a key that cannot be used, it is not valid and says what to set
and where a key is made.

## Its hooks

`present`, `status` (the summary, the facts, `tables`, `actions`, `forms`), `refresh()`, `servers()`, `firewalls()`,
`domains()`, `records(zone)`, `ssh_keys()`; the changes `start_server(zone, instance, accept_costs=False)`,
`stop_server(zone, instance)`,
`reset_server(zone, instance, accept_hard_reset=False)`, `add_firewall_rule(name, network, direction, action, protocol,
ports, ranges, target_tags, priority, description, accept_open_to_internet=False)`,
`remove_firewall_rule(name, accept_risky_removal=False)`, `set_record(zone, name, rtype, data, ttl=None)`,
`remove_record(zone, name, rtype, data)`, `add_ssh_key(user, key)`, `remove_ssh_key(user, fingerprint)`,
`ddns_update(force=True)`, `ddns_take_over(host, holds=None)`. A refused change raises a refusal naming the argument
that accepts it, when one does (the page asks it as a second confirmation).

## From the command line

Its settings read from the environment (as this shell has them); each change asks "yes" on the terminal first, a
start (naming the charges it resumes) and a reset twice:

```
python -m plugin_platform_googlecloud status
python -m plugin_platform_googlecloud servers
python -m plugin_platform_googlecloud domains
python -m plugin_platform_googlecloud records example.com
python -m plugin_platform_googlecloud firewalls
python -m plugin_platform_googlecloud keys
python -m plugin_platform_googlecloud ddns [--now]
python -m plugin_platform_googlecloud power web-1 on|off|reboot
python -m plugin_platform_googlecloud set example-com home A 203.0.113.7 --ttl 300
python -m plugin_platform_googlecloud remove example-com home A 203.0.113.7
```

`--json` before the command prints the answer as JSON. Firewall rules and SSH keys are changed from the page.

## Limits

Compute Engine keeps rate quotas per project and minute by group of calls (their numbers on the project's Quotas
page), 36 project metadata writes a minute among them; Cloud DNS takes at most 1,000 additions and 1,000 deletions a
change; Cloud Billing 300 calls a minute a project. A refresh makes about a dozen reads (each machine type read once,
the zones and the billing account at most hourly, at most 12 zones' records), a token is asked once an hour, and each
Dynamic DNS host costs one read a check.

## Install

```
pip install "plugin-platform-googlecloud @ git+https://github.com/pcxmac-dev/plugin-platform-googlecloud@main"
```

or, for the platform's preview, a checkout in the plugin directory (`LIMINAL_PLUGINS`). It needs `cryptography` for
the key's RS256 signature. Its tests use stand-ins for Google and DNS alone (`python -m pytest`), with a key made for
them: none reaches Google or the network. `LIMINAL_VENDOR_PAGES=1` also asks every address its API card names.
