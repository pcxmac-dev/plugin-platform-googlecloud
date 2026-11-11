# Changelog

## 0.1.1 (2026-11-11)

What an audit of the cloud plugins found before any key went in (session 87405e6a: eight reviewers, a skeptic per
finding), fixed for Google Cloud. Needs liminal-libs>=1.49.2.

- **Start is asked twice.** Starting a stopped server resumes its charges, against the user's "Free changes only", so
  a start is refused first (`accept_costs`). The refusal names what bills again: the machine type with its vCPUs and
  memory, its GPUs, a premium image's licence. The command line asks "yes" twice too.
- **The firewall's risk check is wider.** Asked twice: a rule denying SSH (a lockout); an allow from the whole internet
  of anything but the web's ports 80 and 443 (RDP 3389, Docker's 2375, SSH moved to 2222, any other port or range,
  every port, ping); removing the rule letting SSH or RDP in to a server it reaches. Before, a deny of tcp:22 from
  everywhere, or RDP opened to the internet, went through on one confirmation.
- **Dynamic DNS changes only what is its own**, through the library's Keeper (1.49.2):
  - a host holding another address, or several, is left as it is, with **Take over…** on its row (the hook
    `ddns_take_over`, asked once confirmed, then a pass for that host);
  - what is its own is kept in `googlecloud/ddns.json` under the platform's folder, so its old address is still known
    after a restart;
  - **Update DNS now** is a confirmed form;
  - the record is read again just before a write, and left as it is if it changed meanwhile to what is not its own;
  - a host taken out of the settings is let go.
  Before, `@.example.com` in the hosts setting pointed a live website at home within a minute, unasked.
- **A pass ends once the plugin is detached.**
  - Before, a disable during a pass waited 10 s and left the pass running. Its next request read the settings from
    the process's environment and sent the DNS change.
  - Now the background works with the settings of the login it was attached with, and its stop is checked before each
    part, each request of a pass and each write. Nothing more is read or written once it is set. `working` stays true
    until that thread has ended.
- **The background starts only when the platform attaches the plugin.** The charts app run alone attaches every plugin
  it finds, and now starts none of this.
- **A second confirmation counts only when it is exactly true** (`accept_*` is `True`). Before, "false" or 1 from a
  program of its own passed as one.
- **Smaller fixes:**
  - adding a project-wide SSH key says that Google's guest agent puts the account in google-sudoers, whose members
    get sudo;
  - a DNS change that times out, or meets Google's own trouble, says it may have been made, not "refused, nothing
    changed";
  - the API card links Google's guest agent page.

The platform's one-shot commands (status, machine: `PlatformApp.once`, liminal-platform 0.20.1) start none of its background work.

## 0.1.0 (2026-11-11)

The first release (the user: "lets roll plugins for EC2, vultr, azure and google cloud", choosing "Free changes only";
and "each plugin should reflect the the API its attached to, and present links that provide documentation, the plugin
interface should more or less contain what it already has, BUT, it should also expose more of what the API is about"):

- the settings read through the library's Login interface alone, as pairs named by their variables: GOOGLECLOUD_KEY
  (a service account's JSON key itself, kept in the login, never in a file), GOOGLECLOUD_PROJECT (the key's own
  project unless set), GOOGLECLOUD_DDNS_HOSTS and GOOGLECLOUD_DDNS_MINUTES; the status names the settings set, never a
  value; a key whose token_uri is not Google's, or of another universe, is refused;
- the access token through the library's RestClient and TokenSource: a JWT signed RS256 with the key (iss, scope, aud,
  iat, exp), exchanged at the key's token_uri with the JWT bearer grant, kept until a minute before its hour ends, a
  401 asking a new one; the scopes compute, ndev.clouddns.readwrite and cloud-billing.readonly;
- the reads, every quarter of an hour while attached (detached, nothing runs): the project (its quotas, its common
  metadata), its billing info and account, every zone's servers (state, machine type with its vCPUs and memory,
  addresses, disks), the disks, the regional and global addresses, the VPC firewall rules with the servers each
  reaches, the zones and regions (the quotas of those in use), the Cloud DNS zones and their records; a count of every
  other kind from the project's quotas; about a dozen requests a refresh, each machine type read once;
- the free changes, each through a form the platform's page confirms: a server started (its vCPU and memory charges
  resume: said), stopped (its disks and static addresses keep billing, its ephemeral address let go: said; a Local SSD
  stopped in the console) or reset (hard: asked twice); a record set or removed in a Cloud DNS zone with one change, its
  record set deleted exactly as read, every other record kept; a VPC firewall rule added or removed (asked twice: one
  opening SSH or every port to the whole internet, removing the one letting SSH in to a server or denying ingress to
  one); a project-wide SSH key added or removed with the project metadata's fingerprint, every other item kept and
  checked after; each change with Google's requestId, its operation followed to its end;
- Dynamic DNS through Cloud DNS (the library's ddns.Keeper): hosts of the project's public zones kept at this
  network's public IPv4 address (asked of OpenDNS's and Google's name servers), set only when they differ, Update DNS
  now; a CNAME never written over;
- nothing billable: no server, disk, snapshot, image, reservation, reserved address or zone made, nothing resized,
  suspended, resumed or deleted but a firewall rule; the client holds none of those calls, and refuses any change but
  the free ones before anything is sent;
- its API on its page (plugin API 2.2): the Compute Engine API (every one of its reference's 131 resources, in 27
  parts), the Cloud DNS API, the Cloud Billing API and Google OAuth 2.0, each with Google's pages (reference, guides,
  quotas, pricing, Service Health, release notes, discovery documents, the console, gcloud), the calls it makes and
  the notable others, and what it learned of them (the requests made, the last answer, the token held);
- `python -m plugin_platform_googlecloud status | servers | domains | records | ddns | firewalls | keys | power | set |
  remove` (each change asked "yes" on the terminal, a reset twice).
