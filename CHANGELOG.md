# Changelog

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
