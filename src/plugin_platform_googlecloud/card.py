"""What the plugin attaches to (plugin API 2.2; liminal_libs.sources.apis): Google's Compute Engine API, Cloud DNS API,
Cloud Billing API and its OAuth 2.0 token endpoint, as Google's own pages describe them (read 2026-11-11): what each is
for, where it is reached, how a caller proves who it is, its limits and what of it costs money; Google's pages
(documentation, reference, guides, limits, pricing, status, changes, discovery documents, the console, gcloud); every
part of each reference (covered by the plugin or not); the calls the plugin makes, each with what it makes it for, and
the API's other notable calls, those that change something or cost money marked so. The calls that make, resize,
snapshot, reserve or delete a billable thing are named here alone: the client (api.py) holds none of them."""
from __future__ import annotations

from liminal_libs.sources.apis import Api, Area, Call, Link

VERIFIED = "2026-11-11"
COMPUTE_NAME = "Compute Engine API"
DNS_NAME = "Cloud DNS API"
BILLING_NAME = "Cloud Billing API"
OAUTH_NAME = "Google OAuth 2.0"

_C = "https://docs.cloud.google.com/compute/docs/reference/rest/v1"
_D = "https://docs.cloud.google.com/dns/docs/reference/rest/v1"
_B = "https://docs.cloud.google.com/billing/docs/reference/rest/v1"
STATUS = "https://status.cloud.google.com/"

# the Compute Engine API's resources as its v1 reference lists them (131, read 2026-11-11): each is in one area below
COMPUTE_RESOURCES = (
    "acceleratorTypes", "addresses", "advice", "autoscalers", "backendBuckets", "backendServices", "crossSiteNetworks",
    "diskTypes", "disks", "externalVpnGateways", "firewallPolicies", "firewalls", "forwardingRules", "futureReservations",
    "globalAddresses", "globalForwardingRules", "globalFrontendSettings", "globalNetworkEndpointGroups", "globalOperations",
    "globalOrganizationOperations", "globalPublicDelegatedPrefixes", "globalVmExtensionPolicies", "healthChecks", "hosts",
    "httpHealthChecks", "httpsHealthChecks", "imageFamilyViews", "imageViews", "images",
    "instanceGroupManagerResizeRequests", "instanceGroupManagers", "instanceGroups", "instanceSettings",
    "instanceTemplates", "instances", "instantSnapshotGroups", "instantSnapshots", "interconnectAttachmentGroups",
    "interconnectAttachments", "interconnectGroups", "interconnectLocations", "interconnectRemoteLocations",
    "interconnects", "licenseCodes", "licenses", "machineImages", "machineTypes", "managedRulesets",
    "networkAttachments", "networkEdgeSecurityServices", "networkEndpointGroups", "networkFirewallPolicies",
    "networkProfiles", "networks", "nodeGroups", "nodeTemplates", "nodeTypes", "organizationSecurityPolicies",
    "packetMirrorings", "previewFeatures", "projectViews", "projects", "publicAdvertisedPrefixes",
    "publicDelegatedPrefixes", "regionAutoscalers", "regionBackendBuckets", "regionBackendServices", "regionCommitments",
    "regionCompositeHealthChecks", "regionDiskTypes", "regionDisks", "regionHealthAggregationPolicies",
    "regionHealthCheckServices", "regionHealthChecks", "regionHealthSources", "regionInstanceGroupManagerResizeRequests",
    "regionInstanceGroupManagers", "regionInstanceGroups", "regionInstanceTemplates", "regionInstances",
    "regionInstantSnapshotGroups", "regionInstantSnapshots", "regionNetworkEndpointGroups",
    "regionNetworkFirewallPolicies", "regionNotificationEndpoints", "regionOperations", "regionSecurityPolicies",
    "regionSnapshotSettings", "regionSnapshots", "regionSslCertificates", "regionSslPolicies", "regionTargetHttpProxies",
    "regionTargetHttpsProxies", "regionTargetTcpProxies", "regionUrlMaps", "regionZones", "regions", "reliabilityRisks",
    "reservationBlocks", "reservationSlots", "reservationSubBlocks", "reservations", "resourcePolicies", "rolloutPlans",
    "rollouts", "routers", "routes", "securityPolicies", "serviceAttachments", "snapshotSettings", "snapshots",
    "sslCertificates", "sslPolicies", "storagePoolTypes", "storagePools", "subnetworks", "targetGrpcProxies",
    "targetHttpProxies", "targetHttpsProxies", "targetInstances", "targetPools", "targetSslProxies", "targetTcpProxies",
    "targetVpnGateways", "urlMaps", "vpnGateways", "vpnTunnels", "wireGroups", "zoneOperations",
    "zoneVmExtensionPolicies", "zones",
)

# (area, what it is, its resources, the resource whose page it links, what the plugin does with it)
_COMPUTE_PARTS = (
    ("Instances", "the virtual machines: made, started, stopped, suspended, reset, changed and deleted; their serial "
     "port, screenshots and guest attributes", ("instances", "instanceSettings", "regionInstances"), "instances",
     "every zone's servers read (state, machine type, addresses, disks); started, stopped (gracefully) and reset (hard) "
     "once confirmed"),
    ("Machine and accelerator types", "the shapes a server takes (vCPUs, memory) and the GPUs a zone offers",
     ("machineTypes", "acceleratorTypes"), "machineTypes", "each server's vCPUs and memory, read once a machine type"),
    ("Disks", "persistent disks, zonal and regional, and their types: made, resized, attached, snapshotted",
     ("disks", "regionDisks", "diskTypes", "regionDiskTypes"), "disks",
     "every disk read: its size, type and state, the servers it is attached to"),
    ("Storage pools", "capacity and performance bought ahead and shared by disks", ("storagePools", "storagePoolTypes"),
     "storagePools", ""),
    ("Snapshots", "disk backups, standard and instant, and where they are kept",
     ("snapshots", "snapshotSettings", "regionSnapshots", "regionSnapshotSettings", "instantSnapshots",
      "instantSnapshotGroups", "regionInstantSnapshots", "regionInstantSnapshotGroups"), "snapshots", ""),
    ("Images", "boot images (Google's, your own, by family) and machine images of a whole server",
     ("images", "imageFamilyViews", "imageViews", "machineImages"), "images", ""),
    ("Instance groups and templates", "groups of servers, managed or not, their templates, resize requests and autoscalers",
     ("instanceGroups", "instanceGroupManagers", "instanceGroupManagerResizeRequests", "regionInstanceGroups",
      "regionInstanceGroupManagers", "regionInstanceGroupManagerResizeRequests", "instanceTemplates",
      "regionInstanceTemplates", "autoscalers", "regionAutoscalers"), "instanceGroupManagers", ""),
    ("Addresses", "reserved static addresses, external and internal, regional and global", ("addresses", "globalAddresses"),
     "addresses", "every reserved or in-use address read, regional and global (a static one marked on its server)"),
    ("VPC networks", "networks and their subnets, routes, Cloud Routers, network attachments and profiles, packet mirroring",
     ("networks", "subnetworks", "networkProfiles", "networkAttachments", "routes", "routers", "packetMirrorings"),
     "networks", ""),
    ("VPC firewall rules", "a network's allow and deny rules by direction, protocol, port, source and target",
     ("firewalls",), "firewalls",
     "every rule read with the servers it reaches; rules added and removed once confirmed (a risky one asked twice)"),
    ("Firewall policies", "hierarchical, global and regional network firewall policies, evaluated beside the VPC rules",
     ("firewallPolicies", "networkFirewallPolicies", "regionNetworkFirewallPolicies"), "firewallPolicies", ""),
    ("Load balancing", "backend services and buckets, forwarding rules, target proxies, pools and instances, URL maps, "
     "network endpoint groups",
     ("backendServices", "regionBackendServices", "backendBuckets", "regionBackendBuckets", "forwardingRules",
      "globalForwardingRules", "targetHttpProxies", "targetHttpsProxies", "targetSslProxies", "targetTcpProxies",
      "targetGrpcProxies", "regionTargetHttpProxies", "regionTargetHttpsProxies", "regionTargetTcpProxies", "targetPools",
      "targetInstances", "urlMaps", "regionUrlMaps", "networkEndpointGroups", "globalNetworkEndpointGroups",
      "regionNetworkEndpointGroups"), "backendServices", ""),
    ("Health checks", "the checks load balancers and groups ask of servers, and their notification endpoints",
     ("healthChecks", "httpHealthChecks", "httpsHealthChecks", "regionHealthChecks", "regionHealthCheckServices",
      "regionNotificationEndpoints", "regionCompositeHealthChecks", "regionHealthAggregationPolicies",
      "regionHealthSources"), "healthChecks", ""),
    ("TLS certificates and policies", "the certificates and TLS policies of load balancers",
     ("sslCertificates", "regionSslCertificates", "sslPolicies", "regionSslPolicies"), "sslCertificates", ""),
    ("Cloud Armor", "security policies in front of load balancers, and network edge security",
     ("securityPolicies", "regionSecurityPolicies", "organizationSecurityPolicies", "networkEdgeSecurityServices"),
     "securityPolicies", ""),
    ("Private Service Connect", "services published to other networks", ("serviceAttachments",), "serviceAttachments", ""),
    ("Cloud VPN", "VPN gateways and tunnels to other networks",
     ("vpnGateways", "targetVpnGateways", "vpnTunnels", "externalVpnGateways"), "vpnGateways", ""),
    ("Cloud Interconnect", "dedicated and partner links to Google's network, their attachments and locations, links "
     "between sites", ("interconnects", "interconnectAttachments", "interconnectAttachmentGroups", "interconnectGroups",
                       "interconnectLocations", "interconnectRemoteLocations", "crossSiteNetworks", "wireGroups"),
     "interconnects", ""),
    ("Bring your own IP", "your own address ranges, advertised and delegated by Google",
     ("publicAdvertisedPrefixes", "publicDelegatedPrefixes", "globalPublicDelegatedPrefixes"), "publicAdvertisedPrefixes", ""),
    ("Reservations and commitments", "capacity held for the project and discounts committed to (each bills)",
     ("reservations", "reservationBlocks", "reservationSubBlocks", "reservationSlots", "futureReservations",
      "regionCommitments"), "reservations", ""),
    ("Sole-tenant nodes", "hosts of the project's own, their templates and types",
     ("nodeGroups", "nodeTemplates", "nodeTypes"), "nodeGroups", ""),
    ("Resource policies", "snapshot schedules, instance schedules and placement", ("resourcePolicies",), "resourcePolicies", ""),
    ("Licenses", "the licenses images and disks carry", ("licenses", "licenseCodes"), "licenses", ""),
    ("Zones and regions", "where servers run, whether each is up, a region's quotas", ("zones", "regions", "regionZones"),
     "zones", "every zone's and region's state; the quotas of the regions in use"),
    ("Projects", "the project's quotas, its common metadata (project-wide SSH keys, startup scripts), usage export, "
     "Shared VPC", ("projects", "projectViews"), "projects",
     "the project read: its quotas (a count of each kind it holds) and common metadata; project-wide SSH keys added "
     "and removed with the metadata's fingerprint"),
    ("Operations", "the work a change starts, followed to its end",
     ("globalOperations", "regionOperations", "zoneOperations", "globalOrganizationOperations"), "globalOperations",
     "a firewall rule's or the SSH keys' change followed until Google says it is done"),
    ("Newer parts", "the reference's newest resources", ("advice", "hosts", "previewFeatures", "reliabilityRisks",
                                                          "rolloutPlans", "rollouts", "globalVmExtensionPolicies",
                                                          "zoneVmExtensionPolicies", "globalFrontendSettings",
                                                          "managedRulesets"), "", ""),
)
COMPUTE_AREAS = tuple(Area(name, f"{about} ({', '.join(parts)})", f"{_C}/{page}" if page else _C, covered)
                      for name, about, parts, page, covered in _COMPUTE_PARTS)

_P = "/compute/v1/projects/{project}"
_I = _P + "/zones/{zone}/instances"
COMPUTE_CALLS = (
    # the calls the plugin makes
    Call(f"GET {_P}", "the project: its quotas and its common metadata, with the metadata's fingerprint", "Projects",
         used="the project's facts, the Kinds table (its quotas) and the Project-wide SSH keys table",
         docs=f"{_C}/projects/get"),
    Call(f"GET {_P}/aggregated/instances", "every zone's instances at once", "Instances", used="the Servers table",
         docs=f"{_C}/instances/aggregatedList"),
    Call(f"GET {_I}/{{instance}}", "one instance", "Instances", used="a server read afresh before Start, Stop or Reset",
         docs=f"{_C}/instances/get"),
    Call(f"POST {_I}/{{instance}}/start", "starts a stopped instance: its vCPU and memory charges resume", "Instances",
         used="Start…", docs=f"{_C}/instances/start", writes=True, costs=True),
    Call(f"POST {_I}/{{instance}}/stop", "shuts an instance down (ACPI shutdown, up to 120 seconds); its disks and "
         "external addresses keep billing", "Instances", used="Stop…", docs=f"{_C}/instances/stop", writes=True),
    Call(f"POST {_I}/{{instance}}/reset", "a hard reset: no graceful shutdown, unsaved data lost", "Instances",
         used="Reset… (asked twice)", docs=f"{_C}/instances/reset", writes=True),
    Call(f"GET {_P}/zones/{{zone}}/machineTypes/{{machineType}}", "a machine type's vCPUs and memory",
         "Machine and accelerator types", used="the Servers table's machine types", docs=f"{_C}/machineTypes/get"),
    Call(f"GET {_P}/aggregated/disks", "every disk, zonal and regional", "Disks", used="the Disks table",
         docs=f"{_C}/disks/aggregatedList"),
    Call(f"GET {_P}/aggregated/addresses", "every regional address", "Addresses", used="the Addresses table",
         docs=f"{_C}/addresses/aggregatedList"),
    Call(f"GET {_P}/global/addresses", "the global addresses", "Addresses", used="the Addresses table",
         docs=f"{_C}/globalAddresses/list"),
    Call(f"GET {_P}/global/firewalls", "the VPC firewall rules", "VPC firewall rules", used="the Firewall rules table",
         docs=f"{_C}/firewalls/list"),
    Call(f"POST {_P}/global/firewalls", "adds a VPC firewall rule (free; its logging is left off)", "VPC firewall rules",
         used="Add a rule… (one opening SSH or every port to the internet asked twice)", docs=f"{_C}/firewalls/insert",
         writes=True),
    Call(f"DELETE {_P}/global/firewalls/{{firewall}}", "removes a VPC firewall rule", "VPC firewall rules",
         used="a rule's Remove (the one letting SSH in to a server asked twice)", docs=f"{_C}/firewalls/delete",
         writes=True),
    Call(f"POST {_P}/setCommonInstanceMetadata", "the project's common metadata written whole, with its fingerprint",
         "Projects", used="Add a key… and a key's Remove (the ssh-keys item alone changed)",
         docs=f"{_C}/projects/setCommonInstanceMetadata", writes=True),
    Call(f"GET {_P}/zones", "the zones and whether each is up", "Zones and regions", used="the servers' zones",
         docs=f"{_C}/zones/list"),
    Call(f"GET {_P}/regions", "the regions, their state and quotas", "Zones and regions", used="the Regions in use table",
         docs=f"{_C}/regions/list"),
    Call(f"GET {_P}/global/operations/{{operation}}", "a global operation's state", "Operations",
         used="a rule's or the SSH keys' change followed to its end", docs=f"{_C}/globalOperations/get"),
    # its other notable calls, not made
    Call(f"POST {_I}", "makes an instance (it bills while it runs, its disks while they exist)", "Instances",
         docs=f"{_C}/instances/insert", writes=True, costs=True),
    Call(f"DELETE {_I}/{{instance}}", "deletes an instance", "Instances",
         docs=f"{_C}/instances/delete", writes=True),
    Call(f"POST {_I}/{{instance}}/suspend", "suspends an instance: its memory and state kept on storage, billed as such",
         "Instances", docs=f"{_C}/instances/suspend", writes=True),
    Call(f"POST {_I}/{{instance}}/resume", "resumes a suspended instance: its charges resume", "Instances",
         docs=f"{_C}/instances/resume", writes=True, costs=True),
    Call(f"POST {_I}/{{instance}}/setMachineType", "changes a stopped instance's machine type (a resize)", "Instances",
         docs=f"{_C}/instances/setMachineType", writes=True, costs=True),
    Call(f"POST {_I}/{{instance}}/setMetadata", "sets one instance's metadata (its own SSH keys)", "Instances",
         docs=f"{_C}/instances/setMetadata", writes=True),
    Call(f"GET {_I}/{{instance}}/serialPort", "the last megabyte of a serial port's output", "Instances",
         docs=f"{_C}/instances/getSerialPortOutput"),
    Call(f"GET {_I}/{{instance}}/getEffectiveFirewalls", "the firewall rules and policies in force on an interface",
         "Instances", docs=f"{_C}/instances/getEffectiveFirewalls"),
    Call(f"POST {_P}/zones/{{zone}}/disks", "makes a disk (it bills while it exists)", "Disks", docs=f"{_C}/disks/insert",
         writes=True, costs=True),
    Call(f"POST {_P}/zones/{{zone}}/disks/{{disk}}/createSnapshot", "snapshots a disk (the snapshot bills)", "Disks",
         docs=f"{_C}/disks/createSnapshot", writes=True, costs=True),
    Call(f"POST {_P}/zones/{{zone}}/disks/{{disk}}/resize", "makes a disk larger (it bills more)", "Disks",
         docs=f"{_C}/disks/resize", writes=True, costs=True),
    Call(f"POST {_P}/regions/{{region}}/addresses", "reserves a static address (it bills while reserved)", "Addresses",
         docs=f"{_C}/addresses/insert", writes=True, costs=True),
    Call(f"PATCH {_P}/global/firewalls/{{firewall}}", "changes a rule in place", "VPC firewall rules",
         docs=f"{_C}/firewalls/patch", writes=True),
    Call(f"GET {_P}/aggregated/machineTypes", "every machine type of every zone", "Machine and accelerator types",
         docs=f"{_C}/machineTypes/aggregatedList"),
    Call(f"POST {_P}/zones/{{zone}}/operations/{{operation}}/wait", "waits up to two minutes for a zonal operation",
         "Operations", docs=f"{_C}/zoneOperations/wait"),
)

COMPUTE = Api(
    name=COMPUTE_NAME, maker="Google",
    about=("Compute Engine's REST API: a project's virtual machines and what they stand on, their machine types, "
           "disks, images and snapshots, addresses, VPC networks and firewall rules, load balancing, and the "
           "project's quotas and common metadata. Every change it takes starts an operation that ends on its own."),
    kind="rest", base="https://compute.googleapis.com/compute/v1", version="v1",
    auth=("an OAuth 2.0 access token (Bearer) of a service account, asked with the account's signed JWT (Google "
          "OAuth 2.0); the account's IAM roles decide what it may read and change"),
    limits=("rate quotas per project and minute, by group of calls (reads, writes; global and per region), their "
            "numbers on the project's Quotas page; 36 setCommonInstanceMetadata requests a minute; 500 operations of a "
            "kind under way at once by default (global, and per region); a quota passed answers 403 rateLimitExceeded. "
            "The plugin makes about a dozen reads every quarter of an hour"),
    costs=("its calls cost nothing; what they make bills. A running instance bills its vCPUs and memory (a stopped "
           "one does not), and its disks, snapshots and external addresses bill while they exist, whatever the "
           "instance's state: a stopped server's disks and static addresses keep billing. The API's answers hold no "
           "prices: the pricing pages do"),
    links=(Link("Compute Engine documentation", "https://docs.cloud.google.com/compute/docs", "docs"),
           Link("REST reference (v1)", _C, "reference"),
           Link("Creating API requests and handling responses",
                "https://docs.cloud.google.com/compute/docs/api/how-tos/api-requests-responses", "guide"),
           Link("Best practices for the API", "https://docs.cloud.google.com/compute/docs/api/best-practices", "guide"),
           Link("Stop or restart an instance", "https://docs.cloud.google.com/compute/docs/instances/stop-start-instance",
                "guide"),
           Link("Suspend, stop, or reset instances",
                "https://docs.cloud.google.com/compute/docs/instances/suspend-stop-reset-instances-overview", "guide"),
           Link("Instance lifecycle (what each state bills)",
                "https://docs.cloud.google.com/compute/docs/instances/instance-lifecycle", "guide"),
           Link("Add SSH keys to VMs", "https://docs.cloud.google.com/compute/docs/connect/add-ssh-keys", "guide"),
           Link("VPC firewall rules", "https://docs.cloud.google.com/firewall/docs/firewalls", "guide"),
           Link("Access control (IAM roles)", "https://docs.cloud.google.com/compute/docs/access", "auth"),
           Link("Rate quotas and system limits", "https://docs.cloud.google.com/compute/api-quota", "limits"),
           Link("Concurrent operation quotas", "https://docs.cloud.google.com/compute/operations-quota", "limits"),
           Link("VM instance pricing", "https://cloud.google.com/products/compute/pricing", "pricing"),
           Link("Disk and image pricing", "https://cloud.google.com/compute/disks-image-pricing", "pricing"),
           Link("Network pricing (IP addresses)", "https://cloud.google.com/vpc/network-pricing", "pricing"),
           Link("Pricing calculator", "https://cloud.google.com/products/calculator", "pricing"),
           Link("Google Cloud Service Health", STATUS, "status"),
           Link("Release notes", "https://docs.cloud.google.com/compute/docs/release-notes", "changelog"),
           Link("Discovery document", "https://www.googleapis.com/discovery/v1/apis/compute/v1/rest", "spec"),
           Link("VM instances (console)", "https://console.cloud.google.com/compute/instances", "console"),
           Link("Quotas (console)", "https://console.cloud.google.com/iam-admin/quotas", "console"),
           Link("gcloud compute", "https://docs.cloud.google.com/sdk/gcloud/reference/compute", "tool"),
           Link("Client libraries", "https://docs.cloud.google.com/compute/docs/api/libraries", "sdk"),
           Link("Google Cloud terms", "https://cloud.google.com/terms", "terms")),
    areas=COMPUTE_AREAS, calls=COMPUTE_CALLS, verified=VERIFIED)

_Z = "/dns/v1/projects/{project}/managedZones"
DNS_AREAS = (
    Area("changes", "a zone's record sets changed at once: the sets deleted (exactly as they are) and added together",
         f"{_D}/changes", "records set and removed, each one change (the old set deleted exactly as read, the new one added)"),
    Area("dnsKeys", "the DNSSEC keys of a signed zone", f"{_D}/dnsKeys"),
    Area("locations", "the locations Cloud DNS offers", f"{_D}/locations"),
    Area("managedZoneOperations", "the operations a zone's change of settings starts", f"{_D}/managedZoneOperations"),
    Area("managedZones", "the zones: public or private, DNSSEC, forwarding, peering, logging", f"{_D}/managedZones",
         "every zone read: its name, visibility, DNSSEC and name servers"),
    Area("operations", "Cloud DNS's long-running operations", f"{_D}/operations"),
    Area("outboundEndpoints", "the endpoints queries are forwarded out through", f"{_D}/outboundEndpoints"),
    Area("policies", "a VPC network's DNS server policies: inbound forwarding, other name servers, logging", f"{_D}/policies"),
    Area("projects", "the project's Cloud DNS quotas", f"{_D}/projects"),
    Area("resourceRecordSets", "a zone's record sets, each a name, a type, a TTL and its data", f"{_D}/resourceRecordSets",
         "every zone's records read (at most 12 zones a refresh), and each Dynamic DNS host's A record"),
    Area("responsePolicies", "response policies: answers a VPC network's resolver gives in place of others",
         f"{_D}/responsePolicies"),
    Area("responsePolicyRules", "a response policy's rules", f"{_D}/responsePolicyRules"),
)
DNS_CALLS = (
    Call(f"GET {_Z}", "the project's zones", "managedZones", used="the DNS zones table", docs=f"{_D}/managedZones/list"),
    Call(f"GET {_Z}/{{managedZone}}/rrsets", "a zone's record sets (of one name, one type)", "resourceRecordSets",
         used="each zone's records table; a name's records read afresh before a change; a Dynamic DNS host's A record",
         docs=f"{_D}/resourceRecordSets/list"),
    Call(f"POST {_Z}/{{managedZone}}/changes", "record sets deleted and added at once", "changes",
         used="Set a record…, a record's Remove, Dynamic DNS", docs=f"{_D}/changes/create", writes=True),
    Call(f"POST {_Z}", "makes a zone (it bills while it exists)", "managedZones",
         docs=f"{_D}/managedZones/create", writes=True, costs=True),
    Call(f"DELETE {_Z}/{{managedZone}}", "deletes a zone", "managedZones", docs=f"{_D}/managedZones/delete",
         writes=True),
    Call(f"PATCH {_Z}/{{managedZone}}", "changes a zone's settings", "managedZones",
         docs=f"{_D}/managedZones/patch", writes=True),
    Call(f"POST {_Z}/{{managedZone}}/rrsets", "makes a record set", "resourceRecordSets",
         docs=f"{_D}/resourceRecordSets/create", writes=True),
    Call(f"PATCH {_Z}/{{managedZone}}/rrsets/{{name}}/{{type}}", "changes a record set in place", "resourceRecordSets",
         docs=f"{_D}/resourceRecordSets/patch", writes=True),
    Call(f"DELETE {_Z}/{{managedZone}}/rrsets/{{name}}/{{type}}", "deletes a record set", "resourceRecordSets",
         docs=f"{_D}/resourceRecordSets/delete", writes=True),
    Call(f"GET {_Z}/{{managedZone}}/changes", "a zone's changes", "changes", docs=f"{_D}/changes/list"),
    Call("GET /dns/v1/projects/{project}", "the project's Cloud DNS quotas", "projects", docs=f"{_D}/projects/get"),
)
DNS = Api(
    name=DNS_NAME, maker="Google",
    about=("Cloud DNS's REST API: the project's managed zones, public (answered to the internet) or private (to its "
           "VPC networks), and their record sets, changed atomically; DNSSEC, forwarding, peering, server and response "
           "policies. Dynamic DNS here is a host's A record kept through it."),
    kind="rest", base="https://dns.googleapis.com/dns/v1", version="v1",
    auth="the service account's OAuth 2.0 access token (Bearer), scope ndev.clouddns.readwrite; its roles decide the rest",
    limits=("per-minute read and write quotas (the project's Quotas page); a change holds at most 1,000 additions, "
            "1,000 deletions and 100,000 bytes. The plugin reads its zones every quarter of an hour and each Dynamic "
            "DNS host every few minutes"),
    costs=("a managed zone bills for the part of a month it exists, and queries by the million (its pricing page); the "
           "pricing names no charge for a record change, so the plugin's changes add none"),
    links=(Link("Cloud DNS documentation", "https://docs.cloud.google.com/dns/docs", "docs"),
           Link("REST reference", "https://docs.cloud.google.com/dns/docs/reference/rest", "reference"),
           Link("Add, modify, and delete records", "https://docs.cloud.google.com/dns/docs/records", "guide"),
           Link("Access control", "https://docs.cloud.google.com/dns/docs/access-control", "auth"),
           Link("Quotas and limits", "https://docs.cloud.google.com/dns/quotas", "limits"),
           Link("Cloud DNS pricing", "https://cloud.google.com/dns/pricing", "pricing"),
           Link("Google Cloud Service Health", STATUS, "status"),
           Link("Release notes", "https://docs.cloud.google.com/dns/docs/release-notes", "changelog"),
           Link("Discovery document", "https://dns.googleapis.com/$discovery/rest?version=v1", "spec"),
           Link("Cloud DNS zones (console)", "https://console.cloud.google.com/net-services/dns/zones", "console"),
           Link("gcloud dns", "https://docs.cloud.google.com/sdk/gcloud/reference/dns", "tool")),
    areas=DNS_AREAS, calls=DNS_CALLS, verified=VERIFIED)

BILLING_AREAS = (
    Area("billingAccounts", "the billing accounts the caller may see: their names, whether open, their currency",
         f"{_B}/billingAccounts", "the project's account: its name and whether it is open (with Billing Account Viewer on it)"),
    Area("billingAccounts.projects", "the projects an account pays for", f"{_B}/billingAccounts.projects"),
    Area("billingAccounts.subAccounts", "a reseller's subaccounts", f"{_B}/billingAccounts.subAccounts"),
    Area("organizations.billingAccounts", "an organization's billing accounts", f"{_B}/organizations.billingAccounts"),
    Area("projects", "a project's billing: its account and whether billing is on; linking or unlinking an account",
         f"{_B}/projects", "the project's billing info: its account and whether billing is on"),
    Area("services", "the public catalog of Google Cloud's services", f"{_B}/services"),
    Area("services.skus", "each service's SKUs and their public prices", f"{_B}/services.skus"),
)
BILLING_CALLS = (
    Call("GET /v1/projects/{project}/billingInfo", "whether the project's billing is on, and its account", "projects",
         used="the billing fact", docs=f"{_B}/projects/getBillingInfo"),
    Call("GET /v1/billingAccounts/{account}", "a billing account: its name, open or not, its currency", "billingAccounts",
         used="the billing fact's account (read once an hour)", docs=f"{_B}/billingAccounts/get"),
    Call("PUT /v1/projects/{project}/billingInfo", "links, switches or unlinks a project's billing account", "projects",
         docs=f"{_B}/projects/updateBillingInfo", writes=True),
    Call("GET /v1/billingAccounts", "the billing accounts the caller may see", "billingAccounts",
         docs=f"{_B}/billingAccounts/list"),
    Call("GET /v1/services", "the public catalog's services", "services", docs=f"{_B}/services/list"),
    Call("GET /v1/services/{service}/skus", "a service's SKUs with their public prices", "services.skus",
         docs=f"{_B}/services.skus/list"),
)
BILLING = Api(
    name=BILLING_NAME, maker="Google",
    about=("Cloud Billing's REST API: the billing accounts, the projects they pay for and whether a project's billing "
           "is on, and the public catalog of services and their SKUs' prices. It holds no balance and no spend: "
           "those are the console's Billing pages (or a billing export)."),
    kind="rest", base="https://cloudbilling.googleapis.com/v1", version="v1",
    auth="the service account's OAuth 2.0 access token (Bearer), scope cloud-billing.readonly",
    limits=("300 calls a minute a project (975 an organization, by default). The plugin reads the project's billing "
            "every quarter of an hour"),
    costs="",
    links=(Link("Cloud Billing documentation", "https://docs.cloud.google.com/billing/docs", "docs"),
           Link("REST reference", "https://docs.cloud.google.com/billing/docs/reference/rest", "reference"),
           Link("Enable, disable, or change billing for a project",
                "https://docs.cloud.google.com/billing/docs/how-to/modify-project", "guide"),
           Link("Billing access control", "https://docs.cloud.google.com/billing/docs/how-to/billing-access", "auth"),
           Link("Quotas", "https://docs.cloud.google.com/billing/quotas", "limits"),
           Link("Google Cloud Service Health", STATUS, "status"),
           Link("Release notes", "https://docs.cloud.google.com/billing/docs/release-notes", "changelog"),
           Link("Discovery document", "https://cloudbilling.googleapis.com/$discovery/rest?version=v1", "spec"),
           Link("Billing (console)", "https://console.cloud.google.com/billing", "console")),
    areas=BILLING_AREAS, calls=BILLING_CALLS, verified=VERIFIED)

_O = "https://developers.google.com/identity/protocols/oauth2"
OAUTH = Api(
    name=OAUTH_NAME, maker="Google",
    about=("Google's OAuth 2.0 token endpoint, as a server to server application asks it: a service account proves "
           "itself with a JWT signed by its private key (RS256) and gets an access token for the scopes it asked, "
           "good for an hour, borne by every request to the APIs."),
    kind="rest", base="https://oauth2.googleapis.com/token", version="OAuth 2.0, the JWT bearer grant",
    auth="a JWT signed with the service account key's private key (RS256): iss, scope, aud, iat, exp (an hour at most)",
    limits="a token lasts an hour (expires_in); the plugin asks one an hour, a minute before the last ends",
    costs="",
    links=(Link("Using OAuth 2.0 for server to server applications", f"{_O}/service-account", "guide"),
           Link("Using OAuth 2.0 to access Google APIs", _O, "docs"),
           Link("OAuth 2.0 scopes for Google APIs", f"{_O}/scopes", "reference"),
           Link("Create and delete service account keys", "https://docs.cloud.google.com/iam/docs/keys-create-delete", "auth"),
           Link("Best practices for managing service account keys",
                "https://docs.cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys", "guide"),
           Link("Create and manage custom roles", "https://docs.cloud.google.com/iam/docs/creating-custom-roles", "guide"),
           Link("Service accounts (console)", "https://console.cloud.google.com/iam-admin/serviceaccounts", "console"),
           Link("Errors (AIP-193)", "https://google.aip.dev/193", "reference")),
    areas=(Area("The JWT bearer grant", "a service account's signed JWT exchanged at its key's token_uri for an access "
                "token", f"{_O}/service-account", "the access token, asked an hour at a time"),
           Area("Scopes", "what a token may be used for, space separated", f"{_O}/scopes",
                "compute, ndev.clouddns.readwrite, cloud-billing.readonly"),
           Area("Domain-wide delegation", "a service account acting as a Workspace user (the JWT's sub)",
                f"{_O}/service-account"),
           Area("Authorization without OAuth", "a self-signed JWT borne directly, for the APIs that take one",
                f"{_O}/service-account"),
           Area("Other flows", "web server, installed and limited-input applications' flows", _O)),
    calls=(Call("POST /token", "a signed JWT exchanged for an access token (grant_type jwt-bearer)",
                "The JWT bearer grant", used="every request's access token, an hour at a time",
                docs=f"{_O}/service-account"),),
    verified=VERIFIED)

APIS = (COMPUTE, DNS, BILLING, OAUTH)
