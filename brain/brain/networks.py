"""network owner lists. matched as lowercase substrings of the asn org name."""

# cloud and hosting providers: attackers here are usually bots on rented boxes
CLOUD_ORGS = (
    "amazon",
    "aws",
    "google cloud",
    "google llc",
    "microsoft",
    "azure",
    "digitalocean",
    "ovh",
    "hetzner",
    "linode",
    "akamai",
    "vultr",
    "choopa",
    "contabo",
    "alibaba",
    "aliyun",
    "tencent",
    "huawei cloud",
    "oracle",
    "scaleway",
    "online s.a.s",
    "leaseweb",
    "m247",
    "hostinger",
    "ionos",
    "kamatera",
    "hostwinds",
    "colocrossing",
    "datacamp",
    "psychz",
    "frantech",
    "buyvm",
    "cloudflare",
)

# research scanners that announce themselves: lean harmless
SCANNER_ORGS = (
    "censys",
    "shodan",
    "shadowserver",
    "rapid7",
    "binaryedge",
    "onyphe",
    "palo alto networks",
    "expanse",
    "stretchoid",
    "driftnet",
    "internet measurement",
    "recyber",
    "criminal ip",
    "leakix",
    "netsystemsresearch",
    "alpha strike",
    "internettl",
    "hadrian",
    "academic",
)


def categorize(org: str | None) -> str | None:
    """return "scanner", "cloud" or None for an asn org name."""
    if not org:
        return None
    low = org.lower()
    if any(s in low for s in SCANNER_ORGS):
        return "scanner"
    if any(s in low for s in CLOUD_ORGS):
        return "cloud"
    return None
