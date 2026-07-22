#!/usr/bin/env python3
"""
KFIOSA OSINT Tool Catalog
===========================
Curated catalog of 100+ OSINT tools organized by category with
search, filtering, and lookup capabilities.
"""

import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class OSINTCatalog:
    """Curated catalog of OSINT tools organized by investigation domain."""

    def __init__(self):
        self.tools = self._build_catalog()

    # ------------------------------------------------------------------
    # Catalog data
    # ------------------------------------------------------------------

    def _build_catalog(self) -> Dict[str, List[dict]]:
        """Build the full OSINT tool catalog.

        Returns:
            Dict mapping category names to lists of tool descriptors.
        """
        return {
            "email": [
                {
                    "name": "holehe",
                    "repo": "megadose/holehe",
                    "description": "Check if email is used on 120+ sites",
                    "install": "pip install holehe",
                    "usage": "holehe EMAIL",
                },
                {
                    "name": "emailGuesser",
                    "repo": "WhiteHatInspector/emailGuesser",
                    "description": "Generate email permutations for a target",
                    "install": "git clone",
                    "usage": "python emailGuesser.py",
                },
                {
                    "name": "Email-Harvester",
                    "repo": "SagarBiswas-MultiHAT/Email-Harvester",
                    "description": "Harvest emails from domains",
                    "install": "git clone",
                    "usage": "python harvester.py",
                },
                {
                    "name": "map-email-scraper",
                    "repo": "MickeyUK/map-email-scraper",
                    "description": "Scrape emails from maps",
                    "install": "git clone",
                    "usage": "python scraper.py",
                },
                {
                    "name": "h8mail",
                    "repo": "khast3x/h8mail",
                    "description": "Email OSINT and breach hunting",
                    "install": "pip install h8mail",
                    "usage": "h8mail -t EMAIL",
                },
                {
                    "name": "infoga",
                    "repo": "m4ll0k/Infoga",
                    "description": "Email information gathering",
                    "install": "git clone",
                    "usage": "python infoga.py -t EMAIL",
                },
            ],
            "phone": [
                {
                    "name": "phoneinfoga",
                    "repo": "sundowndev/phoneinfoga",
                    "description": "Phone number OSINT — carrier, location, social",
                    "install": "go install / binary",
                    "usage": "phoneinfoga scan -n NUMBER",
                },
                {
                    "name": "ignorant",
                    "repo": "megadose/ignorant",
                    "description": "Check if phone is used on sites",
                    "install": "pip install ignorant",
                    "usage": "ignorant PHONE",
                },
            ],
            "username": [
                {
                    "name": "nexfil",
                    "repo": "thewhiteh4t/nexfil",
                    "description": "Find usernames across 350+ sites",
                    "install": "pip install nexfil",
                    "usage": "nexfil -u USERNAME",
                },
                {
                    "name": "Mr.Holmes",
                    "repo": "Lucksi/Mr.Holmes",
                    "description": "Multi-purpose OSINT tool",
                    "install": "git clone",
                    "usage": "python mr_holmes.py",
                },
                {
                    "name": "yesitsme",
                    "repo": "0x0be/yesitsme",
                    "description": "Username enumeration across platforms",
                    "install": "git clone",
                    "usage": "python yesitsme.py",
                },
                {
                    "name": "007-TheBond",
                    "repo": "Deadshot0x7/007-TheBond",
                    "description": "OSINT reconnaissance framework",
                    "install": "git clone",
                    "usage": "python thebond.py",
                },
                {
                    "name": "sherlock",
                    "repo": "sherlock-project/sherlock",
                    "description": "Hunt usernames across 400+ social networks",
                    "install": "pip install sherlock-project",
                    "usage": "sherlock USERNAME",
                },
                {
                    "name": "maigret",
                    "repo": "soxoj/maigret",
                    "description": "Username search across 2500+ sites",
                    "install": "pip install maigret",
                    "usage": "maigret USERNAME",
                },
                {
                    "name": "whatsmyname",
                    "repo": "WebBreacher/WhatsMyName",
                    "description": "Username enumeration on 600+ sites",
                    "install": "git clone",
                    "usage": "python whats_my_name.py -u USERNAME",
                },
            ],
            "social_media": [
                {
                    "name": "toutatis",
                    "repo": "megadose/toutatis",
                    "description": "Instagram OSINT — extract user info",
                    "install": "pip install toutatis",
                    "usage": "toutatis -u USERNAME -s SESSION_ID",
                },
                {
                    "name": "Masto",
                    "repo": "C3n7ral051nt4g3ncy/Masto",
                    "description": "Mastodon/Fediverse OSINT",
                    "install": "pip install masto",
                    "usage": "masto -u USERNAME",
                },
                {
                    "name": "saintgram",
                    "repo": "joe444-pnj/saintgram",
                    "description": "Instagram OSINT recon",
                    "install": "git clone",
                    "usage": "python saintgram.py",
                },
                {
                    "name": "facebook_totem",
                    "repo": "megadose/facebook_totem",
                    "description": "Facebook OSINT investigation",
                    "install": "pip install",
                    "usage": "facebook_totem TARGET",
                },
                {
                    "name": "social-monitor",
                    "repo": "777genius/social-monitor",
                    "description": "Social media monitoring & alerting",
                    "install": "git clone",
                    "usage": "python monitor.py",
                },
                {
                    "name": "Inspector",
                    "repo": "N0rz3/Inspector",
                    "description": "Social media investigation tool",
                    "install": "git clone",
                    "usage": "python inspector.py",
                },
                {
                    "name": "cupidcr4wl",
                    "repo": "OSINTI4L/cupidcr4wl",
                    "description": "Dating site OSINT scraper",
                    "install": "git clone",
                    "usage": "python cupidcr4wl.py",
                },
                {
                    "name": "twint",
                    "repo": "twintproject/twint",
                    "description": "Advanced Twitter/X scraping",
                    "install": "pip install twint",
                    "usage": "twint -u USERNAME",
                },
                {
                    "name": "Osintgram",
                    "repo": "Datalux/Osintgram",
                    "description": "Instagram OSINT multi-tool",
                    "install": "git clone",
                    "usage": "python main.py TARGET",
                },
            ],
            "telegram": [
                {
                    "name": "tgspyder",
                    "repo": "Darksight-Analytics/tgspyder",
                    "description": "Telegram OSINT and monitoring",
                    "install": "git clone",
                    "usage": "python tgspyder.py",
                },
                {
                    "name": "telepathy",
                    "repo": "jordanwildon/Telepathy",
                    "description": "Telegram group/channel OSINT",
                    "install": "pip install telepathy",
                    "usage": "telepathy -t CHANNEL",
                },
            ],
            "domain": [
                {
                    "name": "HydraRecon",
                    "repo": "aufzayed/HydraRecon",
                    "description": "Subdomain enumeration & reconnaissance",
                    "install": "git clone",
                    "usage": "python hydrarecon.py",
                },
                {
                    "name": "basilisk",
                    "repo": "spicesouls/basilisk",
                    "description": "Domain intelligence gathering",
                    "install": "git clone",
                    "usage": "python basilisk.py",
                },
                {
                    "name": "collector",
                    "repo": "galihap76/collector",
                    "description": "Multi-source information collector",
                    "install": "git clone",
                    "usage": "python collector.py",
                },
                {
                    "name": "enumerepo",
                    "repo": "trickest/enumerepo",
                    "description": "GitHub repository enumeration",
                    "install": "git clone",
                    "usage": "python enumerepo.py",
                },
                {
                    "name": "subfinder",
                    "repo": "projectdiscovery/subfinder",
                    "description": "Fast passive subdomain discovery",
                    "install": "go install",
                    "usage": "subfinder -d DOMAIN",
                },
                {
                    "name": "amass",
                    "repo": "owasp-amass/amass",
                    "description": "In-depth attack surface mapping",
                    "install": "go install / snap",
                    "usage": "amass enum -d DOMAIN",
                },
                {
                    "name": "theHarvester",
                    "repo": "laramies/theHarvester",
                    "description": "Emails, subdomains, IPs from public sources",
                    "install": "pip install theHarvester",
                    "usage": "theHarvester -d DOMAIN -b all",
                },
                {
                    "name": "dnsrecon",
                    "repo": "darkoperator/dnsrecon",
                    "description": "DNS enumeration and zone transfer",
                    "install": "pip install dnsrecon",
                    "usage": "dnsrecon -d DOMAIN",
                },
            ],
            "git": [
                {
                    "name": "GitSint",
                    "repo": "N0rz3/GitSint",
                    "description": "GitHub OSINT — user profiling",
                    "install": "git clone",
                    "usage": "python gitsint.py",
                },
                {
                    "name": "gitrob",
                    "repo": "michenriksen/gitrob",
                    "description": "Find sensitive data in GitHub repos",
                    "install": "go install",
                    "usage": "gitrob TARGET",
                },
                {
                    "name": "trufflehog",
                    "repo": "trufflesecurity/trufflehog",
                    "description": "Find leaked credentials in Git repos",
                    "install": "pip install trufflehog",
                    "usage": "trufflehog git REPO_URL",
                },
            ],
            "geospatial": [
                {
                    "name": "geospatial-intelligence-library",
                    "repo": "neonpangolin/geospatial-intelligence-library",
                    "description": "GEOINT resources and methodology",
                    "install": "reference",
                    "usage": "reference library",
                },
                {
                    "name": "GeoSpy",
                    "repo": "atiilla/geospy",
                    "description": "Image geolocation tool",
                    "install": "git clone",
                    "usage": "python geospy.py IMAGE",
                },
            ],
            "breach": [
                {
                    "name": "H.I.V.E",
                    "repo": "Shad0w-ops/H.I.V.E",
                    "description": "Breach data analysis framework",
                    "install": "git clone",
                    "usage": "python hive.py",
                },
                {
                    "name": "bitcrook",
                    "repo": "ax-i-om/bitcrook",
                    "description": "Crypto/breach OSINT toolkit",
                    "install": "go install",
                    "usage": "bitcrook TARGET",
                },
                {
                    "name": "pwndb",
                    "repo": "davidtavarez/pwndb",
                    "description": "Search leaked credentials via PwnDB",
                    "install": "git clone",
                    "usage": "python pwndb.py --target EMAIL",
                },
            ],
            "comprehensive": [
                {
                    "name": "OSINT-Tools",
                    "repo": "yogsec/OSINT-Tools",
                    "description": "Comprehensive OSINT toolkit",
                    "install": "git clone",
                    "usage": "various",
                },
                {
                    "name": "awesome-osint",
                    "repo": "brandonhimpfen/awesome-osint",
                    "description": "Curated OSINT resource list",
                    "install": "reference",
                    "usage": "reference",
                },
                {
                    "name": "OSINT-BIBLE",
                    "repo": "frangelbarrera/OSINT-BIBLE",
                    "description": "OSINT Bible — comprehensive reference",
                    "install": "reference",
                    "usage": "reference",
                },
                {
                    "name": "osint.gitbook.io",
                    "repo": "OhShINT/ohshint.gitbook.io",
                    "description": "OSINT resources and guides",
                    "install": "reference",
                    "usage": "reference",
                },
                {
                    "name": "osint-resources",
                    "repo": "BrewedIntel/osint-resources",
                    "description": "OSINT resource collection",
                    "install": "reference",
                    "usage": "reference",
                },
                {
                    "name": "Open-Source-INTelligence",
                    "repo": "txuswashere/Open-Source-INTelligence",
                    "description": "OSINT methodology and resources",
                    "install": "reference",
                    "usage": "reference",
                },
                {
                    "name": "osint-d2",
                    "repo": "Doble-2/osint-d2",
                    "description": "OSINT toolkit",
                    "install": "git clone",
                    "usage": "python osint_d2.py",
                },
                {
                    "name": "recon-ng",
                    "repo": "lanmaster53/recon-ng",
                    "description": "Full-featured recon framework",
                    "install": "pip install recon-ng",
                    "usage": "recon-ng",
                },
                {
                    "name": "SpiderFoot",
                    "repo": "smicallef/spiderfoot",
                    "description": "Automated OSINT with 200+ modules",
                    "install": "pip install spiderfoot",
                    "usage": "spiderfoot -s TARGET",
                },
            ],
            "network": [
                {
                    "name": "huntsman",
                    "repo": "mlcsec/huntsman",
                    "description": "Network reconnaissance tool",
                    "install": "git clone",
                    "usage": "python huntsman.py",
                },
                {
                    "name": "Hunt",
                    "repo": "SwordPuffin/Hunt",
                    "description": "Network hunting tool",
                    "install": "git clone",
                    "usage": "python hunt.py",
                },
                {
                    "name": "TIGMINT",
                    "repo": "TIGMINT/TIGMINT",
                    "description": "Threat intelligence gateway",
                    "install": "git clone",
                    "usage": "python tigmint.py",
                },
                {
                    "name": "IRONSIGHT",
                    "repo": "NoblerWorks-HQ/IRONSIGHT",
                    "description": "Network intelligence platform",
                    "install": "git clone",
                    "usage": "python ironsight.py",
                },
                {
                    "name": "Kunai",
                    "repo": "t0mxplo1t/Kunai",
                    "description": "Network reconnaissance tool",
                    "install": "git clone",
                    "usage": "python kunai.py",
                },
                {
                    "name": "EntraHunt",
                    "repo": "anak0ndah/EntraHunt",
                    "description": "Azure/Entra ID hunting",
                    "install": "git clone",
                    "usage": "python entrahunt.py",
                },
                {
                    "name": "Shodan-CLI",
                    "repo": "achillean/shodan-python",
                    "description": "Shodan command-line interface",
                    "install": "pip install shodan",
                    "usage": "shodan search QUERY",
                },
                {
                    "name": "censys-python",
                    "repo": "censys/censys-python",
                    "description": "Censys search API client",
                    "install": "pip install censys",
                    "usage": "censys search QUERY",
                },
            ],
            "maltego": [
                {
                    "name": "holehe-maltego",
                    "repo": "megadose/holehe-maltego",
                    "description": "Holehe Maltego transforms",
                    "install": "pip install",
                    "usage": "Maltego integration",
                },
                {
                    "name": "phoneinfoga-maltego",
                    "repo": "megadose/phoneinfoga-maltego",
                    "description": "PhoneInfoga Maltego transforms",
                    "install": "pip install",
                    "usage": "Maltego integration",
                },
                {
                    "name": "hunter-maltego",
                    "repo": "megadose/hunter-maltego",
                    "description": "Hunter.io Maltego transforms",
                    "install": "pip install",
                    "usage": "Maltego integration",
                },
                {
                    "name": "totem-maltego",
                    "repo": "megadose/totem-maltego",
                    "description": "Totem Maltego transforms",
                    "install": "pip install",
                    "usage": "Maltego integration",
                },
            ],
            "image": [
                {
                    "name": "ExifTool",
                    "repo": "exiftool/exiftool",
                    "description": "Read/write EXIF metadata",
                    "install": "apt install exiftool",
                    "usage": "exiftool IMAGE",
                },
                {
                    "name": "Stegsolve",
                    "repo": "Giotino/stegsolve",
                    "description": "Steganography analysis",
                    "install": "java -jar",
                    "usage": "java -jar stegsolve.jar",
                },
            ],
            "face": [
                {
                    "name": "search4faces",
                    "repo": "search4faces/search4faces",
                    "description": "Facial recognition search",
                    "install": "web",
                    "usage": "search4faces.com",
                },
                {
                    "name": "pimeyes",
                    "repo": "pimeyes",
                    "description": "Reverse face search engine",
                    "install": "web",
                    "usage": "pimeyes.com",
                },
            ],
            "crypto": [
                {
                    "name": "Breadcrumbs",
                    "repo": "nicedayforawalrus/breadcrumbs",
                    "description": "Blockchain investigation tool",
                    "install": "git clone",
                    "usage": "python breadcrumbs.py ADDRESS",
                },
                {
                    "name": "blockchair",
                    "repo": "Blockchair",
                    "description": "Blockchain explorer and analytics",
                    "install": "web / API",
                    "usage": "blockchair.com",
                },
            ],
        }

    # ------------------------------------------------------------------
    # Query methods
    # ------------------------------------------------------------------

    def get_tools_by_category(self, category: str) -> List[dict]:
        """Get all tools in a specific category.

        Args:
            category: Category name (e.g. 'email', 'phone', 'username').

        Returns:
            List of tool dicts, or empty list if category not found.
        """
        return self.tools.get(category, [])

    def get_all_tools(self) -> List[dict]:
        """Get a flat list of all tools across all categories.

        Returns:
            List of tool dicts with an added 'category' key.
        """
        result = []
        for category, tools in self.tools.items():
            for tool in tools:
                entry = dict(tool)
                entry["category"] = category
                result.append(entry)
        return result

    def search_tools(self, query: str) -> List[dict]:
        """Search tools by name, description, or repo.

        Args:
            query: Search string (case-insensitive).

        Returns:
            List of matching tool dicts with added 'category' key.
        """
        query_lower = query.lower()
        results = []
        for category, tools in self.tools.items():
            for tool in tools:
                searchable = " ".join([
                    tool["name"],
                    tool.get("description", ""),
                    tool.get("repo", ""),
                ]).lower()
                if query_lower in searchable:
                    entry = dict(tool)
                    entry["category"] = category
                    results.append(entry)
        return results

    def tool_count(self) -> int:
        """Return total number of tools in the catalog.

        Returns:
            Integer count of all cataloged tools.
        """
        return sum(len(tools) for tools in self.tools.values())

    def get_tool_by_name(self, name: str) -> Optional[dict]:
        """Look up a tool by exact or fuzzy name match.

        Args:
            name: Tool name (case-insensitive).

        Returns:
            Tool dict with 'category' key, or None if not found.
        """
        name_lower = name.lower()
        for category, tools in self.tools.items():
            for tool in tools:
                if tool["name"].lower() == name_lower:
                    entry = dict(tool)
                    entry["category"] = category
                    return entry
        # Fuzzy fallback: partial match
        for category, tools in self.tools.items():
            for tool in tools:
                if name_lower in tool["name"].lower():
                    entry = dict(tool)
                    entry["category"] = category
                    return entry
        return None

    def get_categories(self) -> List[str]:
        """Return all available categories.

        Returns:
            Sorted list of category names.
        """
        return sorted(self.tools.keys())

    def get_install_guide(self, tool_name: str) -> Optional[str]:
        """Get installation instructions for a tool.

        Args:
            tool_name: Name of the tool.

        Returns:
            Installation string, or None if tool not found.
        """
        tool = self.get_tool_by_name(tool_name)
        if tool:
            repo_url = f"https://github.com/{tool['repo']}"
            install = tool.get("install", "git clone")
            if install == "git clone":
                return f"git clone {repo_url} && cd {tool['name']}"
            elif install.startswith("pip"):
                return install
            elif install == "reference":
                return f"Reference resource — visit {repo_url}"
            else:
                return f"{install}  |  Repo: {repo_url}"
        return None

    def summary(self) -> dict:
        """Return a summary of the catalog.

        Returns:
            Dict with total_tools, categories, and per-category counts.
        """
        return {
            "total_tools": self.tool_count(),
            "categories": {
                cat: len(tools) for cat, tools in sorted(self.tools.items())
            },
        }


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    catalog = OSINTCatalog()
    summary = catalog.summary()
    print(f"OSINT Catalog: {summary['total_tools']} tools in {len(summary['categories'])} categories")
    for cat, count in sorted(summary["categories"].items()):
        print(f"  {cat}: {count} tools")
