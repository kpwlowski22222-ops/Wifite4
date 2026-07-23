"""
CVE Lookup Module
Integrates with CVE databases for vulnerability identification and exploitation
"""

import asyncio
import aiohttp
import json
import logging
from typing import Dict, List, Optional, Any
from pathlib import Path
import time

logger = logging.getLogger(__name__)

class CVELookup:
    """CVE lookup and vulnerability assessment integration"""
    
    def __init__(self, config):
        self.config = config
        self.cve_api_urls = [
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "https://cve.circl.lu/api",
            "https://vulners.com/api/v3"
        ]
        self.session = None
        self.cache = {}
        self.cache_timeout = 3600  # 1 hour cache
        
    async def _get_session(self):
        """Get or create aiohttp session with hard timeouts.

        Unbounded HTTP hangs made adaptive engagement (and post-scan AIO)
        freeze for minutes when NVD was slow/unreachable.
        """
        if self.session is None or self.session.closed:
            timeout = aiohttp.ClientTimeout(total=12, connect=4, sock_read=8)
            self.session = aiohttp.ClientSession(timeout=timeout)
        return self.session
    
    async def close(self):
        """Close the aiohttp session"""
        if self.session and not self.session.closed:
            await self.session.close()
    
    async def search_cves(self, keyword: str, limit: int = 10) -> Dict[str, Any]:
        """Search for CVEs related to a keyword"""
        logger.info(f"Searching for CVEs related to: {keyword}")
        
        # Check cache first
        cache_key = f"cve_search:{keyword}:{limit}"
        if cache_key in self.cache:
            cached_data, timestamp = self.cache[cache_key]
            if time.time() - timestamp < self.cache_timeout:
                logger.debug(f"Returning cached CVE results for {keyword}")
                return cached_data
        
        session = await self._get_session()
        
        # Try different CVE APIs
        for api_url in self.cve_api_urls:
            try:
                if "nvd.nist.gov" in api_url:
                    params = {
                        "keywordSearch": keyword,
                        "resultsPerPage": limit
                    }
                    # Never send an empty apiKey header — NVD rejects it
                    # (operators often see 404/403 in the activity log).
                    headers = {}
                    nvd_key = (self.config.get("nvd_api_key") or "").strip()
                    if nvd_key:
                        headers["apiKey"] = nvd_key
                elif "cve.circl.lu" in api_url:
                    # Legacy ``?search=`` HTML landing is dead; use browse
                    # search path when keyword looks like vendor/product.
                    # Skip generic WiFi keywords — they only return HTML.
                    kw = (keyword or "").strip()
                    if not kw or " " in kw or len(kw) < 3:
                        continue
                    api_url = f"https://cve.circl.lu/api/search/{kw}"
                    params = {}
                    headers = {"Accept": "application/json"}
                elif "vulners.com" in api_url:
                    # Requires auth; skip unless a key is configured.
                    vkey = (self.config.get("vulners_api_key") or "").strip()
                    if not vkey:
                        continue
                    params = {
                        "query": keyword,
                        "size": limit
                    }
                    headers = {"X-Api-Key": vkey}
                else:
                    continue
                
                async with session.get(api_url, params=params, headers=headers) as response:
                    if response.status == 200:
                        # Circl sometimes returns HTML with 200 — require JSON.
                        ctype = (response.headers.get("Content-Type") or "").lower()
                        if "json" not in ctype and "javascript" not in ctype:
                            logger.debug(
                                "CVE API %s returned non-JSON content-type %s",
                                api_url, ctype,
                            )
                            continue
                        data = await response.json(content_type=None)
                        
                        # Process and normalize the data
                        processed_data = self._process_cve_data(data, api_url)
                        
                        # Cache the result
                        self.cache[cache_key] = (processed_data, time.time())
                        
                        logger.info(f"Found {len(processed_data.get('vulnerabilities', []))} CVEs for {keyword}")
                        return processed_data
                    else:
                        logger.debug(
                            "CVE API %s returned status %s (will try next / offline)",
                            api_url, response.status,
                        )
                        
            except Exception as e:
                logger.debug(f"Error querying CVE API {api_url}: {e}")
                continue
        
        # Offline knowledge: only real, well-known public CVEs. Never
        # invent CVE-IDs. If keyword does not match, return empty + error.
        logger.info(
            "CVE live APIs unavailable for %r — using offline knowledge base",
            keyword,
        )

        offline_db = {
            "wpa2": [
                {
                    "id": "CVE-2017-13077",
                    "description": "KRACK: WPA2 4-way handshake key reinstallation.",
                    "published": "2017-10-16",
                    "cvssScore": 8.1,
                    "cvssVector": "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    "references": [{"url": "https://krackattacks.com"}],
                    "source": "OfflineKnowledge",
                },
                {
                    "id": "CVE-2020-24588",
                    "description": "FragAttacks: 802.11 frame aggregation design flaw.",
                    "published": "2021-05-11",
                    "cvssScore": 6.5,
                    "cvssVector": "CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
                    "references": [{"url": "https://www.fragattacks.com"}],
                    "source": "OfflineKnowledge",
                },
            ],
            "wpa3": [
                {
                    "id": "CVE-2019-9494",
                    "description": "Dragonblood SAE side-channel / timing issues (WPA3).",
                    "published": "2019-04-10",
                    "cvssScore": 5.9,
                    "cvssVector": "CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "references": [{"url": "https://wpa3.mathyvanhoef.com/"}],
                    "source": "OfflineKnowledge",
                },
            ],
            "wps": [
                {
                    "id": "CVE-2011-5053",
                    "description": "WPS PIN brute-force design weakness (offline/online PIN).",
                    "published": "2011-12-29",
                    "cvssScore": 5.8,
                    "cvssVector": "AV:A/AC:L/Au:N/C:P/I:P/A:P",
                    "references": [],
                    "source": "OfflineKnowledge",
                },
            ],
            "802.11": [
                {
                    "id": "CVE-2019-15126",
                    "description": "KR00K: Broadcom/Cypress Wi-Fi chipset WPA2 decryption issue.",
                    "published": "2020-02-26",
                    "cvssScore": 3.1,
                    "cvssVector": "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    "references": [],
                    "source": "OfflineKnowledge",
                },
            ],
            "krack": [
                {
                    "id": "CVE-2017-13077",
                    "description": "KRACK: WPA2 4-way handshake key reinstallation.",
                    "published": "2017-10-16",
                    "cvssScore": 8.1,
                    "cvssVector": "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    "references": [{"url": "https://krackattacks.com"}],
                    "source": "OfflineKnowledge",
                },
            ],
        }

        fallback_vulns = []
        kw_lower = (keyword or "").lower()
        for key, vulns in offline_db.items():
            if key in kw_lower or any(part in kw_lower for part in key.split(".") if part):
                fallback_vulns.extend(vulns)

        # Deduplicate by CVE id
        seen = set()
        unique = []
        for v in fallback_vulns:
            vid = v.get("id")
            if vid and vid not in seen:
                seen.add(vid)
                unique.append(v)

        if not unique:
            processed_data = {
                "vulnerabilities": [],
                "totalResults": 0,
                "source": "none",
                "error": (
                    f"all online CVE APIs failed and no offline knowledge "
                    f"match for keyword {keyword!r}"
                ),
            }
        else:
            processed_data = {
                "vulnerabilities": unique[:limit],
                "totalResults": len(unique),
                "source": "OfflineKnowledge",
                "note": "online APIs unreachable; curated public CVEs only",
            }

        self.cache[cache_key] = (processed_data, time.time())
        return processed_data
    
    def _process_cve_data(self, data: Dict[str, Any], source: str) -> Dict[str, Any]:
        """Process and normalize CVE data from different sources"""
        vulnerabilities = []
        
        if "nvd.nist.gov" in source:
            # NVD format
            for item in data.get("vulnerabilities", []):
                cve_item = item.get("cve", {})
                vuln = {
                    "id": cve_item.get("id"),
                    "description": "",
                    "published": cve_item.get("published"),
                    "lastModified": cve_item.get("lastModified"),
                    "cvssScore": None,
                    "cvssVector": "",
                    "references": [],
                    "source": "NVD"
                }
                
                # Extract description
                for desc in cve_item.get("descriptions", []):
                    if desc.get("lang") == "en":
                        vuln["description"] = desc.get("value")
                        break
                
                # Extract CVSS score
                metrics = cve_item.get("metrics", {})
                for metric_type in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if metric_type in metrics and metrics[metric_type]:
                        metric = metrics[metric_type][0]
                        cvss_data = metric.get("cvssData", {})
                        vuln["cvssScore"] = cvss_data.get("baseScore")
                        vuln["cvssVector"] = cvss_data.get("vectorString")
                        break
                
                # Extract references
                for ref in cve_item.get("references", []):
                    vuln["references"].append({
                        "url": ref.get("url"),
                        "source": ref.get("source"),
                        "tags": ref.get("tags", [])
                    })
                
                vulnerabilities.append(vuln)
        
        elif "cve.circl.lu" in source:
            # CIRCL format
            for item in data.get("results", []):
                vuln = {
                    "id": item.get("id"),
                    "description": item.get("summary"),
                    "published": item.get("Published"),
                    "lastModified": item.get("Modified"),
                    "cvssScore": item.get("cvss"),
                    "cvssVector": item.get("cvss-vector"),
                    "references": [],
                    "source": "CIRCL"
                }
                
                # Extract references
                for ref in item.get("references", []):
                    vuln["references"].append({
                        "url": ref,
                        "source": "CIRCL",
                        "tags": []
                    })
                
                vulnerabilities.append(vuln)
        
        elif "vulners.com" in source:
            # Vulners format
            for item in data.get("data", {}).get("search", []):
                source_data = item.get("_source", {})
                vuln = {
                    "id": source_data.get("id"),
                    "description": source_data.get("description"),
                    "published": source_data.get("published"),
                    "lastModified": source_data.get("modified"),
                    "cvssScore": source_data.get("cvss", {}).get("score"),
                    "cvssVector": source_data.get("cvss", {}).get("vector"),
                    "references": [],
                    "source": "Vulners"
                }
                
                # Extract references
                for ref in source_data.get("references", []):
                    vuln["references"].append({
                        "url": ref.get("href"),
                        "source": ref.get("id"),
                        "tags": []
                    })
                
                vulnerabilities.append(vuln)
        
        return {
            "vulnerabilities": vulnerabilities,
            "totalResults": len(vulnerabilities),
            "source": source
        }
    
    async def assess_vulnerabilities(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Assess vulnerabilities based on scan results"""
        logger.info("Assessing vulnerabilities from scan results")
        
        # Extract relevant information from scan results
        keywords_to_search = []
        
        # Extract from WiFi scan results
        if "results" in scan_results:
            # Look for device information, vendors, etc.
            # Extract BSSIDs, ESSIDs, and other relevant info for keyword generation
            for result in scan_results.get("results", []):
                if isinstance(result, dict):
                    # Extract ESSID if available
                    if "essid" in result and result["essid"]:
                        essid = result["essid"].strip()
                        if essid and len(essid) > 2:
                            keywords_to_search.append(essid)
                    
                    # Extract BSSID if available
                    if "bssid" in result and result["bssid"]:
                        bssid = result["bssid"].strip()
                        if bssid and len(bssid) > 2:
                            keywords_to_search.append(bssid.replace(":", ""))
                    
                    # Extract vendor information if available
                    if "vendor" in result and result["vendor"]:
                        vendor = result["vendor"].strip()
                        if vendor and len(vendor) > 2:
                            keywords_to_search.append(vendor)
        
        # For demo, we'll search for common wireless vulnerabilities
        wifi_keywords = [
            "wifi", "wireless", "wpa", "wpa2", "wpa3", 
            "wep", "tkip", "aes", "eap", "peap",
            "wps", "pixiedust", "dragonblood",
            "hostapd", "wpa_supplicant",
            "802.11", "802.1x", "radius"
        ]
        
        all_vulnerabilities = []
        
        for keyword in wifi_keywords[:5]:  # Limit to avoid too many requests
            cve_results = await self.search_cves(keyword, limit=5)
            vulnerabilities = cve_results.get("vulnerabilities", [])
            all_vulnerabilities.extend(vulnerabilities)
            
            # Rate limiting
            await asyncio.sleep(1)
        
        # Sort by CVSS score (descending)
        all_vulnerabilities.sort(
            key=lambda x: x.get("cvssScore") or 0, 
            reverse=True
        )
        
        return {
            "assessment_timestamp": time.time(),
            "keywords_searched": wifi_keywords[:5],
            "total_vulnerabilities_found": len(all_vulnerabilities),
            "vulnerabilities": all_vulnerabilities[:20],  # Top 20
            "high_risk_count": len([v for v in all_vulnerabilities if (v.get("cvssScore") or 0) >= 7.0]),
            "medium_risk_count": len([v for v in all_vulnerabilities if 4.0 <= (v.get("cvssScore") or 0) < 7.0]),
            "low_risk_count": len([v for v in all_vulnerabilities if (v.get("cvssScore") or 0) < 4.0])
        }
    
    async def get_exploit_recommendations(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Get exploit recommendations for a specific CVE"""
        logger.info(f"Getting exploit recommendations for {vulnerability.get('id')}")
        
        cve_id = vulnerability.get("id")
        if not cve_id:
            return {"error": "No CVE ID provided"}
        
        # Search for exploit information
        exploit_keywords = [cve_id, "exploit", "poc", "proof of concept"]
        keyword = " ".join(exploit_keywords)
        
        # Search for exploit databases
        exploit_results = await self.search_cves(keyword, limit=10)
        
        # Also check for Metasploit modules
        msf_search = await self.search_cves(f"{cve_id} metasploit", limit=5)
        
        return {
            "cve_id": cve_id,
            "exploit_search_results": exploit_results,
            "metasploit_modules": msf_search,
            "recommendation": self._generate_exploit_recommendation(vulnerability, exploit_results)
        }
    
    def _generate_exploit_recommendation(self, vulnerability: Dict[str, Any], 
                                       exploit_results: Dict[str, Any]) -> str:
        """Generate exploit recommendation based on CVE and exploit results"""
        cvss_score = vulnerability.get("cvssScore") or 0
        
        if cvss_score >= 9.0:
            severity = "CRITICAL"
        elif cvss_score >= 7.0:
            severity = "HIGH"
        elif cvss_score >= 4.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"
        
        recommendation = f"CVE {vulnerability.get('id')} has a {severity} severity (CVSS: {cvss_score}). "
        
        if exploit_results.get("vulnerabilities"):
            recommendation += "Public exploits may be available. "
        else:
            recommendation += "No public exploits found in searched databases. "
        
        recommendation += f"Description: {vulnerability.get('description', 'No description available')[:200]}..."
        
        return recommendation
    
    async def run_demo(self) -> Dict[str, Any]:
        """Run a demonstration of CVE lookup functionality"""
        logger.info("Running CVE lookup demo")
        
        # Search for some common WiFi-related CVEs
        demo_results = {}
        
        # Search for WPA2 vulnerabilities
        demo_results["wpa2_search"] = await self.search_cves("WPA2 vulnerability", limit=5)
        
        # Search for WPS vulnerabilities
        demo_results["wps_search"] = await self.search_cves("WPS vulnerability", limit=5)
        
        # Search for general wireless vulnerabilities
        demo_results["wireless_search"] = await self.search_cves("802.11 security", limit=5)
        
        return demo_results
