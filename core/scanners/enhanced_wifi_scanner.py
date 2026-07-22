#!/usr/bin/env python3
"""
Enhanced WiFi Scanner with CVE Lookup Integration
Extends the basic WiFi scanner with CVE vulnerability assessment capabilities
"""

import logging
import subprocess
import json
import time
import asyncio
from typing import Dict, Any, List, Optional
import threading
import os
from datetime import datetime

# Import the existing WiFi scanner
from .wifi_scanner import WiFiScanner as BaseWiFiScanner

# Import CVE lookup capabilities
from core.modules.cve_lookup import CVELookup

logger = logging.getLogger(__name__)

class EnhancedWiFiScanner(BaseWiFiScanner):
    """Enhanced WiFi scanner with CVE lookup integration"""
    
    def __init__(self, nvd_api_key: str = None):
        super().__init__()
        # NVD key: param > settings > env; never a hardcoded default key.
        # Single source of truth is core.ai_backend.get_nvd_key.
        from core.ai_backend import get_nvd_key
        self.nvd_api_key = nvd_api_key or get_nvd_key() or os.getenv("NVD_API_KEY", "")
        self.cve_lookup = None
        self.vulnerability_assessments = {}
        
        # Initialize CVE lookup with API key
        self._initialize_cve_lookup()
    
    def _initialize_cve_lookup(self):
        """Initialize the CVE lookup system with NVD API key"""
        try:
            # Create a minimal config dict for the CVE lookup
            config = {
                "nvd_api_key": self.nvd_api_key
            }
            self.cve_lookup = CVELookup(config)
            logger.info("Enhanced WiFi scanner initialized with CVE lookup capabilities")
        except Exception as e:
            logger.error(f"Failed to initialize CVE lookup: {e}")
            self.cve_lookup = None
    
    async def scan_with_cve_assessment(self, interface: str = None, timeout: int = 60) -> Dict[str, Any]:
        """
        Scan for WiFi networks and perform CVE vulnerability assessment
        
        Args:
            interface: Wireless interface to use (optional)
            timeout: Scan timeout in seconds
            
        Returns:
            Dictionary containing scan results and vulnerability assessments
        """
        # Perform basic WiFi scan
        scan_results = super().scan(interface, timeout)
        
        if "error" in scan_results:
            return scan_results
        
        # Perform CVE assessment on scan results
        if self.cve_lookup:
            try:
                logger.info("Performing CVE vulnerability assessment on scan results")
                vulnerability_assessment = await self._assess_vulnerabilities(scan_results)
                
                # Combine scan results with vulnerability assessment
                enhanced_results = {
                    **scan_results,
                    "vulnerability_assessment": vulnerability_assessment
                }
                
                # Store for history
                scan_id = scan_results.get("timestamp", f"scan_{int(time.time())}")
                self.vulnerability_assessments[scan_id] = vulnerability_assessment
                
                return enhanced_results
            except Exception as e:
                logger.error(f"Error during CVE assessment: {e}")
                # Return scan results without assessment if CVE lookup fails
                scan_results["vulnerability_assessment_error"] = str(e)
                return scan_results
        else:
            logger.warning("CVE lookup not available, returning scan results only")
            scan_results["vulnerability_assessment"] = {"error": "CVE lookup not initialized"}
            return scan_results
    
    async def _assess_vulnerabilities(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Assess vulnerabilities for discovered WiFi networks
        
        Args:
            scan_results: Results from WiFi scan
            
        Returns:
            Vulnerability assessment results
        """
        if not self.cve_lookup:
            return {"error": "CVE lookup not available"}
        
        # Extract keywords from scan results for CVE searching
        keywords = self._extract_keywords_from_scan(scan_results)
        
        # Search for CVEs related to discovered networks
        all_vulnerabilities = []
        search_results = {}
        
        # Search for each keyword
        for keyword in keywords[:10]:  # Limit to prevent too many requests
            try:
                logger.info(f"Searching for CVEs related to: {keyword}")
                cve_results = await self.cve_lookup.search_cves(keyword, limit=5)
                search_results[keyword] = cve_results
                
                vulnerabilities = cve_results.get("vulnerabilities", [])
                all_vulnerabilities.extend(vulnerabilities)
                
                # Rate limiting
                await asyncio.sleep(0.5)
            except Exception as e:
                logger.error(f"Error searching for CVEs for keyword '{keyword}': {e}")
                search_results[keyword] = {"error": str(e)}
        
        # Deduplicate vulnerabilities by CVE ID
        seen_cves = set()
        unique_vulnerabilities = []
        for vuln in all_vulnerabilities:
            cve_id = vuln.get("id")
            if cve_id and cve_id not in seen_cves:
                seen_cves.add(cve_id)
                unique_vulnerabilities.append(vuln)
        
        # Sort by CVSS score (descending)
        unique_vulnerabilities.sort(
            key=lambda x: x.get("cvssScore") or 0, 
            reverse=True
        )
        
        # Calculate risk statistics
        high_risk = len([v for v in unique_vulnerabilities if (v.get("cvssScore") or 0) >= 7.0])
        medium_risk = len([v for v in unique_vulnerabilities if 4.0 <= (v.get("cvssScore") or 0) < 7.0])
        low_risk = len([v for v in unique_vulnerabilities if (v.get("cvssScore") or 0) < 4.0])
        
        return {
            "assessment_timestamp": datetime.now().isoformat(),
            "keywords_searched": keywords,
            "search_results": search_results,
            "total_vulnerabilities_found": len(unique_vulnerabilities),
            "vulnerabilities": unique_vulnerabilities[:50],  # Top 50
            "risk_summary": {
                "high_risk_count": high_risk,
                "medium_risk_count": medium_risk,
                "low_risk_count": low_risk
            },
            "scan_correlation": self._correlate_vulnerabilities_to_networks(
                scan_results.get("networks", []), 
                unique_vulnerabilities
            )
        }
    
    def _extract_keywords_from_scan(self, scan_results: Dict[str, Any]) -> List[str]:
        """
        Extract relevant keywords from scan results for CVE searching
        
        Args:
            scan_results: Results from WiFi scan
            
        Returns:
            List of keywords to search for CVEs
        """
        keywords = set()
        
        networks = scan_results.get("networks", [])
        for network in networks:
            if isinstance(network, dict):
                # Extract SSID
                ssid = network.get("ssid", "").strip()
                if ssid and len(ssid) >= 2:
                    keywords.add(ssid)
                
                # Extract BSSID (without colons)
                bssid = network.get("bssid", "").strip()
                if bssid and len(bssid) >= 2:
                    keywords.add(bssid.replace(":", ""))
                
                # Extract vendor
                vendor = network.get("vendor", "").strip()
                if vendor and len(vendor) >= 2:
                    keywords.add(vendor)
                
                # Extract encryption type
                encryption = network.get("encryption", "").strip()
                if encryption and len(encryption) >= 2:
                    keywords.add(encryption)
        
        # Add some common WiFi vulnerability keywords
        wifi_keywords = [
            "wifi", "wireless", "wpa", "wpa2", "wpa3", 
            "wep", "tkip", "aes", "eap", "peap",
            "wps", "pixiedust", "dragonblood",
            "hostapd", "wpa_supplicant",
            "802.11", "802.1x", "radius"
        ]
        
        # Add WiFi keywords that aren't already covered
        for keyword in wifi_keywords:
            if any(wifi_keyword.lower() in keyword.lower() for wifi_keyword in keywords):
                keywords.add(keyword)
        
        return list(keywords)
    
    def _correlate_vulnerabilities_to_networks(self, networks: List[Dict], vulnerabilities: List[Dict]) -> Dict[str, List]:
        """
        Correlate discovered vulnerabilities to specific networks
        
        Args:
            networks: List of discovered network dictionaries
            vulnerabilities: List of vulnerability dictionaries
            
        Returns:
            Dictionary mapping network identifiers to relevant vulnerabilities
        """
        correlation = {}
        
        for i, network in enumerate(networks):
            if not isinstance(network, dict):
                continue
                
            network_id = f"network_{i}"
            network_identifiers = []
            
            # Collect network identifiers for matching
            ssid = network.get("ssid", "").strip()
            bssid = network.get("bssid", "").strip().replace(":", "")
            vendor = network.get("vendor", "").strip()
            
            if ssid:
                network_identifiers.append(ssid.lower())
            if bssid:
                network_identifiers.append(bssid.lower())
            if vendor:
                network_identifiers.append(vendor.lower())
            
            # Find relevant vulnerabilities
            relevant_vulns = []
            for vuln in vulnerabilities:
                vuln_desc = vuln.get("description", "").lower()
                vuln_id = vuln.get("id", "").lower()
                
                # Check if any network identifier appears in vulnerability description or ID
                if any(identifier in vuln_desc or identifier in vuln_id 
                       for identifier in network_identifiers if identifier):
                    relevant_vulns.append(vuln)
            
            if relevant_vulns:
                correlation[network_id] = {
                    "network_info": network,
                    "relevant_vulnerabilities": relevant_vulns,
                    "vulnerability_count": len(relevant_vulns)
                }
        
        return correlation
    
    def get_vulnerability_history(self) -> Dict[str, Any]:
        """Get history of vulnerability assessments"""
        return self.vulnerability_assessments
    
    def cleanup(self):
        """Cleanup resources"""
        super().cleanup()
        if self.cve_lookup:
            # Note: In a real implementation, we'd properly close the CVE lookup session
            pass


# Example usage function
async def demo_enhanced_wifi_scanner():
    """Demonstration of the enhanced WiFi scanner"""
    print("=== Enhanced WiFi Scanner with CVE Lookup Demo ===")
    
    # Initialize enhanced scanner (NVD key read from env/settings)
    scanner = EnhancedWiFiScanner()
    
    # Initialize scanner
    scanner.initialize()
    
    # Perform scan with CVE assessment
    print("\nPerforming WiFi scan with CVE vulnerability assessment...")
    results = await scanner.scan_with_cve_assessment(timeout=30)
    
    # Display results
    print(f"\nScan completed at: {results.get('timestamp')}")
    print(f"Networks found: {results.get('total_found', 0)}")
    
    if "vulnerability_assessment" in results:
        vuln_assessment = results["vulnerability_assessment"]
        print(f"\nVulnerability Assessment:")
        print(f"- Total vulnerabilities found: {vuln_assessment.get('total_vulnerabilities_found', 0)}")
        
        risk_summary = vuln_assessment.get("risk_summary", {})
        print(f"- High risk: {risk_summary.get('high_risk_count', 0)}")
        print(f"- Medium risk: {risk_summary.get('medium_risk_count', 0)}")
        print(f"- Low risk: {risk_summary.get('low_risk_count', 0)}")
        
        # Show top vulnerabilities
        vulnerabilities = vuln_assessment.get("vulnerabilities", [])[:5]
        if vulnerabilities:
            print(f"\nTop {len(vulnerabilities)} Vulnerabilities:")
            for i, vuln in enumerate(vulnerabilities, 1):
                print(f"{i}. {vuln.get('id', 'Unknown')}: {vuln.get('description', 'No description')[:100]}...")
                print(f"   CVSS Score: {vuln.get('cvssScore', 'N/A')}")
    
    # Cleanup
    scanner.cleanup()
    print("\nDemo completed.")

if __name__ == "__main__":
    # Run the demo
    asyncio.run(demo_enhanced_wifi_scanner())