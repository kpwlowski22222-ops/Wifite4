import os
import requests
import json
from typing import Dict, List, Any, Optional
from datetime import datetime

class ShodanIntegration:
    """
    Shodan API integration for retrieving intelligence about IP addresses, domains, and network assets.
    """
    
    def __init__(self, api_key: Optional[str] = None, settings: Any = None):
        """
        Initialize the Shodan integration.

        Resolution order for the API key (env wins, like the NVD pattern):
            1. explicit ``api_key`` argument
            2. ``SHODAN_API_KEY`` environment variable
            3. ``shodan.api_key`` from the SettingsManager/config

        Args:
            api_key: Shodan API key. If None, falls back to env then settings.
            settings: a SettingsManager (or None) used to read shodan.api_key.
        """
        key = api_key or os.getenv('SHODAN_API_KEY', '')
        if not key and settings is not None:
            try:
                if hasattr(settings, "load_settings") and not getattr(settings, "settings", {}):
                    settings.load_settings()
            except Exception:
                pass
            try:
                key = settings.get_setting("shodan.api_key", "") or ""
            except Exception:
                key = ""
        self.api_key = key or ''
        base = 'https://api.shodan.io'
        if settings is not None:
            try:
                base = settings.get_setting("shodan.base_url", base) or base
            except Exception:
                pass
        self.base_url = base
        self.session = requests.Session()

    def initialize(self) -> None:
        """No-op adapter so callers that call .initialize() keep working."""
        # api_key is optional for catalog/search usage; missing key surfaces
        # as an API error on the actual request rather than at construction.
        return None

    def search_host(self, target: str) -> Dict[str, Any]:
        """Dispatcher: IP -> host_lookup, otherwise -> domain_lookup.

        Wraps exceptions into {"error": ...} so the caller never needs a
        try/except just to check for failure.
        """
        import re
        try:
            if re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', target):
                return self.host_lookup(target)
            return self.domain_lookup(target)
        except Exception as e:
            return {"error": str(e)}
    
    def _make_request(self, endpoint: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Make a request to the Shodan API.
        
        Args:
            endpoint: API endpoint to call
            params: Query parameters to include
            
        Returns:
            JSON response from the API
            
        Raises:
            Exception: If the API request fails
        """
        if params is None:
            params = {}
        
        params['key'] = self.api_key
        url = f"{self.base_url}{endpoint}"
        
        try:
            response = self.session.get(url, params=params)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            raise Exception(f"Shodan API request failed: {str(e)}")
    
    def host_lookup(self, ip_address: str) -> Dict[str, Any]:
        """
        Get information about a specific IP address.
        
        Args:
            ip_address: The IP address to look up
            
        Returns:
            Dictionary containing host information
        """
        endpoint = f"/shodan/host/{ip_address}"
        return self._make_request(endpoint)
    
    def domain_lookup(self, domain: str) -> Dict[str, Any]:
        """
        Get information about a domain.
        
        Args:
            domain: The domain to look up
            
        Returns:
            Dictionary containing domain information
        """
        endpoint = f"/dns/domain/{domain}"
        return self._make_request(endpoint)
    
    def search(self, query: str, limit: int = 100) -> Dict[str, Any]:
        """
        Search Shodan for devices matching a query.
        
        Args:
            query: Search query (using Shodan dorks syntax)
            limit: Maximum number of results to return
            
        Returns:
            Dictionary containing search results
        """
        endpoint = "/shodan/host/search"
        params = {
            'query': query,
            'limit': limit
        }
        return self._make_request(endpoint, params)
    
    def get_api_info(self) -> Dict[str, Any]:
        """
        Get information about the API key and plan limits.
        
        Returns:
            Dictionary containing API information
        """
        endpoint = "/api-info"
        return self._make_request(endpoint)
    
    def get_my_ip(self) -> Dict[str, Any]:
        """
        Get your own IP address as seen from the internet.
        
        Returns:
            Dictionary containing your IP information
        """
        endpoint = "/tools/myip"
        return self._make_request(endpoint)
    
    def scan_ip(self, ip_addresses: List[str]) -> Dict[str, Any]:
        """
        Submit IP addresses for scanning.
        
        Args:
            ip_addresses: List of IP addresses to scan
            
        Returns:
            Dictionary containing scan submission information
        """
        endpoint = "/shodan/scan"
        params = {
            'ips': ','.join(ip_addresses)
        }
        return self._make_request(endpoint, params)
    
    def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """
        Get the status of a submitted scan.
        
        Args:
            scan_id: The scan ID to check
            
        Returns:
            Dictionary containing scan status information
        """
        endpoint = f"/shodan/scan/{scan_id}"
        return self._make_request(endpoint)
    
    def format_host_info(self, host_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format host information into a more readable structure.
        
        Args:
            host_data: Raw host data from Shodan API
            
        Returns:
            Formatted host information
        """
        formatted = {
            'ip': host_data.get('ip_str', 'N/A'),
            'organization': host_data.get('org', 'N/A'),
            'operating_system': host_data.get('os', 'N/A'),
            'country': host_data.get('location', {}).get('country_name', 'N/A'),
            'city': host_data.get('location', {}).get('city', 'N/A'),
            'latitude': host_data.get('location', {}).get('latitude', 0),
            'longitude': host_data.get('location', {}).get('longitude', 0),
            'hostnames': host_data.get('hostnames', []),
            'domains': host_data.get('domains', []),
            'open_ports': host_data.get('ports', []),
            'vulnerabilities': list(host_data.get('vulns', {}).keys()),
            'last_update': host_data.get('last_update', 'N/A'),
            'tags': host_data.get('tags', []),
            'asn': host_data.get('asn', 'N/A'),
            'isp': host_data.get('isp', 'N/A')
        }
        
        # Format services/ports information
        services = []
        for item in host_data.get('data', []):
            service_info = {
                'port': item.get('port'),
                'protocol': item.get('transport', 'tcp'),
                'service': item.get('product', 'unknown'),
                'version': item.get('version', ''),
                'banner': item.get('data', '')[:200] + '...' if len(item.get('data', '')) > 200 else item.get('data', ''),
                'timestamp': item.get('timestamp')
            }
            services.append(service_info)
        
        formatted['services'] = services
        return formatted

# Convenience functions for easy usage
def lookup_ip(ip_address: str, api_key: Optional[str] = None) -> Dict[str, Any]:
    """
    Convenience function to look up an IP address.
    
    Args:
        ip_address: The IP address to look up
        api_key: Optional Shodan API key
        
    Returns:
        Formatted host information
    """
    shodan = ShodanIntegration(api_key)
    raw_data = shodan.host_lookup(ip_address)
    return shodan.format_host_info(raw_data)

def search_shodan(query: str, limit: int = 100, api_key: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Convenience function to search Shodan.
    
    Args:
        query: Search query
        limit: Maximum number of results
        api_key: Optional Shodan API key
        
    Returns:
        List of formatted host information
    """
    shodan = ShodanIntegration(api_key)
    results = shodan.search(query, limit)
    formatted_results = []
    
    for host in results.get('matches', []):
        formatted_results.append(shodan.format_host_info(host))
    
    return formatted_results

def get_shodan_api_info(api_key: Optional[str] = None) -> Dict[str, Any]:
    """
    Convenience function to get API information.
    
    Args:
        api_key: Optional Shodan API key
        
    Returns:
        API information dictionary
    """
    shodan = ShodanIntegration(api_key)
    return shodan.get_api_info()

# Example usage
if __name__ == "__main__":
    # Initialize Shodan integration
    shodan = ShodanIntegration()
    
    # Get API info
    print("Shodan API Information:")
    api_info = shodan.get_api_info()
    print(json.dumps(api_info, indent=2))
    
    # Example: Look up a public IP (Google's DNS)
    print("\nLooking up 8.8.8.8:")
    try:
        host_info = shodan.host_lookup("8.8.8.8")
        formatted_info = shodan.format_host_info(host_info)
        print(json.dumps(formatted_info, indent=2))
    except Exception as e:
        print(f"Error: {e}")