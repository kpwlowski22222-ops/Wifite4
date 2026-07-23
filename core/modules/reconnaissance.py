import asyncio
import logging
import subprocess
import re
from typing import List, Dict, Any
from core.modules.debug_logger import (
    debug, info, warning, error, debug_dict, time_it, debug_exception,
)

class ReconnaissanceModule:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.interface = None
        self.scan_results = []
        info("Reconnaissance Module initialized")
        
    @time_it
    async def initialize(self):
        info("Initializing reconnaissance module...")
        try:
            # Check if we have wireless interfaces available
            await self._check_wireless_interfaces()
            info("Reconnaissance module initialized successfully")
        except Exception as e:
            error(f"Failed to initialize reconnaissance module: {e}")
            debug_exception("Reconnaissance initialization")
            raise
            
    @time_it
    async def _check_wireless_interfaces(self):
        """Check for available wireless interfaces"""
        try:
            result = subprocess.run(['iwconfig'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                # Parse wireless interfaces
                interfaces = re.findall(r'^(\w+).*IEEE 802\.11', result.stdout, re.MULTILINE)
                if interfaces:
                    info(f"Found wireless interfaces: {interfaces}")
                    debug_dict("Wireless Interfaces", {"interfaces": interfaces})
                else:
                    warning("No wireless interfaces found via iwconfig")
            else:
                warning("iwconfig command failed")
        except subprocess.TimeoutExpired:
            warning("Timeout checking wireless interfaces")
        except Exception as e:
            debug(f"Error checking wireless interfaces: {e}")
            
    @time_it
    async def scan(self, interface: str) -> List[Dict[str, Any]]:
        info(f"Starting network scan on interface {interface}")
        self.interface = interface
        
        try:
            # Use airodump-ng for scanning
            scan_result = await self._run_airodump_scan(interface)
            self.scan_results = scan_result
            
            info(f"Network scan completed: {len(scan_result)} networks discovered")
            debug_dict("Scan Results", {
                "interface": interface,
                "networks_count": len(scan_result),
                "networks": scan_result[:10]  # First 10 for debugging
            })
            
            return scan_result
            
        except Exception as e:
            error(f"Network scan failed on interface {interface}: {e}")
            debug_exception("Network scan")
            return []
            
    @time_it
    async def _run_airodump_scan(self, interface: str) -> List[Dict[str, Any]]:
        """Run airodump-ng scan and parse results"""
        networks = []
        
        try:
            # Start airodump-ng in background for a short period
            cmd = [
                'airodump-ng',
                '--output-format', 'csv',
                '--write', '/tmp/wifi_scan',
                interface
            ]
            
            info(f"Starting airodump-ng scan: {' '.join(cmd)}")
            
            # Start the process
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Let it run for 10 seconds
            try:
                await asyncio.wait_for(process.wait(), timeout=10.0)
            except asyncio.TimeoutError:
                # Timeout is expected - kill the process
                process.kill()
                await process.wait()
                
            # Parse the CSV output
            networks = self._parse_airodump_csv('/tmp/wifi_scan-01.csv')
            
            info(f"Airodump-ng scan completed: {len(networks)} networks found")
            
        except FileNotFoundError:
            warning("airodump-ng not found — cannot scan (install aircrack-ng)")
            return []
        except Exception as e:
            error(f"Error running airodump-ng scan: {e}")
            debug_exception("Airodump-ng scan")
            return []
            
        return networks
        
    def _parse_airodump_csv(self, filename: str) -> List[Dict[str, Any]]:
        """Parse airodump-ng CSV output"""
        networks = []
        
        try:
            with open(filename, 'r') as f:
                lines = f.readlines()
                
            # Find the network data section
            network_start = -1
            for i, line in enumerate(lines):
                if line.strip() == 'BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key':
                    network_start = i + 1
                    break
                    
            if network_start == -1:
                warning("Could not find network data in airodump-ng output")
                return networks
                
            # Parse network lines
            for line in lines[network_start:]:
                line = line.strip()
                if not line or line.startswith('Station MAC'):
                    break
                    
                parts = line.split(',')
                if len(parts) >= 14:
                    bssid = parts[0].strip()
                    if bssid and bssid != 'BSSID':  # Skip header
                        network = {
                            "bssid": bssid,
                            "ssid": parts[13].strip() if len(parts) > 13 else "",
                            "channel": parts[3].strip() if len(parts) > 3 else "",
                            "encryption": parts[5].strip() if len(parts) > 5 else "",
                            "power": parts[8].strip() if len(parts) > 8 else "",
                            "beacons": parts[9].strip() if len(parts) > 9 else "",
                            "iv": parts[10].strip() if len(parts) > 10 else "",
                            "lan_ip": parts[11].strip() if len(parts) > 11 else "",
                            "id_length": parts[12].strip() if len(parts) > 12 else "",
                            "essid": parts[13].strip() if len(parts) > 13 else "",
                            "key": parts[14].strip() if len(parts) > 14 else ""
                        }
                        networks.append(network)
                        
        except FileNotFoundError:
            debug(f"Airodump-ng CSV file not found: {filename}")
        except Exception as e:
            error(f"Error parsing airodump-ng CSV: {e}")
            debug_exception("CSV parsing")
            
        return networks
        
    @time_it
    async def execute_action(self, target: Any, action: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Run a real recon action. Never fabricates networks or packet counts."""
        info(f"Executing reconnaissance action: {action}")
        debug_dict("Recon Action Parameters", {"target": str(target), "action": action, "parameters": parameters})
        
        try:
            action_l = (action or "").lower()
            iface = (
                parameters.get("interface")
                or self.interface
                or getattr(target, "interface", None)
                or (target.get("interface") if isinstance(target, dict) else None)
            )
            if "scan" in action_l:
                if not iface:
                    return {
                        "success": False,
                        "action": action,
                        "error": "interface required for scan",
                        "message": "Pass parameters.interface or set module.interface",
                    }
                networks = await self.scan(str(iface))
                result = {
                    "success": True,
                    "action": action,
                    "data": {
                        "networks_found": len(networks),
                        "networks": networks[:50],
                        "scan_type": "airodump-ng",
                        "interface": str(iface),
                    },
                    "message": f"Scan completed: {len(networks)} networks",
                }
            elif "monitor" in action_l:
                # Bounded airodump capture if iface present; else honest fail.
                if not iface:
                    return {
                        "success": False,
                        "action": action,
                        "error": "interface required for monitor",
                        "message": "Pass parameters.interface for traffic monitor",
                    }
                networks = await self._run_airodump_scan(str(iface))
                result = {
                    "success": True,
                    "action": action,
                    "data": {
                        "networks_observed": len(networks),
                        "networks": networks[:50],
                        "interface": str(iface),
                        "note": "passive airodump window; not a long-running capture",
                    },
                    "message": f"Monitor window complete: {len(networks)} APs",
                }
            else:
                result = {
                    "success": False,
                    "action": action,
                    "error": f"unknown recon action {action!r}",
                    "message": "Supported: scan, monitor (requires interface)",
                }
                
            info(f"Reconnaissance action {action}: success={result.get('success')}")
            debug_dict("Recon Action Result", result)
            return result
            
        except Exception as e:
            error(f"Reconnaissance action {action} failed: {e}")
            debug_exception(f"Recon action {action}")
            return {
                "success": False,
                "action": action,
                "error": str(e),
                "message": f"Reconnaissance action {action} failed"
            }

# Global instance
recon_module = ReconnaissanceModule()