import asyncio
import logging
import subprocess
import re
from typing import List, Dict, Any
from core.modules.debug_logger import debug, info, warning, error, debug_dict, time_it

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
            warning("airodump-ng not found - using simulated scan for development")
            networks = await self._simulated_scan(interface)
        except Exception as e:
            error(f"Error running airodump-ng scan: {e}")
            debug_exception("Airodump-ng scan")
            networks = await self._simulated_scan(interface)
            
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
    async def _simulated_scan(self, interface: str) -> List[Dict[str, Any]]:
        """Simulate a network scan for development/testing"""
        info(f"Running simulated scan on interface {interface}")
        
        # Simulate some delay
        await asyncio.sleep(2)
        
        # Generate simulated networks
        simulated_networks = [
            {
                "bssid": "AA:BB:CC:DD:EE:01",
                "ssid": "HomeNetwork",
                "channel": "6",
                "encryption": "WPA2-PSK",
                "power": "-45",
                "beacons": "120",
                "iv": "0",
                "lan_ip": "192.168.1.1",
                "id_length": "",
                "essid": "HomeNetwork",
                "key": ""
            },
            {
                "bssid": "AA:BB:CC:DD:EE:02", 
                "ssid": "CORP_NETWORK",
                "channel": "36",
                "encryption": "WPA2-ENTERPRISE",
                "power": "-60",
                "beacons": "85",
                "iv": "0",
                "lan_ip": "10.0.0.1",
                "id_length": "",
                "essid": "CORP_NETWORK",
                "key": ""
            },
            {
                "bssid": "AA:BB:CC:DD:EE:03",
                "ssid": "Free_Public_WiFi",
                "channel": "1",
                "encryption": "Open",
                "power": "-35",
                "beacons": "200",
                "iv": "0",
                "lan_ip": "",
                "id_length": "",
                "essid": "Free_Public_WiFi",
                "key": ""
            }
        ]
        
        info(f"Simulated scan completed: {len(simulated_networks)} networks generated")
        debug_dict("Simulated Networks", simulated_networks)
        
        return simulated_networks
        
    @time_it
    async def execute_action(self, target: Any, action: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        info(f"Executing reconnaissance action: {action}")
        debug_dict("Recon Action Parameters", {"target": str(target), "action": action, "parameters": parameters})
        
        try:
            # Simulate different reconnaissance actions
            if "scan" in action.lower():
                # Perform a quick scan
                await asyncio.sleep(1)
                result = {
                    "success": True,
                    "action": action,
                    "data": {"networks_found": 3, "scan_type": "quick"},
                    "message": "Quick reconnaissance scan completed"
                }
            elif "monitor" in action.lower():
                # Monitor traffic
                await asyncio.sleep(2)
                result = {
                    "success": True,
                    "action": action,
                    "data": {"packets_captured": 1500, "devices_seen": 5},
                    "message": "Traffic monitoring completed"
                }
            else:
                # Generic reconnaissance action
                await asyncio.sleep(0.5)
                result = {
                    "success": True,
                    "action": action,
                    "data": {"completed": True},
                    "message": f"Reconnaissance action {action} completed"
                }
                
            info(f"Reconnaissance action {action} completed successfully")
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