"""
Kali Tools Integration Module
Integrates with Kali Linux penetration testing tools like aircrack-ng, nmap, hashcat, john, etc.
"""

import asyncio
import subprocess
import json
import logging
from typing import Dict, List, Optional, Any
from pathlib import Path
import shlex

logger = logging.getLogger(__name__)

class KaliToolsIntegration:
    """Integration with Kali Linux penetration testing tools"""
    
    def __init__(self, config):
        self.config = config
        self.tools_available = self._check_tool_availability()
        
    def _check_tool_availability(self) -> Dict[str, bool]:
        """Check which Kali tools are available on the system"""
        tools = {
            'aircrack-ng': 'aircrack-ng',
            'airodump-ng': 'airodump-ng',
            'aireplay-ng': 'aireplay-ng',
            'airmon-ng': 'airmon-ng',
            'nmap': 'nmap',
            'hashcat': 'hashcat',
            'john': 'john',
            'hashcat-utils': 'hashcat-utils',
            'hydra': 'hydra',
            'medusa': 'medusa',
            'ncrack': 'ncrack',
            'netcat': 'nc',
            'tcpdump': 'tcpdump',
            'wireshark': 'tshark',
            'bully': 'bully',
            'reaver': 'reaver',
            'pixiewps': 'pixiewps',
            'hcxpcapngtool': 'hcxpcapngtool',
            'wifite': 'wifite',
            'bettercap': 'bettercap',
            'ettercap': 'ettercap',
            'sslscan': 'sslscan',
            'sslyze': 'sslyze',
            'nikto': 'nikto',
            'dirb': 'dirb',
            'gobuster': 'gobuster',
            'sqlmap': 'sqlmap',
            'metasploit': 'msfconsole'
        }
        
        availability = {}
        for tool_name, command in tools.items():
            try:
                result = subprocess.run(
                    ['which', command], 
                    capture_output=True, 
                    text=True, 
                    timeout=5
                )
                availability[tool_name] = result.returncode == 0
                if availability[tool_name]:
                    logger.debug(f"Tool {tool_name} found at: {result.stdout.strip()}")
                else:
                    logger.debug(f"Tool {tool_name} not found")
            except Exception as e:
                logger.debug(f"Error checking tool {tool_name}: {e}")
                availability[tool_name] = False
        
        return availability
    
    async def run_tool(self, tool_name: str, args: List[str], timeout: int = 300) -> Dict[str, Any]:
        """Run a Kali tool and return results"""
        if not self.tools_available.get(tool_name, False):
            return {
                "error": f"Tool {tool_name} not available",
                "available": False
            }
        
        # Get the actual command for the tool
        tool_commands = {
            'aircrack-ng': 'aircrack-ng',
            'airodump-ng': 'airodump-ng',
            'aireplay-ng': 'aireplay-ng',
            'airmon-ng': 'airmon-ng',
            'nmap': 'nmap',
            'hashcat': 'hashcat',
            'john': 'john',
            'hydra': 'hydra',
            'medusa': 'medusa',
            'ncrack': 'ncrack',
            'netcat': 'nc',
            'tcpdump': 'tcpdump',
            'wireshark': 'tshark',
            'bully': 'bully',
            'reaver': 'reaver',
            'pixiewps': 'pixiewps',
            'hcxpcapngtool': 'hcxpcapngtool',
            'wifite': 'wifite',
            'bettercap': 'bettercap',
            'ettercap': 'ettercap',
            'sslscan': 'sslscan',
            'sslyze': 'sslyze',
            'nikto': 'nikto',
            'dirb': 'dirb',
            'gobuster': 'gobuster',
            'sqlmap': 'sqlmap',
            'metasploit': 'msfconsole'
        }
        
        command = tool_commands.get(tool_name, tool_name)
        cmd = [command] + args
        
        logger.info(f"Running Kali tool: {' '.join(cmd)}")
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
            
            result = {
                "tool": tool_name,
                "command": ' '.join(cmd),
                "return_code": process.returncode,
                "stdout": stdout.decode('utf-8', errors='ignore'),
                "stderr": stderr.decode('utf-8', errors='ignore'),
                "success": process.returncode == 0
            }
            
            if process.returncode == 0:
                logger.info(f"Tool {tool_name} completed successfully")
            else:
                logger.warning(f"Tool {tool_name} failed with return code {process.returncode}")
            
            return result
            
        except asyncio.TimeoutError:
            logger.error(f"Tool {tool_name} timed out after {timeout} seconds")
            return {
                "tool": tool_name,
                "command": ' '.join(cmd),
                "error": f"Timeout after {timeout} seconds",
                "success": False
            }
        except Exception as e:
            logger.error(f"Error running tool {tool_name}: {e}")
            return {
                "tool": tool_name,
                "command": ' '.join(cmd),
                "error": str(e),
                "success": False
            }
    
    async def wifi_scan(self, interface: str, duration: int = None) -> Dict[str, Any]:
        """Perform WiFi scanning using airodump-ng (long-range default)."""
        try:
            from core.scanners.scan_limits import wifi_scan_s
            duration = wifi_scan_s(duration)
        except Exception:
            duration = int(duration) if duration is not None else 300
        logger.info(f"Starting WiFi scan on interface {interface} for {duration} seconds")
        
        # Start airodump-ng in background
        scan_file = f"/tmp/wifi_scan_{int(time.time())}"
        cmd = [
            'airodump-ng',
            '--write', scan_file,
            '--output-format', 'json',
            interface
        ]
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Let it run for the specified duration
            await asyncio.sleep(duration)
            
            # Terminate the process
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=5)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
            
            # Read the results
            json_file = f"{scan_file}-01.json"
            if Path(json_file).exists():
                with open(json_file, 'r') as f:
                    data = json.load(f)
                
                # Clean up
                for ext in ['-01.csv', '-01.cap', '-01.kismet.csv', '-01.kismet.netxml']:
                    try:
                        Path(f"{scan_file}{ext}").unlink()
                    except FileNotFoundError:
                        pass
                
                return {
                    "tool": "airodump-ng",
                    "scan_duration": duration,
                    "interface": interface,
                    "results": data,
                    "success": True
                }
            else:
                return {
                    "tool": "airodump-ng",
                    "error": "No output file generated",
                    "success": False
                }
                
        except Exception as e:
            logger.error(f"Error during WiFi scan: {e}")
            return {
                "tool": "airodump-ng",
                "error": str(e),
                "success": False
            }
    
    async def crack_handshake(self, pcap_file: str, wordlist: str, 
                            attack_mode: int = 0) -> Dict[str, Any]:
        """Crack WPA/WPA2 handshake using aircrack-ng"""
        logger.info(f"Attempting to crack handshake in {pcap_file} using {wordlist}")
        
        cmd = [
            'aircrack-ng',
            '-w', wordlist,
            '-a', '2',  # WPA/WPA2
            pcap_file
        ]
        
        return await self.run_tool('aircrack-ng', cmd[1:])  # Skip the tool name
    
    async def pmkid_attack(self, pcap_file: str, wordlist: str) -> Dict[str, Any]:
        """Perform PMKID attack using hashcat (hc22000 / -m 22000).

        Uses hcxpcapngtool to convert the capture to the modern hc22000
        format (the deprecated hccapx/-m 2500 path is no longer used).
        """
        logger.info(f"Attempting PMKID attack on {pcap_file} using {wordlist}")

        # Convert pcap to hc22000 via hcxpcapngtool.
        hc22000_file = pcap_file.replace('.pcap', '.hc22000').replace(
            '.cap', '.hc22000')
        convert_cmd = ['hcxpcapngtool', '-o', hc22000_file, pcap_file]
        convert_result = await self.run_tool('hcxpcapngtool', convert_cmd[1:])
        if not convert_result.get('success'):
            return convert_result

        # Now crack with hashcat using the modern hc22000 mode.
        hashcat_cmd = [
            '-m', '22000',  # WPA/WPA2/PMKID hc22000
            hc22000_file,
            wordlist
        ]
        
        result = await self.run_tool('hashcat', hashcat_cmd)
        
        # Clean up
        try:
            Path(hccapx_file).unlink()
        except FileNotFoundError:
            pass
        
        return result
    
    async def network_scan(self, target: str, scan_type: str = "syn") -> Dict[str, Any]:
        """Perform network scanning using nmap"""
        logger.info(f"Performing {scan_type} scan on {target}")
        
        scan_types = {
            "syn": ["-sS"],      # SYN scan
            "connect": ["-sT"],  # Connect scan
            "udp": ["-sU"],      # UDP scan
            "comprehensive": ["-sS", "-sU", "-sV", "-O"],  # Comprehensive
            "vuln": ["-sV", "--script=vuln"],  # Vulnerability scan
        }
        
        args = scan_types.get(scan_type, ["-sS"]) + [target]
        
        return await self.run_tool('nmap', args)
    
    async def crack_hash(self, hash_file: str, wordlist: str, 
                        hash_type: str = "auto") -> Dict[str, Any]:
        """Crack hashes using hashcat or john"""
        logger.info(f"Attempting to crack hashes in {hash_file} using {wordlist}")
        
        # Try hashcat first
        hashcat_modes = {
            "md5": "0",
            "sha1": "100",
            "sha256": "1400",
            "ntlm": "1000",
            "lm": "3000",
            "wpa": "22000",
            "pmkid": "22000",
            "auto": "0"  # Let hashcat auto-detect
        }
        
        mode = hashcat_modes.get(hash_type.lower(), "0")
        
        hashcat_cmd = [
            '-m', mode,
            hash_file,
            wordlist
        ]
        
        result = await self.run_tool('hashcat', hashcat_cmd)
        
        # If hashcat fails, try john
        if not result.get('success'):
            logger.info("Hashcat failed, trying John the Ripper...")
            john_cmd = [
                '--wordlist=' + wordlist,
                hash_file
            ]
            result = await self.run_tool('john', john_cmd)
        
        return result
    
    async def run_demo(self) -> Dict[str, Any]:
        """Run a demonstration of Kali tools integration"""
        logger.info("Running Kali tools integration demo")
        
        demo_results = {
            "tool_availability": self.tools_available,
            "demonstrations": {}
        }
        
        # Demo a few key tools if available
        if self.tools_available.get('nmap', False):
            # Simple localhost scan
            demo_results["demonstrations"]["nmap"] = await self.network_scan("127.0.0.1", "syn")
        
        if self.tools_available.get('tcpdump', False):
            # Capture a few packets
            demo_results["demonstrations"]["tcpdump"] = await self.run_tool(
                'tcpdump', ['-c', '5', '-i', 'lo']
            )
        
        return demo_results
