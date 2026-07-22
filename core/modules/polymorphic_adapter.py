import asyncio
import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)

class TargetType(Enum):
    HOME_ROUTER = "home_router"
    ENTERPRISE_AP = "enterprise_ap"
    PUBLIC_HOTSPOT = "public_hotspot"
    INDUSTRIAL_IOT = "industrial_iot"
    VEHICLE_SYSTEM = "vehicle_system"
    UNKNOWN = "unknown"

@dataclass
class TargetProfile:
    """Profile that defines how to adapt to a specific target type"""
    target_type: TargetType
    encryption_preferences: List[str] = field(default_factory=list)
    preferred_attack_vectors: List[str] = field(default_factory=list)
    avoided_attack_vectors: List[str] = field(default_factory=list)
    timing_profile: Dict[str, Any] = field(default_factory=dict)
    tool_preferences: Dict[str, str] = field(default_factory=dict)
    evasion_techniques: List[str] = field(default_factory=list)
    success_indicators: List[str] = field(default_factory=list)

class PolymorphicTargetAdapter:
    """Adapts offensive strategies based on target characteristics"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.target_profiles: Dict[TargetType, TargetProfile] = {}
        self._initialize_default_profiles()
        
    def _initialize_default_profiles(self):
        """Initialize default target profiles"""
        
        # Home router profile
        self.target_profiles[TargetType.HOME_ROUTER] = TargetProfile(
            target_type=TargetType.HOME_ROUTER,
            encryption_preferences=["WEP", "WPA-PSK", "WPA2-PSK"],
            preferred_attack_vectors=["wps", "pmkid", "deauth", "brute_force"],
            avoided_attack_vectors=["enterprise_radius_exploit"],
            timing_profile={
                "recon_delay": (1, 3),
                "attack_timeout": (30, 120),
                "retry_attempts": 3
            },
            tool_preferences={
                "wps": "reaver",
                "pmkid": "hcxtools",
                "deauth": "aireplay-ng",
                "brute_force": "hashcat"
            },
            evasion_techniques=[
                "timing_variation",
                "packet_fragmentation",
                "source_spoofing"
            ],
            success_indicators=[
                "handshake_captured",
                "password_found",
                "wps_pin_cracked"
            ]
        )
        
        # Enterprise AP profile
        self.target_profiles[TargetType.ENTERPRISE_AP] = TargetProfile(
            target_type=TargetType.ENTERPRISE_AP,
            encryption_preferences=["WPA2-Enterprise", "WPA3-Enterprise"],
            preferred_attack_vectors=["evil_twin", "radius_exploit", "downgrade_attack"],
            avoided_attack_vectors=["wps_brute_force", "simple_deauth"],
            timing_profile={
                "recon_delay": (5, 15),
                "attack_timeout": (120, 600),
                "retry_attempts": 1
            },
            tool_preferences={
                "evil_twin": "hostapd-wpe",
                "radius_exploit": "radsecproxy",
                "downgrade_attack": "sslstrip",
                "credential_harvest": "bettercap"
            },
            evasion_techniques=[
                "traffic_tunneling",
                "certificate_spoofing",
                "dhcp_starvation"
            ],
            success_indicators=[
                "credential_harvested",
                "radius_bypass",
                "network_pivot_achieved"
            ]
        )
        
        # Public hotspot profile
        self.target_profiles[TargetType.PUBLIC_HOTSPOT] = TargetProfile(
            target_type=TargetType.PUBLIC_HOTSPOT,
            encryption_preferences=["Open", "WPA2-PSK", "Captive Portal"],
            preferred_attack_vectors=["captive_portal_bypass", "ssl_stripping", "dns_spoofing"],
            avoided_attack_vectors=["brute_force", "wps"],
            timing_profile={
                "recon_delay": (2, 5),
                "attack_timeout": (60, 300),
                "retry_attempts": 2
            },
            tool_preferences={
                "captive_portal": "aircrack-ng",
                "ssl_strip": "bettercap",
                "dns_spoof": "dnschef",
                "traffic_mitm": "mitmproxy"
            },
            evasion_techniques=[
                "traffic_blending",
                "timing_randomization",
                "geo_spoofing"
            ],
            success_indicators=[
                "internet_access_achieved",
                "credentials_intercepted",
                "session_hijacked"
            ]
        )
        
        # Industrial IoT profile
        self.target_profiles[TargetType.INDUSTRIAL_IOT] = TargetProfile(
            target_type=TargetType.INDUSTRIAL_IOT,
            encryption_preferences=["WEP", "WPA-PSK", "Proprietary"],
            preferred_attack_vectors=["firmware_exploit", "protocol_fuzzing", "side_channel"],
            avoided_attack_vectors=["noisy_brute_force", "high_power_attacks"],
            timing_profile={
                "recon_delay": (10, 30),
                "attack_timeout": (300, 1800),
                "retry_attempts": 1
            },
            tool_preferences={
                "firmware": "binwalk",
                "fuzzing": "american-fuzzy-lop",
                "side_channel": "chipwhisperer",
                "protocol": "scapy"
            },
            evasion_techniques=[
                "low_and_slow",
                "protocol_mimicry",
                "power_analysis_evasion"
            ],
            success_indicators=[
                "firmware_extracted",
                "protocol_vulnerability_found",
                "device_control_achieved"
            ]
        )
        
        # Vehicle system profile
        self.target_profiles[TargetType.VEHICLE_SYSTEM] = TargetProfile(
            target_type=TargetType.VEHICLE_SYSTEM,
            encryption_preferences=["WPA2-PSK", "Proprietary", "Custom"],
            preferred_attack_vectors=["can_bus_exploit", "key_fob_relay", "ota_update_hijack"],
            avoided_attack_vectors=["high_power_jamming", "physical_tampering_obvious"],
            timing_profile={
                "recon_delay": (15, 60),
                "attack_timeout": (600, 3600),
                "retry_attempts": 1
            },
            tool_preferences={
                "can_bus": "candump",
                "key_fob": "yardstickone",
                "ota": "mitmproxy",
                "bluetooth": "bluetooth-hci_dump"
            },
            evasion_techniques=[
                "signal_attenuation",
                "temporal_evasion",
                "frequency_hopping"
            ],
            success_indicators=[
                "vehicle_access_gained",
                "can_bus_injection",
                "ota_update_control"
            ]
        )
        
    def classify_target(self, target_data: Dict[str, Any]) -> TargetType:
        """Classify a target based on its characteristics"""
        try:
            # Extract key characteristics
            encryption = str(target_data.get("encryption", "")).upper()
            ssid = str(target_data.get("ssid", "")).lower()
            bssid = str(target_data.get("bssid", ""))
            clients = len(target_data.get("clients", []))
            signal = int(target_data.get("signal", -100))
            
            # Debug output
            self.logger.debug(f"Classifying target: encryption={encryption}, ssid={ssid}, clients={clients}, signal={signal}")
            
            # Classification logic
            if any(indicator in ssid for indicator in ["guest", "public", "free", "wifi"]):
                result = TargetType.PUBLIC_HOTSPOT
                self.logger.debug(f"Classified as PUBLIC_HOTSPOT due to SSID indicators")
                return result
                
            if any(indicator in ssid for indicator in ["enterprise", "corp", "office", "business"]):
                result = TargetType.ENTERPRISE_AP
                self.logger.debug(f"Classified as ENTERPRISE_AP due to SSID indicators")
                return result
                
            if "industrial" in ssid or "iot" in ssid or "scada" in ssid:
                result = TargetType.INDUSTRIAL_IOT
                self.logger.debug(f"Classified as INDUSTRIAL_IOT due to SSID indicators")
                return result
                
            if any(indicator in ssid for indicator in ["car", "vehicle", "auto", "tesla", "bmw"]):
                result = TargetType.VEHICLE_SYSTEM
                self.logger.debug(f"Classified as VEHICLE_SYSTEM due to SSID indicators")
                return result
                
            # Default to home router for most cases
            if encryption in ["WEP", "WPA-PSK", "WPA2-PSK"] or clients < 10:
                result = TargetType.HOME_ROUTER
                self.logger.debug(f"Classified as HOME_ROUTER due to encryption={encryption} or clients={clients}")
                return result
            elif encryption in ["WPA2-ENTERPRISE", "WPA3-ENTERPRISE"]:
                result = TargetType.ENTERPRISE_AP
                self.logger.debug(f"Classified as ENTERPRISE_AP due to encryption={encryption}")
                return result
            else:
                result = TargetType.UNKNOWN
                self.logger.debug(f"Classified as UNKNOWN: encryption={encryption}, clients={clients}")
                return result
                
        except Exception as e:
            self.logger.warning(f"Error classifying target: {e}")
            return TargetType.UNKNOWN
            
    def get_target_profile(self, target_data: Dict[str, Any]) -> TargetProfile:
        """Get the appropriate profile for a target"""
        target_type = self.classify_target(target_data)
        return self.target_profiles.get(target_type, TargetProfile(target_type=TargetType.UNKNOWN))
        
    def adapt_strategy(self, base_strategy: Dict[str, Any], target_data: Dict[str, Any]) -> Dict[str, Any]:
        """Adapt a base strategy to be polymorphic for the specific target"""
        try:
            profile = self.get_target_profile(target_data)
            target_type = self.classify_target(target_data)
            
            self.logger.info(f"Adapting strategy for {target_type.value} target")
            
            # Create adapted strategy
            adapted = base_strategy.copy()
            
            # Adjust attack vectors based on profile
            if "attack_plan" in adapted:
                original_vectors = adapted["attack_plan"].get("vectors", [])
                filtered_vectors = [
                    v for v in original_vectors 
                    if v not in profile.avoided_attack_vectors
                ]
                # Add preferred vectors that aren't already present
                for vector in profile.preferred_attack_vectors:
                    if vector not in filtered_vectors:
                        filtered_vectors.append(vector)
                        
                adapted["attack_plan"]["vectors"] = filtered_vectors
                
            # Adjust timing
            if "timing" in adapted:
                adapted["timing"].update(profile.timing_profile)
                
            # Adjust tool preferences
            if "tools" in adapted:
                for tool_category, preferred_tool in profile.tool_preferences.items():
                    if tool_category not in adapted["tools"]:
                        adapted["tools"][tool_category] = preferred_tool
                        
            # Add evasion techniques
            if "evasion" in adapted:
                adapted["evasion"].extend(profile.evasion_techniques)
            else:
                adapted["evasion"] = profile.evasion_techniques.copy()
                
            # Add success indicators
            if "success_criteria" in adapted:
                adapted["success_criteria"].extend(profile.success_indicators)
            else:
                adapted["success_criteria"] = profile.success_indicators.copy()
                
            # Add target-specific metadata
            adapted["target_profile"] = {
                "type": target_type.value,
                "encryption_preferences": profile.encryption_preferences,
                "reasoning": f"Adapted for {target_type.value} based on target characteristics"
            }
            
            return adapted
            
        except Exception as e:
            self.logger.error(f"Error adapting strategy: {e}")
            return base_strategy  # Return original if adaptation fails
            
    def get_available_target_types(self) -> List[TargetType]:
        """Get list of all available target types"""
        return list(self.target_profiles.keys())
        
    def get_profile_info(self, target_type: TargetType) -> Optional[TargetProfile]:
        """Get information about a specific target profile"""
        return self.target_profiles.get(target_type)