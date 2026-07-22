#!/usr/bin/env python3
"""
Settings Manager
Handles loading, saving, and managing application settings
"""

import logging
import json
import os
import copy
from typing import Dict, Any, Optional
from pathlib import Path

class SettingsManager:
    def __init__(self, settings_file: str = "config/dashboard_settings.json"):
        self.logger = logging.getLogger(__name__)
        self.settings_file = Path(settings_file)
        self.default_settings = {
            "ollama": {
                "endpoint": "http://127.0.0.1:11434",
                "temperature": 0.4,
                "num_predict": 1024,
                "domain_models": {
                    "wifi": "xploiter/pentester:latest",
                    "ble": "xploiter/pentester:latest",
                    "osint": "huihui_ai/phi4-abliterated:latest",
                    "post_exploitation": "huihui_ai/foundation-sec-abliterated:8b-fp16",
                    "c2": "supergoatscriptguy/mythos-sec:24b"
                }
            },
            "nvidia": {
                "api_key": "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",
                "base_url": "https://integrate.api.nvidia.com/v1",
                "model": "z-ai/glm-5.2"
            },
            "tools": {},
            "nvd": {
                "api_key": "b4eb1ae2-8fcf-4e8b-bbd9-3bb8ac36586e",
                "base_url": "https://services.nvd.nist.gov/rest/json/cves/2.0"
            },
            "ai_models": {
                "pentest-specialist": {
                    "model_path": "microsoft/DialoGPT-medium",
                    "max_length": 512,
                    "temperature": 0.7,
                    "top_p": 0.9
                },
                "exploit-analyzer": {
                    "model_path": "facebook/CodeLlama-7b-Python-hf",
                    "max_length": 1024,
                    "temperature": 0.3,
                    "top_p": 0.9
                }
            },
            "metasploit": {
                "host": "127.0.0.1",
                "port": 55553,
                "username": "msf",
                "password": "msf"
            },
            "c2": {
                "default_interval": 5,
                "default_jitter": 2,
                "encryption_enabled": True
            },
            "scanning": {
                "wifi_timeout": 60,
                "ble_timeout": 30,
                "osint_sources": ["search_engines", "social_media", "public_records"]
            },
            "logging": {
                "level": "INFO",
                "file": "logs/dashboard.log",
                "max_size": "10MB",
                "backup_count": 5
            }
        }
        self.settings = {}
        
    def load_settings(self) -> Dict[str, Any]:
        """Load settings from file or return defaults"""
        self.logger.info(f"Loading settings from {self.settings_file}")
        
        try:
            if self.settings_file.exists():
                with open(self.settings_file, 'r') as f:
                    self.settings = json.load(f)
                self.logger.info("Settings loaded successfully")
            else:
                self.logger.info("Settings file not found, using defaults")
                self.settings = copy.deepcopy(self.default_settings)
                self.save_settings()  # Create default settings file
        except Exception as e:
            self.logger.error(f"Error loading settings: {e}")
            self.settings = copy.deepcopy(self.default_settings)
        
        return self.settings
    
    def save_settings(self, settings: Dict[str, Any] = None) -> bool:
        """Save settings to file"""
        if settings is not None:
            self.settings = settings
        
        try:
            # Ensure directory exists
            self.settings_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(self.settings_file, 'w') as f:
                json.dump(self.settings, f, indent=4)
            
            self.logger.info(f"Settings saved to {self.settings_file}")
            return True
        except Exception as e:
            self.logger.error(f"Error saving settings: {e}")
            return False
    
    def get_settings(self) -> Dict[str, Any]:
        """Get current settings"""
        return self.settings
    
    def update_setting(self, key_path: str, value: Any) -> bool:
        """Update a specific setting using dot notation"""
        try:
            keys = key_path.split('.')
            current = self.settings
            
            # Navigate to the parent of the target key
            for key in keys[:-1]:
                if key not in current:
                    current[key] = {}
                current = current[key]
            
            # Set the value
            current[keys[-1]] = value
            
            # Save the updated settings
            return self.save_settings()
        except Exception as e:
            self.logger.error(f"Error updating setting {key_path}: {e}")
            return False
    
    def get_setting(self, key_path: str, default: Any = None) -> Any:
        """Get a specific setting using dot notation"""
        try:
            keys = key_path.split('.')
            current = self.settings
            
            for key in keys:
                if key not in current:
                    return default
                current = current[key]
            
            return current
        except Exception as e:
            self.logger.error(f"Error getting setting {key_path}: {e}")
            return default
    
    def reset_to_defaults(self) -> bool:
        """Reset settings to default values"""
        try:
            self.settings = copy.deepcopy(self.default_settings)
            return self.save_settings()
        except Exception as e:
            self.logger.error(f"Error resetting settings to defaults: {e}")
            return False

# Global settings manager instance
settings_manager = SettingsManager()