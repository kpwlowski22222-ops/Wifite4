"""
AI Engine Module
Core AI-driven decision making engine for the WiFi Offensive AI Toolkit
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any
import numpy as np
from pathlib import Path
import json
import pickle

logger = logging.getLogger(__name__)

class AIEngine:
    """AI-driven decision making engine"""
    
    def __init__(self, config):
        self.config = config
        self.models = {}
        self.training_data = []
        self.decision_history = []
        self.model_path = Path(config.get("ai_model_path", "./models/"))
        self.model_path.mkdir(parents=True, exist_ok=True)
        
        # Load any pre-trained models
        self._load_models()
        
        logger.info("AI Engine initialized")
    
    def _load_models(self):
        """Load pre-trained models from disk"""
        try:
            # Load decision model
            decision_model_path = self.model_path / "decision_model.pkl"
            if decision_model_path.exists():
                with open(decision_model_path, 'rb') as f:
                    self.models['decision'] = pickle.load(f)
                logger.info("Loaded decision model")
            
            # Load attack planner model
            attack_model_path = self.model_path / "attack_model.pkl"
            if attack_model_path.exists():
                with open(attack_model_path, 'rb') as f:
                    self.models['attack'] = pickle.load(f)
                logger.info("Loaded attack model")
            
            # Load post-exploitation model
            post_exploit_model_path = self.model_path / "post_exploit_model.pkl"
            if post_exploit_model_path.exists():
                with open(post_exploit_model_path, 'rb') as f:
                    self.models['post_exploit'] = pickle.load(f)
                logger.info("Loaded post-exploitation model")
                
        except Exception as e:
            logger.warning(f"Could not load some models: {e}")
    
    def _save_models(self):
        """Save models to disk"""
        try:
            for name, model in self.models.items():
                model_path = self.model_path / f"{name}_model.pkl"
                with open(model_path, 'wb') as f:
                    pickle.dump(model, f)
            logger.info("Saved models to disk")
        except Exception as e:
            logger.error(f"Error saving models: {e}")
    
    async def make_decision(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Make an AI-driven decision based on context"""
        logger.info("Making AI-driven decision")
        
        # Extract features from context
        features = self._extract_features(context)
        
        # Use AI model if available, otherwise use rule-based fallback
        if 'decision' in self.models and len(features) > 0:
            try:
                # In a real implementation, this would use the actual ML model
                # For now, we'll simulate
                decision = await self._make_ml_decision(features)
            except Exception as e:
                logger.warning(f"ML decision failed, falling back to rule-based: {e}")
                decision = await self._make_rule_based_decision(context)
        else:
            decision = await self._make_rule_based_decision(context)
        
        # Record decision for learning
        self.decision_history.append({
            "context": context,
            "decision": decision,
            "timestamp": self._get_timestamp()
        })
        
        # Keep history manageable
        if len(self.decision_history) > 1000:
            self.decision_history = self.decision_history[-500:]
        
        return decision
    
    def _extract_features(self, context: Dict[str, Any]) -> List[float]:
        """Extract numerical features from context for ML models"""
        features = []
        
        # Extract various features from the context
        # This is a simplified implementation
        
        # Target characteristics
        if 'target' in context:
            target = context['target']
            # Signal strength (if available)
            if 'signal_strength' in target:
                try:
                    # Convert dBm to positive number for feature
                    strength = float(target['signal_strength'].replace('dBm', ''))
                    features.append(max(0, strength + 100))  # Normalize to 0-100 range
                except (ValueError, KeyError, AttributeError):
                    features.append(50)  # Default middle value
            else:
                features.append(50)
            
            # Encryption type
            encryption_map = {'open': 0, 'wep': 1, 'wpa': 2, 'wpa2': 3, 'wpa3': 4}
            enc_type = target.get('encryption', 'unknown').lower()
            features.append(encryption_map.get(enc_type, 0))
            
            # Channel
            try:
                features.append(float(target.get('channel', 6)))
            except (ValueError, TypeError):
                features.append(6.0)
        
        # Network characteristics
        if 'network' in context:
            network = context['network']
            # Number of clients
            try:
                features.append(float(network.get('client_count', 0)))
            except (ValueError, TypeError):
                features.append(0.0)
            
            # Network age (if available)
            features.append(1.0)  # Placeholder
        
        # Environmental factors
        features.append(1.0)  # Time of day factor (simplified)
        features.append(1.0)  # Day of week factor (simplified)
        
        return features
    
    async def _make_ml_decision(self, features: List[float]) -> Dict[str, Any]:
        """Make a decision using ML model"""
        # This is a placeholder for actual ML inference
        # In a real implementation, this would use self.models['decision']
        
        # Simulate ML decision based on features
        if len(features) >= 3:
            signal_strength = features[0] if len(features) > 0 else 50
            encryption = features[1] if len(features) > 1 else 0
            channel = features[2] if len(features) > 2 else 6
            
            # Simple heuristic-based decision (would be replaced by actual ML)
            if signal_strength > 70 and encryption in [2, 3]:  # Strong signal, WPA/WPA2
                action = "attempt_handshake_capture"
                confidence = 0.8
            elif encryption == 0:  # Open network
                action = "direct_connection"
                confidence = 0.9
            elif encryption == 1:  # WEP
                action = "wep_crack"
                confidence = 0.85
            elif encryption == 4:  # WPA3
                action = "research_vulnerabilities"
                confidence = 0.3
            else:
                action = "gather_more_info"
                confidence = 0.5
        else:
            action = "gather_more_info"
            confidence = 0.5
        
        return {
            "action": action,
            "confidence": confidence,
            "method": "ml_based",
            "features_used": len(features),
            "timestamp": self._get_timestamp()
        }
    
    async def _make_rule_based_decision(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Make a decision using rule-based logic"""
        logger.info("Making rule-based decision")
        
        # Extract key information
        target = context.get('target', {})
        network = context.get('network', {})
        scan_results = context.get('scan_results', {})
        
        # Rule-based decision logic
        encryption = target.get('encryption', '').lower()
        signal_strength = target.get('signal_strength', '-50dBm')
        
        # Parse signal strength
        try:
            strength_val = int(signal_strength.replace('dBm', ''))
        except (ValueError, AttributeError):
            strength_val = -50
        
        # Decision logic
        if strength_val > -30:  # Very strong signal
            if encryption in ['wpa', 'wpa2']:
                action = "attempt_handshake_capture"
                confidence = 0.85
            elif encryption == 'wpa3':
                action = "research_wpa3_vulnerabilities"
                confidence = 0.4
            elif encryption == 'wep':
                action = "wep_crack"
                confidence = 0.9
            elif encryption == 'open':
                action = "direct_connection"
                confidence = 0.95
            else:
                action = "gather_more_info"
                confidence = 0.6
        elif strength_val > -60:  # Good signal
            if encryption in ['wpa', 'wpa2']:
                action = "attempt_handshake_capture"
                confidence = 0.7
            elif encryption == 'wep':
                action = "wep_crack"
                confidence = 0.8
            else:
                action = "gather_more_info"
                confidence = 0.5
        else:  # Weak signal
            action = "wait_for_better_signal"
            confidence = 0.6
        
        # Adjust based on network activity
        client_count = network.get('client_count', 0)
        if client_count > 0:
            # More likely to succeed with active clients
            confidence = min(0.95, confidence + 0.1)
            if action == "gather_more_info":
                action = "attempt_handshake_capture"
        
        return {
            "action": action,
            "confidence": confidence,
            "method": "rule_based",
            "factors_considered": ["signal_strength", "encryption", "client_count"],
            "timestamp": self._get_timestamp()
        }
    
    async def plan_attack_sequence(self, target_info: Dict[str, Any], 
                                 available_tools: List[str]) -> Dict[str, Any]:
        """Plan an attack sequence using AI"""
        logger.info("Planning attack sequence with AI")
        
        # This would use the attack planning model
        # For now, return a structured plan
        
        encryption = target_info.get('encryption', '').lower()
        signal_strength = target_info.get('signal_strength', '-50dBm')
        
        try:
            strength_val = int(signal_strength.replace('dBm', ''))
        except (ValueError, AttributeError):
            strength_val = -50
        
        attack_plan = {
            "target": target_info.get('ssid', 'unknown'),
            "phases": [],
            "estimated_time": 0,
            "success_probability": 0.0
        }
        
        # Phase 1: Reconnaissance (always first)
        attack_plan["phases"].append({
            "phase": "reconnaissance",
            "action": "gather_target_info",
            "tools": ["airodump-ng", "iwlist"],
            "estimated_time": 30,
            "success_probability": 0.9
        })
        
        # Phase 2: Based on encryption type
        if encryption == 'open':
            attack_plan["phases"].append({
                "phase": "access",
                "action": "direct_connection",
                "tools": ["iwconfig", "dhclient"],
                "estimated_time": 10,
                "success_probability": 0.95
            })
        elif encryption == 'wep':
            attack_plan["phases"].append({
                "phase": "crack",
                "action": "wep_crack",
                "tools": ["aircrack-ng", "airplay-ng"],
                "estimated_time": 300,  # 5 minutes
                "success_probability": 0.8
            })
        elif encryption in ['wpa', 'wpa2']:
            attack_plan["phases"].append({
                "phase": "handshake",
                "action": "capture_handshake",
                "tools": ["airodump-ng", "aireplay-ng"],
                "estimated_time": 120,  # 2 minutes
                "success_probability": 0.7
            })
            attack_plan["phases"].append({
                "phase": "crack",
                "action": "crack_handshake",
                "tools": ["aircrack-ng"],
                "estimated_time": 1800,  # 30 minutes (variable)
                "success_probability": 0.6  # Depends on wordlist
            })
        elif encryption == 'wpa3':
            attack_plan["phases"].append({
                "phase": "research",
                "action": "research_wpa3_vulnerabilities",
                "tools": ["search_scripts", "check_exploits"],
                "estimated_time": 600,  # 10 minutes
                "success_probability": 0.3  # Lower for newer security
            })
        
        # Calculate totals
        attack_plan["estimated_time"] = sum(
            phase.get("estimated_time", 0) for phase in attack_plan["phases"]
        )
        
        # Overall success probability (simplified)
        if attack_plan["phases"]:
            probs = [phase.get("success_probability", 0.5) for phase in attack_plan["phases"]]
            attack_plan["success_probability"] = np.prod(probs) if len(probs) > 0 else 0.5
        
        attack_plan["timestamp"] = self._get_timestamp()
        
        return attack_plan
    
    async def learn_from_result(self, action: str, context: Dict[str, Any], 
                              result: Dict[str, Any], success: bool):
        """Learn from the result of an action"""
        logger.info(f"Learning from action: {action}, success: {success}")
        
        # Store experience for future learning
        experience = {
            "action": action,
            "context": context,
            "result": result,
            "success": success,
            "timestamp": self._get_timestamp()
        }
        
        self.training_data.append(experience)
        
        # Keep training data manageable
        if len(self.training_data) > 5000:
            self.training_data = self.training_data[-2500:]
        
        # Periodically retrain models (in a real implementation)
        if len(self.training_data) % 100 == 0:
            await self._retrain_models()
    
    async def _retrain_models(self):
        """Retrain AI models with accumulated experience"""
        logger.info("Retraining AI models with new experience")
        
        # In a real implementation, this would:
        # 1. Prepare training data from self.training_data
        # 2. Train/retrain the models in self.models
        # 3. Save the updated models
        # 4. Clear old training data if needed
        
        # For now, just log that we would retrain
        logger.info(f"Would retrain models with {len(self.training_data)} experiences")
    
    def get_model_status(self) -> Dict[str, Any]:
        """Get status of AI models"""
        return {
            "loaded_models": list(self.models.keys()),
            "training_examples": len(self.training_data),
            "decision_history": len(self.decision_history),
            "model_path": str(self.model_path),
            "last_training": self._get_timestamp() if self.training_data else None
        }
    
    def _get_timestamp(self) -> str:
        """Get current timestamp"""
        return str(int(__import__('time').time()))
