import asyncio
import logging
from typing import Dict, Any
from core.modules.debug_logger import debug, info, warning, error, debug_dict, time_it, debug_exception

class AIPlanner:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        info("AI Planner Module initialized")
        
    @time_it
    async def initialize(self):
        info("Initializing AI planner module...")
        try:
            # Load any planning models or data
            await self._load_planning_data()
            info("AI planner module initialized successfully")
        except Exception as e:
            error(f"Failed to initialize AI planner module: {e}")
            debug_exception("AI planner initialization")
            raise
            
    @time_it
    async def _load_planning_data(self):
        """Load planning data and models"""
        # Placeholder for loading ML models, rule sets, etc.
        info("Loading planning data...")
        await asyncio.sleep(0.1)  # Simulate loading time
        debug("Planning data loaded")
        
    @time_it
    async def analyze_target(self, target: Any) -> Dict[str, Any]:
        info(f"Analyzing target with AI planner: {getattr(target, 'ssid', 'Unknown')}")
        
        try:
            # Extract target characteristics
            target_data = {
                "ssid": getattr(target, "ssid", "unknown"),
                "bssid": getattr(target, "bssid", "unknown"),
                "encryption": getattr(target, "encryption", "unknown"),
                "wps": getattr(target, "wps", False),
                "clients": len(getattr(target, "clients", [])),
                "signal": getattr(target, "signal", -100),
                "channel": getattr(target, "channel", 0)
            }
            
            debug_dict("Target Data for AI Planning", target_data)
            
            # Perform AI-based analysis
            analysis = await self._perform_ai_analysis(target_data)
            
            info(f"AI planner analysis completed for {target_data['ssid']}")
            debug_dict("AI Planner Analysis Result", analysis)
            
            return analysis
            
        except Exception as e:
            error(f"AI planner analysis failed: {e}")
            debug_exception("AI planner analysis")
            # Return basic analysis on failure
            return {
                "error": str(e),
                "target_ssid": getattr(target, "ssid", "unknown"),
                "analysis_method": "failed",
                "vulnerability_score": 0.1,
                "recommended_actions": ["monitor"]
            }
            
    @time_it
    async def _perform_ai_analysis(self, target_data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform AI-based target analysis.

        Prefer the AI-driven pentest engine (Hugging Face uncensored base +
        optional fine-tuned wifi adapter) when it is available with the base
        model fetched locally; otherwise fall back to the deterministic
        heuristic below. Any failure in the AI path is logged and degrades
        silently to the heuristic so the planner always returns a result.
        """
        ai_text = await self._hf_plan(target_data)

        # Simulate AI analysis processing
        await asyncio.sleep(0.5)

        # Extract key factors
        encryption = target_data.get("encryption", "").upper()
        wps = target_data.get("wps", False)
        clients = target_data.get("clients", 0)
        signal = target_data.get("signal", -100)
        
        # Calculate vulnerability score based on factors
        vulnerability_score = 0.1  # Base score
        
        # Encryption weaknesses
        if encryption in ["WEP", "WPA-PSK", "WPA2-PSK"]:
            vulnerability_score += 0.4
        elif encryption == "Open":
            vulnerability_score += 0.5
        elif encryption in ["WPA2-ENTERPRISE", "WPA3-ENTERPRISE"]:
            vulnerability_score += 0.1
            
        # WPS vulnerability
        if wps:
            vulnerability_score += 0.3
            
        # Signal strength (better signal = easier attack)
        if signal > -50:
            vulnerability_score += 0.2
        elif signal > -70:
            vulnerability_score += 0.1
            
        # Client activity (more clients = more targets)
        if clients > 10:
            vulnerability_score += 0.2
        elif clients > 5:
            vulnerability_score += 0.1
            
        # Normalize score
        vulnerability_score = min(0.95, max(0.05, vulnerability_score))
        
        # Generate recommended actions based on analysis
        recommended_actions = []
        
        if wps and vulnerability_score > 0.3:
            recommended_actions.append("wps_attack")
        if encryption in ["WEP", "WPA-PSK", "WPA2-PSK"] and vulnerability_score > 0.4:
            recommended_actions.append("handshake_capture")
        if encryption == "Open":
            recommended_actions.append("open_network_exploit")
        if vulnerability_score > 0.6:
            recommended_actions.append("network_pivot")
        if vulnerability_score > 0.7:
            recommended_actions.append("credential_harvest")
            
        # Ensure we have at least one action
        if not recommended_actions:
            recommended_actions = ["monitor"]
            
        # Generate detailed analysis
        analysis = {
            "target_ssid": target_data["ssid"],
            "target_bssid": target_data["bssid"],
            "encryption": encryption,
            "wps_enabled": wps,
            "signal_strength": signal,
            "client_count": clients,
            "channel": target_data["channel"],
            "vulnerability_score": vulnerability_score,
            "risk_level": self._get_risk_level(vulnerability_score),
            "recommended_actions": recommended_actions,
            "estimated_time_to_compromise": self._estimate_time_to_compromise(vulnerability_score, wps, encryption),
            "confidence": 0.75 + (vulnerability_score * 0.2),  # Higher confidence with clearer vulnerabilities
            "analysis_method": "ai_based",
            "factors_considered": ["encryption", "wps", "signal", "clients", "channel"],
            "ai_plan": ai_text or "",
            "ai_engine_used": bool(ai_text),
        }

        return analysis

    async def _hf_plan(self, target_data: Dict[str, Any]) -> str:
        """Best-effort call to the AI-driven pentest engine for a wifi plan.

        Returns "" if the engine is unavailable, the base model is not local,
        or any error occurs — the caller then falls back to the heuristic.
        Runs the (sync, heavy) engine call off the event loop.
        """
        try:
            import sys as _sys
            import os as _os
            root = _os.path.abspath(_os.path.join(_os.path.dirname(__file__), "..", ".."))
            if root not in _sys.path:
                _sys.path.insert(0, root)
            from ai_pentest_engine import get_engine  # type: ignore
            eng = get_engine()
            if not eng.is_available() or not eng._base_available_locally():
                return ""
            # Map the planner's target shape onto the engine's expected fields.
            tgt = {
                "ssid": target_data.get("ssid", "unknown"),
                "bssid": target_data.get("bssid", "unknown"),
                "encryption": target_data.get("encryption", ""),
                "wps": bool(target_data.get("wps", False)),
                "signal": target_data.get("signal", -100),
                "channel": target_data.get("channel", 0),
                "clients": target_data.get("clients", 0),
            }
            text = await asyncio.to_thread(eng.plan_wifi, tgt, max_new_tokens=400)
            return text or ""
        except Exception as e:
            warning(f"AI engine plan unavailable, using heuristic: {e}")
            return ""
        
    def _get_risk_level(self, score: float) -> str:
        """Convert vulnerability score to risk level"""
        if score >= 0.8:
            return "CRITICAL"
        elif score >= 0.6:
            return "HIGH"
        elif score >= 0.4:
            return "MEDIUM"
        elif score >= 0.2:
            return "LOW"
        else:
            return "VERY_LOW"
            
    def _estimate_time_to_compromise(self, vulnerability_score: float, wps: bool, encryption: str) -> Dict[str, Any]:
        """Estimate time to compromise based on factors"""
        base_minutes = 60  # Base 1 hour
        
        # Adjust based on vulnerability score
        time_multiplier = 2.0 - vulnerability_score  # Higher score = lower multiplier
        
        # Adjust for specific factors
        if wps:
            time_multiplier *= 0.5  # WPS makes it faster
        if encryption in ["WEP"]:
            time_multiplier *= 0.3  # WEP is very weak
        elif encryption in ["WPA-PSK", "WPA2-PSK"]:
            time_multiplier *= 0.7  # PSK is weaker than enterprise
        elif encryption == "Open":
            time_multiplier *= 0.1  # Open networks are instant
            
        estimated_minutes = max(1, int(base_minutes * time_multiplier))
        
        return {
            "estimated_minutes": estimated_minutes,
            "estimated_hours": round(estimated_minutes / 60, 1),
            "range_minutes": [max(1, int(estimated_minutes * 0.5)), int(estimated_minutes * 2.0)],
            "confidence": "medium" if vulnerability_score > 0.3 else "low"
        }

# Global instance
ai_planner = AIPlanner()