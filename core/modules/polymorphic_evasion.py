"""
Polymorphic Evasion Module
Provides dynamic code/path modification to avoid detection
"""

import asyncio
import os
import hashlib
import random
import string
import logging
from typing import Dict, List, Optional, Any
from pathlib import Path
import base64
import json
import time

logger = logging.getLogger(__name__)

class PolymorphicEvasion:
    """Polymorphic capabilities for evasion"""
    
    def __init__(self, config):
        self.config = config
        self.mutation_count = 0
        self.obfuscation_techniques = [
            "base64_encode",
            "xor_encrypt",
            "variable_rename",
            "control_flow_flatten",
            "dead_code_insertion",
            "string_obfuscation",
            "function_reorder",
            "import_obfuscation"
        ]
        
        # Load any existing obfuscation rules
        self.obfuscation_rules = self._load_obfuscation_rules()
    
    def _load_obfuscation_rules(self) -> Dict[str, Any]:
        """Load obfuscation rules from configuration"""
        rules_file = self.config.get("obfuscation_rules_file", "config/obfuscation_rules.json")
        try:
            with open(rules_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            # Return default rules
            return {
                "string_obfuscation": True,
                "control_flow": True,
                "data_encoding": True,
                "api_obfuscation": True
            }
    
    def obfuscate_string(self, text: str, method: str = "base64") -> str:
        """Obfuscate a string using various techniques"""
        if method == "base64":
            return base64.b64encode(text.encode()).decode()
        elif method == "reverse":
            return text[::-1]
        elif method == "rot13":
            return self._rot13(text)
        elif method == "xor":
            key = random.randint(1, 255)
            return ''.join(chr(ord(c) ^ key) for c in text)
        elif method == "hex":
            return text.encode().hex()
        else:
            return text
    
    def _rot13(self, text: str) -> str:
        """Apply ROT13 encoding"""
        result = ""
        for char in text:
            if 'a' <= char <= 'z':
                result += chr((ord(char) - ord('a') + 13) % 26 + ord('a'))
            elif 'A' <= char <= 'Z':
                result += chr((ord(char) - ord('A') + 13) % 26 + ord('A'))
            else:
                result += char
        return result
    
    def obfuscate_payload(self, payload: str, techniques: List[str] = None) -> Dict[str, Any]:
        """Obfuscate a payload using multiple techniques"""
        if techniques is None:
            techniques = ["base64", "xor"]
        
        obfuscated = payload
        steps = []
        
        for technique in techniques:
            if technique == "base64":
                obfuscated = self.obfuscate_string(obfuscated, "base64")
                steps.append("base64_encode")
            elif technique == "xor":
                key = random.randint(1, 255)
                obfuscated = ''.join(chr(ord(c) ^ key) for c in obfuscated)
                steps.append(f"xor_key_{key}")
            elif technique == "reverse":
                obfuscated = self.obfuscate_string(obfuscated, "reverse")
                steps.append("reverse")
            elif technique == "rot13":
                obfuscated = self.obfuscate_string(obfuscated, "rot13")
                steps.append("rot13")
        
        self.mutation_count += 1
        
        return {
            "original": payload,
            "obfuscated": obfuscated,
            "techniques_used": steps,
            "mutation_id": self.mutation_count,
            "timestamp": self._get_timestamp()
        }
    
    def deobfuscate_payload(self, obfuscated: str, techniques: List[str]) -> str:
        """Deobfuscate a payload"""
        # Reverse the techniques in reverse order
        deobfuscated = obfuscated
        
        for technique in reversed(techniques):
            if technique.startswith("xor_key_"):
                key = int(technique.split("_")[2])
                deobfuscated = ''.join(chr(ord(c) ^ key) for c in deobfuscated)
            elif technique == "base64_encode":
                deobfuscated = base64.b64decode(deobfuscated.encode()).decode()
            elif technique == "reverse":
                deobfuscated = deobfuscated[::-1]
            elif technique == "rot13":
                deobfuscated = self._rot13(deobfuscated)
        
        return deobfuscated
    
    def generate_random_name(self, length: int = 8, prefix: str = "") -> str:
        """Generate a random name for files, variables, etc."""
        chars = string.ascii_letters + string.digits
        random_part = ''.join(random.choice(chars) for _ in range(length))
        return prefix + random_part
    
    def mutate_code(self, code: str, mutation_level: str = "moderate") -> Dict[str, Any]:
        """Apply mutations to code to avoid signature detection"""
        logger.info(f"Applying {mutation_level} mutation to code")
        
        mutations_applied = []
        mutated_code = code
        
        if mutation_level in ["light", "moderate", "aggressive"]:
            # Variable name obfuscation
            if self.obfuscation_rules.get("variable_rename", True):
                mutated_code, var_changes = self._obfuscate_variable_names(mutated_code)
                mutations_applied.append("variable_rename")
                mutations_applied.extend(var_changes)
            
            # String obfuscation
            if self.obfuscation_rules.get("string_obfuscation", True):
                mutated_code, str_changes = self._obfuscate_strings(mutated_code)
                mutations_applied.append("string_obfuscation")
                mutations_applied.extend(str_changes)
            
            # Control flow modification
            if self.obfuscation_rules.get("control_flow", True) and mutation_level in ["moderate", "aggressive"]:
                mutated_code, flow_changes = self._modify_control_flow(mutated_code)
                mutations_applied.append("control_flow_flatten")
                mutations_applied.extend(flow_changes)
            
            # Dead code insertion
            if self.obfuscation_rules.get("dead_code_insertion", True) and mutation_level == "aggressive":
                mutated_code, dead_code = self._insert_dead_code(mutated_code)
                mutations_applied.append("dead_code_insertion")
                mutations_applied.extend(dead_code)
        
        self.mutation_count += 1
        
        return {
            "original_code": code,
            "mutated_code": mutated_code,
            "mutations_applied": mutations_applied,
            "mutation_id": self.mutation_count,
            "mutation_level": mutation_level,
            "timestamp": self._get_timestamp()
        }
    
    def _obfuscate_variable_names(self, code: str) -> tuple:
        """Obfuscate variable names in code"""
        # Simple implementation - in practice, this would be more sophisticated
        import re
        
        # Find variable names (simplified)
        var_pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b'
        matches = re.findall(var_pattern, code)
        
        # Filter out Python keywords and common names
        python_keywords = {
            'and', 'as', 'assert', 'break', 'class', 'continue', 'def', 'del',
            'elif', 'else', 'except', 'exec', 'finally', 'for', 'from', 'global',
            'if', 'import', 'in', 'is', 'lambda', 'not', 'or', 'pass', 'print',
            'raise', 'return', 'self', 'super', 'try', 'while', 'with', 'yield'
        }
        
        # Create mapping for obfuscation
        var_mapping = {}
        new_code = code
        
        for var in set(matches):
            if var not in python_keywords and not var.startswith('__'):
                # Generate random name
                new_name = self.generate_random_name(6, "var_")
                var_mapping[var] = new_name
                # Replace occurrences (careful with word boundaries)
                pattern = r'\b' + re.escape(var) + r'\b'
                new_code = re.sub(pattern, new_name, new_code)
        
        changes = [f"{orig}->{new}" for orig, new in var_mapping.items()]
        return new_code, changes
    
    def _obfuscate_strings(self, code: str) -> tuple:
        """Obfuscate string literals with base64 + injected decode helper.

        Replaces non-empty string literals and ensures a
        ``_kfiosa_b64`` helper is present so the result remains
        syntactically valid Python.
        """
        import base64
        import re

        helper = (
            "import base64 as _b64\n"
            "def _kfiosa_b64(s):\n"
            "    return _b64.b64decode(s.encode()).decode()\n"
        )
        # Simple non-nested string literals (single or double quotes)
        pattern = re.compile(r'(["\'])([^"\'\\]*(?:\\.[^"\'\\]*)*)\1')
        changes = []
        count = [0]

        def _repl(m):
            content = m.group(2)
            if not content or len(content) > 200:
                return m.group(0)
            # Skip already-obfuscated / helper calls
            if content.startswith("_kfiosa") or "base64" in content:
                return m.group(0)
            try:
                raw = bytes(content, "utf-8").decode("unicode_escape")
            except Exception:  # noqa: BLE001
                raw = content
            enc = base64.b64encode(raw.encode("utf-8")).decode("ascii")
            count[0] += 1
            changes.append(f"string_obfuscated:{raw[:20]}...")
            return f'_kfiosa_b64("{enc}")'

        new_code = pattern.sub(_repl, code)
        if count[0] and "_kfiosa_b64" not in code:
            new_code = helper + new_code
            changes.append("injected:_kfiosa_b64_helper")
        return new_code, changes

    def _modify_control_flow(self, code: str) -> tuple:
        """Lightweight control-flow noise: wrap body in opaque predicates.

        Full CFF is out of scope; this injects always-true predicates
        and an unused branch so static pattern matching is harder.
        """
        import hashlib
        seed = hashlib.sha1(code.encode("utf-8", errors="replace")).hexdigest()[:8]
        # Opaque true: (hash % 2 == hash % 2)
        n = int(seed[:2], 16)
        prelude = (
            f"_kfiosa_pred = ({n} % 2 == {n} % 2)\n"
            f"if not _kfiosa_pred:\n"
            f"    raise RuntimeError('unreachable-{seed}')  # dead\n"
        )
        changes = [f"opaque_predicate:{seed}", "dead_branch_injected"]
        if "_kfiosa_pred" in code:
            return code, ["control_flow_already_modified"]
        return prelude + code, changes
    
    def _insert_dead_code(self, code: str) -> tuple:
        """Insert dead code to confuse analysis"""
        # Add some harmless but confusing code
        dead_code_lines = [
            "# This is dead code for obfuscation",
            "if False:",
            "    pass",
            "# Another dead code section",
            "x = 1 + 1  # This variable is never used",
            "# End of dead code"
        ]
        
        # Insert at random locations
        lines = code.split('\n')
        if len(lines) > 3:
            insert_pos = random.randint(1, len(lines) - 2)
            for i, line in enumerate(dead_code_lines):
                lines.insert(insert_pos + i, line)
        
        new_code = '\n'.join(lines)
        changes = ["dead_code_inserted"]
        return new_code, changes
    
    def generate_polymorphic_variant(self, base_content: str, 
                                   variant_type: str = "script") -> Dict[str, Any]:
        """Generate a polymorphic variant of content"""
        logger.info(f"Generating polymorphic variant of type: {variant_type}")
        
        # Apply different mutation levels based on type
        if variant_type == "script":
            mutation_level = "moderate"
        elif variant_type == "payload":
            mutation_level = "aggressive"
        else:
            mutation_level = "light"
        
        mutation_result = self.mutate_code(base_content, mutation_level)
        
        # Add metadata
        mutation_result["variant_type"] = variant_type
        mutation_result["detection_evasion_score"] = self._calculate_evasion_score(
            mutation_result["mutations_applied"]
        )
        
        return mutation_result
    
    def _calculate_evasion_score(self, mutations: List[str]) -> float:
        """Calculate estimated evasion score based on mutations applied"""
        # Simple scoring - more mutations = higher evasion
        base_score = 0.3
        mutation_bonus = len(mutations) * 0.1
        technique_bonus = 0.0
        
        # Bonus for specific techniques
        high_value_techniques = [
            "control_flow_flatten", "dead_code_insertion", 
            "variable_rename", "string_obfuscation"
        ]
        
        for mutation in mutations:
            if any(tech in mutation for tech in high_value_techniques):
                technique_bonus += 0.05
        
        return min(0.95, base_score + mutation_bonus + technique_bonus)
    
    def get_evasion_techniques(self) -> Dict[str, Any]:
        """Get available evasion techniques"""
        return {
            "available_techniques": self.obfuscation_techniques,
            "obfuscation_rules": self.obfuscation_rules,
            "mutation_count": self.mutation_count,
            "supported_operations": [
                "string_obfuscation",
                "payload_obfuscation",
                "code_mutation",
                "variable_obfuscation",
                "control_flow_modification",
                "dead_code_insertion"
            ]
        }
    
    async def run_demo(self) -> Dict[str, Any]:
        """Run a demonstration of polymorphic evasion"""
        logger.info("Running polymorphic evasion demo")
        
        demo_results = {}
        
        # Test string obfuscation
        test_string = "This is a secret payload for wireless attack"
        obfuscated_result = self.obfuscate_payload(test_string, ["base64", "xor", "reverse"])
        demo_results["string_obfuscation"] = obfuscated_result
        
        # Test code mutation
        sample_code = '''
def attack_wifi(target):
    """Attack a WiFi network"""
    password = "secret123"
    print(f"Attacking {target} with password {password}")
    return True
'''
        
        mutated_result = self.mutate_code(sample_code, "moderate")
        demo_results["code_mutation"] = mutated_result
        
        # Test polymorphic variant generation
        variant_result = self.generate_polymorphic_variant(sample_code, "script")
        demo_results["polymorphic_variant"] = variant_result
        
        # Get available techniques
        demo_results["techniques"] = self.get_evasion_techniques()
        
        return demo_results
    
    def _get_timestamp(self) -> str:
        """Get current timestamp"""
        return str(int(time.time()))
