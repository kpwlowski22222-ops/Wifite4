#!/usr/bin/env python3
"""
Algorithm Registry
===================
Registers and documents algorithms used throughout the system.
"""

from typing import Any, Callable, Dict, List, Optional


class AlgorithmRegistry:
    def __init__(self):
        self._registry: Dict[str, Dict[str, Any]] = {}

    def register(
        self, name: str, domain: str, description: Optional[str] = None
    ):
        """
        Decorator to register an algorithm.
        """
        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            desc = description or func.__doc__
            if desc:
                desc = desc.strip()

            self._registry[name] = {
                "name": name,
                "domain": domain,
                "func": func,
                "description": desc,
                "module": func.__module__,
                "qualname": func.__qualname__
            }
            return func
        return decorator

    def list_by_domain(
        self, domain: str
    ) -> List[Dict[str, Any]]:
        return [
            meta for meta in self._registry.values()
            if meta.get("domain") == domain
        ]

    def get(self, name: str) -> Optional[Callable[..., Any]]:
        """Retrieve the registered function for an algorithm."""
        entry = self._registry.get(name)
        return entry["func"] if entry else None

    def get_metadata(self, name: str) -> Optional[Dict[str, Any]]:
        """Retrieve the metadata for a registered algorithm."""
        return self._registry.get(name)

    def list_registered(self) -> List[str]:
        """List all registered algorithm names."""
        return list(self._registry.keys())

    def get_all(self) -> Dict[str, Dict[str, Any]]:
        """Retrieve the full registry dictionary."""
        return self._registry


# Global instance of the registry
algo_registry = AlgorithmRegistry()
