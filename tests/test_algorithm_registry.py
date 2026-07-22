"""Tests for core.algorithm_registry — Phase 4 T22 coverage."""
from __future__ import annotations

import importlib

import pytest


def _import_mod():
    return importlib.import_module("core.algorithm_registry")


mod = _import_mod()


# ---------------------------------------------------------------------------
# AlgorithmRegistry class
# ---------------------------------------------------------------------------

class TestRegistryBasics:
    def test_empty_registry(self):
        r = mod.AlgorithmRegistry()
        assert r.list_registered() == []

    def test_register_decorator(self):
        r = mod.AlgorithmRegistry()
        @r.register("test_algo", domain="test")
        def f(x):
            return x * 2
        assert "test_algo" in r.list_registered()

    def test_register_returns_function(self):
        r = mod.AlgorithmRegistry()
        @r.register("returns_self", domain="x")
        def f(x):
            return x
        # Decorator returns the function unchanged
        assert f(42) == 42

    def test_get_function(self):
        r = mod.AlgorithmRegistry()
        @r.register("my_algo", domain="d")
        def f(x):
            return x + 1
        fn = r.get("my_algo")
        assert fn(5) == 6

    def test_get_unknown_returns_none(self):
        r = mod.AlgorithmRegistry()
        assert r.get("nonexistent") is None

    def test_get_metadata(self):
        r = mod.AlgorithmRegistry()
        @r.register("meta_test", domain="d", description="My desc")
        def f():
            return None
        meta = r.get_metadata("meta_test")
        assert meta is not None
        assert meta["name"] == "meta_test"
        assert meta["domain"] == "d"
        assert meta["description"] == "My desc"
        assert meta["module"] == __name__
        assert "qualname" in meta

    def test_get_metadata_unknown(self):
        r = mod.AlgorithmRegistry()
        assert r.get_metadata("nonexistent") is None

    def test_list_by_domain(self):
        r = mod.AlgorithmRegistry()
        @r.register("a1", domain="wifi")
        def f1():
            pass
        @r.register("a2", domain="wifi")
        def f2():
            pass
        @r.register("b1", domain="ble")
        def f3():
            pass
        wifi = r.list_by_domain("wifi")
        assert len(wifi) == 2
        ble = r.list_by_domain("ble")
        assert len(ble) == 1
        assert r.list_by_domain("nonexistent") == []

    def test_list_registered(self):
        r = mod.AlgorithmRegistry()
        @r.register("x", domain="d")
        def f():
            pass
        @r.register("y", domain="d")
        def f2():
            pass
        assert set(r.list_registered()) == {"x", "y"}

    def test_get_all(self):
        r = mod.AlgorithmRegistry()
        @r.register("a", domain="d")
        def f():
            pass
        all_entries = r.get_all()
        assert "a" in all_entries
        assert all_entries["a"]["name"] == "a"

    def test_overwrite(self):
        # Re-registering the same name overwrites
        r = mod.AlgorithmRegistry()
        @r.register("dup", domain="d1")
        def f1():
            return 1
        @r.register("dup", domain="d2")
        def f2():
            return 2
        meta = r.get_metadata("dup")
        assert meta["domain"] == "d2"
        assert r.get("dup")() == 2

    def test_description_defaults_to_doc(self):
        r = mod.AlgorithmRegistry()
        @r.register("with_doc", domain="d")
        def f():
            """This is the docstring."""
            pass
        meta = r.get_metadata("with_doc")
        assert "docstring" in meta["description"]


# ---------------------------------------------------------------------------
# Global instance
# ---------------------------------------------------------------------------

class TestGlobalInstance:
    def test_global_instance_exists(self):
        assert isinstance(mod.algo_registry, mod.AlgorithmRegistry)

    def test_global_instance_is_usable(self):
        # The global should be a real registry
        assert hasattr(mod.algo_registry, "register")
        assert hasattr(mod.algo_registry, "list_registered")
