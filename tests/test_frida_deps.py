"""tests.test_frida_deps — verify the frida installation is importable.

Frida 16+ requires Python 3.11+ (uses typing.NotRequired). The
operator's host is Python 3.10, so this test pins the frida<16
constraint in requirements.txt and verifies the import.
"""

import pytest


def test_frida_imports():
    """frida must be importable. Skip the network-bound RPC tests;
    only the import is in scope for the dep-fix."""
    import frida  # noqa: F401
    assert hasattr(frida, "__version__")
    assert frida.__version__.startswith("15."), (
        f"frida {frida.__version__!r} is not pinned to 15.x; "
        "frida 16+ requires Python 3.11+"
    )


def test_frida_tools_imports():
    """frida-tools CLI must be importable (provides frida, frida-ls,
    frida-ps, frida-trace)."""
    try:
        import frida_tools  # noqa: F401
    except ImportError as e:
        pytest.fail(f"frida-tools not importable: {e}")


def test_frida_python_compatibility():
    """Hard guard: frida 16+ on Python 3.10 raises ImportError at
    module load. If that ever happens in CI, this test fails fast."""
    import sys
    if sys.version_info >= (3, 11):
        pytest.skip("Python 3.11+ allows frida 16+; the pin is a 3.10 constraint")
    import frida
    # The RPC bindings work on 15.x — Device/Session are on the
    # `frida.core` submodule, not the top-level `frida` namespace.
    import frida.core  # noqa: F401
    assert hasattr(frida, "get_local_device")
    assert hasattr(frida, "enumerate_devices")
    assert hasattr(frida.core, "Device")
    assert hasattr(frida.core, "Session")


def test_no_typing_not_required_error():
    """Regression: frida 16.x raised `ImportError: cannot import name
    'NotRequired' from 'typing'` on Python 3.10. This test asserts the
    import does NOT raise that specific error."""
    try:
        import frida  # noqa: F401
    except ImportError as e:
        if "NotRequired" in str(e):
            pytest.fail(
                f"frida raised NotRequired ImportError — needs pinning to 15.x: {e}"
            )
        raise
