"""TuiConfirmFn — the ACCEPT/CANCEL gate (Phase I bug-fix coverage)."""

import threading
import time

from core.orchestrator.autonomous_orchestrator import TuiConfirmFn


def test_confirm_returns_when_responded():
    t = TuiConfirmFn()
    out = {}
    th = threading.Thread(target=lambda: out.__setitem__("v", t.confirm("step?", timeout=2.0)))
    th.start()
    time.sleep(0.15)
    assert t.poll(None, []) == "prompt:step?"
    assert t.current_prompt == "step?"
    t.respond(True)
    th.join(timeout=3)
    assert out["v"] is True
    assert not th.is_alive()


def test_confirm_timeout_default_deny_no_hang():
    """The deadlock fix: with no drain loop, confirm() must default-deny and
    return instead of blocking the worker forever."""
    t = TuiConfirmFn()
    out = {}
    th = threading.Thread(target=lambda: out.__setitem__("v", t.confirm("step?", timeout=0.4)))
    th.start()
    th.join(timeout=3)
    assert out["v"] is False
    assert not th.is_alive()


def test_timeout_cleans_stale_prompt():
    """A timed-out prompt must be removed from the queue so it cannot later
    steal an operator's response meant for a different prompt."""
    t = TuiConfirmFn()
    threading.Thread(target=lambda: None, daemon=True).start()  # noop warmup
    done = {}
    th1 = threading.Thread(target=lambda: done.__setitem__("a", t.confirm("old?", timeout=0.3)))
    th1.start(); th1.join(timeout=3)
    assert done["a"] is False
    # The stale prompt must not be lingering in pending.
    assert t.pending.empty()

    # A fresh prompt is now the only one in flight; the operator's ACCEPT
    # must reach THIS prompt, not the stale one.
    done2 = {}
    th2 = threading.Thread(target=lambda: done2.__setitem__("b", t.confirm("new?", timeout=2.0)))
    th2.start()
    time.sleep(0.15)
    t.poll(None, [])  # promote the fresh prompt into _current
    assert t.current_prompt == "new?"
    t.respond(True)
    th2.join(timeout=3)
    assert done2["b"] is True


def test_stale_respond_dropped_not_redelivered():
    """A keystroke when no prompt is active must be dropped loudly, NOT
    re-delivered to the next queued prompt (re-delivery would auto-ACCEPT an
    unseen offensive step). The real queued prompt must still get answered."""
    t = TuiConfirmFn()
    out = {}
    th = threading.Thread(target=lambda: out.__setitem__("v", t.confirm("real-step?", timeout=2.0)))
    th.start()
    time.sleep(0.1)
    t.respond(False)  # stale keystroke — _current is None, must be dropped
    # The real prompt is still waiting and must be answerable.
    t.poll(None, [])
    assert t.current_prompt == "real-step?"
    t.respond(True)
    th.join(timeout=3)
    assert out["v"] is True


def test_has_pending_reflects_state():
    t = TuiConfirmFn()
    assert t.has_pending() is False
    th = threading.Thread(target=lambda: t.confirm("x?", timeout=1.0))
    th.start()
    time.sleep(0.1)
    assert t.has_pending() is True
    th.join(timeout=3)