"""core.live_target.safe_patches — whitelist of 9 polyglot safe patches.

Each patch is a *literal* text/byte swap with a fixed
``old_str``/``new_str`` pair. The patches are pre-vetted at
module load; the :mod:`validator` re-checks every patch's
*swapped* string + the ``params`` values at runtime.

The 9 patches (3 per target class):

  microsoft::
    swap_bloodhound_query_param    - rewrite a Cypher MATCH param
                                     in a saved .cypher file
    swap_powerview_filter          - rewrite a PowerView -Filter
                                     argument
    swap_certipy_template          - rewrite a certipy ``-template``
                                     argument
  android::
    swap_frida_script_steal_method - rewrite a Frida ``Java.choose``
                                     filter in a .js file
    swap_apk_package_id            - rename the package id in an
                                     AndroidManifest.xml snippet
    swap_magisk_module_prop        - swap ``id=``/``name=`` in a
                                     Magisk module.prop
  ios::
    swap_plist_key_value           - literal pair-replace in a
                                     .plist snippet
    swap_frida_ios_dump_bundle_id  - bundle-id swap in a Frida
                                     script
    swap_checkm8_args              - checkm8 arglist patch in a
                                     shell wrapper

The runner writes the new text to a caller-supplied ``out_path``
(default: in-memory echo, no file write). The operator's job is
to copy the modified artifact to the target themselves.
"""
from __future__ import annotations

import os
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

from core.live_target.validator import (
    validate_params,
    validate_swap,
)


# ---------------------------------------------------------------------------
# Microsoft patches
# ---------------------------------------------------------------------------
def _apply_swap_literal(text: str, old: str, new: str) -> str:
    """Single literal swap (first occurrence). The old/new pair is
    validated by the caller (the ``run_patch`` function)."""
    if old and old in text:
        return text.replace(old, new, 1)
    return text


def _microsoft_swap_bloodhound_query_param(artifact: str,
                                           params: Dict[str, Any]) -> Dict[str, Any]:
    """Rewrite a Cypher MATCH param in a saved .cypher file::

        MATCH (n:User {name:$old_param}) RETURN n
        ->
        MATCH (n:User {name:$new_param}) RETURN n
    """
    old = (params.get("old_param") or params.get("old") or "").strip()
    new = (params.get("new_param") or params.get("new") or "").strip()
    if not old or not new:
        return {"ok": False, "error": "old_param/new_param required"}
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", new):
        return {"ok": False, "error": "new_param must be Cypher identifier"}
    pattern = re.compile(r"\$\b" + re.escape(old) + r"\b")
    new_text, n = pattern.subn("$" + new, artifact)
    if n == 0:
        return {"ok": False,
                "error": f"old_param {old!r} not found in artifact"}
    return {"ok": True, "text": new_text, "replacements": n,
            "model": "literal Cypher param rename"}


def _microsoft_swap_powerview_filter(artifact: str,
                                      params: Dict[str, Any]) -> Dict[str, Any]:
    """Rewrite a PowerView ``-Filter`` argument in a .ps1 wrapper::

        Get-DomainUser -Filter 'old_filter'
        ->
        Get-DomainUser -Filter 'new_filter'
    """
    old = params.get("old") or params.get("old_filter") or ""
    new = params.get("new") or params.get("new_filter") or ""
    if not old or not new:
        return {"ok": False, "error": "old/new required"}
    # Wrap old in single-quotes if not already.
    if not (old.startswith("'") and old.endswith("'")):
        old_q = "'" + old.replace("'", "''") + "'"
    else:
        old_q = old
    if not (new.startswith("'") and new.endswith("'")):
        new_q = "'" + new.replace("'", "''") + "'"
    else:
        new_q = new
    new_text, n = re.subn(r"-Filter\s+" + re.escape(old_q),
                          "-Filter " + new_q, artifact)
    if n == 0:
        return {"ok": False, "error": "old -Filter not found in artifact"}
    return {"ok": True, "text": new_text, "replacements": n,
            "model": "PowerView -Filter literal swap"}


def _microsoft_swap_certipy_template(artifact: str,
                                      params: Dict[str, Any]) -> Dict[str, Any]:
    """Rewrite a certipy ``-template`` argument in a certipy
    command line::

        certipy req -template 'OldTemplate' ...
        ->
        certipy req -template 'NewTemplate' ...
    """
    old = params.get("old") or ""
    new = params.get("new") or ""
    if not old or not new:
        return {"ok": False, "error": "old/new required"}
    if not re.fullmatch(r"[A-Za-z0-9_\-]+", new):
        return {"ok": False, "error": "new template name invalid"}
    new_text, n = re.subn(r"-template\s+['\"]?" + re.escape(old) + r"['\"]?",
                          "-template '" + new + "'", artifact)
    if n == 0:
        return {"ok": False, "error": "old -template not found"}
    return {"ok": True, "text": new_text, "replacements": n,
            "model": "certipy -template literal swap"}


# ---------------------------------------------------------------------------
# Android patches
# ---------------------------------------------------------------------------
def _android_swap_frida_script_steal_method(artifact: str,
                                              params: Dict[str, Any]) -> Dict[str, Any]:
    """Rewrite the ``Java.choose(...)`` filter in a Frida script::

        Java.choose('com.example.OldClass', {...})
        ->
        Java.choose('com.example.NewClass', {...})
    """
    old = params.get("old") or ""
    new = params.get("new") or ""
    if not old or not new:
        return {"ok": False, "error": "old/new required"}
    if not re.fullmatch(r"[A-Za-z0-9._\$]+", new):
        return {"ok": False, "error": "new class name invalid"}
    new_text, n = re.subn(
        r"Java\.choose\(\s*['\"]" + re.escape(old) + r"['\"]",
        "Java.choose('" + new + "'", artifact)
    if n == 0:
        return {"ok": False, "error": "old Java.choose class not found"}
    return {"ok": True, "text": new_text, "replacements": n,
            "model": "Frida Java.choose filter literal swap"}


def _android_swap_apk_package_id(artifact: str,
                                   params: Dict[str, Any]) -> Dict[str, Any]:
    """Rename the package id in an AndroidManifest.xml snippet::

        package="com.example.old"
        ->
        package="com.example.new"

    Only the ``package=`` attribute on the root <manifest> element
    is touched (not every random ``package=`` in the file)."""
    old = params.get("old") or ""
    new = params.get("new") or ""
    if not old or not new:
        return {"ok": False, "error": "old/new required"}
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+",
                        new):
        return {"ok": False, "error": "new package id invalid"}
    pattern = re.compile(r'(<manifest\b[^>]*\bpackage=")'
                         + re.escape(old) + r'(")')
    new_text, n = pattern.subn(r"\1" + new + r"\2", artifact)
    if n == 0:
        return {"ok": False, "error": "old package= attribute not found"}
    return {"ok": True, "text": new_text, "replacements": n,
            "model": "AndroidManifest package= attribute rename"}


def _android_swap_magisk_module_prop(artifact: str,
                                       params: Dict[str, Any]) -> Dict[str, Any]:
    """Swap ``id=``/``name=`` in a Magisk module.prop::

        id=old_id
        ->
        id=new_id
    """
    field = (params.get("field") or "id").strip()
    old = params.get("old") or ""
    new = params.get("new") or ""
    if field not in ("id", "name", "author", "version", "versionCode"):
        return {"ok": False, "error": "field must be id/name/author/version/versionCode"}
    if not old or not new:
        return {"ok": False, "error": "old/new required"}
    if not re.fullmatch(r"[A-Za-z0-9_\-\.]+", new):
        return {"ok": False, "error": "new value invalid"}
    pattern = re.compile(r"^" + re.escape(field) + r"=.*$",
                          re.MULTILINE)
    new_text, n = pattern.subn(field + "=" + new, artifact)
    if n == 0:
        return {"ok": False, "error": f"{field}= not found"}
    return {"ok": True, "text": new_text, "replacements": n,
            "model": "Magisk module.prop literal swap"}


# ---------------------------------------------------------------------------
# iOS patches
# ---------------------------------------------------------------------------
def _ios_swap_plist_key_value(artifact: str,
                                params: Dict[str, Any]) -> Dict[str, Any]:
    """Literal pair-replace in a .plist snippet::

        <key>OldKey</key>
        <string>OldValue</string>
        ->
        <key>NewKey</key>
        <string>NewValue</string>
    """
    old_key = params.get("old_key") or ""
    new_key = params.get("new_key") or old_key
    old_val = params.get("old_value")
    new_val = params.get("new_value")
    if not old_key or new_val is None:
        return {"ok": False, "error": "old_key and new_value required"}
    if not re.fullmatch(r"[A-Za-z0-9_\-\./]+", new_key):
        return {"ok": False, "error": "new_key invalid"}
    pattern_key = re.compile(
        r"<key>\s*" + re.escape(old_key) + r"\s*</key>\s*"
        r"(<string>\s*[^<]*\s*</string>)")
    if old_val is not None:
        # Swap the inner <string> too.
        pattern_full = re.compile(
            r"(<key>\s*)" + re.escape(old_key) + r"(\s*</key>\s*)"
            r"<string>\s*" + re.escape(str(old_val)) + r"\s*</string>")
        new_text, n = pattern_full.subn(
            r"\1" + new_key + r"\2<string>" + str(new_val) + "</string>",
            artifact)
    else:
        # Just rename the key.
        new_text, n = pattern_key.subn(
            r"<key>" + new_key + r"</key>\1", artifact)
    if n == 0:
        return {"ok": False,
                "error": f"plist key {old_key!r} not found"}
    return {"ok": True, "text": new_text, "replacements": n,
            "model": "plist key/value literal swap"}


def _ios_swap_frida_ios_dump_bundle_id(artifact: str,
                                         params: Dict[str, Any]) -> Dict[str, Any]:
    """Bundle-id swap in a Frida script::

        var old_bundle = "com.example.old"
        ->
        var old_bundle = "com.example.new"
    """
    old = params.get("old") or ""
    new = params.get("new") or ""
    if not old or not new:
        return {"ok": False, "error": "old/new required"}
    if not re.fullmatch(r"[A-Za-z0-9_\-\.]+", new):
        return {"ok": False, "error": "new bundle id invalid"}
    new_text, n = re.subn(
        r'(["\'])' + re.escape(old) + r'(["\'])',
        r'\1' + new + r'\2', artifact)
    if n == 0:
        return {"ok": False, "error": "old bundle id not found"}
    return {"ok": True, "text": new_text, "replacements": n,
            "model": "Frida script bundle-id literal swap"}


def _ios_swap_checkm8_args(artifact: str,
                             params: Dict[str, Any]) -> Dict[str, Any]:
    """checkm8 arglist patch in a shell wrapper::

        ./ipwnder -p old_payload
        ->
        ./ipwnder -p new_payload
    """
    old = params.get("old") or ""
    new = params.get("new") or ""
    if not old or not new:
        return {"ok": False, "error": "old/new required"}
    if not re.fullmatch(r"[A-Za-z0-9_/.\-]+", new):
        return {"ok": False, "error": "new payload path invalid"}
    new_text, n = re.subn(
        r"(-p\s+)" + re.escape(old),
        r"\1" + new, artifact)
    if n == 0:
        return {"ok": False, "error": "old -p arg not found"}
    return {"ok": True, "text": new_text, "replacements": n,
            "model": "checkm8 -p arg literal swap"}


# ---------------------------------------------------------------------------
# Patch catalog
# ---------------------------------------------------------------------------
def _build_catalog() -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    catalog = [
        ("microsoft", "swap_bloodhound_query_param",
         "Rewrite a Cypher MATCH param in a saved .cypher file "
         "(literal text swap, whitelist-validated).",
         {"type": "object",
          "properties": {"artifact": {"type": "string"},
                          "out_path": {"type": "string"},
                          "old_param": {"type": "string"},
                          "new_param": {"type": "string"}},
          "required": ["artifact", "old_param", "new_param"]},
         ["old_param", "new_param"],
         _microsoft_swap_bloodhound_query_param),
        ("microsoft", "swap_powerview_filter",
         "Rewrite a PowerView -Filter argument in a .ps1 wrapper "
         "(literal text swap, whitelist-validated).",
         {"type": "object",
          "properties": {"artifact": {"type": "string"},
                          "out_path": {"type": "string"},
                          "old": {"type": "string"},
                          "new": {"type": "string"}},
          "required": ["artifact", "old", "new"]},
         ["old", "new"],
         _microsoft_swap_powerview_filter),
        ("microsoft", "swap_certipy_template",
         "Rewrite a certipy -template argument (literal text swap, "
         "whitelist-validated).",
         {"type": "object",
          "properties": {"artifact": {"type": "string"},
                          "out_path": {"type": "string"},
                          "old": {"type": "string"},
                          "new": {"type": "string"}},
          "required": ["artifact", "old", "new"]},
         ["old", "new"],
         _microsoft_swap_certipy_template),
        ("android", "swap_frida_script_steal_method",
         "Rewrite a Frida Java.choose filter in a .js file (literal "
         "text swap, whitelist-validated).",
         {"type": "object",
          "properties": {"artifact": {"type": "string"},
                          "out_path": {"type": "string"},
                          "old": {"type": "string"},
                          "new": {"type": "string"}},
          "required": ["artifact", "old", "new"]},
         ["old", "new"],
         _android_swap_frida_script_steal_method),
        ("android", "swap_apk_package_id",
         "Rename the package id in an AndroidManifest.xml snippet "
         "(root <manifest package=> attribute only).",
         {"type": "object",
          "properties": {"artifact": {"type": "string"},
                          "out_path": {"type": "string"},
                          "old": {"type": "string"},
                          "new": {"type": "string"}},
          "required": ["artifact", "old", "new"]},
         ["old", "new"],
         _android_swap_apk_package_id),
        ("android", "swap_magisk_module_prop",
         "Swap id=/name=/author=/version= in a Magisk module.prop.",
         {"type": "object",
          "properties": {"artifact": {"type": "string"},
                          "out_path": {"type": "string"},
                          "field": {"type": "string",
                                    "enum": ["id", "name", "author",
                                             "version", "versionCode"]},
                          "old": {"type": "string"},
                          "new": {"type": "string"}},
          "required": ["artifact", "field", "old", "new"]},
         ["old", "new"],
         _android_swap_magisk_module_prop),
        ("ios", "swap_plist_key_value",
         "Literal pair-replace of <key>/<string> in a .plist snippet.",
         {"type": "object",
          "properties": {"artifact": {"type": "string"},
                          "out_path": {"type": "string"},
                          "old_key": {"type": "string"},
                          "new_key": {"type": "string"},
                          "old_value": {"type": "string"},
                          "new_value": {"type": "string"}},
          "required": ["artifact", "old_key", "new_value"]},
         ["new_value"],
         _ios_swap_plist_key_value),
        ("ios", "swap_frida_ios_dump_bundle_id",
         "Bundle-id swap in a Frida iOS-dump script.",
         {"type": "object",
          "properties": {"artifact": {"type": "string"},
                          "out_path": {"type": "string"},
                          "old": {"type": "string"},
                          "new": {"type": "string"}},
          "required": ["artifact", "old", "new"]},
         ["old", "new"],
         _ios_swap_frida_ios_dump_bundle_id),
        ("ios", "swap_checkm8_args",
         "checkm8 -p arglist patch in a shell wrapper (literal text "
         "swap, whitelist-validated).",
         {"type": "object",
          "properties": {"artifact": {"type": "string"},
                          "out_path": {"type": "string"},
                          "old": {"type": "string"},
                          "new": {"type": "string"}},
          "required": ["artifact", "old", "new"]},
         ["old", "new"],
         _ios_swap_checkm8_args),
    ]
    for tc, pid, desc, schema, mut_keys, fn in catalog:
        out.append({
            "patch_id": f"{tc}::{pid}",
            "target_class": tc,
            "method": pid,
            "name": f"live_target_{tc}_{pid}",
            "description": desc,
            "input_schema": schema,
            "examples": [f"live_target(patch_id='{tc}::{pid}', "
                          f"artifact=<text>, ...)"],
            "risk_level": "intrusive",
            "requires_root": False,
            "mutable_keys": mut_keys,
            "fn": fn,
        })
    return out


LIVE_TARGET_PATCHES: List[Dict[str, Any]] = _build_catalog()


# ---------------------------------------------------------------------------
# Module-level entrypoint
# ---------------------------------------------------------------------------
def run_patch(patch_id: str, target_class: str = "",
              params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Apply a single safe patch. The patch is identified by
    ``patch_id`` (e.g. ``"microsoft::swap_powerview_filter"``) or
    by just the method name (e.g. ``"swap_powerview_filter"``)
    when ``target_class`` is supplied.

    The runner:
      1. Looks up the patch in :data:`LIVE_TARGET_PATCHES`.
      2. Validates the params (no shell metas, no forbidden exec
         APIs).
      3. Applies the patch (literal text swap inside the supplied
         artifact text).
      4. Optionally writes the modified text to ``out_path``
         (default: in-memory echo, no file write).
      5. Returns ``{ok, data, error}``. Never raises."""
    params = params or {}
    # Resolve patch.
    spec = None
    if "::" in (patch_id or ""):
        for s in LIVE_TARGET_PATCHES:
            if s["patch_id"] == patch_id:
                spec = s
                break
    else:
        for s in LIVE_TARGET_PATCHES:
            if s["method"] == patch_id:
                if not target_class or s["target_class"] == target_class:
                    spec = s
                    break
    if spec is None:
        return {"ok": False, "error": f"unknown patch_id {patch_id!r}",
                "data": None, "name": "live_target",
                "duration_s": 0.0}
    tc = spec["target_class"]
    pid = spec["method"]
    artifact = params.get("artifact") or ""
    if not artifact:
        return {"ok": False, "error": "artifact text required",
                "data": None, "name": f"live_target_{tc}_{pid}",
                "duration_s": 0.0}
    v = validate_params(tc, pid, params)
    if not v["ok"]:
        return {"ok": False, "error": v["error"],
                "data": None, "name": f"live_target_{tc}_{pid}",
                "duration_s": 0.0}
    try:
        res = spec["fn"](artifact, params)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"patch: {e}",
                "data": None, "name": f"live_target_{tc}_{pid}",
                "duration_s": 0.0}
    if not res.get("ok"):
        return {"ok": False, "error": res.get("error") or "patch failed",
                "data": None, "name": f"live_target_{tc}_{pid}",
                "duration_s": 0.0}
    new_text = res.get("text") or ""
    # Validate the swapped-in *value* (not the entire artifact
    # text) through the runtime guard. The ``new``/``new_value``/
    # ``new_param`` param is the only string the patch injects; the
    # original artifact is operator-supplied and may already
    # contain any byte sequence.
    injected = (params.get("new") or params.get("new_value")
                or params.get("new_param") or "")
    g = validate_swap(tc, pid, params.get("old") or "", injected)
    if not g["ok"]:
        return {"ok": False, "error": g["error"],
                "data": None, "name": f"live_target_{tc}_{pid}",
                "duration_s": 0.0}
    # Optionally write to out_path.
    out_path = params.get("out_path")
    if out_path:
        try:
            os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
            with open(out_path, "w", encoding="utf-8") as fh:
                fh.write(new_text)
        except OSError as e:
            return {"ok": False, "error": f"write out_path: {e}",
                    "data": None,
                    "name": f"live_target_{tc}_{pid}",
                    "duration_s": 0.0}
    return {"ok": True, "data": {
                "patch_id": spec["patch_id"],
                "target_class": tc,
                "method": pid,
                "replacements": res.get("replacements", 0),
                "model": res.get("model", ""),
                "new_text": new_text,
                "out_path": out_path or "",
                "wrote_file": bool(out_path),
                "warnings": g.get("warnings", []),
            },
            "name": f"live_target_{tc}_{pid}",
            "error": "",
            "duration_s": 0.0}
