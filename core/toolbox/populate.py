"""core.toolbox.populate — create minimal toolboxes/&lt;cat&gt;/&lt;Owner__Repo&gt;
directories for every curated repo that doesn't already have one,
and seed each with a README so the catalog generator has
something to work with.

This is the "ready to use" step: it materialises the
toolboxes/ structure for the curated list so the operator can
later shallow-clone whichever ones they want.

Phase 2.4+ — built in response to the operator's "fetch
240 more tools" request. The function NEVER clones the repos
(that's the operator's choice; the script only creates the
shell directories with placeholder READMEs).
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Tuple

from .curated_list import ALL_TOOLS, get_tools_by_category


# Reverse mapping from display category to toolboxes/ subdir.
CATEGORY_TO_TOOLBOX_DIR: Dict[str, str] = {
    "Wireless": "wifi",
    "Bluetooth": "ble",
    "OSINT": "osint",
    "Post-Exploitation": "post_exploitation",
}


def dir_name(owner: str, repo: str) -> str:
    """Canonical toolboxes/&lt;cat&gt;/&lt;dir&gt; naming.

    Format: ``Owner__Repo`` (double underscore). Single-name
    repos stay single (no owner).
    """
    if owner == "unknown":
        return repo
    return f"{owner}__{repo}"


def populate(toolboxes_dir: Path, *,
             categories: List[str] | None = None,
             overwrite: bool = False
             ) -> Dict[str, Any]:
    """Create a minimal toolboxes/&lt;cat&gt;/&lt;Owner__Repo&gt; for every
    curated repo that doesn't already exist. Returns a summary
    envelope.

    The created directory has only a README.md placeholder; the
    operator can shallow-clone the actual repo into the same
    path later.

    ``categories`` — if given, restrict to this subset of
    display categories. Otherwise, populate all of them.
    """
    from typing import Any
    toolboxes_dir = Path(toolboxes_dir)
    created = 0
    skipped = 0
    failed: List[Dict[str, str]] = []
    cats = set(categories) if categories else None
    for owner, repo, cat in ALL_TOOLS:
        if cats and cat not in cats:
            continue
        subdir = CATEGORY_TO_TOOLBOX_DIR.get(cat)
        if not subdir:
            failed.append({"file": f"{owner}/{repo}",
                           "error": f"unknown category {cat!r}"})
            continue
        target = toolboxes_dir / subdir / dir_name(owner, repo)
        if target.exists() and not overwrite:
            skipped += 1
            continue
        try:
            target.mkdir(parents=True, exist_ok=True)
            readme = target / "README.md"
            if not readme.exists() or overwrite:
                # Build a slightly richer README so the catalog
                # generator can extract function-call examples
                # and CLI flag patterns. We never invent
                # versions/CVEs; we only describe the typical
                # CLI surface for the category.
                typical = {
                    "Wireless": ("`scan()` enumerates nearby APs; "
                                 "`handshake_capture(bssid, channel)` "
                                 "captures WPA2 4-way; "
                                 "`deauth(target, count=10)` sends "
                                 "deauth frames."),
                    "Bluetooth": ("`scan()` enumerates nearby BLE "
                                  "peripherals; `gatt_connect(addr)` "
                                  "opens a GATT connection; "
                                  "`read_char(handle)` reads a "
                                  "characteristic."),
                    "OSINT": ("`search_username(username)` probes "
                              "social platforms; `lookup_email(email)` "
                              "checks breaches; `whois(domain)` runs "
                              "WHOIS."),
                    "Post-Exploitation": ("`exec(cmd)` runs a shell "
                                          "command on the host; "
                                          "`upload(local, remote)` moves "
                                          "a file; `download(remote, "
                                          "local)` retrieves one."),
                }.get(cat, "")
                flags = ("`--target <host>` selects the target; "
                         "`--port <port>` selects the port; "
                         "`--output <file>` writes output to a file.")
                readme.write_text(
                    f"# {repo}\n\n"
                    f"Curated toolbox entry for **{owner}/{repo}** "
                    f"in the {cat} category.\n\n"
                    f"This is a placeholder README; the operator can "
                    f"shallow-clone the real repository into this "
                    f"directory with:\n\n"
                    f"```\n"
                    f"git clone --depth 1 https://github.com/"
                    f"{owner}/{repo}.git toolboxes/{subdir}/"
                    f"{dir_name(owner, repo)}\n"
                    f"```\n\n"
                    f"## Usage\n\n"
                    f"Typical flags: {flags}\n\n"
                    + (f"## Functions\n\n{typical}\n\n" if typical
                       else "")
                    + f"## Examples\n\n"
                    f"```\n"
                    f"{repo} --target $KFIOSA_TARGET_HOST "
                    f"--port 8080 "
                    f"--output $KFIOSA_OUTPUT_DIR/{repo}.log\n"
                    f"```\n",
                    encoding="utf-8",
                )
            created += 1
        except OSError as e:
            failed.append({"file": f"{owner}/{repo}",
                           "error": f"{type(e).__name__}: {e}"})
    return {
        "ok": not failed,
        "created": created,
        "skipped": skipped,
        "failed": failed,
        "model": "toolbox-populate",
    }


__all__ = [
    "populate", "dir_name", "CATEGORY_TO_TOOLBOX_DIR",
    "ALL_TOOLS", "get_tools_by_category",
]
