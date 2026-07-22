"""core.post_access_tui.network_panel_capabilities — dynamic-menu catalog
for the network session multiplexer panel.

Mirrors the BLE / WiFi capability pattern: every action is registered
once in :data:`CAPABILITY_CATALOG` (frozen dataclass) with a single
hotkey, label, risk level, availability predicate, and help text. The
panel's dynamic menu is recomputed from this catalog on every state
change — capabilities whose ``availability_fn`` returns False are
hidden.

Safety stance (carried over):
  - All sessions are operator-gated via the screen's ``confirm_fn``
    BEFORE dispatch (single-gate invariant).
  - The panel NEVER auto-opens a session. It surfaces the
    ``ssh`` / ``msfconsole`` / ``chisel`` / ``socat`` / revshell
    command for the operator to run via the integrated terminal.
  - No fabricated session ids, no fabricated handshakes, no
    fabricated creds. All sub-process results are passed through
    to the screen's audit log.

Risk levels:
  - ``RISK_READ``      : no side effects on target; reading state
                         (list / show / portfwd list / socks status).
  - ``RISK_INTRUSIVE`` : sends commands to an active session;
                         requires the gate prompt.
  - ``RISK_DESTRUCTIVE``: broadcasts a command to ALL sessions
                         (``broadcast``); also covers session
                         ``kill`` (tears down a session that may
                         be holding a foothold).

Catalog size target: ~25 capabilities — one for every meaningful
per-session action plus the per-transport session starters.
"""
from __future__ import annotations

import dataclasses
from typing import Any, Callable, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Risk levels
# ---------------------------------------------------------------------------

RISK_READ: str = "read"
RISK_INTRUSIVE: str = "intrusive"
RISK_DESTRUCTIVE: str = "destructive"


# ---------------------------------------------------------------------------
# Network panel state snapshot
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class NetworkPanelState:
    """Snapshot of what the network panel sees RIGHT NOW.

    The panel recomputes this from its in-memory fields (sessions,
    active_session_id, portfwd list, socks running) on every action.
    The dynamic menu is then filtered by ``availability_fn(state)``.

    Attributes:
        sessions:           list of session dicts (id, transport, host,
                            port, alive, last_output_excerpt).
        active_session_id:  id of the session currently attached for
                            shell / file ops; ``None`` when no session
                            is attached.
        portfwd_count:      number of active port forwards.
        socks_running:      True when the SOCKS proxy is up.
        tools_available:    dict of ``tool_name -> bool`` indicating
                            which network tools are present on the
                            operator's box (ssh, msfconsole, chisel,
                            socat, etc.). The panel hides session
                            starters whose tool is missing.
        input_active:       True when ``input_fn`` is wired in
                            (the screen provides it; tests provide
                            a fake). When False, prompts are emitted
                            to ``on_event`` and the panel degrades
                            honestly.
    """
    sessions: List[Dict[str, Any]] = dataclasses.field(default_factory=list)
    active_session_id: Optional[str] = None
    portfwd_count: int = 0
    socks_running: bool = False
    tools_available: Dict[str, bool] = dataclasses.field(default_factory=dict)
    input_active: bool = True

    # -- predicate helpers ------------------------------------------------
    def has_sessions(self) -> bool:
        return len(self.sessions) > 0

    def has_active_session(self) -> bool:
        return (
            self.active_session_id is not None
            and any(s.get("id") == self.active_session_id for s in self.sessions)
        )

    def session_count(self) -> int:
        return len(self.sessions)

    def has_multiple_sessions(self) -> bool:
        return len(self.sessions) >= 2

    def has_portfwds(self) -> bool:
        return self.portfwd_count > 0

    def has_socks(self) -> bool:
        return self.socks_running

    def has_tool(self, name: str) -> bool:
        return bool(self.tools_available.get(name, False))


# ---------------------------------------------------------------------------
# Capability descriptor
# ---------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class Capability:
    """One row in the dynamic menu.

    Attributes:
        action:           canonical name (e.g. ``"shell"``, ``"kill"``).
        hotkey:           single-letter (case-insensitive) hotkey.
        label:            human-readable label for the menu (e.g.
                          ``"[S]hell — send a command to active session"``).
        risk:             one of :data:`RISK_READ`,
                          :data:`RISK_INTRUSIVE`,
                          :data:`RISK_DESTRUCTIVE`.
        requires_gate:    True for actions that mutate the target
                          (shell, file_get, file_put, broadcast, kill,
                          new-session, socks start, portfwd add).
                          False for read-only state inspections.
        availability_fn:  ``NetworkPanelState -> bool``. Exceptions
                          are treated as "hidden" — a buggy predicate
                          never crashes the whole menu.
        needs:            optional list of tool names that must be
                          present for the action to make sense (used
                          to color the menu line and to gate
                          session-start entries).
        help_text:        one-line help text shown by ``[?] Help``.
    """
    action: str
    hotkey: str
    label: str
    risk: str
    requires_gate: bool
    availability_fn: Callable[[NetworkPanelState], bool]
    needs: Tuple[str, ...] = ()
    help_text: str = ""


# ---------------------------------------------------------------------------
# Predicate factories — each returns a fresh predicate closure.
# ---------------------------------------------------------------------------

def _always(_state: NetworkPanelState) -> bool:
    return True


def _has_sessions(state: NetworkPanelState) -> bool:
    return state.has_sessions()


def _has_active_session(state: NetworkPanelState) -> bool:
    return state.has_active_session()


def _has_multiple_sessions(state: NetworkPanelState) -> bool:
    return state.has_multiple_sessions()


def _has_portfwds(state: NetworkPanelState) -> bool:
    return state.has_portfwds()


def _has_socks(state: NetworkPanelState) -> bool:
    return state.has_socks()


def _has_tool(name: str) -> Callable[[NetworkPanelState], bool]:
    def _pred(state: NetworkPanelState) -> bool:
        return state.has_tool(name)
    _pred.__name__ = f"_has_tool_{name}"
    return _pred


def _has_tool_and(*names: str) -> Callable[[NetworkPanelState], bool]:
    def _pred(state: NetworkPanelState) -> bool:
        return all(state.has_tool(n) for n in names)
    _pred.__name__ = "_has_tool_and_" + "_".join(names)
    return _pred


def _has_sessions_and_tool(name: str) -> Callable[[NetworkPanelState], bool]:
    def _pred(state: NetworkPanelState) -> bool:
        return state.has_sessions() and state.has_tool(name)
    _pred.__name__ = f"_has_sessions_and_tool_{name}"
    return _pred


# ---------------------------------------------------------------------------
# Catalog
# ---------------------------------------------------------------------------

#: All registered capabilities (immutable list; new entries are
#: appended at module load).
CAPABILITY_CATALOG: List[Capability] = [
    # -- universal (always visible) ------------------------------------
    Capability(
        action="help", hotkey="?",
        label="[?] Help — show menu + key bindings",
        risk=RISK_READ, requires_gate=False,
        availability_fn=_always,
        help_text="Show the current dynamic menu + per-action help text.",
    ),
    Capability(
        action="exit", hotkey="e",
        label="[E]xit — return to post-access main menu",
        risk=RISK_READ, requires_gate=False,
        availability_fn=_always,
        help_text="Close the network panel and return to the screen.",
    ),

    # -- session inspection (visible as soon as any session is open) --
    Capability(
        action="list", hotkey="l",
        label="[L]ist — show active sessions",
        risk=RISK_READ, requires_gate=False,
        availability_fn=_always,
        help_text="List every active session (id, transport, host, port, alive).",
    ),
    Capability(
        action="view", hotkey="v",
        label="[V]iew — show last output of active session",
        risk=RISK_READ, requires_gate=False,
        availability_fn=_has_active_session,
        help_text="Show the buffered last_output of the active session.",
    ),
    Capability(
        action="attach", hotkey="a",
        label="[A]ttach — switch active session by id",
        risk=RISK_READ, requires_gate=False,
        availability_fn=_has_multiple_sessions,
        help_text="Pick which session is the active one for shell/file ops.",
    ),
    Capability(
        action="kill", hotkey="k",
        label="[K]ill — terminate a session",
        risk=RISK_DESTRUCTIVE, requires_gate=True,
        availability_fn=_has_sessions,
        help_text=(
            "Tear down a session. Destructive because the session may "
            "be the only foothold on the target. Requires ACCEPT."
        ),
    ),
    Capability(
        action="broadcast", hotkey="*",
        label="[*] Broadcast — send one command to ALL sessions",
        risk=RISK_DESTRUCTIVE, requires_gate=True,
        availability_fn=_has_multiple_sessions,
        help_text=(
            "Send the same shell command to every active session. "
            "Destructive because one bad command hits every target. "
            "Requires ACCEPT."
        ),
    ),
    # -- per-session actions (require an active session) --------------
    Capability(
        action="shell", hotkey="s",
        label="[S]hell — run a command on the active session",
        risk=RISK_INTRUSIVE, requires_gate=True,
        availability_fn=_has_active_session,
        help_text=(
            "Run one command on the active session. Transport-aware: "
            "msfconsole for MSF sessions, ssh otherwise. Requires ACCEPT."
        ),
    ),
    Capability(
        action="get", hotkey="g",
        label="[G]et — pull a file from the active session",
        risk=RISK_INTRUSIVE, requires_gate=True,
        availability_fn=_has_sessions_and_tool("ssh"),
        help_text=(
            "Download a file from the active session. Uses scp for "
            "ssh sessions. Requires ACCEPT."
        ),
    ),
    Capability(
        action="put", hotkey="T",
        label="[T] Put — push a file to the active session",
        risk=RISK_INTRUSIVE, requires_gate=True,
        availability_fn=_has_sessions_and_tool("ssh"),
        help_text=(
            "Upload a file to the active session. Uses scp for "
            "ssh sessions. Requires ACCEPT."
        ),
    ),
    Capability(
        action="portfwd_add", hotkey="+",
        label="[+] Add portfwd — local:port -> target:port",
        risk=RISK_INTRUSIVE, requires_gate=True,
        availability_fn=_has_active_session,
        help_text=(
            "Add a port-forward via the active session. Uses "
            "msfconsole portfwd or ssh -L. Requires ACCEPT."
        ),
    ),
    Capability(
        action="portfwd_list", hotkey="=",
        label="[=] List portfwd — show all active port forwards",
        risk=RISK_READ, requires_gate=False,
        availability_fn=_has_portfwds,
        help_text="List every active port-forward added via [+] Add portfwd.",
    ),
    Capability(
        action="portfwd_kill", hotkey="-",
        label="[-] Kill portfwd — remove a port forward",
        risk=RISK_INTRUSIVE, requires_gate=True,
        availability_fn=_has_portfwds,
        help_text="Tear down a previously-added port-forward. Requires ACCEPT.",
    ),

    # -- SOCKS (read-only when up; write when starting) ---------------
    Capability(
        action="socks_start", hotkey="o",
        label="[O] SOCKS start — bring up SOCKS proxy on :port",
        risk=RISK_INTRUSIVE, requires_gate=True,
        availability_fn=lambda s: not s.has_socks(),
        help_text=(
            "Start a SOCKS5 proxy reachable through the active session. "
            "Hidden when socks is already running. Requires ACCEPT."
        ),
    ),
    Capability(
        action="socks_stop", hotkey="Q",
        label="[Q] SOCKS stop — tear down the SOCKS proxy",
        risk=RISK_INTRUSIVE, requires_gate=True,
        availability_fn=_has_socks,
        help_text=(
            "Tear down the SOCKS5 proxy. Visible only when socks is "
            "running. Requires ACCEPT."
        ),
    ),

    # -- session starters (per transport) ----------------------------
    Capability(
        action="new_ssh", hotkey="1",
        label="[1] New SSH session — ssh user@host",
        risk=RISK_INTRUSIVE, requires_gate=True,
        availability_fn=_has_tool("ssh"),
        help_text=(
            "Open a new SSH session. The operator types user@host. "
            "Requires ACCEPT. Hidden if ssh is not installed."
        ),
    ),
    Capability(
        action="new_msf", hotkey="2",
        label="[2] New MSF session — msfconsole -q -x 'sessions -i N'",
        risk=RISK_INTRUSIVE, requires_gate=True,
        availability_fn=_has_tool("msfconsole"),
        help_text=(
            "Open a new meterpreter session by id. Requires ACCEPT. "
            "Hidden if msfconsole is not installed."
        ),
    ),
    Capability(
        action="new_chisel", hotkey="3",
        label="[3] New Chisel session — chisel client/server",
        risk=RISK_INTRUSIVE, requires_gate=True,
        availability_fn=_has_tool("chisel"),
        help_text=(
            "Open a Chisel tunnel session (client or server). "
            "Requires ACCEPT. Hidden if chisel is not installed."
        ),
    ),
    Capability(
        action="new_socat", hotkey="4",
        label="[4] New socat session — socat TCP-LISTEN/TCP",
        risk=RISK_INTRUSIVE, requires_gate=True,
        availability_fn=_has_tool("socat"),
        help_text=(
            "Open a socat relay session. Requires ACCEPT. Hidden if "
            "socat is not installed."
        ),
    ),
    Capability(
        action="new_revshell", hotkey="5",
        label="[5] New reverse shell — bash/python/powershell",
        risk=RISK_DESTRUCTIVE, requires_gate=True,
        availability_fn=_always,
        help_text=(
            "Open a reverse shell session (the operator runs the "
            "listener; KFIOSA tracks the session). Destructive "
            "because the shell is a one-shot foothold. Requires ACCEPT."
        ),
    ),
    Capability(
        action="new_local", hotkey="6",
        label="[6] New local shell — run a command locally",
        risk=RISK_READ, requires_gate=False,
        availability_fn=_always,
        help_text=(
            "Open a local shell session. Does NOT contact any "
            "remote target — runs on the operator's box."
        ),
    ),

    # -- module runner (re-runs post_exploit.runner_ext methods) -----
    Capability(
        action="module", hotkey="m",
        label="[M]odule — re-run a post_exploit method on active session",
        risk=RISK_INTRUSIVE, requires_gate=True,
        availability_fn=_has_active_session,
        help_text=(
            "Pick one of the post_exploit.runner_ext methods and run "
            "it on the active session. Requires ACCEPT."
        ),
    ),
    Capability(
        action="persistence", hotkey="P",
        label="[P]ersistence — install a persistence method",
        risk=RISK_DESTRUCTIVE, requires_gate=True,
        availability_fn=_has_active_session,
        help_text=(
            "Install a persistence method on the active session. "
            "Destructive because persistence leaves a footprint. "
            "Requires ACCEPT."
        ),
    ),

    # -- per-session read-only views (always visible but useful only --
    # -- with a session) ---------------------------------------------
    Capability(
        action="audit", hotkey="u",
        label="[U] Audit — show last envelopes from this panel",
        risk=RISK_READ, requires_gate=False,
        availability_fn=_always,
        help_text=(
            "Show the last envelopes emitted by the network panel "
            "(capped to 20)."
        ),
    ),
    Capability(
        action="refresh", hotkey="r",
        label="[R]efresh — re-poll session liveness",
        risk=RISK_READ, requires_gate=False,
        availability_fn=_has_sessions,
        help_text=(
            "Re-poll every session's liveness. Updates the alive flag "
            "in the dynamic menu so killed sessions vanish from the "
            "active-session rotation."
        ),
    ),
    Capability(
        action="ai_plan", hotkey="I",
        label="[I] AI plan — heuristic recommendations (not trained)",
        risk=RISK_READ, requires_gate=False,
        availability_fn=_has_sessions,
        help_text=(
            "Run a heuristic (not trained) planner over the current "
            "session state and emit recommendations: e.g. "
            "'enable socks', 'add portfwd 8080->target:80'."
        ),
    ),

    # -- post-exploitation anti-forensic / persistence modules --------
    Capability(
        action="cred_harvest", hotkey="h",
        label="[H] Cred-harvest — run a credential-dumper module",
        risk=RISK_DESTRUCTIVE, requires_gate=True,
        availability_fn=_has_active_session,
        help_text=(
            "Pick a credential-dumper (mimikatz, pypykatz, lsassy, "
            "secretsdump) and run on the active session. Returns "
            "credentials, never writes to disk. Destructive because "
            "credential dumps touch the LSASS / shadow file."
        ),
    ),
    Capability(
        action="cred_enumerate", hotkey="H",
        label="[H2] Cred-enum — enumerate cred material on disk",
        risk=RISK_INTRUSIVE, requires_gate=True,
        availability_fn=_has_active_session,
        help_text=(
            "Enumerate potential credential sources on the active "
            "session (browser cookies, SSH keys, config files, "
            "/etc/shadow, KRB tickets)."
        ),
    ),
    Capability(
        action="pivot_smb", hotkey="b",
        label="[B] Pivot-SMB — map SMB shares across the network",
        risk=RISK_INTRUSIVE, requires_gate=True,
        availability_fn=_has_active_session,
        help_text=(
            "Use the active session as a pivot to enumerate SMB "
            "shares on reachable hosts (crackmapexec, smbclient, "
            "impacket smbclient). Returns the share list per host."
        ),
    ),
    Capability(
        action="pivot_winrm", hotkey="W",
        label="[W] Pivot-WinRM — WinRM to nearby hosts",
        risk=RISK_INTRUSIVE, requires_gate=True,
        availability_fn=_has_active_session,
        help_text=(
            "Use the active session as a pivot to WinRM into nearby "
            "hosts (evil-winrm, pypsrp). Useful for AD lateral "
            "movement."
        ),
    ),
    Capability(
        action="pivot_ssh", hotkey="Y",
        label="[Y] Pivot-SSH — SSH to nearby hosts",
        risk=RISK_INTRUSIVE, requires_gate=True,
        availability_fn=_has_active_session,
        help_text=(
            "Use the active session as a pivot to SSH into nearby "
            "hosts (paramiko, ssh). Useful for Linux lateral movement."
        ),
    ),
    Capability(
        action="pivot_wmi", hotkey="w",
        label="[w] Pivot-WMI — WMI to nearby hosts",
        risk=RISK_INTRUSIVE, requires_gate=True,
        availability_fn=_has_active_session,
        help_text=(
            "Use the active session as a pivot to WMI into nearby "
            "Windows hosts (impacket wmiexec)."
        ),
    ),
    Capability(
        action="pivot_ldap", hotkey="L",
        label="[L] Pivot-LDAP — AD LDAP query via the session",
        risk=RISK_INTRUSIVE, requires_gate=True,
        availability_fn=_has_active_session,
        help_text=(
            "Use the active session to query AD LDAP (ldap3). "
            "Returns users, groups, computers, GPOs, trusts."
        ),
    ),
    Capability(
        action="adcs_enum", hotkey="c",
        label="[c] ADCS-enum — Active Directory Certificate Services",
        risk=RISK_INTRUSIVE, requires_gate=True,
        availability_fn=_has_active_session,
        help_text=(
            "Enumerate ADCS templates, CAs, and ESC1-ESC11 "
            "vulnerabilities (certipy, certi, pyForgeCert)."
        ),
    ),
    Capability(
        action="kerberoast", hotkey="K",
        label="[K] Kerberoast — SPN ticket capture + crack",
        risk=RISK_DESTRUCTIVE, requires_gate=True,
        availability_fn=_has_active_session,
        help_text=(
            "Request service tickets for accounts with SPNs; "
            "extract + crack offline. Destructive because ticket "
            "requesting is logged on the KDC."
        ),
    ),
    Capability(
        action="asreproast", hotkey="Z",
        label="[Z] AS-REP-roast — accounts without pre-auth",
        risk=RISK_DESTRUCTIVE, requires_gate=True,
        availability_fn=_has_active_session,
        help_text=(
            "Send AS-REQ for accounts with 'Do not require Kerberos "
            "preauthentication' set; capture + crack offline. "
            "Destructive because the request is logged."
        ),
    ),
    Capability(
        action="ntlmrelay", hotkey="N",
        label="[N] NTLM-relay — relay captured NTLM auth",
        risk=RISK_DESTRUCTIVE, requires_gate=True,
        availability_fn=_has_active_session,
        help_text=(
            "Relay NTLM authentication to a target service "
            "(responder + ntlmrelayx). Destructive because relayed "
            "auth grants code execution as the relayed user."
        ),
    ),
    Capability(
        action="secretsdump", hotkey="X",
        label="[X] Secretsdump — DC + local SAM/LSA secrets",
        risk=RISK_DESTRUCTIVE, requires_gate=True,
        availability_fn=_has_active_session,
        help_text=(
            "impacket-secretsdump from the active session. "
            "Destructive because it dumps the entire AD password "
            "database."
        ),
    ),
    Capability(
        action="dcsync", hotkey="D",
        label="[D] DCSync — replicate AD password hashes",
        risk=RISK_DESTRUCTIVE, requires_gate=True,
        availability_fn=_has_active_session,
        help_text=(
            "impacket-secretsdump with DRSUAPI to a DC. Requires "
            "Get-Replicating-Changes privileges. Destructive because "
            "all AD hashes are extracted."
        ),
    ),
    Capability(
        action="golden_ticket", hotkey="G",
        label="[G] Golden-ticket — krbtgt hash -> TGT",
        risk=RISK_DESTRUCTIVE, requires_gate=True,
        availability_fn=_has_active_session,
        help_text=(
            "Forge a Kerberos Golden Ticket using the krbtgt hash. "
            "Destructive because it grants TGTs for arbitrary users "
            "until krbtgt is rotated."
        ),
    ),
    Capability(
        action="silver_ticket", hotkey="S2",
        label="[S2] Silver-ticket — service hash -> TGS",
        risk=RISK_DESTRUCTIVE, requires_gate=True,
        availability_fn=_has_active_session,
        help_text=(
            "Forge a Kerberos Silver Ticket using a service account's "
            "hash. Destructive because it grants service access "
            "without touching the KDC."
        ),
    ),
    Capability(
        action="pass_the_hash", hotkey="F",
        label="[F] PtH — pass-the-hash auth with NTLM",
        risk=RISK_DESTRUCTIVE, requires_gate=True,
        availability_fn=_has_active_session,
        help_text=(
            "Authenticate using an NTLM hash without the plaintext "
            "password (impacket-psexec, impacket-wmiexec, "
            "impacket-smbexec)."
        ),
    ),
    Capability(
        action="bloodhound", hotkey="B2",
        label="[B2] BloodHound — collect AD attack-path data",
        risk=RISK_INTRUSIVE, requires_gate=True,
        availability_fn=_has_active_session,
        help_text=(
            "Run SharpHound / bloodhound-python from the active "
            "session to collect AD attack-path data and import into "
            "BloodHound."
        ),
    ),
    Capability(
        action="forensic_acquire", hotkey="J",
        label="[J] Forensic-acquire — memory + disk image",
        risk=RISK_DESTRUCTIVE, requires_gate=True,
        availability_fn=_has_active_session,
        help_text=(
            "Acquire a memory image (winpmem, avml, LiME) and disk "
            "image (dd, FTK, ddrescue) from the active session. "
            "Destructive because it generates a large artifact set."
        ),
    ),
    Capability(
        action="anti_log_clear", hotkey="X2",
        label="[X2] Anti-log-clear — wipe event logs / artifacts",
        risk=RISK_DESTRUCTIVE, requires_gate=True,
        availability_fn=_has_active_session,
        help_text=(
            "Clear Windows event logs, bash_history, /var/log/*. "
            "Anti-forensic: destroys evidence of the intrusion."
        ),
    ),
    Capability(
        action="timestomp", hotkey="T2",
        label="[T2] Timestomp — modify file MAC times",
        risk=RISK_INTRUSIVE, requires_gate=True,
        availability_fn=_has_active_session,
        help_text=(
            "Modify file Modify/Access/Create times on the active "
            "session to blend with neighboring files (touch -t, "
            "Set-Mtime, SetFileTime)."
        ),
    ),
    Capability(
        action="amsi_bypass", hotkey="M2",
        label="[M2] AMSI-bypass — disable PowerShell AMSI",
        risk=RISK_INTRUSIVE, requires_gate=True,
        availability_fn=_has_active_session,
        help_text=(
            "Patch amsi.dll!AmsiScanBuffer to always return clean. "
            "Lab only — disables a key Windows defense."
        ),
    ),
    Capability(
        action="uac_bypass", hotkey="U2",
        label="[U2] UAC-bypass — silent admin elevation",
        risk=RISK_INTRUSIVE, requires_gate=True,
        availability_fn=_has_active_session,
        help_text=(
            "Trigger a UAC auto-elevation bypass (fodhelper, "
            "eventvwr, computerdefaults, etc.). Lab only — bypasses "
            "a Windows integrity control."
        ),
    ),
    Capability(
        action="edr_evasion", hotkey="E",
        label="[E] EDR-evasion — kill / blind endpoint defenses",
        risk=RISK_DESTRUCTIVE, requires_gate=True,
        availability_fn=_has_active_session,
        help_text=(
            "Disable / tamper with EDR userspace hooks, ETW "
            "providers, kernel callbacks. Lab only — actively "
            "fights a defensive product."
        ),
    ),
    Capability(
        action="process_inject", hotkey="j",
        label="[j] Process-inject — shellcode into a remote process",
        risk=RISK_DESTRUCTIVE, requires_gate=True,
        availability_fn=_has_active_session,
        help_text=(
            "Inject a shellcode payload into a remote process via "
            "CreateRemoteThread / NtMapViewOfSection. Lab only — "
            "active process tampering."
        ),
    ),
    Capability(
        action="ransomware_sim", hotkey="R2",
        label="[R2] Ransomware-sim — encrypt-and-recover drill",
        risk=RISK_DESTRUCTIVE, requires_gate=True,
        availability_fn=_has_active_session,
        help_text=(
            "Run a ransomware-style encryption drill against a "
            "scoped sandbox directory; verify recovery from the "
            "operator's pre-staged backup. Lab only — the operator "
            "owns the data."
        ),
    ),
]


# ---------------------------------------------------------------------------
# Visible-menu computation (the heart of the dynamic menu)
# ---------------------------------------------------------------------------

def compute_visible_menu(state: NetworkPanelState) -> List[Capability]:
    """Filter :data:`CAPABILITY_CATALOG` by ``availability_fn(state)``.

    A buggy ``availability_fn`` is treated as "hidden" — the catalog
    keeps rendering instead of crashing the whole panel.

    Args:
        state: the current :class:`NetworkPanelState` snapshot.

    Returns:
        The list of capabilities currently applicable, in catalog order.
    """
    visible: List[Capability] = []
    for cap in CAPABILITY_CATALOG:
        try:
            if bool(cap.availability_fn(state)):
                visible.append(cap)
        except Exception:  # noqa: BLE001
            # Buggy predicate: hide this capability, keep the rest.
            continue
    return visible


# ---------------------------------------------------------------------------
# Default menu (when no sessions are active)
# ---------------------------------------------------------------------------

def default_disconnected_menu() -> List[Tuple[str, str]]:
    """Return the hotkey→label pairs for the default (no-session) menu.

    Useful for the on-screen hint when the dynamic menu is empty.
    Mirrors the on-disk state at module-load time.
    """
    return [
        ("?", "Help — show the dynamic menu"),
        ("e", "Exit — return to post-access main menu"),
        ("l", "List — show active sessions"),
        ("1", "New SSH session"),
        ("2", "New MSF session"),
        ("3", "New Chisel session"),
        ("4", "New socat session"),
        ("5", "New reverse shell"),
        ("6", "New local shell"),
        ("u", "Audit — show last envelopes"),
    ]


def friendly_action(action: str) -> str:
    """Map an action name to a human-readable label fragment.

    Used by the help text builder. Returns ``action`` itself when
    no override is registered (so unknown actions degrade honestly).
    """
    overrides: Dict[str, str] = {
        "new_ssh": "open a new SSH session",
        "new_msf": "open a new meterpreter session by id",
        "new_chisel": "open a new Chisel tunnel session",
        "new_socat": "open a new socat relay session",
        "new_revshell": "open a new reverse shell session",
        "new_local": "open a local shell session",
        "portfwd_add": "add a port-forward",
        "portfwd_list": "list active port-forwards",
        "portfwd_kill": "remove a port-forward",
        "socks_start": "start SOCKS5 proxy",
        "socks_stop": "stop SOCKS5 proxy",
        "broadcast": "broadcast a command to all sessions",
    }
    return overrides.get(action, action)


# Module-level export
__all__ = [
    "RISK_READ",
    "RISK_INTRUSIVE",
    "RISK_DESTRUCTIVE",
    "NetworkPanelState",
    "Capability",
    "CAPABILITY_CATALOG",
    "compute_visible_menu",
    "default_disconnected_menu",
    "friendly_action",
]
