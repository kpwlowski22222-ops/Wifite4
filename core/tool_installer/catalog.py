"""core.tool_installer.catalog — map tool-name → install source(s).

Each entry tells `maybe_install` what to try (in order):
    1. apt: `apt-get install -y <apt>` (root, requires sudo)
    2. pip: `pip install <pip>` (user)
    3. git: `git clone <repo> <target_dir>` (user)
    4. brew: `brew install <formula>` (macOS, future)

If none are set, the catalog is "documentation only" — `maybe_install`
returns False and the runner degrades.

`confirm_required: True` means the operator must OK the install via the
per-step gate. The runner surfaces the install list ("apt: bluez; pip: -
git: -") in the gate prompt; the operator decides.
"""
from __future__ import annotations

import dataclasses
from typing import Optional, Tuple


@dataclasses.dataclass(frozen=True)
class InstallSpec:
    apt: Optional[str] = None
    pip: Optional[str] = None
    brew: Optional[str] = None
    git: Optional[Tuple[str, str]] = None  # (repo_url, target_dir)
    confirm_required: bool = True

    def describe(self) -> str:
        parts = []
        if self.apt:
            parts.append(f"apt:{self.apt}")
        if self.pip:
            parts.append(f"pip:{self.pip}")
        if self.brew:
            parts.append(f"brew:{self.brew}")
        if self.git:
            parts.append(f"git:{self.git[0]}")
        return ";".join(parts) if parts else "(no install source)"


# Tools referenced in the runners. apt is preferred (Kali/Parrot standard);
# pip/git are fallbacks.
TOOL_CATALOG: dict[str, InstallSpec] = {
    # --- WiFi tools (apt) ---
    "aircrack-ng": InstallSpec(apt="aircrack-ng"),
    "aireplay-ng": InstallSpec(apt="aircrack-ng"),
    "airodump-ng": InstallSpec(apt="aircrack-ng"),
    "airoway-ng":  InstallSpec(apt="aircrack-ng"),
    "iw":          InstallSpec(apt="iw"),
    "iwconfig":    InstallSpec(apt="wireless-tools"),
    "ifconfig":    InstallSpec(apt="net-tools"),
    "ip":          InstallSpec(apt="iproute2"),
    "hashcat":     InstallSpec(apt="hashcat"),
    "hcxdumptool": InstallSpec(apt="hcxdumptool"),
    "hcxpcapngtool": InstallSpec(apt="hcxtools"),
    "mdk3":        InstallSpec(apt="mdk3"),
    "mdk4":        InstallSpec(apt="mdk4"),
    "bully":       InstallSpec(apt="bully"),
    "reaver":      InstallSpec(apt="reaver"),
    "wash":        InstallSpec(apt="reaver"),
    "hostapd":     InstallSpec(apt="hostapd"),
    "dnsmasq":     InstallSpec(apt="dnsmasq"),
    "iptables":    InstallSpec(apt="iptables"),
    "ettercap":    InstallSpec(apt="ettercap"),
    "tcpdump":     InstallSpec(apt="tcpdump"),
    "tshark":      InstallSpec(apt="wireshark-common"),
    "wireshark":   InstallSpec(apt="wireshark"),
    "nmap":        InstallSpec(apt="nmap"),
    "masscan":     InstallSpec(apt="masscan"),
    "searchsploit": InstallSpec(apt="exploitdb"),
    "amass":       InstallSpec(apt="amass"),
    "subfinder":   InstallSpec(apt="subfinder"),
    "theharvester": InstallSpec(apt="theharvester"),
    "dnsenum":     InstallSpec(apt="dnsenum"),
    "dmitry":      InstallSpec(apt="dmitry"),
    "netdiscover": InstallSpec(apt="netdiscover"),
    "netcat":      InstallSpec(apt="netcat-openbsd"),
    "ncat":        InstallSpec(apt="ncat"),
    "socat":       InstallSpec(apt="socat"),
    "ssh":         InstallSpec(apt="openssh-client"),
    "curl":        InstallSpec(apt="curl"),
    "wget":        InstallSpec(apt="wget"),
    "python3":     InstallSpec(apt="python3"),
    "git":         InstallSpec(apt="git"),
    # --- BLE tools (apt) ---
    "gatttool":    InstallSpec(apt="bluez"),
    "btmgmt":      InstallSpec(apt="bluez"),
    "hcitool":     InstallSpec(apt="bluez"),
    "bluetoothctl": InstallSpec(apt="bluez"),
    "btmon":       InstallSpec(apt="bluez"),
    "hcidump":     InstallSpec(apt="bluez"),
    "btsnoop":     InstallSpec(apt="bluez-hcidump"),
    "l2ping":      InstallSpec(apt="bluez"),
    "rfcomm":      InstallSpec(apt="bluez"),
    # --- Python tools (pip) ---
    "scapy":       InstallSpec(pip="scapy"),
    "responder":   InstallSpec(pip="responder"),
    "impacket-secretsdump": InstallSpec(pip="impacket"),
    "impacket-psexec": InstallSpec(pip="impacket"),
    "impacket-wmiexec": InstallSpec(pip="impacket"),
    "impacket-smbexec": InstallSpec(pip="impacket"),
    "impacket-atexec": InstallSpec(pip="impacket"),
    "impacket-mssqlclient": InstallSpec(pip="impacket"),
    "impacket-dcomexec": InstallSpec(pip="impacket"),
    "impacket-ntlmrelayx": InstallSpec(pip="impacket"),
    "impacket-ticketer": InstallSpec(pip="impacket"),
    "impacket-getTGT": InstallSpec(pip="impacket"),
    "impacket-getST": InstallSpec(pip="impacket"),
    "impacket-raiseChild": InstallSpec(pip="impacket"),
    "impacket-rpcdump": InstallSpec(pip="impacket"),
    "impacket-samrdump": InstallSpec(pip="impacket"),
    "impacket-services": InstallSpec(pip="impacket"),
    "impacket-reg": InstallSpec(pip="impacket"),
    "impacket-mqtt_check": InstallSpec(pip="impacket"),
    "impacket-rdp_check": InstallSpec(pip="impacket"),
    "impacket-marshal": InstallSpec(pip="impacket"),
    "impacket-addcomputer": InstallSpec(pip="impacket"),
    "impacket-changepasswd": InstallSpec(pip="impacket"),
    "impacket-describeTicket": InstallSpec(pip="impacket"),
    "impacket-findDelegation": InstallSpec(pip="impacket"),
    "impacket-getPac": InstallSpec(pip="impacket"),
    "impacket-goldenPac": InstallSpec(pip="impacket"),
    "impacket-karmaSMB": InstallSpec(pip="impacket"),
    "impacket-lookupsid": InstallSpec(pip="impacket"),
    "impacket-netview": InstallSpec(pip="impacket"),
    "impacket-nslookup": InstallSpec(pip="impacket"),
    "impacket-ptt": InstallSpec(pip="impacket"),
    "impacket-smbclient": InstallSpec(pip="impacket"),
    "impacket-smbrelayx": InstallSpec(pip="impacket"),
    "impacket-sniff": InstallSpec(pip="impacket"),
    "impacket-split": InstallSpec(pip="impacket"),
    "impacket-ticketConverter": InstallSpec(pip="impacket"),
    "impacket-wmipersist": InstallSpec(pip="impacket"),
    "impacket-wmiquery": InstallSpec(pip="impacket"),
    "crackmapexec": InstallSpec(pip="crackmapexec"),
    "bloodhound-python": InstallSpec(pip="bloodhound"),
    "pypykatz":    InstallSpec(pip="pypykatz"),
    "mitm6":       InstallSpec(pip="mitm6"),
    "ldap3":       InstallSpec(pip="ldap3"),
    "bloodhound":  InstallSpec(pip="bloodhound"),
    "kerbrute":    InstallSpec(apt="kerbrute"),
    "enum4linux":  InstallSpec(apt="enum4linux"),
    "enum4linux-ng": InstallSpec(pip="enum4linux-ng"),
    "smbclient":   InstallSpec(apt="smbclient"),
    "smbmap":      InstallSpec(pip="smbmap"),
    "rpcclient":   InstallSpec(apt="smbclient"),
    "ldapsearch":  InstallSpec(apt="ldap-utils"),
    "nikto":       InstallSpec(apt="nikto"),
    "whatweb":     InstallSpec(apt="whatweb"),
    "wpscan":      InstallSpec(apt="wpscan"),
    "joomscan":    InstallSpec(apt="joomscan"),
    "droopescan":  InstallSpec(pip="droopescan"),
    "sslyze":      InstallSpec(pip="sslyze"),
    "testssl":     InstallSpec(apt="testssl.sh"),
    "sslscan":     InstallSpec(apt="sslscan"),
    "dirb":        InstallSpec(apt="dirb"),
    "gobuster":    InstallSpec(apt="gobuster"),
    "ffuf":        InstallSpec(apt="ffuf"),
    "feroxbuster": InstallSpec(apt="feroxbuster"),
    "dirsearch":   InstallSpec(pip="dirsearch"),
    "wfuzz":       InstallSpec(pip="wfuzz"),
    "sqlmap":      InstallSpec(apt="sqlmap"),
    "xsstrike":    InstallSpec(pip="xsstrike"),
    "hydra":       InstallSpec(apt="hydra"),
    "john":        InstallSpec(apt="john"),
    "medusa":      InstallSpec(apt="medusa"),
    "patator":     InstallSpec(apt="patator"),
    "cewl":        InstallSpec(apt="cewl"),
    "crunch":      InstallSpec(apt="crunch"),
    "exiftool":    InstallSpec(apt="libimage-exiftool-perl"),
    "steghide":    InstallSpec(apt="steghide"),
    "binwalk":     InstallSpec(apt="binwalk"),
    "foremost":    InstallSpec(apt="foremost"),
    "photorec":    InstallSpec(apt="testdisk"),
    "strings":     InstallSpec(apt="binutils"),
    "xxd":         InstallSpec(apt="xxd"),
    "file":        InstallSpec(apt="file"),
    "yara":        InstallSpec(apt="yara"),
    "volatility":  InstallSpec(pip="volatility3"),
    "volatility3": InstallSpec(pip="volatility3"),
    "pdf-parser":  InstallSpec(pip="pdf-parser"),
    "pdfid":       InstallSpec(pip="pdfid"),
    "qpdf":        InstallSpec(apt="qpdf"),
    "office2john": InstallSpec(apt="office2john"),
    "keepass2john": InstallSpec(apt="john"),
    "hashid":      InstallSpec(pip="hashid"),
    "hash-identifier": InstallSpec(apt="hash-identifier"),
    # --- git repos (offensive tools that aren't packaged) ---
    "mimikatz":    InstallSpec(
        git=("https://github.com/gentilkiwi/mimikatz", "toolboxes/post_exploit/mimikatz"),
        confirm_required=True,
    ),
    "routersploit": InstallSpec(
        git=("https://github.com/threat9/routersploit", "toolboxes/post_exploit/routersploit"),
    ),
    "empire":      InstallSpec(
        git=("https://github.com/BC-SECURITY/Empire", "toolboxes/post_exploit/Empire"),
    ),
    "sliver":      InstallSpec(
        git=("https://github.com/BishopFox/sliver", "toolboxes/c2/sliver"),
    ),
    "covenant":    InstallSpec(
        git=("https://github.com/cobbr/Covenant", "toolboxes/c2/Covenant"),
    ),
    "villain":     InstallSpec(
        git=("https://github.com/t3l3makus/Villain", "toolboxes/c2/Villain"),
    ),
    "trevorc2":    InstallSpec(
        git=("https://github.com/trustedsec/trevorc2", "toolboxes/c2/trevorc2"),
    ),
    "pupy":        InstallSpec(
        git=("https://github.com/n1nj4sec/pupy", "toolboxes/c2/pupy"),
    ),
    "nishang":     InstallSpec(
        git=("https://github.com/samratashok/nishang", "toolboxes/post_exploit/nishang"),
    ),
    "PowerSploit": InstallSpec(
        git=("https://github.com/PowerShellMafia/PowerSploit", "toolboxes/post_exploit/PowerSploit"),
    ),
    "SharpHound":  InstallSpec(
        git=("https://github.com/BloodHoundAD/SharpHound", "toolboxes/post_exploit/SharpHound"),
    ),
    "bettercap":   InstallSpec(apt="bettercap"),
    "wifiphisher": InstallSpec(
        git=("https://github.com/wifiphisher/wifiphisher", "toolboxes/wifi_attack/wifiphisher"),
    ),
    "fluxion":     InstallSpec(
        git=("https://github.com/FluxionNetwork/fluxion", "toolboxes/wifi_attack/fluxion"),
    ),
    "eaphammer":   InstallSpec(
        git=("https://github.com/s0lst1c3/eaphammer", "toolboxes/wifi_attack/eaphammer"),
    ),
    "wpa-sec-stash": InstallSpec(apt="wpa-sec-stash"),
    "pyrit":       InstallSpec(apt="pyrit"),
    "cowpatty":    InstallSpec(apt="cowpatty"),
    "genpmk":      InstallSpec(apt="cowpatty"),
    "asleap":      InstallSpec(apt="asleap"),
    "johnny":      InstallSpec(apt="johnny"),
    "airgeddon":   InstallSpec(
        git=("https://github.com/v1s1t0r1sh3r3/airgeddon", "toolboxes/wifi_attack/airgeddon"),
    ),
    "infernal-twin": InstallSpec(
        git=("https://github.com/entropy1337/infernal-twin", "toolboxes/wifi_attack/infernal-twin"),
    ),
    # --- iOS tools (apt: libimobiledevice-utils brings the idevice* family) ---
    "idevicebackup2":  InstallSpec(apt="libimobiledevice-utils"),
    "ideviceinfo":     InstallSpec(apt="libimobiledevice-utils"),
    "idevicedebug":    InstallSpec(apt="libimobiledevice-utils"),
    "idevicebackup":   InstallSpec(apt="libimobiledevice-utils"),
    "idevicesyslog":   InstallSpec(apt="libimobiledevice-utils"),
    "idevicepair":     InstallSpec(apt="libimobiledevice-utils"),
    "idevicediagnostics": InstallSpec(apt="libimobiledevice-utils"),
    "ideviceenterrecovery": InstallSpec(apt="libimobiledevice-utils"),
    "idevicedate":     InstallSpec(apt="libimobiledevice-utils"),
    "idevicescreenshot": InstallSpec(apt="libimobiledevice-utils"),
    "ideviceprovision": InstallSpec(apt="libimobiledevice-utils"),
    "ideviceimagemounter": InstallSpec(apt="libimobiledevice-utils"),
    "idevice_id":      InstallSpec(apt="libimobiledevice-utils"),
    "usbmuxd":         InstallSpec(apt="usbmuxd"),
    "ideviceinstaller": InstallSpec(apt="ideviceinstaller"),
    "libimobiledevice": InstallSpec(apt="libimobiledevice-utils"),
    # --- Android tools (apt) ---
    "adb":             InstallSpec(apt="adb"),
    "fastboot":        InstallSpec(apt="fastboot"),
    "apktool":         InstallSpec(apt="apktool"),
    "jadx":            InstallSpec(apt="jadx"),
    "drozer":          InstallSpec(pip="drozer"),
    # --- iOS / Android dynamic analysis (pip / pipx) ---
    "frida":           InstallSpec(pip="frida-tools"),
    "frida-ps":        InstallSpec(pip="frida-tools"),
    "frida-trace":     InstallSpec(pip="frida-tools"),
    "frida-server":    InstallSpec(pip="frida-tools"),  # binary; on-device frida-server is separate
    "objection":       InstallSpec(pip="objection"),
    # --- Microsoft / AD tools (apt + pip) ---
    "certipy":         InstallSpec(pip="certipy-ad"),  # ly4k/Certipy v5.x, AD CS attack tool
    "certipy-ad":      InstallSpec(pip="certipy-ad"),
    "krbrelayx":       InstallSpec(apt="krbrelayx"),
    "bloodhound-python": InstallSpec(apt="bloodhound"),
    "kerbrute":        InstallSpec(pip="kerbrute"),
    "impacket-secretsdump": InstallSpec(apt="impacket-scripts"),
    "impacket-psexec": InstallSpec(apt="impacket-scripts"),
    "impacket-smbclient": InstallSpec(apt="impacket-scripts"),
    "impacket-lookupsid": InstallSpec(apt="impacket-scripts"),
    "impacket-scripts": InstallSpec(apt="impacket-scripts"),
    "Responder":       InstallSpec(apt="responder"),
    "crackmapexec":    InstallSpec(apt="crackmapexec"),
    "mitm6":           InstallSpec(pip="mitm6"),
    "pypykatz":        InstallSpec(pip="pypykatz"),
    "ldapsearch":      InstallSpec(apt="ldap-utils"),
    "smbclient":       InstallSpec(apt="smbclient"),
    "enum4linux":      InstallSpec(apt="enum4linux"),
    "enum4linux-ng":   InstallSpec(pip="enum4linux-ng"),
    # --- Microsoft coerce tools (git-only — symlink from toolboxes) ---
    "PetitPotam":   InstallSpec(
        git=("https://github.com/topotam/PetitPotam", "toolboxes/microsoft/PetitPotam"),
    ),
    "ShadowCoerce": InstallSpec(
        git=("https://github.com/ShutdownRepo/ShadowCoerce", "toolboxes/microsoft/ShadowCoerce"),
    ),
    "DFSCoerce":    InstallSpec(
        git=("https://github.com/Wh04m1001/DFSCoerce", "toolboxes/microsoft/DFSCoerce"),
    ),
    "PrinterBug":   InstallSpec(
        git=("https://github.com/ly4k/PrinterBug", "toolboxes/microsoft/PrinterBug"),
    ),
    # --- WiFi / monitor / capture helpers (apt) ---
    "airmon-ng":     InstallSpec(apt="aircrack-ng"),
    "gpspipe":       InstallSpec(apt="gpsd"),
    "hcxpsktool":    InstallSpec(apt="hcxtools"),
    # --- LAN post-exploit (apt) ---
    "arpspoof":      InstallSpec(apt="dsniff"),
    "dnsspoof":      InstallSpec(apt="dsniff"),
    "ssldump":       InstallSpec(apt="ssldump"),
    "snmpwalk":      InstallSpec(apt="snmp"),
    "dig":           InstallSpec(apt="dnsutils"),
    "telnet":        InstallSpec(apt="telnet"),
    "evil-winrm":    InstallSpec(apt="evil-winrm"),
    "msfconsole":    InstallSpec(apt="metasploit-framework"),
    "msfvenom":      InstallSpec(apt="metasploit-framework"),
    "pwsh":          InstallSpec(apt="powershell"),
    # --- tunnel / pivot (git) ---
    "chisel":        InstallSpec(
        git=("https://github.com/jpillora/chisel", "toolboxes/post_exploit/chisel"),
    ),
    "ligolo-ng":     InstallSpec(
        git=("https://github.com/tnpitsecurity/ligolo-ng", "toolboxes/post_exploit/ligolo-ng"),
    ),
    # --- OSINT (pip / git) ---
    "holehe":        InstallSpec(pip="holehe"),
    "maigret":       InstallSpec(pip="maigret"),
    "sherlock":      InstallSpec(pip="sherlock-project"),
    "nexfil":        InstallSpec(pip="nexfil"),
    "toutatis":      InstallSpec(pip="toutatis"),
    "phoneinfoga":   InstallSpec(
        git=("https://github.com/sundowndev/phoneinfoga", "toolboxes/osint/phoneinfoga"),
    ),
    # --- AI / BLE (apt + pip) ---
    "ollama":        InstallSpec(apt="ollama"),
    "bleak":         InstallSpec(pip="bleak"),
    # --- iOS / Android transitive (apt + pip) ---
    "ios-deploy":    InstallSpec(apt="ios-deploy"),
    "httptools":     InstallSpec(pip="httptools"),
    "mitmdump":      InstallSpec(pip="mitmproxy"),
}
