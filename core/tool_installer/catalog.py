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
from pathlib import Path
from typing import Optional, Tuple, FrozenSet


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
    # --- SDR / wireless chipset helpers (apt) ---
    "hackrf_info":   InstallSpec(
        apt="hackrf",
        git=("https://github.com/greatscottgadgets/hackrf", "toolboxes/recon/hackrf"),
    ),
    "rtl_test":      InstallSpec(
        apt="rtl-sdr",
        git=("https://github.com/osmocom/rtl-sdr", "toolboxes/recon/rtl-sdr"),
    ),
    "bladeRF-cli":   InstallSpec(
        apt="bladerf",
        git=("https://github.com/Nuand/bladeRF", "toolboxes/recon/bladeRF"),
    ),
    "lsusb":         InstallSpec(apt="usbutils"),
    # --- WiFi-Pixie / WPS (apt + git) ---
    "pixiewps":      InstallSpec(
        apt="pixiewps",
        git=("https://github.com/wiire/pixiewps", "toolboxes/wifi_attack/pixiewps"),
        confirm_required=True,
    ),
    "wifite":        InstallSpec(
        apt="wifite",
        git=("https://github.com/derv82/wifite2", "toolboxes/wifi_attack/wifite"),
        confirm_required=True,
    ),
    # --- Wireless / Bluetooth CLI helpers (apt) ---
    "iwlist":        InstallSpec(apt="wireless-tools"),
    "hciconfig":     InstallSpec(apt="bluez"),
    # --- Firewall / GUI helpers (apt) ---
    "ufw":           InstallSpec(apt="ufw"),
    "vncviewer":     InstallSpec(apt="tigervnc-viewer", confirm_required=True),
    "wkhtmltopdf":   InstallSpec(apt="wkhtmltopdf"),
    "xdg-open":      InstallSpec(apt="xdg-utils"),
    # --- Container / packaging CLI (apt + git) ---
    "docker-compose": InstallSpec(
        apt="docker-compose",
        git=("https://github.com/docker/compose", "toolboxes/c2/docker-compose"),
        confirm_required=True,
    ),
    # --- Recon / Python wrapper repos (git; CLI entry points) ---
    "pyExploitDb":   InstallSpec(
        git=("https://github.com/vulnersCom/PyExploitDb", "toolboxes/recon/PyExploitDb"),
    ),
    "libnmap":       InstallSpec(
        git=("https://github.com/savon-noir/python-libnmap", "toolboxes/recon/python-libnmap"),
        confirm_required=True,
    ),
    "mitmproxy":     InstallSpec(
        git=("https://github.com/mitmproxy/mitmproxy", "toolboxes/recon/mitmproxy"),
        confirm_required=True,
    ),
    "mss":           InstallSpec(
        git=("https://github.com/BoboTiG/cookiecutter-mss", "toolboxes/recon/mss"),
        confirm_required=True,
    ),
    "curl_cffi":     InstallSpec(
        git=("https://github.com/yifeikong/curl_cffi", "toolboxes/c2/curl_cffi"),
        confirm_required=True,
    ),
    # --- NTLM (PyPI: package name `python-ntlm` — note: not `ntlm3`/`impacket`) ---
    "ntlm":          InstallSpec(pip="python-ntlm", confirm_required=True),
    # --- Kismet (apt package: kismet; client + cap-to-pcap on PATH) ---
    "kismet":        InstallSpec(apt="kismet", confirm_required=True),
    # --- Phase 2.3.B: Flask ecosystem for the RAT-like dashboard ---
    "flask":         InstallSpec(pip="flask", confirm_required=True),
    "werkzeug":      InstallSpec(pip="werkzeug", confirm_required=True),
    "jinja2":        InstallSpec(pip="jinja2", confirm_required=True),
    "flask-cors":    InstallSpec(pip="flask-cors", confirm_required=True),
    "itsdangerous":  InstallSpec(pip="itsdangerous", confirm_required=True),
    "markupsafe":    InstallSpec(pip="markupsafe", confirm_required=True),
    "click":         InstallSpec(pip="click", confirm_required=True),
    # --- Phase 2.3.B: Polish OSINT helper libs ---
    "phonenumbers":     InstallSpec(pip="phonenumbers", confirm_required=True),
    "email-validator":  InstallSpec(pip="email-validator", confirm_required=True),
    "python-dateutil":  InstallSpec(pip="python-dateutil", confirm_required=True),
    "lxml":             InstallSpec(pip="lxml", confirm_required=True),
    "beautifulsoup4":   InstallSpec(pip="beautifulsoup4", confirm_required=True),
    "requests-html":    InstallSpec(pip="requests-html", confirm_required=True),
    "furl":             InstallSpec(pip="furl", confirm_required=True),
    # --- Phase 2.3.B: additional post-exploit / AD tools ---
    "mimikatz":     InstallSpec(
        git=("https://github.com/gentilkiwi/mimikatz", "toolboxes/post_exploit/mimikatz"),
        confirm_required=True,
    ),
    "RDP-Checker":  InstallSpec(
        git=("https://github.com/JoelGMSec/RDP-Checker", "toolboxes/post_exploit/RDP-Checker"),
        confirm_required=True,
    ),
    "sprayingtoolkit": InstallSpec(
        git=("https://github.com/byt3bl33d3r/SprayingToolkit", "toolboxes/post_exploit/SprayingToolkit"),
        confirm_required=True,
    ),
    "krbrelayx":    InstallSpec(
        git=("https://github.com/dirkjanm/krbrelayx", "toolboxes/post_exploit/krbrelayx"),
        confirm_required=True,
    ),
    "certipy":      InstallSpec(pip="certipy-ad", confirm_required=True),
    "mitm6":        InstallSpec(pip="mitm6", confirm_required=True),
    "bloodhound":   InstallSpec(apt="bloodhound", confirm_required=True),
    # --- Phase 2.3.B: APT tools that support polish-OSINT and more ---
    "whois":        InstallSpec(apt="whois", confirm_required=True),
    "dig":          InstallSpec(apt="dnsutils", confirm_required=True),
    "nslookup":     InstallSpec(apt="dnsutils", confirm_required=True),
    # --- Phase 2.4: expanded catalog (~50 new entries) ---
    # WiFi extras
    "tshark":       InstallSpec(apt="tshark", confirm_required=True),
    "hostapd-mana": InstallSpec(apt="hostapd-mana", confirm_required=True),
    "wpasupplicant":InstallSpec(apt="wpasupplicant", confirm_required=True),
    "onesixtyone":  InstallSpec(apt="onesixtyone", confirm_required=True),
    "bully":        InstallSpec(apt="bully", confirm_required=True),
    "hcxdumptool":  InstallSpec(apt="hcxdumptool", confirm_required=True),
    "hcxtools":     InstallSpec(apt="hcxtools", confirm_required=True),
    "mdk4":         InstallSpec(apt="mdk4", confirm_required=True),
    "asleap":       InstallSpec(apt="asleap", confirm_required=True),
    "pixiewps":     InstallSpec(apt="pixiewps", confirm_required=True),
    # BLE / BT
    "bluetooth":    InstallSpec(apt="bluez", confirm_required=True),
    "bluez-tools":  InstallSpec(apt="bluez-tools", confirm_required=True),
    "obexftp":      InstallSpec(apt="obexftp", confirm_required=True),
    "bluetoothctl": InstallSpec(apt="bluez", confirm_required=True),
    # Smb / AD / Kerberos
    "smbclient":    InstallSpec(apt="smbclient", confirm_required=True),
    "ldap-utils":   InstallSpec(apt="ldap-utils", confirm_required=True),
    "ldapsearch":   InstallSpec(apt="ldap-utils", confirm_required=True),
    "krb5-user":    InstallSpec(apt="krb5-user", confirm_required=True),
    "kadmin":       InstallSpec(apt="krb5-user", confirm_required=True),
    "crackmapexec": InstallSpec(apt="crackmapexec", confirm_required=True),
    "ntlmrelayx":   InstallSpec(pip="impacket", confirm_required=True),
    # Forensics / OSINT
    "tesseract":    InstallSpec(apt="tesseract-ocr", confirm_required=True),
    "tesseract-pol":InstallSpec(apt="tesseract-ocr-pol", confirm_required=True),
    "steghide":     InstallSpec(apt="steghide", confirm_required=True),
    "binwalk":      InstallSpec(apt="binwalk", confirm_required=True),
    "sleuthkit":    InstallSpec(apt="sleuthkit", confirm_required=True),
    "volatility3":  InstallSpec(pip="volatility3", confirm_required=True),
    "yara":         InstallSpec(apt="yara", confirm_required=True),
    "webanalyze":   InstallSpec(apt="webanalyze", confirm_required=True),
    "exiftool":     InstallSpec(apt="libimage-exiftool-perl", confirm_required=True),
    # Nmap & friends
    "nmap":         InstallSpec(apt="nmap", confirm_required=True),
    "hydra":        InstallSpec(apt="hydra", confirm_required=True),
    "medusa":       InstallSpec(apt="medusa", confirm_required=True),
    # VPN
    "openvpn":      InstallSpec(apt="openvpn", confirm_required=True),
    "wireguard":    InstallSpec(apt="wireguard", confirm_required=True),
    # Network capture
    "tcpdump":      InstallSpec(apt="tcpdump", confirm_required=True),
    # Pip-only extras (already in requirements)
    "fpdf2":        InstallSpec(pip="fpdf2", confirm_required=True),
    "phonenumbers": InstallSpec(pip="phonenumbers", confirm_required=True),
    "python-stdnum":InstallSpec(pip="python-stdnum", confirm_required=True),
    "lxml-html-clean": InstallSpec(pip="lxml-html-clean", confirm_required=True),
    # Phase 2.4 git-cloned tools (the 30 new tools)
    "airgeddon":        InstallSpec(git=("https://github.com/v1s1t0r1sh3r3/airgeddon", "toolboxes/wifi/airgeddon"), confirm_required=True),
    "wifite2_git":      InstallSpec(git=("https://github.com/derv82/wifite2", "toolboxes/wifi/wifite2"), confirm_required=True),
    "eaphammer":        InstallSpec(git=("https://github.com/s0lst1c3/eaphammer", "toolboxes/wifi/eaphammer"), confirm_required=True),
    "infernal-twin":    InstallSpec(git=("https://github.com/entropy1337/infernal-twin", "toolboxes/wifi/infernal-twin"), confirm_required=True),
    "wifi-pumpkin":     InstallSpec(git=("https://github.com/P0cL4ty/WiFi-Pumpkin", "toolboxes/wifi/wifi-pumpkin"), confirm_required=True),
    "m5stick-nemo":     InstallSpec(git=("https://github.com/n0xa/m5stick-nemo", "toolboxes/ble/m5stick-nemo"), confirm_required=True),
    "btlejack":         InstallSpec(git=("https://github.com/virtualabs/btlejack", "toolboxes/ble/btlejack"), confirm_required=True),
    "internalblue":     InstallSpec(git=("https://github.com/seemoo-lab/internalblue", "toolboxes/ble/internalblue"), confirm_required=True),
    "spiderfoot":       InstallSpec(git=("https://github.com/smicallef/spiderfoot", "toolboxes/osint/spiderfoot"), confirm_required=True),
    "theHarvester":     InstallSpec(git=("https://github.com/laramies/theHarvester", "toolboxes/osint/theHarvester"), confirm_required=True),
    "waybackurls":      InstallSpec(git=("https://github.com/tomnomnom/waybackurls", "toolboxes/osint/waybackurls"), confirm_required=True),
    "meg":              InstallSpec(git=("https://github.com/tomnomnom/meg", "toolboxes/osint/meg"), confirm_required=True),
    "gau":              InstallSpec(git=("https://github.com/lc/gau", "toolboxes/osint/gau"), confirm_required=True),
    "subfinder":        InstallSpec(git=("https://github.com/projectdiscovery/subfinder", "toolboxes/osint/subfinder"), confirm_required=True),
    "gobuster":         InstallSpec(git=("https://github.com/OJ/gobuster", "toolboxes/osint/gobuster"), confirm_required=True),
    "SecretFinder":     InstallSpec(git=("https://github.com/m4ll0k/SecretFinder", "toolboxes/osint/SecretFinder"), confirm_required=True),
    "WhoDat":           InstallSpec(git=("https://github.com/urbanadventurer/WhoDat", "toolboxes/osint/WhoDat"), confirm_required=True),
    "cloud_enum":       InstallSpec(git=("https://github.com/initstring/cloud_enum", "toolboxes/osint/cloud_enum"), confirm_required=True),
    "impacket_git":     InstallSpec(git=("https://github.com/fortra/impacket", "toolboxes/post_exploit/impacket"), confirm_required=True),
    "CrackMapExec":     InstallSpec(git=("https://github.com/byt3bl33d3r/CrackMapExec", "toolboxes/post_exploit/CrackMapExec"), confirm_required=True),
    "Certipy":          InstallSpec(git=("https://github.com/ly4k/Certipy", "toolboxes/post_exploit/Certipy"), confirm_required=True),
    "krbrelayx_git":    InstallSpec(git=("https://github.com/dirkjanm/krbrelayx", "toolboxes/post_exploit/krbrelayx"), confirm_required=True),
    "Windows-Exploit-Suggester": InstallSpec(git=("https://github.com/S1ckB0y1337/Windows-Exploit-Suggester", "toolboxes/post_exploit/Windows-Exploit-Suggester"), confirm_required=True),
    "sqlmap":           InstallSpec(git=("https://github.com/OJ/sqlmap", "toolboxes/web/sqlmap"), confirm_required=True),
    "nuclei":           InstallSpec(git=("https://github.com/projectdiscovery/nuclei", "toolboxes/web/nuclei"), confirm_required=True),
    "httpx":            InstallSpec(git=("https://github.com/projectdiscovery/httpx", "toolboxes/web/httpx"), confirm_required=True),
    "Interlace":        InstallSpec(git=("https://github.com/codingo/Interlace", "toolboxes/web/Interlace"), confirm_required=True),
    "mimikatz_git":     InstallSpec(git=("https://github.com/gentilkiwi/mimikatz", "toolboxes/post_exploit/mimikatz"), confirm_required=True),
    "PowerSploit":      InstallSpec(git=("https://github.com/PowerShellMafia/PowerSploit", "toolboxes/post_exploit/PowerSploit"), confirm_required=True),
    "Empire":           InstallSpec(git=("https://github.com/BC-SECURITY/Empire", "toolboxes/post_exploit/Empire"), confirm_required=True),
    # --- Phase 2.4 — browser automation + DB integrations (per operator) ---
    "selenium":           InstallSpec(pip="selenium", confirm_required=True),
    "playwright":         InstallSpec(pip="playwright", confirm_required=True),
    "mechanicalsoup":     InstallSpec(pip="mechanicalsoup", confirm_required=True),
    "requests-html":      InstallSpec(pip="requests-html", confirm_required=True),
    "beautifulsoup4":     InstallSpec(pip="beautifulsoup4", confirm_required=True),
    "pymssql":            InstallSpec(pip="pymssql", confirm_required=True),
    "pymysql":            InstallSpec(pip="pymysql", confirm_required=True),
    "psycopg2-binary":    InstallSpec(pip="psycopg2-binary", confirm_required=True),
    "SQLAlchemy":         InstallSpec(pip="SQLAlchemy", confirm_required=True),
    "alembic":            InstallSpec(pip="alembic", confirm_required=True),
    "dataset":            InstallSpec(pip="dataset", confirm_required=True),
    "peewee":             InstallSpec(pip="peewee", confirm_required=True),
    "sqlmodel":           InstallSpec(pip="sqlmodel", confirm_required=True),
    "pyodbc":             InstallSpec(pip="pyodbc", confirm_required=True),
    "oracledb":           InstallSpec(pip="oracledb", confirm_required=True),
    "geoip2":             InstallSpec(pip="geoip2", confirm_required=True),
    "phonenumbers":       InstallSpec(pip="phonenumbers", confirm_required=True),
    "email-validator":    InstallSpec(pip="email-validator", confirm_required=True),
    "python-stdnum":      InstallSpec(pip="python-stdnum", confirm_required=True),
    "fpdf2":              InstallSpec(pip="fpdf2", confirm_required=True),
    "reportlab":          InstallSpec(pip="reportlab", confirm_required=True),
    "Pillow":             InstallSpec(pip="Pillow", confirm_required=True),
    "pytesseract":        InstallSpec(pip="pytesseract", confirm_required=True),
    "opencv-python":      InstallSpec(pip="opencv-python", confirm_required=True),
    "tldextract":         InstallSpec(pip="tldextract", confirm_required=True),
    "dnspython":          InstallSpec(pip="dnspython", confirm_required=True),
    "pycryptodome":       InstallSpec(pip="pycryptodome", confirm_required=True),
    "cryptography":       InstallSpec(pip="cryptography", confirm_required=True),
    "paramiko":           InstallSpec(pip="paramiko", confirm_required=True),
    "pysmb":              InstallSpec(pip="pysmb", confirm_required=True),
    "impacket_pip":       InstallSpec(pip="impacket", confirm_required=True),
    "ldap3":              InstallSpec(pip="ldap3", confirm_required=True),
    "ldapdomaindump":     InstallSpec(pip="ldapdomaindump", confirm_required=True),
    "pypykatz":           InstallSpec(pip="pypykatz", confirm_required=True),
    "mitm6_pip":          InstallSpec(pip="mitm6", confirm_required=True),
    "aiodns":             InstallSpec(pip="aiodns", confirm_required=True),
    "aiohttp":            InstallSpec(pip="aiohttp", confirm_required=True),
    "httpx":              InstallSpec(pip="httpx", confirm_required=True),
    "websockets":         InstallSpec(pip="websockets", confirm_required=True),
    "paho-mqtt":          InstallSpec(pip="paho-mqtt", confirm_required=True),
    "pymodbus":           InstallSpec(pip="pymodbus", confirm_required=True),
    "pyzmq":              InstallSpec(pip="pyzmq", confirm_required=True),
    "pyngus":             InstallSpec(pip="pyngus", confirm_required=True),
    "asn1crypto":         InstallSpec(pip="asn1crypto", confirm_required=True),
    "pyOpenSSL":          InstallSpec(pip="pyOpenSSL", confirm_required=True),
    "certvalidator":      InstallSpec(pip="certvalidator", confirm_required=True),
    "trustme":            InstallSpec(pip="trustme", confirm_required=True),
    "mitmproxy":          InstallSpec(pip="mitmproxy", confirm_required=True),
    "stem":               InstallSpec(pip="stem", confirm_required=True),
    "txtorcon":           InstallSpec(pip="txtorcon", confirm_required=True),
    "graphene":           InstallSpec(pip="graphene", confirm_required=True),
    "graphql-core":       InstallSpec(pip="graphql-core", confirm_required=True),
}


# ---------------------------------------------------------------------------
# SDR skip file (Phase 2.3.B)
# ---------------------------------------------------------------------------

_SKIPPED_FILE_NAME = "_skipped.txt"


def _skipped_path() -> Path:
    """Return the absolute path to the SDR-skip list."""
    return Path(__file__).resolve().parent / _SKIPPED_FILE_NAME


def _load_skipped() -> FrozenSet[str]:
    """Read the skip list. Each non-empty, non-comment line is a tool
    name. Returns a frozen set."""
    p = _skipped_path()
    if not p.exists():
        return frozenset()
    out = set()
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        out.add(line)
    return frozenset(out)


_SKIPPED_CACHE: Optional[FrozenSet[str]] = None


def skipped_tools() -> FrozenSet[str]:
    """Return the set of tool names the operator has marked 'skip'.
    Cached after the first read."""
    global _SKIPPED_CACHE
    if _SKIPPED_CACHE is None:
        _SKIPPED_CACHE = _load_skipped()
    return _SKIPPED_CACHE


def is_skipped(tool: str) -> bool:
    """Predicate: is this tool in the operator's skip list?"""
    return tool in skipped_tools()


def reset_skipped_cache() -> None:
    """Clear the cached skip set (tests)."""
    global _SKIPPED_CACHE
    _SKIPPED_CACHE = None
