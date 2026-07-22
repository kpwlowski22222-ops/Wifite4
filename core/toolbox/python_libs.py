"""core.toolbox.python_libs — curated registry of offensive-security
Python libraries.

This is the Phase 2.3 registry. Each entry describes one
PyPI package: import name, pip distribution name, summary,
category, install command, a short example, the risk
classification, and the runnable entry-point pattern
(``python3 -m <entry>`` or direct ``python3 -c '...'``).

The registry is the single source of truth for the LLM
prompt stanza + the chain-step dispatch + the catalog
emitter. Adding a new library is a one-line edit to
``PYTHON_LIBRARIES`` below.

The categories mirror the chain planner's domain layout
plus a few Python-specific ones:

  - network: scapy, impacket, paramiko, twisted, mitmproxy, ...
  - exploit: pwntools, ropper, pwnlib, pdb, ...
  - web: requests, httpx, aiohttp, beautifulsoup4, ...
  - crypto: cryptography, pycryptodome, hashpumpy, ...
  - osint: shodan, censys, ipinfo, dnspython, ...
  - recon: wafw00f, sqlmap, ...
  - ble: bleak, pybluez2, scapy (BLE)
  - wifi: scapy (802.11), wifi, pyric, ...
  - c2: pyngus, impacket (psexec / wmiexec)
  - post_exploitation: impacket, pypykatz, lsassy, ...
  - utility: rich, typer, click, jinja2, ...

Each entry has a ``risk_level`` (low | medium | high |
critical) and a ``requires_gate`` (True for any library
that can interact with the target — the chain step is
per-step ACCEPT-gated by the orchestrator).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Single source of truth: PYTHON_LIBRARIES list
# ---------------------------------------------------------------------------

PYTHON_LIBRARIES: List[Dict[str, Any]] = [
    # ---- Network ------------------------------------------------------------
    {
        "name": "scapy", "import_name": "scapy", "pip": "scapy",
        "version": "2.5.0", "category": "network",
        "summary": "Interactive packet manipulation program + library.",
        "description": (
            "Scapy is a powerful Python-based interactive packet "
            "manipulation program and library. It can forge or decode "
            "packets of a wide number of protocols, send them on the "
            "wire, capture them, match requests and replies, and much "
            "more."
        ),
        "entry": "scapy.main",
        "example": "from scapy.all import ARP, Ether, srp; ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst='10.0.0.0/24'), timeout=2)",
        "risk_level": "high", "requires_gate": True,
    },
    {
        "name": "impacket", "import_name": "impacket", "pip": "impacket",
        "version": "0.11.0", "category": "post_exploitation",
        "summary": "Network protocols constructors/dissectors + Impacket examples (psexec, wmiexec, secretsdump, ...).",
        "description": (
            "Impacket is a collection of Python classes for working "
            "with network protocols. It focuses on providing low-level "
            "programmatic access to the packets and to some protocol "
            "internals, with focus on Windows / SMB / MSRPC / Kerberos."
        ),
        "entry": "impacket.examples",
        "example": "python3 -m impacket.examples.psexec Administrator@10.0.0.5",
        "risk_level": "critical", "requires_gate": True,
    },
    {
        "name": "paramiko", "import_name": "paramiko", "pip": "paramiko",
        "version": "3.4.0", "category": "network",
        "summary": "SSH2 protocol library for Python (client + server).",
        "description": (
            "Paramiko is a Python (2.7, 3.x) implementation of the "
            "SSHv2 protocol, providing both client and server "
            "functionality."
        ),
        "entry": "paramiko",
        "example": "import paramiko; c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy()); c.connect('10.0.0.5', username='u', password='p')",
        "risk_level": "high", "requires_gate": True,
    },
    {
        "name": "twisted", "import_name": "twisted", "pip": "twisted",
        "version": "24.7.0", "category": "network",
        "summary": "Asynchronous networking framework.",
        "description": (
            "Twisted is an event-driven networking engine written in "
            "Python. It includes a web server, multiple protocols, "
            "clients, servers, and a flexible channel abstraction."
        ),
        "entry": "twisted",
        "example": "from twisted.internet import reactor",
        "risk_level": "medium", "requires_gate": True,
    },
    {
        "name": "mitmproxy", "import_name": "mitmproxy", "pip": "mitmproxy",
        "version": "10.0.0", "category": "network",
        "summary": "Intercepting HTTPS proxy for penetration testers.",
        "description": (
            "mitmproxy is an interactive, SSL/TLS-capable intercepting "
            "proxy with a console interface. Allows traffic flow to be "
            "intercepted, inspected, modified and replayed."
        ),
        "entry": "mitmproxy",
        "example": "mitmproxy --listen-port 8080",
        "risk_level": "high", "requires_gate": True,
    },
    {
        "name": "dpkt", "import_name": "dpkt", "pip": "dpkt",
        "version": "1.9.8", "category": "network",
        "summary": "Fast, simple packet creation / parsing, with definitions for TCP, UDP, IP, ICMP, Ethernet, ARP, ...",  # noqa: E501
        "description": (
            "dpkt is a Python library for fast, simple packet "
            "creation / parsing, with definitions for TCP, UDP, IP, "
            "ICMP, Ethernet, ARP, IPv6, BGP, OSPF, RIP, DNS, etc."
        ),
        "entry": "dpkt",
        "example": "import dpkt, socket; pcap = dpkt.pcap.Reader(open('cap.pcap', 'rb')); [print(socket.inet_ntoa(p[1].dst)) for _, p in pcap]",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "pyzmq", "import_name": "zmq", "pip": "pyzmq",
        "version": "26.0.0", "category": "network",
        "summary": "Python bindings for the ZeroMQ messaging library.",
        "description": (
            "PyZMQ is the official Python binding for ZeroMQ, a "
            "high-performance asynchronous messaging library."
        ),
        "entry": "zmq",
        "example": "import zmq; ctx = zmq.Context(); s = ctx.socket(zmq.PUB); s.bind('tcp://*:5555')",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "pika", "import_name": "pika", "pip": "pika",
        "version": "1.3.2", "category": "network",
        "summary": "Pure-Python AMQP 0-9-1 client (RabbitMQ).",
        "description": (
            "Pika is a pure-Python implementation of the AMQP 0-9-1 "
            "protocol used by RabbitMQ. Useful for C2 channels."
        ),
        "entry": "pika",
        "example": "import pika; conn = pika.BlockingConnection(pika.ConnectionParameters('10.0.0.5'))",
        "risk_level": "medium", "requires_gate": True,
    },
    {
        "name": "dnspython", "import_name": "dns", "pip": "dnspython",
        "version": "2.6.1", "category": "recon",
        "summary": "DNS toolkit for Python (resolver, zone, TSIG, ...).",
        "description": (
            "dnspython is a DNS toolkit for Python. It supports "
            "almost all record types, can be used for zone transfers, "
            "dynamic updates, messages, TSIG, EDNS, and more."
        ),
        "entry": "dns",
        "example": "import dns.resolver; print(dns.resolver.resolve('example.com', 'A'))",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "requests", "import_name": "requests", "pip": "requests",
        "version": "2.32.0", "category": "web",
        "summary": "Elegant HTTP for Humans.",
        "description": (
            "Requests is an elegant and simple HTTP library for "
            "Python, built for human beings. The de-facto standard "
            "for HTTP clients in Python."
        ),
        "entry": "requests",
        "example": "import requests; r = requests.get('https://example.com'); print(r.status_code)",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "httpx", "import_name": "httpx", "pip": "httpx",
        "version": "0.27.0", "category": "web",
        "summary": "Async HTTP client (HTTP/1.1, HTTP/2, HTTP/3).",
        "description": (
            "httpx is a modern HTTP client for Python with "
            "asynchronous support and HTTP/2 + HTTP/3 support."
        ),
        "entry": "httpx",
        "example": "import httpx; r = httpx.get('https://example.com'); print(r.status_code)",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "aiohttp", "import_name": "aiohttp", "pip": "aiohttp",
        "version": "3.9.5", "category": "web",
        "summary": "Async HTTP client/server framework.",
        "description": (
            "aiohttp is an asynchronous HTTP client/server framework "
            "built on top of asyncio. Supports both client and "
            "server."
        ),
        "entry": "aiohttp",
        "example": "import aiohttp, asyncio; async def main(): async with aiohttp.ClientSession() as s: print(await (await s.get('https://example.com')).text())",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "beautifulsoup4", "import_name": "bs4", "pip": "beautifulsoup4",
        "version": "4.12.3", "category": "web",
        "summary": "HTML/XML parser for pulling data out of web pages.",
        "description": (
            "Beautiful Soup is a Python library for pulling data out "
            "of HTML and XML files. Works with your favorite parser "
            "to provide idiomatic ways of navigating, searching, and "
            "modifying the parse tree."
        ),
        "entry": "bs4",
        "example": "from bs4 import BeautifulSoup; print(BeautifulSoup('<a>x</a>', 'html.parser').a.text)",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "lxml", "import_name": "lxml", "pip": "lxml",
        "version": "5.3.0", "category": "web",
        "summary": "Powerful XML/HTML processing library (libxml2/libxslt bindings).",  # noqa: E501
        "description": (
            "lxml is the most feature-rich and easy-to-use library "
            "for processing XML and HTML in the Python language."
        ),
        "entry": "lxml",
        "example": "from lxml import etree; print(etree.tostring(etree.fromstring('<a/>')))",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "selenium", "import_name": "selenium", "pip": "selenium",
        "version": "4.22.0", "category": "web",
        "summary": "Browser automation framework (WebDriver).",
        "description": (
            "Selenium automates browsers. Use it for browser-based "
            "recon, XSS proof-of-concept, or session-aware testing."
        ),
        "entry": "selenium",
        "example": "from selenium import webdriver; d = webdriver.Firefox(); d.get('https://example.com')",
        "risk_level": "medium", "requires_gate": True,
    },
    {
        "name": "playwright", "import_name": "playwright", "pip": "playwright",
        "version": "1.45.0", "category": "web",
        "summary": "Browser automation (Chromium, Firefox, WebKit).",
        "description": (
            "Playwright is a framework for Web Testing and Automation. "
            "It allows testing Chromium, WebKit and Firefox with a "
            "single API."
        ),
        "entry": "playwright",
        "example": "from playwright.sync_api import sync_playwright; p = sync_playwright().start(); b = p.chromium.launch(); b.close()",
        "risk_level": "medium", "requires_gate": True,
    },
    {
        "name": "pyjwt", "import_name": "jwt", "pip": "pyjwt",
        "version": "2.8.0", "category": "web",
        "summary": "JSON Web Token encoder/decoder.",
        "description": (
            "PyJWT is a Python library which allows you to encode "
            "and decode JSON Web Tokens (JWT). JWT is an open, "
            "industry-standard (RFC 7519) for representing claims "
            "securely between two parties."
        ),
        "entry": "jwt",
        "example": "import jwt; print(jwt.encode({'sub': '1'}, 'secret', algorithm='HS256'))",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "cryptography", "import_name": "cryptography", "pip": "cryptography",
        "version": "43.0.0", "category": "crypto",
        "summary": "Cryptographic recipes and primitives (Fernet, RSA, X.509, TLS, ...).",  # noqa: E501
        "description": (
            "The cryptography library is a Python package that "
            "provides cryptographic recipes and primitives to "
            "developers."
        ),
        "entry": "cryptography",
        "example": "from cryptography.fernet import Fernet; print(Fernet.generate_key())",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "pycryptodome", "import_name": "Crypto", "pip": "pycryptodome",
        "version": "3.20.0", "category": "crypto",
        "summary": "Self-contained cryptographic library (AES, RSA, ...).",
        "description": (
            "PyCryptodome is a self-contained Python package of "
            "low-level cryptographic primitives. Supports AES, RSA, "
            "DES, 3DES, hashing, HMAC, PBKDF2, scrypt, etc."
        ),
        "entry": "Crypto",
        "example": "from Crypto.Cipher import AES; print(AES.new(b'0'*16, AES.MODE_ECB).encrypt(b'0'*16).hex())",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "pynacl", "import_name": "nacl", "pip": "pynacl",
        "version": "1.5.0", "category": "crypto",
        "summary": "Python bindings to libsodium (NaCl).",
        "description": (
            "PyNaCl is a Python binding to the Networking and "
            "Cryptography library (NaCl / libsodium). Provides "
            "sealed boxes, signing, key exchange, hashing."
        ),
        "entry": "nacl",
        "example": "from nacl.public import PrivateKey; print(PrivateKey.generate().encode().hex())",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "passlib", "import_name": "passlib", "pip": "passlib",
        "version": "1.7.4", "category": "crypto",
        "summary": "Password hashing library (bcrypt, scrypt, pbkdf2, ...).",
        "description": (
            "Passlib is a password hashing library for Python, "
            "providing cross-platform implementations of over 30 "
            "password hashing algorithms."
        ),
        "entry": "passlib",
        "example": "from passlib.hash import bcrypt; print(bcrypt.using(rounds=4).hash('x'))",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "pyOpenSSL", "import_name": "OpenSSL", "pip": "pyOpenSSL",
        "version": "24.2.1", "category": "crypto",
        "summary": "Python wrapper around a small subset of the OpenSSL library.",
        "description": (
            "pyOpenSSL is a Python wrapper for a subset of the "
            "OpenSSL library. Provides SSL/TLS contexts, X.509 "
            "certificates, ASN.1, signing/verification."
        ),
        "entry": "OpenSSL",
        "example": "from OpenSSL import crypto; print(crypto.dump_certificate(crypto.FILETYPE_PEM, crypto.X509()))",
        "risk_level": "low", "requires_gate": False,
    },
    # ---- Exploit / pwn ---------------------------------------------------
    {
        "name": "pwntools", "import_name": "pwn", "pip": "pwntools",
        "version": "4.12.0", "category": "exploit",
        "summary": "CTF framework and exploit development library.",
        "description": (
            "pwntools is a CTF framework and exploit development "
            "library. Written in Python, designed for rapid "
            "prototyping and development."
        ),
        "entry": "pwn",
        "example": "from pwn import remote, p64; r = remote('10.0.0.5', 1337); r.sendline(b'A' * 64 + p64(0xdeadbeef))",
        "risk_level": "critical", "requires_gate": True,
    },
    {
        "name": "ropper", "import_name": "ropper", "pip": "ropper",
        "version": "1.13.8", "category": "exploit",
        "summary": "ROP gadget finder.",
        "description": (
            "Ropper is a multi-architecture ROP gadget finder. It "
            "supports x86, x86_64, ARM, ARM64, MIPS, PowerPC, SPARC "
            "and RISC-V."
        ),
        "entry": "ropper",
        "example": "ropper --file /bin/ls --search 'pop rdi'",
        "risk_level": "medium", "requires_gate": False,
    },
    {
        "name": "pwnlib", "import_name": "pwnlib", "pip": "pwnlib",
        "version": "4.12.0", "category": "exploit",
        "summary": "Re-export of pwntools core (pwnlib.*).",
        "description": (
            "pwnlib is the re-export namespace of pwntools. "
            "Importable separately; depends on pwntools install."
        ),
        "entry": "pwnlib",
        "example": "from pwnlib.util.packing import p64; print(hex(p64(0x41414141)))",
        "risk_level": "critical", "requires_gate": True,
    },
    {
        "name": "angr", "import_name": "angr", "pip": "angr",
        "version": "9.2.144", "category": "exploit",
        "summary": "Platform-agnostic binary analysis framework.",
        "description": (
            "angr is a platform-agnostic binary analysis framework "
            "built on top of symbolic execution engines. Useful for "
            "automated reverse engineering and CTF challenges."
        ),
        "entry": "angr",
        "example": "import angr; p = angr.Project('/bin/ls', auto_load_libs=False)",
        "risk_level": "medium", "requires_gate": False,
    },
    {
        "name": "capstone", "import_name": "capstone", "pip": "capstone",
        "version": "5.0.1", "category": "exploit",
        "summary": "Disassembly framework (multi-arch).",
        "description": (
            "Capstone is a disassembly framework with the target of "
            "becoming the ultimate disassembly engine. Supports x86, "
            "ARM, ARM64, MIPS, PPC, SPARC, etc."
        ),
        "entry": "capstone",
        "example": "from capstone import Cs, CS_ARCH_X86, CS_MODE_64; md = Cs(CS_ARCH_X86, CS_MODE_64); [print(f'{i.address:#x}: {i.mnemonic} {i.op_str}') for i in md.disasm(b'\\x90\\x90', 0)]",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "unicorn", "import_name": "unicorn", "pip": "unicorn",
        "version": "2.0.1", "category": "exploit",
        "summary": "CPU emulator engine (multi-arch).",
        "description": (
            "Unicorn is a lightweight multi-platform, multi-architecture "
            "CPU emulator framework, based on QEMU. Useful for "
            "binary emulation in exploits."
        ),
        "entry": "unicorn",
        "example": "from unicorn import Uc, UC_ARCH_X86, UC_MODE_64; u = Uc(UC_ARCH_X86, UC_MODE_64); u.mem_map(0x1000, 0x1000)",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "keystone", "import_name": "keystone", "pip": "keystone",
        "version": "0.9.10", "category": "exploit",
        "summary": "Assembler framework (multi-arch).",
        "description": (
            "Keystone is a lightweight multi-platform, multi-architecture "
            "assembler framework. Based on LLVM / Capstone / Unicorn."
        ),
        "entry": "keystone",
        "example": "from keystone import Kc, KS_ARCH_X86, KS_MODE_64; print(Kc(KS_ARCH_X86, KS_MODE_64).asm('nop')[0])",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "lief", "import_name": "lief", "pip": "lief",
        "version": "0.15.0", "category": "exploit",
        "summary": "Library to Instrument Executable Formats (PE, ELF, Mach-O).",  # noqa: E501
        "description": (
            "LIEF is a library to instrument executable formats. It "
            "supports PE, ELF, Mach-O, and DEX formats. Useful for "
            "binary analysis and patching."
        ),
        "entry": "lief",
        "example": "import lief; b = lief.parse('/bin/ls'); print(b.header)",
        "risk_level": "low", "requires_gate": False,
    },
    # ---- OSINT / recon ---------------------------------------------------
    {
        "name": "shodan", "import_name": "shodan", "pip": "shodan",
        "version": "1.31.0", "category": "osint",
        "summary": "Shodan API client.",
        "description": (
            "Shodan is a search engine for internet-connected "
            "devices. This library wraps the Shodan REST API."
        ),
        "entry": "shodan",
        "example": "import shodan; api = shodan.Shodan('KEY'); print(api.host('8.8.8.8'))",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "censys", "import_name": "censys", "pip": "censys",
        "version": "2.2.0", "category": "osint",
        "summary": "Censys search engine client.",
        "description": (
            "Censys is a search engine for hosts, certificates, and "
            "websites. This library wraps the Censys API v2."
        ),
        "entry": "censys",
        "example": "from censys.search import CensysHosts; h = CensysHosts(); print(h.search('services.service_name: HTTP'))",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "ipinfo", "import_name": "ipinfo", "pip": "ipinfo",
        "version": "0.3.2", "category": "osint",
        "summary": "IPinfo.io API client.",
        "description": (
            "ipinfo is a Python client for ipinfo.io, a public IP "
            "address information service."
        ),
        "entry": "ipinfo",
        "example": "import ipinfo; h = ipinfo.getHandler('TOKEN'); print(h.getDetails('8.8.8.8').all)",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "whois", "import_name": "whois", "pip": "whois",
        "version": "0.9.27", "category": "osint",
        "summary": "WHOIS lookup for domains and IPs.",
        "description": (
            "whois is a Python module/library for retrieving WHOIS "
            "data for domain names and IP addresses."
        ),
        "entry": "whois",
        "example": "import whois; print(whois.whois('example.com'))",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "emailrep", "import_name": "emailrep", "pip": "emailrep",
        "version": "0.2.13", "category": "osint",
        "summary": "EmailRep.io API client (email reputation).",
        "description": (
            "emailrep is a Python client for the EmailRep API, "
            "which provides email reputation / OSINT lookups."
        ),
        "entry": "emailrep",
        "example": "import emailrep; print(emailrep.query('test@example.com'))",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "holehe", "import_name": "holehe", "pip": "holehe",
        "version": "0.0.2", "category": "osint",
        "summary": "Email-to-registered-accounts lookup (80+ sites).",
        "description": (
            "holehe checks if an email is registered on 80+ sites "
            "without notifying the user. Useful for OSINT on a "
            "target's online presence."
        ),
        "entry": "holehe",
        "example": "holehe test@example.com",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "theHarvester", "import_name": "theHarvester", "pip": "theHarvester",
        "version": "4.4.4", "category": "osint",
        "summary": "Email, subdomain, and name harvester (search engines, PGP, ...).",  # noqa: E501
        "description": (
            "theHarvester is a tool for gathering OSINT: emails, "
            "names, subdomains, IPs, and URLs from public sources "
            "(search engines, PGP key servers, SHODAN)."
        ),
        "entry": "theHarvester",
        "example": "theHarvester -d example.com -b google",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "socialscan", "import_name": "socialscan", "pip": "socialscan",
        "version": "0.2.7", "category": "osint",
        "summary": "Username / email availability checker (accurate).",
        "description": (
            "socialscan offers accurate and fast checks for email "
            "address and username usage on online platforms."
        ),
        "entry": "socialscan",
        "example": "socialscan test",
        "risk_level": "low", "requires_gate": False,
    },
    # ---- Web exploitation -----------------------------------------------
    {
        "name": "sqlmap", "import_name": "sqlmap", "pip": "sqlmap",
        "version": "1.8.0", "category": "exploit",
        "summary": "Automatic SQL injection and database takeover tool.",
        "description": (
            "sqlmap is an open source penetration testing tool that "
            "automates the process of detecting and exploiting SQL "
            "injection flaws."
        ),
        "entry": "sqlmap",
        "example": "sqlmap -u 'http://10.0.0.5/?id=1' --dbs",
        "risk_level": "high", "requires_gate": True,
    },
    {
        "name": "wafw00f", "import_name": "wafw00f", "pip": "wafw00f",
        "version": "2.2.0", "category": "recon",
        "summary": "Web Application Firewall fingerprinting.",
        "description": (
            "wafw00f identifies and fingerprints Web Application "
            "Firewall (WAF) products. Useful as a pre-attack recon."
        ),
        "entry": "wafw00f",
        "example": "wafw00f https://example.com",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "dirsearch", "import_name": "dirsearch", "pip": "dirsearch",
        "version": "0.4.8", "category": "recon",
        "summary": "Command-line web path scanner.",
        "description": (
            "dirsearch is a command-line web path scanner for "
            "discovering files and directories on a web server."
        ),
        "entry": "dirsearch",
        "example": "dirsearch -u https://example.com -e php,html",
        "risk_level": "medium", "requires_gate": True,
    },
    {
        "name": "XSStrike", "import_name": "xsstrike", "pip": "XSStrike",
        "version": "0.0.4", "category": "exploit",
        "summary": "Advanced XSS detection suite (fuzzing, crawler, ...).",
        "description": (
            "XSStrike is an advanced XSS detection suite. It "
            "features a powerful fuzzing engine and an intelligent "
            "payload generator."
        ),
        "entry": "xsstrike",
        "example": "python xsstrike.py -u 'https://example.com/?q=test'",
        "risk_level": "high", "requires_gate": True,
    },
    {
        "name": "arjun", "import_name": "arjun", "pip": "arjun",
        "version": "2.2.1", "category": "recon",
        "summary": "HTTP parameter discovery suite.",
        "description": (
            "Arjun can find query parameters for URL endpoints. "
            "Useful for finding hidden parameters in web APIs."
        ),
        "entry": "arjun",
        "example": "arjun -u https://example.com/api",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "ffuf", "import_name": "ffuf", "pip": "ffuf",
        "version": "2.1.0", "category": "recon",
        "summary": "Fast web fuzzer (Go-based, also Python wrapper).",
        "description": (
            "ffuf is a fast web fuzzer written in Go. The Python "
            "package is a thin wrapper."
        ),
        "entry": "ffuf",
        "example": "ffuf -u https://example.com/FUZZ -w /usr/share/wordlists/dirb/common.txt",
        "risk_level": "low", "requires_gate": False,
    },
    # ---- Wireless / BLE / WiFi -----------------------------------------
    {
        "name": "pybluez2", "import_name": "bluetooth", "pip": "pybluez2",
        "version": "0.46", "category": "ble",
        "summary": "Bluetooth / BLE Python bindings (BlueZ).",
        "description": (
            "PyBluez2 is a Python extension module for accessing "
            "system Bluetooth resources on Linux via BlueZ."
        ),
        "entry": "bluetooth",
        "example": "import bluetooth; print(bluetooth.discover_devices())",
        "risk_level": "medium", "requires_gate": True,
    },
    {
        "name": "bleak", "import_name": "bleak", "pip": "bleak",
        "version": "0.21.3", "category": "ble",
        "summary": "Cross-platform BLE library (async).",
        "description": (
            "bleak is a cross-platform Bluetooth Low Energy (BLE) "
            "client library for Python. Supports Windows, Linux, "
            "macOS."
        ),
        "entry": "bleak",
        "example": "import asyncio, bleak; asyncio.run(bleak.BleakScanner.discover())",
        "risk_level": "medium", "requires_gate": True,
    },
    {
        "name": "pyric", "import_name": "pyric", "pip": "pyric",
        "version": "0.1.6.3", "category": "wifi",
        "summary": "Python wireless library (Linux / nl80211).",
        "description": (
            "pyric is a Python library to interact with the Linux "
            "netlink 802.11 subsystem (nl80211). Allows interface "
            "manipulation, channel switching, monitor mode."
        ),
        "entry": "pyric",
        "example": "import pyric.pyric as pyric; print(pyric.devinfo())",
        "risk_level": "high", "requires_gate": True,
    },
    {
        "name": "wifi", "import_name": "wifi", "pip": "wifi",
        "version": "0.3.8", "category": "wifi",
        "summary": "WiFi management (scan/connect) on Linux.",
        "description": (
            "wifi is a Python library providing WiFi management "
            "functionality (scan, connect, disconnect) on Linux via "
            "wpa_supplicant."
        ),
        "entry": "wifi",
        "example": "from wifi import Cell; print([c.ssid for c in Cell.all('wlan0')])",
        "risk_level": "medium", "requires_gate": True,
    },
    {
        "name": "scapy-80211", "import_name": "scapy.layers.dot11", "pip": "scapy",
        "version": "2.5.0", "category": "wifi",
        "summary": "Scapy's 802.11 layer (built-in when scapy installed).",
        "description": (
            "scapy.contrib.dot11 is the 802.11 (WiFi) layer for "
            "Scapy. Supports beacon, probe, EAPOL, deauth, etc."
        ),
        "entry": "scapy.layers.dot11",
        "example": "from scapy.all import Dot11, RadioTap, sendp; sendp(RadioTap()/Dot11(addr1='ff:ff:ff:ff:ff:ff', addr2='AA:BB:CC:DD:EE:FF', addr3='AA:BB:CC:DD:EE:FF')/Dot11Deauth(), iface='wlan0mon')",
        "risk_level": "high", "requires_gate": True,
    },
    # ---- Post-exploitation -----------------------------------------------
    {
        "name": "pypykatz", "import_name": "pypykatz", "pip": "pypykatz",
        "version": "0.6.8", "category": "post_exploitation",
        "summary": "Mimikatz implementation in pure Python.",
        "description": (
            "pypykatz is a Python implementation of Mimikatz, "
            "with the ability to extract credentials from LSASS "
            "process memory dumps."
        ),
        "entry": "pypykatz",
        "example": "pypykatz rekall lsass.DMP",
        "risk_level": "critical", "requires_gate": True,
    },
    {
        "name": "lsassy", "import_name": "lsassy", "pip": "lsassy",
        "version": "3.0.6", "category": "post_exploitation",
        "summary": "Remote LSASS dumping via impacket.",
        "description": (
            "lsassy is a Python tool to remotely extract "
            "credentials from a Windows host, by reading LSASS "
            "process memory via various methods."
        ),
        "entry": "lsassy",
        "example": "lsassy -u Administrator -p 'PASS' 10.0.0.5",
        "risk_level": "critical", "requires_gate": True,
    },
    {
        "name": "mimipenguin", "import_name": "mimipenguin", "pip": "mimipenguin",
        "version": "0.0.1", "category": "post_exploitation",
        "summary": "Linux equivalent of mimikatz (reads /proc).",
        "description": (
            "mimipenguin is a tool to dump cleartext Linux "
            "credentials from memory by reading /proc/<pid>/maps "
            "and using gdb to attach."
        ),
        "entry": "mimipenguin",
        "example": "sudo mimipenguin",
        "risk_level": "critical", "requires_gate": True,
    },
    {
        "name": "bloodhound", "import_name": "bloodhound", "pip": "bloodhound",
        "version": "1.0.0", "category": "post_exploitation",
        "summary": "AD attack-path mapper (Python client).",
        "description": (
            "BloodHound is a single page JavaScript web application, "
            "built on top of Linkurious, compiled with Electron, "
            "with a Neo4j database fed by data from a Powershell "
            "ingestor."
        ),
        "entry": "bloodhound",
        "example": "bloodhound-python -u user -p 'PASS' -d example.com -ns 10.0.0.5",
        "risk_level": "high", "requires_gate": True,
    },
    {
        "name": "crackmapexec", "import_name": "cme", "pip": "crackmapexec",
        "version": "5.4.0", "category": "post_exploitation",
        "summary": "Post-exploitation tool for AD (the Python package).",
        "description": (
            "CrackMapExec (a.k.a. CME) is a post-exploitation tool "
            "that helps automate assessing the security of large "
            "Active Directory networks."
        ),
        "entry": "cme",
        "example": "cme smb 10.0.0.0/24 -u Administrator -p 'PASS'",
        "risk_level": "high", "requires_gate": True,
    },
    {
        "name": "pypsrp", "import_name": "pypsrp", "pip": "pypsrp",
        "version": "0.8.1", "category": "post_exploitation",
        "summary": "Pure-Python PowerShell Remoting Protocol client.",
        "description": (
            "pypsrp is a pure-Python client for the PowerShell "
            "Remoting Protocol (PSRP). It allows you to invoke "
            "PowerShell commands on a remote Windows host."
        ),
        "entry": "pypsrp",
        "example": "from pypsrp.client import Client; c = Client('10.0.0.5', 'u', 'p'); c.execute_cmd('Get-Process')",
        "risk_level": "high", "requires_gate": True,
    },
    {
        "name": "pymetasploit3", "import_name": "pymetasploit3", "pip": "pymetasploit3",
        "version": "1.0.4", "category": "exploit",
        "summary": "Python client for Metasploit's msgrpc.",
        "description": (
            "pymetasploit3 is a Python wrapper for the Metasploit "
            "Framework's msgrpc interface."
        ),
        "entry": "pymetasploit3",
        "example": "from pymetasploit3.msfrpc import MsfRpcClient; c = MsfRpcClient('pass'); print(c.modules.exploits)",
        "risk_level": "high", "requires_gate": True,
    },
    {
        "name": "pyrdp", "import_name": "pyrdp", "pip": "pyrdp",
        "version": "0.1.0", "category": "post_exploitation",
        "summary": "RDP man-in-the-middle and library.",
        "description": (
            "pyrdp is a Python RDP man-in-the-middle and library "
            "for interacting with RDP services. Can be used to "
            "record sessions, MITM, and extract credentials."
        ),
        "entry": "pyrdp",
        "example": "pyrdp-mitm 10.0.0.5:3389",
        "risk_level": "high", "requires_gate": True,
    },
    # ---- Password cracking / wordlist ---------------------------------
    {
        "name": "hashcat-brain", "import_name": "hashcat", "pip": "hashcat-brain",
        "version": "0.0.1", "category": "exploit",
        "summary": "Hashcat client library (Python).",
        "description": (
            "hashcat-brain is a Python client for the hashcat "
            "distributed cracking server (hashcat brain)."
        ),
        "entry": "hashcat",
        "example": "import hashcat; print(hashcat.hashcat('-m', '0', '--help'))",
        "risk_level": "low", "requires_gate": False,
    },
    # ---- C2 / RAT building ---------------------------------------------
    {
        "name": "pyngus", "import_name": "pyngus", "pip": "pyngus",
        "version": "2.3.0", "category": "c2",
        "summary": "Pure-Python AMQP 1.0 client (Apache Qpid).",
        "description": (
            "pyngus is a pure-Python client library for the AMQP "
            "1.0 protocol. Useful for building C2 channels over "
            "messaging brokers."
        ),
        "entry": "pyngus",
        "example": "import pyngus; c = pyngus.Connection('amqp://10.0.0.5')",
        "risk_level": "medium", "requires_gate": True,
    },
    {
        "name": "donut", "import_name": "donut", "pip": "donut-shellcode",
        "version": "0.9.3", "category": "c2",
        "summary": "Generate position-independent shellcode from VBS/JS/JAR/EXE/DLL.",  # noqa: E501
        "description": (
            "Donut is a tool for generating position-independent "
            "shellcode from VBScript, JScript, .NET assemblies, "
            "EXE / DLL files. The Python package wraps the binary."
        ),
        "entry": "donut",
        "example": "donut -i payload.exe -o shellcode.bin",
        "risk_level": "critical", "requires_gate": True,
    },
    # ---- Staging / loader ----------------------------------------------
    {
        "name": "pyinstaller", "import_name": "PyInstaller", "pip": "pyinstaller",
        "version": "6.10.0", "category": "utility",
        "summary": "Bundle a Python app into a single executable.",
        "description": (
            "PyInstaller bundles a Python application and all its "
            "dependencies into a single package (folder or "
            "executable)."
        ),
        "entry": "PyInstaller",
        "example": "pyinstaller --onefile myapp.py",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "nuitka", "import_name": "nuitka", "pip": "nuitka",
        "version": "2.5.0", "category": "utility",
        "summary": "Python compiler (Python -> C -> native).",
        "description": (
            "Nuitka is a Python compiler written in Python. It "
            "translates Python code into C, and then compiles the C "
            "code into a native binary."
        ),
        "entry": "nuitka",
        "example": "nuitka --onefile myapp.py",
        "risk_level": "low", "requires_gate": False,
    },
    # ---- Utility / TUI ------------------------------------------------
    {
        "name": "rich", "import_name": "rich", "pip": "rich",
        "version": "13.7.1", "category": "utility",
        "summary": "Rich text + beautiful formatting in the terminal.",
        "description": (
            "Rich is a Python library for rich text and beautiful "
            "formatting in the terminal. Used by KFIOSA for the TUI."
        ),
        "entry": "rich",
        "example": "from rich import print; print('[bold red]hi[/bold red]')",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "typer", "import_name": "typer", "pip": "typer",
        "version": "0.12.3", "category": "utility",
        "summary": "CLI library (build on Click).",
        "description": (
            "Typer is a library for building CLI applications. "
            "Built on top of Click, with type hints."
        ),
        "entry": "typer",
        "example": "import typer; app = typer.Typer()",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "click", "import_name": "click", "pip": "click",
        "version": "8.1.7", "category": "utility",
        "summary": "Python composable command line interface toolkit.",
        "description": (
            "Click is a Python package for creating beautiful "
            "command line interfaces in a composable way."
        ),
        "entry": "click",
        "example": "import click; @click.command()\ndef hi(): print('hi')",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "colorama", "import_name": "colorama", "pip": "colorama",
        "version": "0.4.6", "category": "utility",
        "summary": "Cross-platform colored terminal text.",
        "description": (
            "Colorama makes ANSI escape character sequences "
            "(for producing colored terminal text and cursor "
            "positioning) work under MS Windows."
        ),
        "entry": "colorama",
        "example": "import colorama; colorama.init(); print(colorama.Fore.RED + 'red')",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "jinja2", "import_name": "jinja2", "pip": "jinja2",
        "version": "3.1.4", "category": "utility",
        "summary": "Templating engine.",
        "description": (
            "Jinja2 is a fast, expressive, extensible templating "
            "engine. Used to render exploit HTML, payloads, etc."
        ),
        "entry": "jinja2",
        "example": "from jinja2 import Template; print(Template('hi {{ n }}').render(n='x'))",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "pyyaml", "import_name": "yaml", "pip": "pyyaml",
        "version": "6.0.1", "category": "utility",
        "summary": "YAML parser and emitter.",
        "description": (
            "PyYAML is a YAML parser and emitter for Python. "
            "Used for parsing tool outputs (e.g., nmap, bloodhound)."
        ),
        "entry": "yaml",
        "example": "import yaml; print(yaml.safe_load('a: 1'))",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "toml", "import_name": "toml", "pip": "toml",
        "version": "0.10.2", "category": "utility",
        "summary": "TOML parser / writer.",
        "description": (
            "A lil' TOML parser / writer for Python. Useful for "
            "config files."
        ),
        "entry": "toml",
        "example": "import toml; print(toml.loads('a = 1'))",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "pydantic", "import_name": "pydantic", "pip": "pydantic",
        "version": "2.8.0", "category": "utility",
        "summary": "Data validation using Python type hints.",
        "description": (
            "Data validation and settings management using Python "
            "type hints. Fast, JSON-schema aware."
        ),
        "entry": "pydantic",
        "example": "from pydantic import BaseModel; class M(BaseModel): x: int; print(M(x=1))",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "huggingface_hub", "import_name": "huggingface_hub", "pip": "huggingface_hub",
        "version": "0.24.0", "category": "ai",
        "summary": "Client for the Hugging Face Hub.",
        "description": (
            "huggingface_hub is a client for the Hugging Face "
            "Model Hub. Download / upload models, manage Spaces, "
            "etc."
        ),
        "entry": "huggingface_hub",
        "example": "from huggingface_hub import snapshot_download; snapshot_download('bert-base-uncased')",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "transformers", "import_name": "transformers", "pip": "transformers",
        "version": "4.44.0", "category": "ai",
        "summary": "State-of-the-art ML for PyTorch / TensorFlow / JAX (LLMs, vision, ...).",  # noqa: E501
        "description": (
            "Transformers provides thousands of pretrained models "
            "to perform tasks on different modalities such as text, "
            "vision, and audio."
        ),
        "entry": "transformers",
        "example": "from transformers import pipeline; print(pipeline('sentiment-analysis')('I love KFIOSA'))",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "torch", "import_name": "torch", "pip": "torch",
        "version": "2.4.0", "category": "ai",
        "summary": "PyTorch deep learning framework.",
        "description": (
            "Tensors and dynamic neural networks in Python with "
            "strong GPU acceleration."
        ),
        "entry": "torch",
        "example": "import torch; print(torch.tensor([1,2,3]).sum())",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "datasets", "import_name": "datasets", "pip": "datasets",
        "version": "2.20.0", "category": "ai",
        "summary": "HuggingFace Datasets (one-line data loaders).",
        "description": (
            "Datasets is a library for easily accessing and sharing "
            "datasets for Audio, Computer Vision, and NLP tasks."
        ),
        "entry": "datasets",
        "example": "from datasets import load_dataset; print(load_dataset('squad', split='train[:1]'))",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "numpy", "import_name": "numpy", "pip": "numpy",
        "version": "2.0.0", "category": "ai",
        "summary": "Fundamental package for scientific computing with Python.",
        "description": (
            "NumPy is the fundamental package for scientific "
            "computing in Python: arrays, linear algebra, "
            "random number generation."
        ),
        "entry": "numpy",
        "example": "import numpy; print(numpy.array([1,2,3]).sum())",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "scipy", "import_name": "scipy", "pip": "scipy",
        "version": "1.13.0", "category": "ai",
        "summary": "Fundamental algorithms for scientific computing.",
        "description": (
            "SciPy provides algorithms for optimization, "
            "integration, interpolation, eigenvalue problems, "
            "statistical distributions, etc."
        ),
        "entry": "scipy",
        "example": "from scipy import stats; print(stats.norm.pdf(0))",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "pandas", "import_name": "pandas", "pip": "pandas",
        "version": "2.2.0", "category": "ai",
        "summary": "Data analysis and manipulation library.",
        "description": (
            "pandas is a fast, powerful, flexible and easy to use "
            "open source data analysis and manipulation tool, built "
            "on top of the Python programming language."
        ),
        "entry": "pandas",
        "example": "import pandas; print(pandas.DataFrame({'a': [1]}))",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "matplotlib", "import_name": "matplotlib", "pip": "matplotlib",
        "version": "3.9.0", "category": "ai",
        "summary": "Plotting library (static, animated, interactive).",
        "description": (
            "Matplotlib is a comprehensive library for creating "
            "static, animated, and interactive visualizations in "
            "Python."
        ),
        "entry": "matplotlib",
        "example": "import matplotlib; print(matplotlib.__version__)",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "pillow", "import_name": "PIL", "pip": "pillow",
        "version": "10.4.0", "category": "utility",
        "summary": "PIL fork (image processing).",
        "description": (
            "Pillow is the friendly PIL fork by Alex Clark and "
            "contributors. Adds image processing capabilities to "
            "your Python interpreter."
        ),
        "entry": "PIL",
        "example": "from PIL import Image; print(Image.new('RGB', (10, 10)).size)",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "pdfminer.six", "import_name": "pdfminer", "pip": "pdfminer.six",
        "version": "20231228", "category": "osint",
        "summary": "PDF text extraction.",
        "description": (
            "pdfminer.six is a community-maintained fork of "
            "pdfminer. Extracts text from PDF files."
        ),
        "entry": "pdfminer",
        "example": "from pdfminer.high_level import extract_text; print(extract_text('doc.pdf')[:100])",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "docx2txt", "import_name": "docx2txt", "pip": "docx2txt",
        "version": "0.8", "category": "osint",
        "summary": "Extract text from .docx files.",
        "description": (
            "docx2txt is a pure python based utility to extract "
            "text from .docx files."
        ),
        "entry": "docx2txt",
        "example": "import docx2txt; print(docx2txt.process('doc.docx')[:100])",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "olefile", "import_name": "olefile", "pip": "olefile",
        "version": "0.47", "category": "osint",
        "summary": "OLE / OLE2 / Compound Document parser (DOC/XLS/...).",
        "description": (
            "olefile is a Python package to parse, read and write "
            "Microsoft OLE2 files (also called Structured Storage "
            "or Compound Document)."
        ),
        "entry": "olefile",
        "example": "import olefile; print(olefile.OleFileIO('doc.doc').listdir())",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "pefile", "import_name": "pefile", "pip": "pefile",
        "version": "2024.8.26", "category": "exploit",
        "summary": "PE (Portable Executable) parser.",
        "description": (
            "pefile is a Python module to read and work with PE "
            "(Portable Executable) files. Useful for malware "
            "analysis."
        ),
        "entry": "pefile",
        "example": "import pefile; print(pefile.PE('/bin/ls').sections)",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "yara-python", "import_name": "yara", "pip": "yara-python",
        "version": "4.5.1", "category": "exploit",
        "summary": "YARA pattern-matching (Python bindings).",
        "description": (
            "yara-python allows you to use YARA from Python. "
            "Useful for malware analysis and detection."
        ),
        "entry": "yara",
        "example": "import yara; rules = yara.compile(filepath='rules.yar'); rules.match('/bin/ls')",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "r2pipe", "import_name": "r2pipe", "pip": "r2pipe",
        "version": "1.9.4", "category": "exploit",
        "summary": "Radare2 reverse engineering framework (Python bindings).",  # noqa: E501
        "description": (
            "r2pipe is a Python client for radare2, the reverse "
            "engineering framework."
        ),
        "entry": "r2pipe",
        "example": "import r2pipe; r2 = r2pipe.open('/bin/ls'); print(r2.cmd('iI'))",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "ghidra_bridge", "import_name": "ghidra_bridge", "pip": "ghidra-bridge",
        "version": "2.0.0", "category": "exploit",
        "summary": "Ghidra RE bridge (Python client).",
        "description": (
            "ghidra_bridge is a Python client for the Ghidra "
            "reverse engineering tool. Useful for AI-driven RE."
        ),
        "entry": "ghidra_bridge",
        "example": "import ghidra_bridge; b = ghidra_bridge.GhidraBridge(); print(b.remote_ghidra)",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "binwalk", "import_name": "binwalk", "pip": "binwalk",
        "version": "2.3.3", "category": "exploit",
        "summary": "Firmware analysis / extract embedded files.",
        "description": (
            "binwalk is a tool for searching binary images for "
            "embedded files and executable code."
        ),
        "entry": "binwalk",
        "example": "binwalk firmware.bin",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "volatility3", "import_name": "volatility3", "pip": "volatility3",
        "version": "2.11.0", "category": "post_exploitation",
        "summary": "Memory forensics framework (v3).",
        "description": (
            "Volatility 3 is the world's most advanced memory "
            "forensics framework. It supports Windows, Linux, and "
            "macOS memory dumps."
        ),
        "entry": "volatility3",
        "example": "vol -f memdump.raw windows.info",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "exrex", "import_name": "exrex", "pip": "exrex",
        "version": "0.11.0", "category": "utility",
        "summary": "Generate strings from regex.",
        "description": (
            "exrex is a tool to generate all matching strings to a "
            "given regular expression. Useful for fuzzing."
        ),
        "entry": "exrex",
        "example": "import exrex; print(list(exrex.generate('a{1,3}'))[:5])",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "boofuzz", "import_name": "boofuzz", "pip": "boofuzz",
        "version": "0.4.0", "category": "exploit",
        "summary": "Network protocol fuzzer.",
        "description": (
            "boofuzz is a fork of and successor to the famous "
            "Sulley fuzzing framework. Generates and sends "
            "malformed inputs to network services."
        ),
        "entry": "boofuzz",
        "example": "from boofuzz import Session; Session(target=Target(connection=SocketConnection('10.0.0.5', 80))).fuzz()",
        "risk_level": "high", "requires_gate": True,
    },
    {
        "name": "afl-utils", "import_name": "afl_utils", "pip": "afl-utils",
        "version": "0.7.3", "category": "exploit",
        "summary": "Helper for AFL (American Fuzzy Lop) runs.",
        "description": (
            "afl-utils is a collection of utilities for working "
            "with AFL (American Fuzzy Lop) fuzz results."
        ),
        "entry": "afl_utils",
        "example": "afl-collect",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "truffleHog", "import_name": "truffleHog", "pip": "trufflehog",
        "version": "3.0.0", "category": "osint",
        "summary": "Find leaked secrets in git repos.",
        "description": (
            "TruffleHog is a tool for finding leaked credentials "
            "in git repositories, S3 buckets, Docker images, etc."
        ),
        "entry": "trufflehog",
        "example": "trufflehog git https://github.com/foo/bar",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "git-dumper", "import_name": "git_dumper", "pip": "git-dumper",
        "version": "1.0.6", "category": "osint",
        "summary": "Dump exposed .git directories.",
        "description": (
            "git-dumper is a tool to dump a git repository from a "
            "website that exposes the .git directory."
        ),
        "entry": "git_dumper",
        "example": "git-dumper https://example.com/.git/ ./dump",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "waybackpy", "import_name": "waybackpy", "pip": "waybackpy",
        "version": "3.0.0", "category": "osint",
        "summary": "Wayback Machine API client.",
        "description": (
            "waybackpy is a Python library to query the Internet "
            "Archive's Wayback Machine."
        ),
        "entry": "waybackpy",
        "example": "import waybackpy; w = waybackpy.WaybackMachine('https://example.com'); print(w.oldest())",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "google", "import_name": "google", "pip": "google",
        "version": "3.0.0", "category": "osint",
        "summary": "Google search results (unofficial wrapper).",
        "description": (
            "google is a Python library to query Google Search "
            "(unofficial / scraper-based)."
        ),
        "entry": "google",
        "example": "from google import search; [print(r) for r in search('test', num_results=5)]",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "pyDNS", "import_name": "DNS", "pip": "pydns",
        "version": "2.3.6", "category": "recon",
        "summary": "DNS client (older API, still used).",
        "description": (
            "pydns is a Python DNS client library that provides "
            "both high and low level access to the DNS protocol. "
            "Older API than dnspython."
        ),
        "entry": "DNS",
        "example": "import DNS; print(DNS.DnsRequest(name='example.com', qtype='A').req().answers)",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "ldap3", "import_name": "ldap3", "pip": "ldap3",
        "version": "3.4.8", "category": "post_exploitation",
        "summary": "Pure-Python LDAP v3 client.",
        "description": (
            "ldap3 is a pure-Python LDAP v3 client. Strictly RFC "
            "compliant. Useful for AD recon, ldap injection, etc."
        ),
        "entry": "ldap3",
        "example": "from ldap3 import Server, Connection, ALL; c = Connection(Server('10.0.0.5', get_info=ALL), 'cn=admin,dc=example,dc=com', 'PASS', auto_bind=True); c.search('dc=example,dc=com', '(objectClass=*)')",
        "risk_level": "high", "requires_gate": True,
    },
    {
        "name": "pyad", "import_name": "pyad", "pip": "pyad",
        "version": "0.6.0", "category": "post_exploitation",
        "summary": "ADSI / Active Directory client (Windows).",
        "description": (
            "pyad is a Python library to manage Active Directory "
            "via ADSI on Windows. Use only on Windows."
        ),
        "entry": "pyad",
        "example": "from pyad import aduser; u = aduser.ADUser.from_cn('administrator'); print(u)",
        "risk_level": "high", "requires_gate": True,
    },
    {
        "name": "python-nmap", "import_name": "nmap", "pip": "python-nmap",
        "version": "0.7.1", "category": "recon",
        "summary": "Nmap wrapper for Python.",
        "description": (
            "python-nmap is a Python class to use nmap port "
            "scanner. It allows to manipulate nmap scan results "
            "in Python."
        ),
        "entry": "nmap",
        "example": "import nmap; nm = nmap.PortScanner(); print(nm.scan('127.0.0.1', '22-80'))",
        "risk_level": "medium", "requires_gate": True,
    },
    {
        "name": "masscan", "import_name": "masscan", "pip": "masscan",
        "version": "1.0.6", "category": "recon",
        "summary": "masscan wrapper (high-speed port scanner).",
        "description": (
            "masscan is a Python wrapper around masscan, an "
            "asynchronous TCP port scanner."
        ),
        "entry": "masscan",
        "example": "import masscan; m = masscan.PortScanner(); print(m.scan('10.0.0.0/24', ports='22,80'))",
        "risk_level": "medium", "requires_gate": True,
    },
    {
        "name": "scapy-http", "import_name": "scapy.http", "pip": "scapy",
        "version": "2.5.0", "category": "web",
        "summary": "Scapy's HTTP layer (built-in).",
        "description": (
            "scapy.contrib.http is the HTTP layer for Scapy. "
            "Useful for HTTP-level packet crafting."
        ),
        "entry": "scapy.http",
        "example": "from scapy.all import IP, TCP, Raw; from scapy.layers.http import HTTP; print(HTTP())",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "openpyxl", "import_name": "openpyxl", "pip": "openpyxl",
        "version": "3.1.5", "category": "utility",
        "summary": "Read/write Excel 2010+ .xlsx files.",
        "description": (
            "openpyxl is a Python library to read/write Excel "
            "2010 xlsx/xlsm files."
        ),
        "entry": "openpyxl",
        "example": "import openpyxl; print(openpyxl.load_workbook('book.xlsx').sheetnames)",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "phonenumbers", "import_name": "phonenumbers", "pip": "phonenumbers",
        "version": "8.13.40", "category": "osint",
        "summary": "Phone number parsing / formatting / carrier lookup.",
        "description": (
            "phonenumbers is a Python port of Google's libphonenumber "
            "library. Validates, formats, and looks up phone numbers."
        ),
        "entry": "phonenumbers",
        "example": "import phonenumbers; print(phonenumbers.parse('+12025551234'))",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "pyotp", "import_name": "pyotp", "pip": "pyotp",
        "version": "2.9.0", "category": "exploit",
        "summary": "TOTP / HOTP implementation.",
        "description": (
            "pyotp is a Python library for generating and parsing "
            "one-time passwords. Supports HOTP, TOTP, and Steam "
            "guard codes."
        ),
        "entry": "pyotp",
        "example": "import pyotp; print(pyotp.TOTP('JBSWY3DPEHPK3PXP').now())",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "wget", "import_name": "wget", "pip": "wget",
        "version": "3.2", "category": "utility",
        "summary": "Pure-Python wget (download files).",
        "description": (
            "wget is a pure Python download utility for Python 2 "
            "and Python 3."
        ),
        "entry": "wget",
        "example": "import wget; wget.download('https://example.com/file')",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "python-dateutil", "import_name": "dateutil", "pip": "python-dateutil",
        "version": "2.9.0", "category": "utility",
        "summary": "Powerful extensions to datetime.",
        "description": (
            "The dateutil module provides powerful extensions to "
            "the standard datetime module."
        ),
        "entry": "dateutil",
        "example": "from dateutil.parser import parse; print(parse('2026-07-20 12:00 UTC'))",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "tqdm", "import_name": "tqdm", "pip": "tqdm",
        "version": "4.66.5", "category": "utility",
        "summary": "Fast, extensible progress meter for loops.",
        "description": (
            "tqdm is a fast, extensible progress meter for Python "
            "and CLI."
        ),
        "entry": "tqdm",
        "example": "from tqdm import tqdm; [x for x in tqdm(range(100))]",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "psutil", "import_name": "psutil", "pip": "psutil",
        "version": "6.0.0", "category": "utility",
        "summary": "Process and system monitoring.",
        "description": (
            "psutil is a cross-platform library for retrieving "
            "information on running processes and system "
            "utilization."
        ),
        "entry": "psutil",
        "example": "import psutil; print(psutil.cpu_percent())",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "urllib3", "import_name": "urllib3", "pip": "urllib3",
        "version": "2.2.2", "category": "utility",
        "summary": "HTTP client (powering requests).",
        "description": (
            "urllib3 is a powerful, user-friendly HTTP client for "
            "Python. Used by requests and many others."
        ),
        "entry": "urllib3",
        "example": "import urllib3; print(urllib3.PoolManager().request('GET', 'https://example.com').status)",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "fpdf2", "import_name": "fpdf", "pip": "fpdf2",
        "version": "2.7.9", "category": "utility",
        "summary": "PDF generation library.",
        "description": (
            "fpdf2 is a simple, fast PDF generation library for "
            "Python. Useful for report generation."
        ),
        "entry": "fpdf",
        "example": "from fpdf import FPDF; pdf = FPDF(); pdf.add_page(); pdf.set_font('helvetica', size=12); pdf.cell(text='hi'); pdf.output('out.pdf')",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "reportlab", "import_name": "reportlab", "pip": "reportlab",
        "version": "4.2.0", "category": "utility",
        "summary": "PDF / chart generation library (RML, platypus).",
        "description": (
            "ReportLab is the time-proven, ultra-reliable open "
            "source engine for creating complex, data-driven PDF "
            "documents and charts."
        ),
        "entry": "reportlab",
        "example": "from reportlab.pdfgen import canvas; c = canvas.Canvas('out.pdf'); c.drawString(72, 72, 'hi'); c.save()",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "fpdf", "import_name": "fpdf", "pip": "fpdf",
        "version": "1.7.2", "category": "utility",
        "summary": "PDF generation (older fork of fpdf2).",
        "description": (
            "fpdf is a Python port of the FPDF PHP library. "
            "Older fork of fpdf2; many examples online still use "
            "this."
        ),
        "entry": "fpdf",
        "example": "from fpdf import FPDF; pdf = FPDF(); pdf.add_page(); pdf.output('out.pdf')",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "pylnk3", "import_name": "pylnk3", "pip": "pylnk3",
        "version": "0.4.2", "category": "exploit",
        "summary": "Read/write Windows .lnk shortcut files.",
        "description": (
            "pylnk3 is a python library to parse / create Windows "
            "Shortcut File (.lnk) files. Useful for payload "
            "delivery."
        ),
        "entry": "pylnk3",
        "example": "import pylnk3; print(pylnk3.parse('shortcut.lnk').path)",
        "risk_level": "medium", "requires_gate": True,
    },
    {
        "name": "olefile2", "import_name": "olefile", "pip": "olefile2",
        "version": "0.0.1", "category": "exploit",
        "summary": "OLE2 parser (legacy fork).",
        "description": (
            "Legacy fork of olefile for reading OLE2 / compound "
            "documents."
        ),
        "entry": "olefile",
        "example": "import olefile; print(olefile.OleFileIO('doc.doc').exists('worddocument'))",
        "risk_level": "low", "requires_gate": False,
    },
    {
        "name": "lzx", "import_name": "lzx", "pip": "lzx",
        "version": "0.0.1", "category": "utility",
        "summary": "LZX compression (Windows Cabinet / WIM).",
        "description": (
            "lzx is a Python wrapper for the LZX compression "
            "algorithm used in Windows Cabinet / WIM files."
        ),
        "entry": "lzx",
        "example": "import lzx; print(lzx.decompress(b''))",
        "risk_level": "low", "requires_gate": False,
    },
]


# ---------------------------------------------------------------------------
# Index by name + import_name for O(1) lookups
# ---------------------------------------------------------------------------

PYTHON_LIB_BY_NAME: Dict[str, Dict[str, Any]] = {
    lib["name"]: lib for lib in PYTHON_LIBRARIES
}

# By-import name: maps import_name -> list of libs (in case
# multiple pip packages share an import name; e.g. `olefile`
# is imported by both `olefile` and `olefile2`, and `fpdf` by
# both `fpdf` and `fpdf2`). The first match is the canonical
# one for ``get_library``.
PYTHON_LIB_BY_IMPORT: Dict[str, List[Dict[str, Any]]] = {}
for lib in PYTHON_LIBRARIES:
    PYTHON_LIB_BY_IMPORT.setdefault(
        lib["import_name"], [],
    ).append(lib)


def get_library(name_or_import: str) -> Optional[Dict[str, Any]]:
    """Look up a library by its pip name OR import name. Returns
    ``None`` when no match is found."""
    if not name_or_import:
        return None
    if name_or_import in PYTHON_LIB_BY_NAME:
        return PYTHON_LIB_BY_NAME[name_or_import]
    matches = PYTHON_LIB_BY_IMPORT.get(name_or_import)
    if matches:
        return matches[0]
    return None


def get_libraries_by_import(import_name: str) -> List[Dict[str, Any]]:
    """Return all libraries sharing the given import name. Used
    when more than one pip package provides the same import
    (e.g. ``olefile``)."""
    if not import_name:
        return []
    return list(PYTHON_LIB_BY_IMPORT.get(import_name, []))


def list_libraries(category: Optional[str] = None) -> List[Dict[str, Any]]:
    """List libraries, optionally filtered by category."""
    if category is None:
        return list(PYTHON_LIBRARIES)
    return [lib for lib in PYTHON_LIBRARIES if lib.get("category") == category]


def list_categories() -> List[str]:
    """List the distinct categories present in the registry."""
    seen: List[str] = []
    for lib in PYTHON_LIBRARIES:
        cat = lib.get("category")
        if cat and cat not in seen:
            seen.append(cat)
    return seen


def categories_count() -> Dict[str, int]:
    """Per-category count, e.g. ``{"network": 5, "exploit": 12}``."""
    out: Dict[str, int] = {}
    for lib in PYTHON_LIBRARIES:
        cat = lib.get("category", "other")
        out[cat] = out.get(cat, 0) + 1
    return out


__all__ = [
    "PYTHON_LIBRARIES",
    "PYTHON_LIB_BY_NAME",
    "PYTHON_LIB_BY_IMPORT",
    "get_library",
    "get_libraries_by_import",
    "list_libraries",
    "list_categories",
    "categories_count",
]
