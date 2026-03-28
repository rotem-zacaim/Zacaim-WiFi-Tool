"""Shared application constants."""

APP_NAME = "ZACAIM V2 - Pentest Workbench"
APP_VERSION = "2.5"
APP_TAGLINE = "Operator Workbench for Host, Web, Evidence, and Reporting Pipelines"

WEB_PORT_HINTS = {80, 81, 88, 443, 591, 8000, 8008, 8080, 8081, 8088, 8443, 8888}

COMMON_SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
]

KNOWN_WEB_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/security.txt",
]

HOST_PROFILES = {
    "quick": {
        "nmap_flags": ["-sV"],
        "reverse_dns": True,
        "ssh_keyscan": True,
        "naabu": False,
        "dnsx": False,
        "sslscan": False,
        "enum4linux_ng": False,
        "ldapsearch": False,
        "snmpwalk": False,
        "rdpscan": False,
        "ike_scan": False,
        "http_probe": True,
        "whatweb": False,
        "httpx": False,
        "known_paths": False,
        "wafw00f": False,
        "katana": False,
        "katana_deep": False,
        "testssl": False,
        "tls_probe": False,
    },
    "standard": {
        "nmap_flags": ["-sV", "-sC"],
        "reverse_dns": True,
        "ssh_keyscan": True,
        "naabu": True,
        "dnsx": True,
        "sslscan": True,
        "enum4linux_ng": True,
        "ldapsearch": True,
        "snmpwalk": False,
        "rdpscan": True,
        "ike_scan": False,
        "http_probe": True,
        "whatweb": True,
        "httpx": True,
        "known_paths": True,
        "wafw00f": True,
        "katana": False,
        "katana_deep": False,
        "testssl": False,
        "tls_probe": True,
    },
    "deep": {
        "nmap_flags": ["-sV", "-sC", "--version-all", "-O"],
        "reverse_dns": True,
        "ssh_keyscan": True,
        "naabu": True,
        "dnsx": True,
        "sslscan": True,
        "enum4linux_ng": True,
        "ldapsearch": True,
        "snmpwalk": True,
        "rdpscan": True,
        "ike_scan": True,
        "http_probe": True,
        "whatweb": True,
        "httpx": True,
        "known_paths": True,
        "wafw00f": True,
        "katana": True,
        "katana_deep": True,
        "testssl": True,
        "tls_probe": True,
    },
}

WEB_PROFILES = {
    "safe": {
        "dnsx": True,
        "naabu": False,
        "http_probe": True,
        "tls_probe": True,
        "whatweb": True,
        "httpx": True,
        "known_paths": True,
        "ffuf": False,
        "nikto": False,
        "subfinder": False,
        "gau": False,
        "wafw00f": False,
        "katana": False,
        "katana_deep": False,
        "testssl": False,
    },
    "standard": {
        "dnsx": True,
        "naabu": True,
        "http_probe": True,
        "tls_probe": True,
        "whatweb": True,
        "httpx": True,
        "known_paths": True,
        "ffuf": True,
        "nikto": True,
        "subfinder": False,
        "gau": True,
        "wafw00f": True,
        "katana": True,
        "katana_deep": False,
        "testssl": False,
    },
    "deep": {
        "dnsx": True,
        "naabu": True,
        "http_probe": True,
        "tls_probe": True,
        "whatweb": True,
        "httpx": True,
        "known_paths": True,
        "ffuf": True,
        "nikto": True,
        "subfinder": True,
        "gau": True,
        "wafw00f": True,
        "katana": True,
        "katana_deep": True,
        "testssl": True,
    },
}

ADMIN_SERVICES = {"ssh", "telnet", "ms-wbt-server", "rdp", "vnc", "winrm", "http-rpc-epmap"}
FILE_SERVICES = {"ftp", "tftp", "smb", "microsoft-ds", "netbios-ssn", "nfs"}
DATABASE_SERVICES = {"mysql", "postgresql", "ms-sql-s", "mongodb", "redis", "oracle-tns", "oracle"}
