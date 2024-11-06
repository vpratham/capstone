persistence_attack_ports = {
    22: {
        "protocol": "TCP",
        "service_name": "SSH (Secure Shell)",
        "description": "Remote login and command execution."
    },
    23: {
        "protocol": "TCP",
        "service_name": "Telnet",
        "description": "Unencrypted remote login service."
    },
    3389: {
        "protocol": "TCP",
        "service_name": "RDP (Remote Desktop Protocol)",
        "description": "Remote desktop access."
    },
    80: {
        "protocol": "TCP",
        "service_name": "HTTP",
        "description": "Standard web traffic, often exploited for backdoors."
    },
    443: {
        "protocol": "TCP",
        "service_name": "HTTPS",
        "description": "Secure web traffic, can be exploited for persistence."
    },
    3306: {
        "protocol": "TCP",
        "service_name": "MySQL",
        "description": "Database management system access."
    },
    5432: {
        "protocol": "TCP",
        "service_name": "PostgreSQL",
        "description": "Database management system access."
    },
    25: {
        "protocol": "TCP",
        "service_name": "SMTP (Simple Mail Transfer Protocol)",
        "description": "Email transmission, used for spam and malware distribution."
    },
    53: {
        "protocol": "UDP",
        "service_name": "DNS (Domain Name System)",
        "description": "Used for domain name resolution, can be exploited for persistence through DNS tunneling."
    },
    135: {
        "protocol": "TCP",
        "service_name": "RPC (Remote Procedure Call)",
        "description": "Used for various Windows services, including DCOM."
    },
    139: {
        "protocol": "TCP",
        "service_name": "NetBIOS Session Service",
        "description": "Used for file and printer sharing on Windows networks."
    },
    445: {
        "protocol": "TCP",
        "service_name": "SMB (Server Message Block)",
        "description": "File sharing and printer sharing, often targeted in ransomware attacks."
    },
    8080: {
        "protocol": "TCP",
        "service_name": "HTTP Alternate",
        "description": "Often used for web traffic, can host malicious services."
    },
    5000: {
        "protocol": "TCP",
        "service_name": "UPnP (Universal Plug and Play)",
        "description": "Exploitable service often found in IoT devices."
    },
    5900: {
        "protocol": "TCP",
        "service_name": "VNC (Virtual Network Computing)",
        "description": "Remote desktop sharing service."
    }
}