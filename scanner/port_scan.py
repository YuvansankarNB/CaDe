import socket

# Common ports to scan
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL"
}

def scan_ports(host, ports=COMMON_PORTS):
    results = []
    for port, service in ports.items():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.0)
                result = s.connect_ex((host, port))
                status = "Open" if result == 0 else "Closed"
                results.append({"port": port, "service": service, "status": status})
        except Exception as e:
            results.append({"port": port, "service": service, "status": f"Error: {e}"})
    return results
