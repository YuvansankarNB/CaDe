# scanner/vuln_scan.py
import requests

COMMON_PATHS = [
    "/admin",
    "/login",
    "/phpinfo.php",
    "/robots.txt",
    "/.env",
    "/.git",
    "/config.php",
    "/server-status"
]

def check_vulnerable_paths(domain):
    results = []
    if not domain.startswith("http"):
        domain = "http://" + domain  # Default to HTTP

    for path in COMMON_PATHS:
        url = domain + path
        try:
            response = requests.get(url, timeout=3)
            status = response.status_code
            results.append({
                "path": path,
                "status": status,
                "found": status in [200, 401, 403]
            })
        except requests.RequestException as e:
            results.append({"path": path,"status": "Error","found": False})

    return results
