import requests

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]

def check_http_headers(domain):
    url = f"http://{domain}"
    results = {}

    try:
        response = requests.get(url, timeout=5)
        headers = response.headers

        for header in SECURITY_HEADERS:
            results[header] = headers.get(header, "Missing")

    except Exception as e:
        results["error"] = str(e)

    return results
