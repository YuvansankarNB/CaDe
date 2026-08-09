import requests
from bs4 import BeautifulSoup

def fingerprint(domain):
    tech_info = {}
    if not domain.startswith("http"):
        domain = "http://" + domain

    try:
        response = requests.get(domain, timeout=5)
        headers = response.headers

        tech_info["Server"] = headers.get("Server", "Unknown")
        tech_info["X-Powered-By"] = headers.get("X-Powered-By", "Unknown")

        soup = BeautifulSoup(response.text, "html.parser")
        meta_generator = soup.find("meta", attrs={"name": "generator"})
        if meta_generator:
            tech_info["Meta Generator"] = meta_generator.get("content")

    except Exception as e:
        tech_info["error"] = str(e)

    return tech_info
