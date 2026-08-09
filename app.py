from flask import Flask, render_template, request
import json
import whois
import socket
import requests
from urllib.parse import urlparse
from datetime import datetime, date
from scanner.port_scan import scan_ports
from scanner.subdomain_finder import find_subdomains
from scanner.http_headers import check_http_headers
from scanner.vuln_scan import check_vulnerable_paths
from scanner.fingerprint import fingerprint

app = Flask(__name__)

def clean_whois_data(data):
    """Recursively convert datetime objects to ISO strings for JSON serialization."""
    if isinstance(data, (datetime, date)):
        return data.isoformat()
    elif isinstance(data, list):
        return [clean_whois_data(item) for item in data]
    elif isinstance(data, dict):
        return {k: clean_whois_data(v) for k, v in data.items()}
    return data

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    raw_domain = request.form['domain'].strip()
    # Sanitize domain input (remove http://, https://, paths)
    domain = raw_domain.replace("http://", "").replace("https://", "").split("/")[0].strip()

    scan_types = request.form.getlist('scan_options')

    results = {}

    # WHOIS Lookup
    if 'whois' in scan_types:
        try:
            w = whois.whois(domain)
            # Convert whois object/dict to serializable dictionary
            if isinstance(w, dict) or hasattr(w, 'items'):
                whois_dict = {k: clean_whois_data(v) for k, v in w.items() if v is not None}
                results['whois'] = whois_dict
            else:
                results['whois'] = str(w)
        except Exception as e:
            results['whois'] = {"error": f"WHOIS Error: {str(e)}"}

    # Port Scanning
    if 'port' in scan_types:
        try:
            ip = socket.gethostbyname(domain)
            port_results = scan_ports(ip)
            results['ports'] = port_results
        except Exception as e:
            results['ports'] = [{"error": str(e)}]

    # Subdomain Finding
    if 'subdomain' in scan_types:
        try:
            subdomains = find_subdomains(domain)
            results['subdomains'] = subdomains
        except Exception as e:
            results['subdomains'] = [f"Error: {str(e)}"]

    # HTTP Headers Check
    if 'headers' in scan_types:
        try:
            headers = check_http_headers(domain)
            results['headers'] = headers
        except Exception as e:
            results['headers'] = {"error": str(e)}

    # Basic Vulnerability Check
    if 'vuln' in scan_types:
        try:
            vulns = check_vulnerable_paths(domain)
            results['vulnerabilities'] = vulns
        except Exception as e:
            results['vulnerabilities'] = [{"error": str(e)}]

    # Tech Stack Fingerprinting
    if 'fingerprint' in scan_types or 'tech' in scan_types:
        try:
            tech = fingerprint(domain)
            results['fingerprint'] = tech
        except Exception as e:
            results['fingerprint'] = {"error": str(e)}

    return render_template('result.html', domain=domain, results=results)


if __name__ == '__main__':
    app.run(debug=True)


