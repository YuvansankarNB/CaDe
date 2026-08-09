import socket
import os

def find_subdomains(domain, wordlist_path=None):
    if wordlist_path is None:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        wordlist_path = os.path.join(base_dir, "wordlists", "subdomains.txt")
        
    found = []
    if not os.path.exists(wordlist_path):
        return found

    with open(wordlist_path, 'r') as file:
        for line in file:
            sub = line.strip()
            if not sub:
                continue
            subdomain = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(subdomain)
                found.append({"subdomain": subdomain, "ip": ip})
            except socket.gaierror:
                continue  # Skip if subdomain doesn't resolve
    return found

