#!/usr/bin/env python3
import requests
from datetime import datetime
from collections import defaultdict

BLOCKLIST_URLS = [
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/ads/blocklistproject/youtube.fork.txt",
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/ads/firebog/AdguardDNS.fork.txt",
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/ads/jerryn70/GoodbyeAds.fork.txt",
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/ads/kboghdady/youtubelist.fork.txt",
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/extensions/MajkiIT/adguard-host.fork.txt",
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/extensions/hagezi/pro.fork.txt",
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/extensions/oisd/big.fork.txt",
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/fakenews/StevenBlack/hosts.fork.txt",
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/fraud/blocklistproject/hosts.fork.txt",
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/malicious/RPiList/Malware.fork.txt",
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/malicious/blocklistproject/malware.fork.txt",
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/other/StevenBlack/hosts.fork.txt",
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/other/polish-blocklists/cert.pl/domains-hosts.fork.txt",
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/phishing/RPiList/Phishing-Angriffe.fork.txt",
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/phishing/blocklistproject/phishing.fork.txt",
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/ransomware/blocklistproject/ransomware.fork.txt",
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/redirect/blocklistproject/redirect.fork.txt",
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/scam/jarelllama/scam.fork.txt",
    #"https://blocklist.sefinek.net/generated/v1/0.0.0.0/sites/youtube-extended.txt",
    #"https://blocklist.sefinek.net/generated/v1/0.0.0.0/sites/youtube.txt",
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/social/instagram.txt",
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/social/snapchat.txt",
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/social/tiktok.txt",
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/spam/RPiList/spam-mails.fork.txt",
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/tracking-and-telemetry/ShadowWhisperer/tracking.fork.txt",
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/tracking-and-telemetry/neodevpro/host.fork.txt"
]
def download_list(url):
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        return response.text.splitlines()
    except Exception as e:
        print(f"Błąd: {url} - {e}")
        return []

def extract_domain(line):
    if line and line[0] == '0':
        return line.split()[1]
    return None

def main():
    all_domains = set()
    stats = {}

    print(f"Pobieranie {len(BLOCKLIST_URLS)} list...\n")

    for url in BLOCKLIST_URLS:
        print(f"Pobieram: {url.split('/')[-1]}")
        
        lines = download_list(url)
        list_domains = set()
        
        # Wyciągnij domeny z tej listy
        for line in lines:
            domain = extract_domain(line)
            if domain:
                list_domains.add(domain)
        
        # Statystyki
        new = list_domains - all_domains
        duplicates = list_domains & all_domains
        
        stats[url] = {
            'total': len(list_domains),
            'new': len(new),
            'dup': len(duplicates)
        }
        
        all_domains.update(list_domains)
        
        print(f"  Znaleziono: {len(list_domains)}, nowych: {len(new)}, duplikatów: {len(duplicates)}\n")

    with open('blocklist.txt', 'w') as f:
        f.write(f"# Wygenerowano: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Unikalnych domen: {len(all_domains)}\n#\n")
        for domain in sorted(all_domains):
            f.write(f"0.0.0.0 {domain}\n")

    with open('stats.txt', 'w') as f:
        f.write(f"Statystyki - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Unikalnych domen: {len(all_domains)}\n\n")
        for url, s in stats.items():
            f.write(f"{url.split('/')[-1]}\n")
            f.write(f"  Ogółem: {s['total']}, nowych: {s['new']}, duplikatów: {s['dup']}\n\n")

    print(f"\nGotowe! {len(all_domains)} unikalnych domen w blocklist.txt")

if __name__ == "__main__":
    main()
