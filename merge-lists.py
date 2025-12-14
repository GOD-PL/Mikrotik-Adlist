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
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/phishing/RPiList/Phishing-Angriffe.fork.txt"
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/phishing/blocklistproject/phishing.fork.txt",
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/ransomware/blocklistproject/ransomware.fork.txt",
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/redirect/blocklistproject/redirect.fork.txt",
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/scam/jarelllama/scam.fork.txt",
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/sites/youtube-extended.txt",
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/sites/youtube.txt",
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/social/instagram.txt",
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/social/snapchat.txt",
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/social/tiktok.txt",
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/spam/RPiList/spam-mails.fork.txt",
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/tracking-and-telemetry/ShadowWhisperer/tracking.fork.txt",
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/tracking-and-telemetry/neodevpro/host.fork.txt",
]

def extract_category(url):
    return url.split("/0.0.0.0/")[1].split("/")[0]

def download_list(url):
    try:
        r = requests.get(url, timeout = 30)
        r.raise_for_status()
        return r.text.splitlines()
    except requests.RequestException as e:
        print(f"BŁĄD: {e}")
        return []

def parse_domain(line):
    if line[0] == '0':
        return line.split()[1]
    return None

def main():
    category_domains = defaultdict(set)
    url_stats = []
    
    print(f"Pobieram {len(BLOCKLIST_URLS)} list...")
    print("=" * 80)
    
    for url in BLOCKLIST_URLS:
        category = extract_category(url)
        print(f"\nURL: {url}\nKAT: [{category}]")
        
        lines = download_list(url)
        
        domains = set()
        for line in lines:
            domain = parse_domain(line)
            if domain:
                domains.add(domain)
        
        category_domains[category].update(domains)
        url_stats.append((category, url.split('/')[-1], len(domains)))
        
        print(f"DOMEN: {len(domains)} | KAT_OGÓŁEM: {len(category_domains[category])}")
    
    print("\n" + "=" * 80 + "\nZAPISYWANIE...")
    
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    for category, domains in category_domains.items():
        filename = f"{category}_blocklist.txt"
        sorted_domains = sorted(domains)
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"# GEN: {timestamp}\n# KAT: {category}\n# ILE: {len(sorted_domains)}\n\n")
            for domain in sorted_domains:
                f.write(f"0.0.0.0 {domain}\n")
        
        print(f"OK: {filename} ({len(sorted_domains)})")
    
    with open('stats.txt', 'w', encoding='utf-8') as f:
        total = sum(len(d) for d in category_domains.values())
        f.write(f"STATS: {timestamp}\n{'=' * 80}\n\n")
        for cat, domains in category_domains.items():
            f.write(f"{cat}: {len(domains)}\n")
        f.write(f"\nRAZEM: {total}\n\nURL:\n")
        for cat, name, count in url_stats:
            f.write(f"{cat} | {name} | {count}\n")
    
    print(f"\nOK: {len(category_domains)} plików")

if __name__ == "__main__":
    main()
