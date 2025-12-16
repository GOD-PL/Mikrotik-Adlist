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
    #"https://blocklist.sefinek.net/generated/v1/0.0.0.0/scam/jarelllama/scam.fork.txt",
    #"https://blocklist.sefinek.net/generated/v1/0.0.0.0/sites/youtube-extended.txt",
    #"https://blocklist.sefinek.net/generated/v1/0.0.0.0/sites/youtube.txt",
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/social/instagram.txt",
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/social/snapchat.txt",
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/social/tiktok.txt",
    #"https://blocklist.sefinek.net/generated/v1/0.0.0.0/spam/RPiList/spam-mails.fork.txt",
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
    stats = []

    print(f"Pobieram {len(BLOCKLIST_URLS)} list...")

    for url in BLOCKLIST_URLS:
        name = url.split('/')[-1]
        lines = download_list(url)

        before = len(all_domains)
        count = 0

        for line in lines:
            domain = parse_domain(line)
            if domain:
                all_domains.add(domain)
                count += 1

        new = len(all_domains) - before
        dup = count - new
        stats.append((name, count, new, dup))

        print(f"{name}: {count} domen, {new} nowych, {dup} duplikatów")

    # Zapisz blocklist.txt
    sorted_domains = sorted(all_domains)
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    with open('blocklist.txt', 'w', encoding='utf-8') as f:
        f.write(f"# Wygenerowano: {timestamp}\n")
        f.write(f"# Unikalnych domen: {len(sorted_domains)}\n#\n")
        for domain in sorted_domains:
            f.write(f"0.0.0.0 {domain}\n")
            
    with open('stats.txt', 'w', encoding='utf-8') as f:
        f.write(f"Statystyki - {timestamp}\n")
        f.write("=" * 80 + "\n\n")
        f.write(f"Unikalnych domen: {len(all_domains)}\n")
        f.write(f"Źródeł: {len(BLOCKLIST_URLS)}\n\n")
        f.write(f"{'Źródło':40} {'Razem':>10} {'Nowe':>10} {'Dupl.':>10}\n")
        f.write("-" * 80 + "\n")
        for name, total, new, dup in stats:
            f.write(f"{name:40} {total:10} {new:10} {dup:10}\n")

    print(f"\nZapisano: blocklist.txt ({len(sorted_domains)} unikalnych domen)")
    print("Zapisano: stats.txt")

if __name__ == "__main__":
    main()
