#!/usr/bin/env python3
import requests
import sys
from datetime import datetime
from collections import defaultdict

# Listy do połączenia (URL)
BLOCKLIST_URLS = [
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/pro.txt",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/tif.txt",
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/extensions/oisd/big.fork.txt",
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/extensions/notracking/hostnames.fork.txt",
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/ads/jerryn70/GoodbyeAds.fork.txt",
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/ads/firebog/AdguardDNS.fork.txt",
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/ads/kboghdady/youtubelist.fork.txt",
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/ads/blocklistproject/youtube.fork.txt",
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/ads/anudeepND/adservers.fork.txt",
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/malicious/blocklistproject/malware.fork.txt",
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/other/polish-blocklists/cert.pl/domains-hosts.fork.txt",
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/phishing/RPiList/Phishing-Angriffe.fork.txt",
    "https://blocklist.sefinek.net/generated/v1/0.0.0.0/tracking-and-telemetry/ShadowWhisperer/tracking.fork.txt"
]

def download_list(url):
    # Pobiera listę z podanego URL
    try:
        response = requests.get(url, timeout = 30)
        response.raise_for_status()
        return response.text.splitlines()
    except Exception as e:
        print(f"Błąd pobierania {url}: {e}")
        return []

def clean_line(line):
    # Czyści linię z komentarzy i białych znaków
    line = line.strip()
    if '#' in line:
        line = line.split('#')[0].strip()
    return line

def is_valid_entry(line):
    # Sprawdza czy linia jest prawidłowym wpisem
    if not line or line.startswith('#'):
        return False
    # Pomija nagłówki i komentarze
    if line.startswith('!') or line.startswith('['):
        return False
    # Sprawdza czy to format hosts (0.0.0.0 domena lub 127.0.0.1 domena)
    parts = line.split()
    if len(parts) >= 2 and parts[0] in ['0.0.0.0', '127.0.0.1']:
        return True
    # Sprawdza czy to sama domena
    if len(parts) == 1 and '.' in parts[0]:
        return True
    return False

def extract_domain(line):
    # Wyciąga domenę z linii
    parts = line.split()
    if len(parts) >= 2 and parts[0] in ['0.0.0.0', '127.0.0.1']:
        return parts[1]
    elif len(parts) == 1:
        return parts[0]
    return None

def main():
    all_domains = set()
    stats = defaultdict(int)
    domain_sources = defaultdict(list)
    
    print(f"Rozpoczynam pobieranie {len(BLOCKLIST_URLS)} list...")
    print("=" * 80)
    
    for url in BLOCKLIST_URLS:
        print(f"\nPobieram: {url}")
        lines = download_list(url)
        domains_from_this_list = set()
        
        for line in lines:
            cleaned = clean_line(line)
            if is_valid_entry(cleaned):
                domain = extract_domain(cleaned)
                if domain and domain != 'localhost':
                    domains_from_this_list.add(domain)
                    domain_sources[domain].append(url.split('/')[-1])  # Zapisz źródło
        
        # Statystyki dla tej listy
        new_domains = domains_from_this_list - all_domains
        duplicate_domains = domains_from_this_list & all_domains
        
        print(f"\tZnaleziono domen: {len(domains_from_this_list)}")
        print(f"\tNowych domen: {len(new_domains)}")
        print(f"\tDuplikatów (już w liście): {len(duplicate_domains)}")
        
        stats[url] = {
            'total': len(domains_from_this_list),
            'new': len(new_domains),
            'duplicates': len(duplicate_domains)
        }
        
        all_domains.update(domains_from_this_list)
    
    print("\n" + "=" * 80)
    print(f"PODSUMOWANIE:")
    print(f"\tŁącznie unikalnych domen: {len(all_domains)}")
    
    # Znajdź domeny występujące w wielu listach
    domains_in_multiple_lists = {d: sources for d, sources in domain_sources.items() if len(sources) > 1}
    print(f"\tDomen występujących w wielu listach: {len(domains_in_multiple_lists)}")
    
    # Sortuj domeny alfabetycznie
    sorted_domains = sorted(all_domains)
    
    # Zapisz w formacie hosts kompatybilnym z Mikrotik
    with open('blocklist.txt', 'w') as f:
        f.write(f"# Wygenerowano automatycznie: {datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z')}\n")
        f.write(f"# Liczba unikalnych domen: {len(sorted_domains)}\n")
        f.write(f"# Źródła: {len(BLOCKLIST_URLS)}\n")
        f.write("#\n")
        f.write("# Statystyki:\n")
        for url, stat in stats.items():
            f.write(f"# - {url.split('/')[-1]}: {stat['total']} domen ({stat['new']} unikalnych, {stat['duplicates']} duplikatów)\n")
        f.write("#\n\n")
        
        for domain in sorted_domains:
            f.write(f"0.0.0.0 {domain}\n")
    
    # Zapisz statystyki do osobnego pliku
    with open('stats.txt', 'w') as f:
        f.write(f"Statystyka - {datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z')}\n")
        f.write("=" * 80 + "\n\n")
        f.write(f"Liczba unikalnych domen: {len(all_domains)}\n")
        f.write(f"Liczba domen we wszystkich listach: {len(domains_in_multiple_lists)}\n\n")
        
        f.write("Domeny per źródło:\n")
        for url, stat in stats.items():
            f.write(f"\t{url.split('/')[-1]}:\n")
            f.write(f"\tOgólnie: {stat['total']}\n")
            f.write(f"\tUnikalnych: {stat['new']}\n")
            f.write(f"\tW innych listach: {stat['duplicates']}\n\n")
    
    print(f"\nLista zapisana jako blocklist.txt")
    print(f"Statystyki zapisane jako stats.txt")

if __name__ == "__main__":
    main()
