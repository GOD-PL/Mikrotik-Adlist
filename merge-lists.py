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
    if line and line[0] == '0':
        return line.split()[1]
    return None

''' V2 ONLY
def write_blocklist(filename, domains, category, timestamp):
    sorted_domains = sorted(domains)
    with open(filename, 'w') as f:
        f.write(f"# WYGENEROWANO: {timestamp}\n# KATEGORIA: {category}\n# RAZEM: {len(sorted_domains)}\n\n")
        for domain in sorted_domains:
            f.write(f"0.0.0.0 {domain}\n")
    return len(sorted_domains)
'''
#''' V1
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
#'''
'''V2
def main():
    category_domains = defaultdict(set)
    domain_categories = defaultdict(set)  # domena -> w których kategoriach występuje
    url_stats = []
    
    print(f"Pobieram {len(BLOCKLIST_URLS)} list...")
    print("=" * 80)
    
    for url in BLOCKLIST_URLS:
        category = extract_category(url)
        print(f"\nURL: {url}\nKATEGORIA: [{category}]")
        
        lines = download_list(url)
        
        domains = set()
        for line in lines:
            domain = parse_domain(line)
            if domain:
                domains.add(domain)
                domain_categories[domain].add(category)
        
        category_domains[category].update(domains)
        url_stats.append((category, url.split('/')[-1], len(domains)))
        
        print(f"DOMEN: {len(domains)} | W KATEGORII RAZEM: {len(category_domains[category])}")
    
    # Rozdziel domeny: wspólne vs unikalne dla kategorii
    shared_domains = {d for d, cats in domain_categories.items() if len(cats) > 1}
    
    print("\n" + "=" * 80 + "\nZAPISYWANIE...")
    
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Zapisz wspólne domeny
    count = write_blocklist('blocklist.txt', shared_domains, 'shared', timestamp)
    print(f"ZAPISANO: blocklist.txt ({count})")
    
    # Zapisz unikalne dla każdej kategorii
    for category, domains in category_domains.items():
        unique = domains - shared_domains
        filename = f'{category}_blocklist.txt'
        count = write_blocklist(filename, unique, category, timestamp)
        print(f"ZAPISANO: {filename} ({count})")
    
    # Stats
    with open('stats.txt', 'w') as f:
        total_unique = sum(len(d - shared_domains) for d in category_domains.values())
        f.write(f"STATS: {timestamp}\n{'=' * 80}\n\n")
        f.write(f"SHARED: {len(shared_domains)}\n\n")
        for cat, domains in category_domains.items():
            unique = len(domains - shared_domains)
            f.write(f"{cat}: {unique} (total: {len(domains)})\n")
        f.write(f"\nUNIQUE TOTAL: {total_unique}\nALL DOMAINS: {len(domain_categories)}\n\nURL:\n")
        for cat, name, count in url_stats:
            f.write(f"{cat} | {name} | {count}\n")
    
    print(f"\nZAPISANO: {len(category_domains) + 1} plików")
'''
if __name__ == "__main__":
    main()
