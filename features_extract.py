import requests
from bs4 import BeautifulSoup
import whois
import socket
import re
from urllib.parse import urlparse
import tldextract
import csv
import socket
import pandas as pd
from requests.exceptions import RequestException, TooManyRedirects
from ssl import SSLContext, PROTOCOL_TLSv1_2, CERT_NONE, PROTOCOL_TLS
from concurrent.futures import ThreadPoolExecutor

# Using IP address
def get_using_ip(url):
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.split(':')[0]  # Extract domain without port
        ip = socket.gethostbyname(domain)
        return 1 if ip in url else 0
    except:
        return -1

# Long URL
def get_long_url(url):
    url_length = len(url)
    return 1 if url_length > 54 else 0

# Short URL
def get_short_url(url):
    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net', url)
    if match:
        return 1
    return 0

# Symbol
def get_symbol(url):
    return 1 if "@" in url else 0

# Redirecting
def get_redirecting(url):
    session = requests.Session()
    session.max_redirects = 5
    redirect_count = 0

    try:
        response = session.get(url, timeout=5, allow_redirects=False)
        while response.status_code in (301, 302):
            redirect_count += 1
            if redirect_count > session.max_redirects:
                break
            redirect_url = response.headers['Location']
            response = session.get(redirect_url, timeout=5, allow_redirects=False)
    except:
        pass

    return redirect_count

# Prefix-Suffix
def get_prefix_suffix(url):
    parsed_url = urlparse(url)
    domain_name = parsed_url.netloc
    return 1 if '-' in domain_name else 0

# Subdomains
def get_subdomains(url):
    ext = tldextract.extract(url)
    subdomain_count = ext.subdomain.count('.')
    return subdomain_count

# HTTPS
def get_https(url):
    return 1 if url.startswith("https") else 0

# SSL
def has_ssl(url):
    try:

        if not url.startswith('http'):
            url = 'https://' + url

        response = requests.get(url, timeout=5)

        if response.url.startswith('https://'):
            return 1
        else:
            return 0
    except requests.exceptions.RequestException:
        return 0

# Domain Registration Length
def get_domain_reg_length(url):
    ext = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}"
    try:
        domain_info = whois.whois(domain)
        if isinstance(domain_info.expiration_date, list):
            expiration_date = domain_info.expiration_date[0]
        else:
            expiration_date = domain_info.expiration_date

        if isinstance(domain_info.creation_date, list):
            creation_date = domain_info.creation_date[0]
        else:
            creation_date = domain_info.creation_date

        if expiration_date and creation_date:
            reg_length = (expiration_date - creation_date).days
            return 1 if reg_length > 365 else 0
    except:
        pass
    return -1

# Favicon
def get_favicon(url, content):
    soup = BeautifulSoup(content, "html.parser")
    favicon = soup.find("link", rel="shortcut icon")
    if favicon:
        favicon_href = favicon.get("href")
        favicon_url = urlparse(favicon_href)
        if favicon_url.netloc == "":
            return 0
    return 1

# Non-standard port
def get_non_std_port(url):
    parsed_url = urlparse(url)
    port = parsed_url.port
    if port:
        return 1 if port not in (80, 443) else 0
    return 0

# Feature Extraction
def extract_features(url, label):
    features = {}
    try:
        parsed_url = urlparse(url)
        if not parsed_url.scheme:
            url = 'http://' + url
        response = requests.get(url, timeout=10)
        content = response.content

        features['UsingIp'] = get_using_ip(url)
        features['longUrl'] = get_long_url(url)
        features['shortUrl'] = get_short_url(url)
        features['symbol'] = get_symbol(url)
        features['redirecting'] = get_redirecting(url)
        features['prefixSuffix'] = get_prefix_suffix(url)
        features['SubDomains'] = get_subdomains(url)
        features['Https'] = get_https(url)
        features['hasSsl'] = has_ssl(url)
        features['DomainRegLen'] = get_domain_reg_length(url)
        features['Favicon'] = get_favicon(url, content)
        features['NonStdPort'] = get_non_std_port(url)
        features['label'] = label
        
    except (RequestException, TooManyRedirects) as e:
        print(f"Error processing URL {url}: {e}")
        return None
    except Exception as e:
        print(f"Error processing URL {url}: {e}")
        return None
    return features

def process_url(url_label):
    url, label = url_label
    features = extract_features(url, label)
    if features is not None:
        features["Url"] = url
    return features

def main():
    input_file = "phish_score.csv"
    dataset_type = "bad"
    output_file = "phishing_output.csv"
    # input_file = "100-legitimate-art.txt"
    # dataset_type = "good"
    # output_file = "legit_output.csv"

    num_threads = 10000

    with open(input_file, "r", encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        urls_labels = [(row['url'], dataset_type) for row in reader]

    with open(output_file, "w", newline="", encoding='utf-8') as csvfile:
        fieldnames = [
            "UsingIp",
            "longUrl",
            "shortUrl",
            "symbol",
            "redirecting",
            "prefixSuffix",
            "SubDomains",
            "Https",
            "hasSsl",
            "DomainRegLen",
            "Favicon",
            "NonStdPort",
            "label",
            "Url"
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            for result in executor.map(process_url, urls_labels):
                if result:
                    writer.writerow(result)

if __name__ == "__main__":
    main()