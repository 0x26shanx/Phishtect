import requests
import urllib.request
from bs4 import BeautifulSoup
import whois
import socket
import re
from googlesearch import search
from urllib.parse import urlparse
import tldextract
import csv
import os
import socket
import urllib.parse
import string
import pandas as pd
from datetime import datetime, timedelta
from dateutil.parser import parse as date_parse
from requests.exceptions import RequestException, TooManyRedirects
from ssl import SSLContext, PROTOCOL_TLSv1_2, CERT_NONE, PROTOCOL_TLS
from concurrent.futures import ThreadPoolExecutor
import concurrent.futures

def get_response(url, headers):
    try:
        response = requests.get(url, timeout=5, headers=headers)
        return response
    except:
        if not url.startswith('www.'):
            url = 'www.' + url
        try:
            response = requests.get(url, timeout=5, headers=headers)
            return response
        except:
            return None

# Using IP address
def get_using_ip(url):
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.split(':')[0]
        ip = socket.gethostbyname(domain)
        return 1 if ip in url else 0
    except Exception as e:
        # print(f"Using IP Error processing URL {url}: {e}")
        return -1

# Long URL
def get_long_url(url):
    try:
        url_length = len(url)
        return 1 if url_length > 54 else 0
    except Exception as e:
        # print(f"Long Url Error processing URL {url}: {e}")
        return -1

# Short URL
def get_short_url(url):
    try:
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
    except Exception as e:
        # print(f"Short URL Error processing URL {url}: {e}")
        return -1
# Symbol
def get_symbol(url):
    try:
        return 1 if "@" in url else 0
    except Exception as e:
        # print(f"Get Symbol URL Error processing URL {url}: {e}")
        return -1

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
    except requests.exceptions.Timeout:
        # print(f"Redirecting Timeout occurred for URL: {url}")
        return -1
    except requests.exceptions.TooManyRedirects:
        # print(f"Redirecting Too many redirects for URL: {url}")
        return -1
    except Exception as e:
        # print(f"Redirecting Error processing URL {url}: {e}")
        return -1

    return redirect_count

# Prefix-Suffix
def get_prefix_suffix(url):
    try:
        parsed_url = urlparse(url)
        domain_name = parsed_url.netloc
        return 1 if '-' in domain_name else 0
    except Exception as e:
        # print(f"Prefix Suffix Error processing URL {url}: {e}")
        return -1

# Subdomains
def get_subdomains(url):
    try:
        ext = tldextract.extract(url)
        subdomain_count = ext.subdomain.count('.')
        return subdomain_count
    except Exception as e:
        # print(f"Subdomains Error processing URL {url}: {e}")
        return -1

# HTTPS
def get_https(url):
    try:
        return 1 if url.startswith("https") else 0
    except Exception as e:
        # print(f"HTTPS Error processing URL {url}: {e}")
        return -1

# SSL
def has_ssl(url):
    try:

        if not url.startswith('http'):
            url = 'https://' + url

        response = requests.get(url, timeout=5)

        if response.url.startswith('https://'):
            return 0
        else:
            return 1
    except requests.exceptions.ConnectionError:
        # print(f"SSL Error processing URL {url}: Connection Error")
        return -1   
    except requests.exceptions.Timeout:
        # print(f"SSL Timeout occurred for URL: {url}")
        return -1
    except requests.exceptions.TooManyRedirects:
        # print(f"SSL Too many redirects for URL: {url}")
        return -1
    except requests.exceptions.RequestException as e:
        # print(f"SSL General Request Exception for URL {url}: {e}")
        return -1

# Domain Registration Length
def get_domain_reg_length(url):
    try:
        domain_info = whois.whois(url)
        if domain_info.creation_date is None:
            return -1

        if isinstance(domain_info.creation_date, list):
            creation_date = domain_info.creation_date[0]
        else:
            creation_date = domain_info.creation_date

        # convert to datetime if not already
        if isinstance(creation_date, str):
            creation_date = date_parse(creation_date)

        age_in_days = (datetime.now() - creation_date).days

        # Check if domain is less than 1 year old
        if age_in_days < 365:
            return 1
        else:
            return 0
    except Exception as e:
        # print(f"Domain Reg Length Error processing URL {url}: {e}")
        return -1


# Favicon
def get_favicon(url, content):
    try:
        soup = BeautifulSoup(content, "html.parser")
        favicon = soup.find("link", rel="shortcut icon")
        if favicon:
            favicon_href = favicon.get("href")
            favicon_url = urlparse(favicon_href)
            if favicon_url.netloc == "":
                return 0
        return 1
    except Exception as e:
        # print(f" Favicon Error processing URL {url}: {e}")
        return -1

# Non-standard port
def get_non_std_port(url):
    try:
        parsed_url = urlparse(url)
        port = parsed_url.port
        if port is None: # If no port specified, assume it's a standard web port
            return 0
        elif port not in [80, 443]: # If port is not standard HTTP or HTTPS port
            return 1
        else:
            return 0
    except Exception as e:
        # print(f" Non-standard Error Port processing URL {url}: {e}")
        return -1

# Dots
def count_dots(url):
    try:
        return url.count('.')
    except Exception as e:
        # print(f" Count dots Error processing URL {url}: {e}")
        return -1

# Rediretion '//'
def count_double_slash(url):
    try:
        return url[url.find('//')+2:].count('//')
    except Exception as e:
        # print(f" Double Slash Error processing URL {url}: {e}")
        return -1


def email_in_url(url):
    try:
        return 1 if re.search(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", url) else 0
    except Exception as e:
        # print(f" Email in Url Error processing URL {url}: {e}")
        return -1
    
def abnormalURL(url):
    try:
        # Parse the URL to extract the path and parameters
        parsed_url = urllib.parse.urlparse(url)
        url_path_and_params = parsed_url.path + parsed_url.params + parsed_url.query + parsed_url.fragment

        # Check if more than 50% of characters are non-alphanumeric
        alphanumeric_chars = string.ascii_letters + string.digits
        non_alphanumeric_chars = [ch for ch in url_path_and_params if ch not in alphanumeric_chars]
        if len(non_alphanumeric_chars) > 0.5 * len(url_path_and_params):
            return 1
        else:
            return 0
    except Exception as e:
        # print(f" Abnormal URL Error processing URL {url}: {str(e)}")
        return -1

def WebsiteForwarding(url):
    try:
        response = requests.get(url)
        if response.history:
            return 1  # there is a redirect, hence website forwarding is enabled
        else:
            return 0  # no redirect, hence no website forwarding
    except Exception as e:
        # print(f" Website Forwarding Error processing URL {url}: {str(e)}")
        return -1    

def DisableRightClick(url):
    try:
        # Get webpage content
        response = requests.get(url)
        content = response.text

        # Look for common patterns that disable right-click
        patterns = [
            r"contextmenu[^{]*return false",
            r"event.button ?== ?2[^{]*return false",
            r"addEventListener\(['\"]contextmenu['\"]",
            r"oncontextmenu\s*=\s*['\"]return false['\"]"
        ]

        for pattern in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                # Return '1' if pattern that disables right-click is found
                return 1

        # Return '0' if no patterns are found
        return 0

    except Exception as e:
        # print(f"Disable Right Click Error processing URL {url}: {str(e)}")
        return -1
    
def UsingPopupWindow(url):
    try:
        # Get webpage content
        response = requests.get(url)
        content = response.text

        # Look for "window.open" pattern
        if re.search(r"window.open", content, re.IGNORECASE):
            return 1
        else:
            return 0
    except Exception as e:
        # print(f" Popup Error processing URL {url}: {str(e)}")
        return -1

def age_domain(url):
    try:
        w = whois.whois(url)
        if w.creation_date is not None:
            if type(w.creation_date) is list:
                creation_date = w.creation_date[0]
            else:
                creation_date = w.creation_date
            ageofdomain = abs((creation_date - datetime.now()).days)
            if ageofdomain <= 60:
                return 1
            else:
                return 0
        else:
            return -1
    except Exception as e:
        # print(f"Age Domain Error processing URL {url}: {e}")
        return -1
    
def DNSRecording(url):
    try:
        domain = urlparse(url).netloc
        if domain:
            record = socket.gethostbyname(domain)
            if record:
                return 0  # DNS record exists, not bad
            else:
                return 1  # No DNS record, bad
        else:
            return 1  # No domain in URL, bad
    except Exception as e:
        # print(f" DNS Recording Error processing URL {url}: {e}")
        return -1
    
def LinksPointingToPage(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        links = soup.find_all('a', href=True)

        for link in links:
            if 'http' in link['href'] and url not in link['href']:
                return 1  # External link found
        return 0  # No external links
    except Exception as e:
        # print(f"Links Pointing Error processing URL {url}: {e}")
        return -1

# Feature Extraction
def extract_features(url,label=None):
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
        features['Dots'] = count_dots(url)
        features['Redirection //'] = count_double_slash(url)
        features['InfoEmail'] = email_in_url(url)
        features['AbnormalURL'] = abnormalURL(url)
        features['WebsiteForwarding'] = WebsiteForwarding(url)
        features['DisableRightClick'] = DisableRightClick(url)
        features['UsingPopupWindow'] = UsingPopupWindow(url)
        features['AgeofDomain'] = age_domain(url)
        features['DNSRecording'] = DNSRecording(url)
        features['LinksPointingToPage'] = LinksPointingToPage(url)

        if label is not None:
            features['label'] = label
        
    except (RequestException, TooManyRedirects) as e:
        # print(f"Feature Extraction Too many Redirects Error processing URL {url}: {e}")
        return None
    except Exception as e:
        # print(f"Feature Extraction Error processing URL {url}: {e}")
        return None
    return features

def process_url(url_label):
    url, label = url_label
    headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
    }
    # Check if the URL starts with a scheme
    if not url.startswith(('http://', 'https://')):
        # Prepend 'http://' if no scheme is found
        url = 'https://' + url

    try:
        # Add timeout to request.get() call
        response = requests.get(url, timeout=5, headers=headers)
        if response.status_code == 200:
            features = extract_features(url, label)
            if features is not None:
                features["Url"] = url
            return features
        else:
            # print(f"Process URL not accessible: {url}")
            return None
    except requests.exceptions.ReadTimeout as e:
        # print(f"Process URL Timeout error processing URL {url}: {e}")
        return None
    except requests.exceptions.RequestException as e:
        # print(f"Process URL Error processing URL {url}: {e}")
        return None
    except Exception as e:
        # print(f"Process URL Unexpected error processing URL {url}: {e}")
        return None


def main():
    datasets = [
        # {
        #     "input_file": "repo/legitrepo.csv",
        #     "dataset_type": "0"
        # },
        {
            "input_file": "online-valid.csv",
            "dataset_type": "1"
        }
    ]

    num_threads = 50
    output_file = "dataset_output.csv"

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
            "Dots",
            "Redirection //",
            "InfoEmail",
            "AbnormalURL",
            "WebsiteForwarding",
            "DisableRightClick",
            "UsingPopupWindow",
            "AgeofDomain",
            "DNSRecording",
            "LinksPointingToPage",
            "label",
            "Url"
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            for dataset in datasets:
                input_file = dataset["input_file"]
                dataset_type = dataset["dataset_type"]

                with open(input_file, "r", encoding='utf-8') as csvfile:
                    reader = csv.DictReader(csvfile)
                    urls_labels = [(row['url'], dataset_type) for row in reader]

                for result in executor.map(process_url, urls_labels):
                    if result:
                        writer.writerow(result)

if __name__ == "__main__":
    main()
