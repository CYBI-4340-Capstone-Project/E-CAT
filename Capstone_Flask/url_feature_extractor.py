# import urllib.parse
import ipaddress
import re
import math
from collections import Counter
from urllib.parse import urlparse

def url_detect_feature_extract(url):
    """Extract security features from a single URL"""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        query = parsed.query
    except:
        domain = path = query = None

    return {
        'havingIP': int(is_ip_address(domain) if domain else 0),
        'haveAtSign': int('@' in url),
        'getLength': int(len(url) >= 54),
        'getDepth': count_path_depth(path) if path else 0,
        'redirection': int(url.rfind('//') > 6),
        'httpDomain': int('https' in domain) if domain else 0,
        'tinyURL': int(is_shortened(url)),
        'numDots': domain.count('.') if domain else 0,
        'numHyphens': domain.count('-') if domain else 0,
        'numSubdomains': count_subdomains(domain) if domain else 0,
        'hasPort': int(':' in domain) if domain else 0,
        'pathLength': len(path) if path else 0,
        'numQueryParams': len(query.split('&')) if query else 0,
        'hasSensitiveKeywords': int(has_sensitive_keywords(url)),
        'numSpecialChars': len(re.findall(r'[^\w\s]', url)),
        'calculateEntropy': calculate_entropy(url),
        'hasTyposquatting': int(has_typosquatting(domain)) if domain else 0,
        'hasBrandName': int(has_brand_name(domain, path)) if domain else 0
    }

# Helper functions
def is_ip_address(domain):
    try:
        ipaddress.ip_address(domain)
        return True
    except:
        return False

def count_path_depth(path):
    return len([p for p in path.split('/') if p])

shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                    r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                    r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                    r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                    r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                    r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                    r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                    r"tr\.im|link\.zip\.net"

def is_shortened(url):
    return bool(re.search(shortening_services, url))

def count_subdomains(domain):
    return domain.count('.') - 1 if domain.count('.') > 1 else 0

def has_sensitive_keywords(url):
    keywords = ['login', 'bank', 'verify', 'secure', 'account', 'password'] ## updating this soon
    return any(kw in url.lower() for kw in keywords)

def calculate_entropy(text):
    try:
        p, lns = Counter(text), float(len(text))
        return -sum(count/lns * math.log(count/lns, 2) for count in p.values())
    except:
        return 0

def has_typosquatting(domain):
    typos = ['g00gle', 'facebok', 'amaz0n', 'paypa1']
    return any(typo in domain for typo in typos)

def has_brand_name(domain, path):
    brands = ['google', 'facebook', 'amazon', 'paypal', 'apple', 'microsoft']
    return any(brand in domain or (path and brand in path) for brand in brands)