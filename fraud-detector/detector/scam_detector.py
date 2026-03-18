import re
import requests
import tldextract
import os
import joblib
import dns.resolver
from datetime import datetime
import math
from collections import Counter

# ----------------------------
# Load trained ML phishing model
# ----------------------------

base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
model_path = os.path.join(base_dir, "phishing_model.pkl")
model = joblib.load(model_path)

# ----------------------------
# Suspicious domain words
# ----------------------------

suspicious_domain_words = [
    "login","verify","secure","bonus","reward",
    "gift","bank","wallet","upi","pay"
]

# ----------------------------
# Target brands
# ----------------------------

target_brands = [
    "google","amazon","paypal","apple","facebook",
    "instagram","whatsapp","paytm","phonepe",
    "gpay","upi","sbi","hdfc","icici","axis"
]

# ----------------------------
# Popular trusted domains
# ----------------------------

popular_domains = [
    "google.com","youtube.com","facebook.com","amazon.com",
    "amazon.in","microsoft.com","apple.com",
    "github.com","linkedin.com","wikipedia.org"
]

# ----------------------------
# Short URL services
# ----------------------------

short_url_services = [
    "bit.ly","tinyurl.com","t.co","goo.gl","cutt.ly","is.gd"
]

# ----------------------------
# Suspicious keywords
# ----------------------------

suspicious_keywords = [
    "lottery","reward","claim","urgent","verify","otp","win"
]

# ----------------------------
# Suspicious TLDs
# ----------------------------

suspicious_tlds = [
    "xyz","top","click","site","live","gq","cf","ml"
]

# ----------------------------
# Load scam patterns
# ----------------------------

def load_scam_patterns():

    patterns = []
    file_path = os.path.join(base_dir,"data","scam_patterns.txt")

    try:
        with open(file_path,"r") as file:
            for line in file:
                patterns.append(line.strip().lower())
    except:
        print("Scam pattern dataset not found")

    return patterns

scam_patterns = load_scam_patterns()










# ----------------------------
# Load URLhaus database
# ----------------------------

def load_urlhaus():

    urlhaus_set = set()

    file_path = os.path.join(base_dir, "data", "urlhaus.csv")

    try:
        with open(file_path, "r", encoding="utf-8") as f:

            for line in f:

                # Skip comments
                if line.startswith("#"):
                    continue

                parts = line.split(",")

                # URL is 3rd column (index 2)
                if len(parts) > 2:
                    url = parts[2].strip().strip('"')
                    urlhaus_set.add(url)

    except:
        print("URLhaus dataset not found")

    return urlhaus_set


# Load once
urlhaus_db = load_urlhaus()









# ----------------------------
# Jaccard similarity
# ----------------------------

def jaccard_similarity(text1,text2):

    text1 = re.sub(r'[^\w\s]','',text1)
    text2 = re.sub(r'[^\w\s]','',text2)

    words1=set(text1.split())
    words2=set(text2.split())

    intersection=words1.intersection(words2)
    union=words1.union(words2)

    if len(union)==0:
        return 0

    return len(intersection)/len(union)

# ----------------------------
# Domain age using APILayer
# ----------------------------

def get_domain_age(domain):

    API_KEY = "nOmMJNL00UiCQgHbPVn698GXNVce7otZ"

    url = "https://api.apilayer.com/whois/query"

    headers = {
        "apikey": API_KEY
    }

    params = {
        "domain": domain
    }

    try:

        response = requests.get(url, headers=headers, params=params, timeout=5)

        data = response.json()

        result = data.get("result")

        if not result:
            return None

        creation_date = result.get("creation_date")

        if not creation_date:
            return None

        creation_date = datetime.strptime(creation_date[:10], "%Y-%m-%d")

        today = datetime.now()

        age_days = (today - creation_date).days

        return age_days

    except:
        return None

# ----------------------------
# Domain entropy
# ----------------------------

def calculate_entropy(text):

    counter=Counter(text)
    length=len(text)

    entropy=0

    for count in counter.values():
        probability=count/length
        entropy-=probability*math.log2(probability)

    return entropy

# ----------------------------
# Levenshtein distance
# ----------------------------

def levenshtein_distance(a,b):

    if len(a)<len(b):
        return levenshtein_distance(b,a)

    if len(b)==0:
        return len(a)

    previous_row=range(len(b)+1)

    for i,c1 in enumerate(a):

        current_row=[i+1]

        for j,c2 in enumerate(b):

            insertions=previous_row[j+1]+1
            deletions=current_row[j]+1
            substitutions=previous_row[j]+(c1!=c2)

            current_row.append(min(insertions,deletions,substitutions))

        previous_row=current_row

    return previous_row[-1]

# ----------------------------
# Resolve redirect URL
# ----------------------------

def resolve_final_url(url):

    try:
        response=requests.get(url,allow_redirects=True,timeout=5)
        return response.url
    except:
        return url

# ----------------------------
# PhishTank API check
# ----------------------------

def check_phishtank(url):

    api_url = "https://checkurl.phishtank.com/checkurl/"

    payload = {
        "url": url,
        "format": "json"
    }

    headers = {
        "User-Agent": "fraud-detector"
    }

    try:

        response = requests.post(api_url, data=payload, headers=headers, timeout=5)
        data = response.json()

        if "results" in data:

            result = data["results"]

            if result.get("in_database") and result.get("verified"):
                return True

    except:
        pass

    return False

# ----------------------------
# ML phishing detection
# ----------------------------

def ml_detect(url):

    features = [
        len(url),
        url.count("-"),
        url.count("."),
        int("https" in url),
        int(re.search(r'\d+\.\d+\.\d+\.\d+', url) is not None)
    ]

    prediction = model.predict([features])

    return prediction[0]








def check_google_safe_browsing(url):

    API_KEY = "AIzaSyDkldRwcVa83tl5PJu-qqIOADeTSUhV4jk"

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"

    payload = {
        "client": {
            "clientId": "fraud-detector",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "POTENTIALLY_HARMFUL_APPLICATION",
                "UNWANTED_SOFTWARE"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:

        response = requests.post(endpoint, json=payload, timeout=5)

        data = response.json()

        print("Safe Browsing API Response:", data)  # DEBUG

        if "matches" in data:
            return True

    except Exception as e:
        print("Safe Browsing error:", e)

    return False






def check_urlhaus(url):

    api_url = "https://urlhaus-api.abuse.ch/v1/url/"

    headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "application/json"
    }

    payload = {
        "url": url
    }

    try:
        response = requests.post(api_url, headers=headers, data=payload, timeout=5)

        result = response.json()

        print("URLhaus response:", result)  # DEBUG

        if result.get("query_status") == "ok":
            return True

    except Exception as e:
        print("URLhaus error:", e)

    return False










def check_abuseipdb(ip):

    API_KEY = "9e9c72067b88af9d60f3618d3a1d02a4866be923ad5e8a640b70a3739c7f901eeb050d08e425303c"

    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=5)
        data = response.json()

        abuse_score = data["data"]["abuseConfidenceScore"]

        if abuse_score > 50:
            return True, abuse_score

    except:
        pass

    return False, 0








def load_threatfox():

    threatfox_set = set()

    file_path = os.path.join(base_dir, "data", "threatfox.json")

    try:
        import json

        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

            # Loop through dictionary values
            for key in data:
                entries = data[key]

                for item in entries:
                    ioc = item.get("ioc_value")

                    if ioc:
                        threatfox_set.add(ioc.strip())

        print("Total ThreatFox entries:", len(threatfox_set))

    except Exception as e:
        print("ThreatFox dataset error:", e)

    return threatfox_set
threatfox_db = load_threatfox()





# ----------------------------
# MAIN DETECTION FUNCTION
# ----------------------------

def analyze_message(message):

    score = 0
    reasons = []

    text = message.lower()

    # Keyword detection
    for word in suspicious_keywords:
        if word in text:
            score += 20
            reasons.append("Suspicious keyword detected: " + word)

    # Pattern detection
    pattern_matched = False

    for pattern in scam_patterns:
        if pattern in text:
            score += 40
            reasons.append("Matched known scam pattern: " + pattern)
            pattern_matched = True
            break

    # Similarity detection
    if not pattern_matched:
        for pattern in scam_patterns:
            similarity = jaccard_similarity(text, pattern)
            if similarity > 0.3:
                score += 30
                reasons.append("Message similar to scam pattern: " + pattern)
                break

    # URL extraction
    urls = re.findall(r'https?://\S+', text)

    if urls:
        score += 20
        reasons.append("Message contains external link")

    # URL analysis
    for url in urls:

        final_url = resolve_final_url(url)
        clean_url = final_url.rstrip("/")

        # Google Safe Browsing
        if check_google_safe_browsing(final_url):
            score += 50
            reasons.append("Google Safe Browsing flagged this URL as dangerous")

        # PhishTank
        if check_phishtank(final_url):
            score += 50
            reasons.append("URL found in PhishTank phishing database")

        # URLhaus (CSV ONLY)
        if clean_url in urlhaus_db:
            score += 50
            reasons.append("URL found in URLhaus malware database")
        



        # ThreatFox API (only if not found in DB)
        # if domain_name in threatfox_db:
            # score += 50
            # reasons.append("Domain found in ThreatFox database")

        # Domain extraction
        domain_info = tldextract.extract(final_url)
        domain = domain_info.domain
        suffix = domain_info.suffix

        domain_name = domain + "." + suffix




        # ThreatFox API (only if not found in DB)
        if domain_name in threatfox_db or final_url in threatfox_db:
            score += 50
            reasons.append("Found in ThreatFox database")




        # Get IP from domain
        try:
            ip = dns.resolver.resolve(domain_name, "A")[0].to_text()
        except:
            ip = None
        

        if ip:
            is_bad, score_ip = check_abuseipdb(ip)
        if is_bad:
            score += 40
            reasons.append(f"IP reported malicious (AbuseIPDB score: {score_ip})")




        # Entropy
        entropy = calculate_entropy(domain)
        if entropy > 3.5:
            score += 30
            reasons.append("Domain has high entropy")

        # Domain popularity
        if domain_name not in popular_domains:
            score += 10
            reasons.append("Domain not in popular domain list")

        # Brand impersonation
        for brand in target_brands:
            if brand in domain.lower():
                score += 35
                reasons.append("Brand impersonation detected: " + brand)

        # Domain age
        age = get_domain_age(domain_name)
        if age is not None and age < 30:
            score += 40
            reasons.append("Domain very new (<30 days)")

        reasons.append("Detected domain: " + domain_name)

        # ML detection
        if ml_detect(final_url) == 1:
            score += 40
            reasons.append("ML model detected phishing")

        # DNS check
        try:
            dns.resolver.resolve(domain_name, "A")
        except:
            score += 25
            reasons.append("DNS lookup failed")

    if score > 100:
        score = 100

    return score, reasons


print("Total URLhaus entries:", len(urlhaus_db))

    # print(get_domain_age("google.com"))
