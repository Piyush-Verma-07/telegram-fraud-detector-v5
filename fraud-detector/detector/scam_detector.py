import re
import tldextract
import os
import whois
import joblib
from datetime import datetime

# Load trained ML phishing model
# Load ML model using absolute project path
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
model_path = os.path.join(base_dir, "phishing_model.pkl")

model = joblib.load(model_path)


# Suspicious words often used in scam domains
suspicious_domain_words = [
    "login", "verify", "secure", "bonus", "reward",
    "gift", "bank", "wallet", "upi", "pay"
]


# Popular brands commonly targeted by phishing
target_brands = [
    "google",
    "amazon",
    "paypal",
    "apple",
    "facebook",
    "instagram",
    "whatsapp",
    "paytm",
    "phonepe",
    "gpay",
    "upi",
    "sbi",
    "hdfc",
    "icici",
    "axis"
]


# Short URL services
short_url_services = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly", "is.gd"
]

# Suspicious keywords in messages
suspicious_keywords = [
    "lottery", "reward", "claim", "urgent", "verify", "otp", "win"
]

# Suspicious domain extensions
suspicious_tlds = [
    "xyz", "top", "click", "site", "live", "gq", "cf", "ml"
]


# ----------------------------
# Load scam message patterns
# ----------------------------
def load_scam_patterns():

    patterns = []

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    file_path = os.path.join(base_dir, "data", "scam_patterns.txt")

    try:
        with open(file_path, "r") as file:
            for line in file:
                patterns.append(line.strip().lower())
    except:
        print("Scam pattern dataset not found")

    return patterns


scam_patterns = load_scam_patterns()


# ----------------------------
# Text similarity function
# ----------------------------
def jaccard_similarity(text1, text2):

    text1 = re.sub(r'[^\w\s]', '', text1)
    text2 = re.sub(r'[^\w\s]', '', text2)

    words1 = set(text1.split())
    words2 = set(text2.split())

    intersection = words1.intersection(words2)
    union = words1.union(words2)

    if len(union) == 0:
        return 0

    return len(intersection) / len(union)




# Check domain age
def get_domain_age(domain):

    try:
        domain_info = whois.whois(domain)

        creation_date = domain_info.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date is None:
            return None

        today = datetime.now()

        age_days = (today - creation_date).days

        return age_days

    except:
        return None




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



# ----------------------------
# Main detection function
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

    # URL detection
    urls = re.findall(r'https?://\S+', text)

    if urls:
        score += 20
        reasons.append("Message contains external link")

    # URL analysis
    for url in urls:

        domain_info = tldextract.extract(url)

        domain = domain_info.domain
        suffix = domain_info.suffix

        domain_name = domain + "." + suffix

        # Brand impersonation detection
        for brand in target_brands:
            if brand in domain.lower():
                score += 35
                reasons.append("Possible brand impersonation detected: " + brand)

        age = get_domain_age(domain_name)

        if age is not None and age < 30:
            score += 40
            reasons.append("Domain is very new (less than 30 days old): " + domain_name)

        full_domain = domain + "." + suffix
        reasons.append("Detected domain: " + full_domain)

        # Suspicious TLD detection
        if suffix in suspicious_tlds:
            score += 35
            reasons.append("Suspicious domain extension detected: ." + suffix)

        # Short URL detection
        for short in short_url_services:
            if short in url:
                score += 30
                reasons.append("Shortened URL detected: " + url)

        # Suspicious domain word detection
        for word in suspicious_domain_words:
            if word in url:
                score += 25
                reasons.append("Suspicious word in URL: " + word)


        # Detect IP address URLs
        ip_pattern = r'http[s]?://\d+\.\d+\.\d+\.\d+'

        if re.match(ip_pattern, url):
            score += 40
            reasons.append("URL uses IP address instead of domain")


        # Detect excessive hyphens
        if domain.count("-") >= 3:
            score += 30
            reasons.append("Domain contains excessive hyphens (possible phishing)")


        # Detect very long domains
        if len(domain) > 25:
            score += 25
            reasons.append("Domain name unusually long")

        # Detect suspicious subdomain tricks
        if domain_info.subdomain:
            if any(brand in domain_info.subdomain for brand in target_brands):
                score += 35
                reasons.append("Brand name used in subdomain (possible phishing)")


        # Machine learning phishing detection
        ml_result = ml_detect(url)
        
        if ml_result == 1:
            score += 40
            reasons.append("Machine learning model detected phishing URL")






    # Cap score
    if score > 100:
        score = 100

    return score, reasons