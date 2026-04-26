import re
import socket
import datetime
from urllib.parse import urlparse

import requests
import tldextract
import validators
import whois
from bs4 import BeautifulSoup

# --- External AI Integration ---
# Ensure reasoning_llm.py exists in your directory or comment this out
try:
    from reasoning_llm import generate_ai_reasoning
except ImportError:
    def generate_ai_reasoning(data):
        return "AI reasoning module not found."

# --- Configuration ---
SUSPICIOUS_WORDS = [
    "login", "verify", "secure", "account", "bank", "update",
    "free", "gift", "bonus", "wallet", "signin", "confirm",
    "password", "payment", "urgent", "limited"
]

SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rebrand.ly", "shorturl.at"
]

HIGH_RISK_TLDS = [
    "tk", "ml", "ga", "cf", "gq"
]

BRANDS = [
    "google", "paypal", "microsoft", "amazon",
    "facebook", "apple", "netflix", "instagram",
    "bank", "whatsapp"
]

# --- Helper Functions ---

def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url

def extract_domain_info(url: str):
    ext = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    subdomain = ext.subdomain
    suffix = ext.suffix
    return domain, subdomain, suffix

def extract_features(url: str):
    parsed = urlparse(url)
    domain, subdomain, suffix = extract_domain_info(url)
    parsed_path = parsed.path.lower()
    full_lower = url.lower()

    features = {}
    features["url_length"] = len(url)
    features["https"] = 1 if parsed.scheme == "https" else 0
    features["dot_count"] = url.count(".")
    features["hyphen_count"] = url.count("-")
    features["slash_count"] = url.count("/")
    features["at_symbol"] = 1 if "@" in url else 0
    features["double_slash_redirect"] = 1 if url[8:].find("//") != -1 else 0
    features["has_ip"] = 1 if re.search(r"\d+\.\d+\.\d+\.\d+", parsed.netloc or url) else 0
    features["suspicious_words"] = sum(word in url.lower() for word in SUSPICIOUS_WORDS)
    features["subdomain_count"] = len([x for x in subdomain.split(".") if x]) if subdomain else 0
    features["is_shortener"] = 1 if domain.lower() in SHORTENERS else 0
    features["punycode"] = 1 if "xn--" in url.lower() else 0
    features["high_risk_tld"] = 1 if suffix.lower() in HIGH_RISK_TLDS else 0
    features["domain"] = domain
    features["subdomain"] = subdomain
    features["suffix"] = suffix
    
    # Path & Pattern Signals
    features["has_login_path"] = 1 if "login" in parsed_path else 0
    features["has_verify_path"] = 1 if "verify" in parsed_path else 0
    features["has_account_path"] = 1 if "account" in parsed_path else 0
    features["query_length"] = len(parsed.query)
    features["has_encoded_chars"] = 1 if any(x in full_lower for x in ["%2f", "%2e", "%40", "%25"]) else 0
    features["digit_count"] = sum(c.isdigit() for c in url)

    # Brand Detection
    features["brand_in_domain"] = sum(brand in domain.lower() for brand in BRANDS)
    features["brand_in_url"] = sum(brand in url.lower() for brand in BRANDS)
    features["suspicious_domain_pattern"] = 1 if "-" in domain and any(b in domain.lower() for b in BRANDS) else 0

    return features

def check_domain_age(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            now = datetime.datetime.now()
            if creation_date.tzinfo is not None:
                creation_date = creation_date.replace(tzinfo=None)
            return (now - creation_date).days
    except Exception:
        return None
    return None

def resolve_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None

def fetch_page_signals(url):
    result = {
        "fetch_ok": False,
        "final_url": None,
        "redirect_count": 0,
        "status_code": None,
        "page_title": None,
        "has_login_form": 0,
        "has_password_field": 0,
        "iframe_count": 0,
        "external_form_action": 0,
        "suspicious_html_keywords": 0,
        "external_link_count": 0,
        "script_count": 0,
        "has_obfuscated_js_hint": 0,
    }
    try:
        response = requests.get(
            url,
            timeout=6,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        )
        result["fetch_ok"] = True
        result["final_url"] = response.url
        result["redirect_count"] = len(response.history)
        result["status_code"] = response.status_code

        content_type = response.headers.get("Content-Type", "")
        if "text/html" not in content_type.lower():
            return result

        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")
        inputs = soup.find_all("input")
        links = soup.find_all("a", href=True)
        
        result["iframe_count"] = len(soup.find_all("iframe"))
        result["script_count"] = len(soup.find_all("script"))
        result["has_login_form"] = 1 if forms else 0
        result["has_password_field"] = 1 if any((inp.get("type") or "").lower() == "password" for inp in inputs) else 0

        parsed_base = urlparse(response.url).netloc.lower()
        
        ext_links = 0
        for link in links:
            host = urlparse(link.get("href", "")).netloc.lower()
            if host and host != parsed_base: ext_links += 1
        result["external_link_count"] = ext_links

        for form in forms:
            action = (form.get("action") or "").strip()
            if action.startswith("http") and urlparse(action).netloc.lower() != parsed_base:
                result["external_form_action"] = 1
                break

        html_lower = response.text.lower()
        result["has_obfuscated_js_hint"] = 1 if any(x in html_lower for x in ["eval(", "unescape(", "atob("]) else 0
        result["suspicious_html_keywords"] = sum(k in html_lower for k in ["verify account", "login now", "urgent action"])
        
    except Exception:
        pass
    return result

# --- Main Analysis Engine ---

def analyze_url(url: str):
    url = normalize_url(url)
    if not validators.url(url):
        return {"error": "Invalid URL format"}

    f = extract_features(url)
    domain_age = check_domain_age(f["domain"])
    ip = resolve_ip(f["domain"])
    page = fetch_page_signals(url)

    score = 0
    reasons = []

    # 1. Path Signals
    if f["has_login_path"]:
        score += 8
        reasons.append("Login-related path detected")
    if f["has_verify_path"]:
        score += 8
        reasons.append("Verification-related path detected")
    if f["has_account_path"]:
        score += 6
        reasons.append("Account-related path detected")

    # 2. Brand Signals
    if f["brand_in_domain"] > 0:
        score += 12
        reasons.append("Known brand name found in domain")
    if f["brand_in_url"] > 0 and f["suspicious_words"] > 0:
        score += 12
        reasons.append("Brand name combined with suspicious keywords")
    if f["suspicious_domain_pattern"]:
        score += 25
        reasons.append("Domain mimics a known brand")

    # 3. Technical Signals
    if f["has_ip"]:
        score += 30
        reasons.append("IP address used in URL")
    if f["punycode"]:
        score += 25
        reasons.append("Punycode domain detected")
    if page["external_form_action"]:
        score += 25
        reasons.append("Form submits to external domain")
    if f["is_shortener"]:
        score += 18
        reasons.append("URL shortener used")
    if f["https"] == 0:
        score += 10
        reasons.append("No HTTPS")
    if f["subdomain_count"] > 2:
        score += 15
        reasons.append("Too many subdomains")

    # 4. Suspicious URL content
    if f["suspicious_words"] > 0:
        score += min(18, f["suspicious_words"] * 4)
        reasons.append(f"{f['suspicious_words']} suspicious keyword(s) detected")

    if f["hyphen_count"] > 2:
        score += 8
        reasons.append("Too many hyphens")

    if f["url_length"] > 75:
        score += 8
        reasons.append("Long URL")

    if f["high_risk_tld"]:
        score += 10
        reasons.append("High-risk top-level domain")

    if f["has_encoded_chars"]:
        score += 8
        reasons.append("Encoded characters in URL")

    if f["query_length"] > 60:
        score += 6
        reasons.append("Long query string")

    if f["digit_count"] > 10:
        score += 5
        reasons.append("Unusually high number of digits in URL")

    if f["at_symbol"]:
        score += 12
        reasons.append("@ symbol found in URL")

    if f["double_slash_redirect"]:
        score += 8
        reasons.append("Suspicious double-slash pattern")

    # 5. Domain intelligence
    if domain_age is not None:
        if domain_age < 30:
            score += 20
            reasons.append("Very new domain")
        elif domain_age < 180:
            score += 12
            reasons.append("Recently registered domain")
    else:
        score += 4
        reasons.append("Domain age unavailable")

    if ip is None:
        score += 5
        reasons.append("Domain could not be resolved")

    # 6. Page behavior
    if page["redirect_count"] >= 3:
        score += 12
        reasons.append("Multiple redirects detected")

    if page["has_password_field"]:
        score += 15
        reasons.append("Password field detected")

    if page["iframe_count"] >= 3:
        score += 8
        reasons.append("Multiple iframes detected")

    if page["suspicious_html_keywords"] > 0:
        score += 12
        reasons.append("Phishing content detected")

    if page["has_obfuscated_js_hint"]:
        score += 10
        reasons.append("Possible obfuscated JavaScript detected")

    if page["external_link_count"] >= 15:
        score += 8
        reasons.append("Many external links on page")

    # 7. Combo Rules
    if f["https"] == 0 and f["suspicious_words"] > 0:
        score += 10
        reasons.append("No HTTPS combined with suspicious keywords")

    if f["brand_in_url"] > 0 and f["hyphen_count"] > 1:
        score += 10
        reasons.append("Brand-like URL combined with deceptive hyphen pattern")

    if f["subdomain_count"] > 1 and f["brand_in_url"] > 0:
        score += 12
        reasons.append("Brand name hidden in complex subdomain structure")

    if page["has_password_field"] and page["has_login_form"]:
        score += 10
        reasons.append("Login form with password field detected")

    if page["redirect_count"] >= 2 and f["https"] == 0:
        score += 8
        reasons.append("Redirecting non-HTTPS page")

    # 8. Hard fail
    if f["has_ip"] and f["https"] == 0 and page["has_password_field"]:
        score = max(score, 90)
        reasons.append("Critical phishing pattern detected")

    score = min(score, 100)

    # 9. Verdict
    if score >= 80:
        verdict, confidence = "High Confidence Phishing", "High"
    elif score >= 55:
        verdict, confidence = "Likely Phishing", "Medium"
    elif score >= 30:
        verdict, confidence = "Suspicious", "Medium"
    else:
        verdict, confidence = "Likely Safe", "Lower"

    try:
        ai_explanation = generate_ai_reasoning({
            "verdict": verdict,
            "risk_score": score,
            "features": f,
            "page_analysis": page,
            "reasons": reasons
        })
    except Exception:
        ai_explanation = "AI reasoning unavailable due to API error."

    return {
        "url": url,
        "domain": f["domain"],
        "subdomain": f["subdomain"],
        "tld": f["suffix"],
        "ip": ip,
        "domain_age_days": domain_age,
        "risk_score": score,
        "verdict": verdict,
        "confidence": confidence,
        "reasons": reasons,
        "features": f,
        "page_analysis": page,
        "ai_explanation": ai_explanation
    }

# --- Example Execution ---
if __name__ == "__main__":
    test_url = "http://secure-login-paypal.com.tk/update"
    results = analyze_url(test_url)
    
    print(f"URL: {results['url']}")
    print(f"Verdict: {results['verdict']} (Score: {results['risk_score']})")
    print("-" * 30)
    print("Reasons Found:")
    for reason in results['reasons']:
        print(f"- {reason}")