"""
Phishing URL Detection Engine
Rule-based analysis using cybersecurity heuristics.
"""

import re
import socket
import ssl
from urllib.parse import urlparse, unquote

# Known suspicious keywords often used in phishing URLs
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "update", "secure", "account", "banking",
    "confirm", "password", "credential", "wallet", "paypal", "amazon",
    "appleid", "support", "suspend", "unlock", "validation", "webscr",
    "free", "bonus", "click", "urgent", "limited", "offer", "prize",
]

# TLDs frequently abused in phishing campaigns
SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work",
    ".click", ".link", ".buzz", ".loan", ".win", ".review",
]

# Short URL services (can hide real destination)
SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "cutt.ly", "rb.gy", "shorturl.at",
]

# Trusted domains (reduce false positives for subdomains)
TRUSTED_DOMAINS = [
    "google.com", "microsoft.com", "apple.com", "amazon.com",
    "github.com", "linkedin.com", "facebook.com", "twitter.com",
    "instagram.com", "youtube.com", "wikipedia.org", "gov.in",
    "nic.in", "paypal.com", "stripe.com",
]


def normalize_url(url: str) -> str:
    """Ensure URL has a scheme for parsing."""
    url = url.strip()
    if not url:
        return ""
    if not re.match(r"^https?://", url, re.I):
        url = "http://" + url
    return url


def extract_domain(url: str) -> str:
    """Extract hostname from URL."""
    try:
        parsed = urlparse(normalize_url(url))
        return (parsed.netloc or parsed.path.split("/")[0]).lower()
    except Exception:
        return ""


def count_subdomains(domain: str) -> int:
    """Count subdomain levels."""
    parts = domain.split(".")
    if len(parts) <= 2:
        return 0
    return len(parts) - 2


def is_ip_address(domain: str) -> bool:
    """Check if domain is an IP address."""
    domain = domain.split(":")[0]
    ipv4 = re.match(r"^(\d{1,3}\.){3}\d{1,3}$", domain)
    if ipv4:
        return True
    return bool(re.match(r"^\[?[\da-fA-F:]+\]?$", domain))


def has_homograph_chars(url: str) -> bool:
    """Detect mixed scripts / lookalike Unicode."""
    suspicious = re.findall(r"[^\x00-\x7F]", url)
    return len(suspicious) > 0


def check_https(domain: str) -> tuple[bool, str]:
    """Check if domain supports HTTPS with a valid certificate."""
    host = domain.split(":")[0]
    if not host or is_ip_address(host):
        return False, "Cannot verify SSL for this host"
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as secure_sock:
                cert = secure_sock.getpeercert()
                if cert:
                    return True, "Valid SSL/TLS certificate found"
        return True, "Valid SSL/TLS connection"
    except ssl.SSLCertVerificationError:
        return False, "SSL certificate verification failed"
    except socket.timeout:
        return False, "SSL connection timed out"
    except Exception:
        return False, "No valid HTTPS certificate found"


def is_trusted_domain(domain: str) -> bool:
    """Check if domain belongs to a trusted organization."""
    for trusted in TRUSTED_DOMAINS:
        if domain == trusted or domain.endswith("." + trusted):
            return True
    return False


URL_PATTERN = re.compile(
    r"https?://[^\s<>\"')\]]+|www\.[^\s<>\"')\]]+",
    re.IGNORECASE,
)

EMAIL_URGENCY_WORDS = [
    "urgent", "immediately", "act now", "expire", "limited time",
    "तुरंत", "अभी", "जल्दी", "सीमित समय", "आखिरी मौका",
]

EMAIL_THREAT_WORDS = [
    "suspended", "locked", "unauthorized", "verify your account",
    "confirm your identity", "security alert", "unusual activity",
    "खाता बंद", "सुरक्षा चेतावनी", "अनधिकृत", "पासवर्ड बदलें",
]

EMAIL_PRIZE_WORDS = [
    "winner", "congratulations", "lottery", "prize", "free gift",
    "बधाई", "इनाम", "लॉटरी", "मुफ्त", "जीत गए",
]

EMAIL_GENERIC_GREETINGS = [
    "dear customer", "dear user", "dear member", "dear valued",
    "प्रिय ग्राहक", "प्रिय उपयोगकर्ता", "प्रिय सदस्य",
]


def extract_urls_from_text(text: str) -> list[str]:
    """Extract all URLs from email or plain text."""
    if not text:
        return []
    found = URL_PATTERN.findall(text)
    cleaned = []
    for url in found:
        url = url.rstrip(".,;:!?)")
        if not url.startswith("http"):
            url = "http://" + url
        if url not in cleaned:
            cleaned.append(url)
    return cleaned


def get_tips(lang: str = "en") -> list[str]:
    if lang == "hi":
        return [
            "ईमेल लिंक पर कभी भी पासवर्ड न दर्ज करें।",
            "डोमेन नाम को अक्षर दर अक्षर जाँचें।",
            "महत्वपूर्ण खातों पर दो-चरण प्रमाणीकरण चालू करें।",
            "संदिग्ध URL को CERT-In या IT टीम को रिपोर्ट करें।",
            "संदेह हो तो सीधे आधिकारिक वेबसाइट पर जाएँ।",
        ]
    return [
        "Never enter passwords on sites reached via email links.",
        "Always verify the domain spelling character by character.",
        "Use two-factor authentication on all important accounts.",
        "Report suspicious URLs to your IT security team or CERT-In.",
        "When in doubt, visit the official site directly by typing the URL.",
    ]


def get_verdict(score: int, lang: str = "en") -> tuple[str, str, bool]:
    if score >= 60:
        if lang == "hi":
            return "उच्च", "संभवतः फ़िशिंग", True
        return "High", "Likely Phishing", True
    if score >= 35:
        if lang == "hi":
            return "मध्यम", "संदिग्ध", True
        return "Medium", "Suspicious", True
    if score >= 15:
        if lang == "hi":
            return "निम्न", "सावधानी बरतें", False
        return "Low", "Caution Advised", False
    if lang == "hi":
        return "सुरक्षित", "संभवतः सुरक्षित", False
    return "Safe", "Likely Safe", False


def analyze_url(url: str, lang: str = "en") -> dict:
    """
    Analyze a URL and return phishing risk assessment.
    Returns dict with score, verdict, risk_level, and detailed findings.
    """
    findings = []
    score = 0
    max_score = 100

    if not url or not url.strip():
        invalid_msg = "कृपया मान्य URL दर्ज करें" if lang == "hi" else "Please enter a valid URL"
        return {
            "url": url,
            "score": 0,
            "risk_percent": 0,
            "risk_level": "अज्ञात" if lang == "hi" else "Unknown",
            "verdict": "अमान्य" if lang == "hi" else "Invalid",
            "is_phishing": False,
            "findings": [{"type": "error", "message": invalid_msg, "points": 0}],
            "domain": "",
            "tips": [],
        }

    normalized = normalize_url(url)
    parsed = urlparse(normalized)
    domain = extract_domain(url)
    full_url_lower = unquote(normalized.lower())
    path_query = (parsed.path + "?" + parsed.query).lower()

    # --- Heuristic checks ---

    # 1. IP address instead of domain (+20)
    if is_ip_address(domain):
        score += 20
        msg = "URL में IP पता है, डोमेन नाम नहीं" if lang == "hi" else "URL uses IP address instead of domain name"
        findings.append({"type": "danger", "message": msg, "points": 20})

    # 2. @ symbol in URL (+25)
    if "@" in normalized:
        score += 25
        msg = "URL में '@' चिह्न है (पासवर्ड छुपाने की तरकीब)" if lang == "hi" else "URL contains '@' symbol (credential hiding trick)"
        findings.append({"type": "danger", "message": msg, "points": 25})

    # 3. Excessive URL length (+10)
    if len(normalized) > 75:
        score += 10
        msg = f"बहुत लंबा URL ({len(normalized)} अक्षर)" if lang == "hi" else f"Unusually long URL ({len(normalized)} characters)"
        findings.append({"type": "warning", "message": msg, "points": 10})

    # 4. Too many subdomains (+15)
    sub_count = count_subdomains(domain)
    if sub_count >= 4:
        score += 15
        msg = f"बहुत अधिक सबडोमेन ({sub_count} स्तर)" if lang == "hi" else f"Excessive subdomains detected ({sub_count} levels)"
        findings.append({"type": "warning", "message": msg, "points": 15})
    elif sub_count >= 2 and not is_trusted_domain(domain):
        score += 8
        msg = f"कई सबडोमेन ({sub_count}) — संभवतः नकली साइट" if lang == "hi" else f"Multiple subdomains ({sub_count} levels) — possible spoofing"
        findings.append({"type": "warning", "message": msg, "points": 8})

    # 5. Suspicious keywords (+5 each, max 20)
    keyword_hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_url_lower]
    if keyword_hits:
        kw_points = min(len(keyword_hits) * 5, 20)
        score += kw_points
        kw_label = "संदिग्ध शब्द मिले" if lang == "hi" else "Suspicious keywords found"
        findings.append({
            "type": "warning",
            "message": f"{kw_label}: {', '.join(keyword_hits[:5])}",
            "points": kw_points,
        })

    # 6. Suspicious TLD (+15)
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 15
            msg = f"उच्च जोखिम वाला डोमेन: {tld}" if lang == "hi" else f"High-risk top-level domain: {tld}"
            findings.append({"type": "danger", "message": msg, "points": 15})
            break

    # 7. URL shortener (+12)
    for shortener in SHORTENERS:
        if shortener in domain:
            score += 12
            msg = f"URL शॉर्टनर मिला ({shortener}) — असली लिंक छुपी है" if lang == "hi" else f"URL shortener detected ({shortener}) — destination hidden"
            findings.append({"type": "warning", "message": msg, "points": 12})
            break

    # 8. Hyphens in domain (+8)
    domain_name = domain.split(":")[0]
    if domain_name.count("-") >= 3:
        score += 8
        msg = "डोमेन में कई हाइफ़न (फ़िशिंग में आम)" if lang == "hi" else "Multiple hyphens in domain (common in phishing)"
        findings.append({"type": "warning", "message": msg, "points": 8})

    # 9. Port in URL (+10)
    if parsed.port and parsed.port not in (80, 443):
        score += 10
        msg = f"गैर-मानक पोर्ट: {parsed.port}" if lang == "hi" else f"Non-standard port used: {parsed.port}"
        findings.append({"type": "warning", "message": msg, "points": 10})

    # 10. Homograph / Unicode (+20)
    if has_homograph_chars(url):
        score += 20
        msg = "गैर-ASCII अक्षर मिले (होमोग्राफ़ हमला संभव)" if lang == "hi" else "Non-ASCII characters detected (possible homograph attack)"
        findings.append({"type": "danger", "message": msg, "points": 20})

    # 11. HTTP instead of HTTPS (+15)
    if parsed.scheme == "http" and not is_ip_address(domain):
        score += 15
        msg = "HTTP कनेक्शन (एन्क्रिप्टेड नहीं)" if lang == "hi" else "Connection uses HTTP (not encrypted)"
        findings.append({"type": "warning", "message": msg, "points": 15})

    # 12. Double slashes in path (+10)
    if "//" in path_query:
        score += 10
        msg = "URL पथ में डबल स्लैश (रिडायरेक्ट ट्रिक)" if lang == "hi" else "Double slashes in URL path (redirection trick)"
        findings.append({"type": "warning", "message": msg, "points": 10})

    # 13. Trusted domain reduces score
    if is_trusted_domain(domain):
        score = max(0, score - 25)
        msg = "ज्ञात विश्वसनीय संस्था का डोमेन" if lang == "hi" else "Domain matches known trusted organization"
        findings.append({"type": "safe", "message": msg, "points": -25})

    # 14. HTTPS certificate check
    if domain and not is_ip_address(domain):
        has_ssl, ssl_msg_en = check_https(domain)
        ssl_msg = "मान्य SSL/TLS कनेक्शन" if has_ssl and lang == "hi" else ssl_msg_en
        if not has_ssl and lang == "hi":
            ssl_msg = "कोई मान्य HTTPS प्रमाणपत्र नहीं मिला"
        if has_ssl:
            findings.append({"type": "safe", "message": ssl_msg, "points": 0})
        else:
            score += 10
            findings.append({"type": "warning", "message": ssl_msg, "points": 10})

    score = min(score, max_score)
    risk_percent = score
    risk_level, verdict, is_phishing = get_verdict(score, lang)
    tips = get_tips(lang)

    if not findings:
        msg = "कोई महत्वपूर्ण फ़िशिंग संकेतक नहीं मिला" if lang == "hi" else "No significant phishing indicators detected"
        findings.append({"type": "safe", "message": msg, "points": 0})

    return {
        "url": normalized,
        "domain": domain,
        "score": score,
        "risk_percent": risk_percent,
        "risk_level": risk_level,
        "verdict": verdict,
        "is_phishing": is_phishing,
        "findings": findings,
        "tips": tips,
    }


def analyze_email(content: str, lang: str = "en") -> dict:
    """Analyze email content for phishing indicators and embedded URLs."""
    if not content or not content.strip():
        msg = "कृपया ईमेल सामग्री दर्ज करें" if lang == "hi" else "Please enter email content"
        return {
            "error": msg,
            "email_score": 0,
            "risk_level": "अज्ञात" if lang == "hi" else "Unknown",
            "verdict": "अमान्य" if lang == "hi" else "Invalid",
            "is_phishing": False,
            "email_findings": [],
            "urls_found": 0,
            "url_results": [],
            "tips": get_tips(lang),
        }

    text_lower = content.lower()
    email_findings = []
    email_score = 0

    urgency_hits = [w for w in EMAIL_URGENCY_WORDS if w in text_lower]
    if urgency_hits:
        email_score += 15
        label = "तत्काल कार्रवाई का दबाव" if lang == "hi" else "Urgency pressure detected"
        email_findings.append({
            "type": "warning",
            "message": f"{label}: {', '.join(urgency_hits[:3])}",
            "points": 15,
        })

    threat_hits = [w for w in EMAIL_THREAT_WORDS if w in text_lower]
    if threat_hits:
        email_score += 20
        label = "धमकी/चेतावनी भाषा" if lang == "hi" else "Threatening language detected"
        email_findings.append({
            "type": "danger",
            "message": f"{label}: {', '.join(threat_hits[:3])}",
            "points": 20,
        })

    prize_hits = [w for w in EMAIL_PRIZE_WORDS if w in text_lower]
    if prize_hits:
        email_score += 18
        label = "इनाम/लॉटरी संबंधी भाषा" if lang == "hi" else "Prize/lottery language detected"
        email_findings.append({
            "type": "danger",
            "message": f"{label}: {', '.join(prize_hits[:3])}",
            "points": 18,
        })

    greeting_hits = [g for g in EMAIL_GENERIC_GREETINGS if g in text_lower]
    if greeting_hits:
        email_score += 8
        label = "सामान्य अभिवादन (व्यक्तिगत नहीं)" if lang == "hi" else "Generic greeting (not personalized)"
        email_findings.append({
            "type": "warning",
            "message": label,
            "points": 8,
        })

    if text_lower.count("!") >= 3:
        email_score += 5
        msg = "अत्यधिक विस्मयादिबोधक चिह्न (!)" if lang == "hi" else "Excessive exclamation marks"
        email_findings.append({"type": "warning", "message": msg, "points": 5})

    urls = extract_urls_from_text(content)
    url_results = [analyze_url(u, lang) for u in urls]

    if not urls:
        email_score += 0
        msg = "ईमेल में कोई लिंक नहीं मिली" if lang == "hi" else "No links found in email"
        email_findings.append({"type": "safe", "message": msg, "points": 0})
    else:
        msg = f"{len(urls)} लिंक मिली" if lang == "hi" else f"{len(urls)} link(s) found in email"
        email_findings.append({"type": "safe", "message": msg, "points": 0})

        phishing_links = sum(1 for r in url_results if r["is_phishing"])
        if phishing_links > 0:
            bonus = min(phishing_links * 15, 30)
            email_score += bonus
            label = f"{phishing_links} संदिग्ध/फ़िशिंग लिंक" if lang == "hi" else f"{phishing_links} suspicious/phishing link(s)"
            email_findings.append({"type": "danger", "message": label, "points": bonus})

    if url_results:
        max_url_score = max(r["score"] for r in url_results)
        email_score = min(100, max(email_score, int((email_score + max_url_score) / 2)))

    email_score = min(email_score, 100)
    risk_level, verdict, is_phishing = get_verdict(email_score, lang)

    if not email_findings:
        msg = "कोई महत्वपूर्ण ईमेल फ़िशिंग संकेतक नहीं" if lang == "hi" else "No significant email phishing indicators"
        email_findings.append({"type": "safe", "message": msg, "points": 0})

    return {
        "email_score": email_score,
        "risk_percent": email_score,
        "risk_level": risk_level,
        "verdict": verdict,
        "is_phishing": is_phishing,
        "email_findings": email_findings,
        "urls_found": len(urls),
        "url_results": url_results,
        "tips": get_tips(lang),
    }


def check_ssl_url(url: str, lang: str = "en") -> dict:
    """Dedicated SSL/TLS certificate check for a URL."""
    if not url or not url.strip():
        msg = "Please enter a valid URL" if lang == "en" else "कृपया मान्य URL दर्ज करें"
        return {
            "url": url,
            "domain": "",
            "ssl_valid": False,
            "verdict": "Invalid" if lang == "en" else "अमान्य",
            "message": msg,
            "details": [],
        }

    normalized = normalize_url(url)
    domain = extract_domain(url)

    if not domain:
        msg = "Could not extract domain from URL" if lang == "en" else "URL से डोमेन नहीं मिला"
        return {
            "url": normalized,
            "domain": "",
            "ssl_valid": False,
            "verdict": "Invalid" if lang == "en" else "अमान्य",
            "message": msg,
            "details": [],
        }

    if is_ip_address(domain):
        msg = "SSL check requires a domain name, not an IP address" if lang == "en" else "SSL जाँच के लिए IP नहीं, डोमेन चाहिए"
        return {
            "url": normalized,
            "domain": domain,
            "ssl_valid": False,
            "verdict": "Not Supported" if lang == "en" else "समर्थित नहीं",
            "message": msg,
            "details": [{"type": "warning", "message": msg}],
        }

    has_ssl, ssl_msg = check_https(domain)
    details = []

    if has_ssl:
        details.append({"type": "safe", "message": ssl_msg})
        details.append({
            "type": "safe",
            "message": f"HTTPS port 443 is open on {domain}" if lang == "en" else f"{domain} पर HTTPS पोर्ट 443 खुला है",
        })
        verdict = "SSL Valid" if lang == "en" else "SSL मान्य"
    else:
        details.append({"type": "danger", "message": ssl_msg})
        details.append({
            "type": "warning",
            "message": "Site may not be safe for entering passwords" if lang == "en" else "पासवर्ड दर्ज करना सुरक्षित नहीं हो सकता",
        })
        verdict = "SSL Invalid" if lang == "en" else "SSL अमान्य"

    parsed = urlparse(normalized)
    if parsed.scheme == "http":
        details.append({
            "type": "warning",
            "message": "URL uses HTTP — data is not encrypted in transit" if lang == "en" else "URL HTTP उपयोग करता है — डेटा एन्क्रिप्टेड नहीं",
        })

    return {
        "url": normalized,
        "domain": domain,
        "ssl_valid": has_ssl,
        "verdict": verdict,
        "message": ssl_msg,
        "details": details,
        "tips": get_tips(lang),
    }
