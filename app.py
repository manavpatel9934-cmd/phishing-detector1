"""
PhishGuard - Phishing Detection Web Application
Cyber Security URL Scanner built with Python Flask
"""

from flask import Flask, render_template, request, jsonify
from detector import analyze_url, analyze_email, check_ssl_url

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False


def get_lang() -> str:
    data = request.get_json(silent=True) or {}
    lang = data.get("lang") or request.args.get("lang", "en")
    return "hi" if lang == "hi" else "en"


@app.route("/")
def index():
    """Home page with URL scanner."""
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def scan_url():
    """API endpoint to scan a URL for phishing indicators."""
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()
    lang = data.get("lang", "en")
    ssl_only = data.get("ssl_only", False)

    if not url:
        msg = "URL आवश्यक है" if lang == "hi" else "URL is required"
        return jsonify({"error": msg}), 400

    if ssl_only:
        return jsonify(check_ssl_url(url, lang))

    result = analyze_url(url, lang)
    return jsonify(result)


@app.route("/api/batch-scan", methods=["POST"])
def batch_scan():
    """Scan multiple URLs at once."""
    data = request.get_json(silent=True) or {}
    urls = data.get("urls", [])
    lang = data.get("lang", "en")

    if not urls or not isinstance(urls, list):
        msg = "URLs की सूची आवश्यक है" if lang == "hi" else "URLs list is required"
        return jsonify({"error": msg}), 400

    results = [analyze_url(u.strip(), lang) for u in urls if u.strip()]
    return jsonify({"results": results, "total": len(results)})


@app.route("/api/ssl-check", methods=["POST"])
def ssl_check():
    """Check SSL/TLS certificate for a URL."""
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()
    lang = data.get("lang", "en")

    if not url:
        msg = "URL is required" if lang == "en" else "URL आवश्यक है"
        return jsonify({"error": msg}), 400

    result = check_ssl_url(url, lang)
    return jsonify(result)


@app.route("/api/email-scan", methods=["POST"])
def email_scan():
    """Analyze email content for phishing indicators."""
    data = request.get_json(silent=True) or {}
    content = data.get("content", "").strip()
    lang = data.get("lang", "en")

    if not content:
        msg = "ईमेल सामग्री आवश्यक है" if lang == "hi" else "Email content is required"
        return jsonify({"error": msg}), 400

    result = analyze_email(content, lang)
    if "error" in result:
        return jsonify(result), 400
    return jsonify(result)


@app.route("/about")
def about():
    """About page explaining how detection works."""
    return render_template("about.html")


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
