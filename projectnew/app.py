from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import numpy as np
import requests
import whois
import ipaddress
import math
import re
from datetime import datetime
from urllib.parse import urlparse, parse_qs
import tldextract
import os
import diskcache as dc
from bs4 import BeautifulSoup

# =========================
# INIT
# =========================
app = Flask(__name__)
CORS(app)

cache = dc.Cache('./cache')

model  = joblib.load('phishing_model.pkl')
scaler = joblib.load('scaler.pkl')

# =========================
# LEGIT DOMAIN LIST
# =========================
LEGIT_DOMAINS_FILE = os.path.join(os.path.dirname(__file__), 'dataset', 'legit_domains.txt')

def load_legit_domains(filepath):
    try:
        with open(filepath, 'r') as f:
            return set(
                line.strip().lower().replace('https://', '').replace('http://', '')
                for line in f if line.strip()
            )
    except:
        return set()

LEGIT_DOMAINS = load_legit_domains(LEGIT_DOMAINS_FILE)

def is_legit_domain(domain):
    return domain.lower() in LEGIT_DOMAINS

# =========================
# CONSTANTS
# =========================
HIGH_RISK_TLDS = [
    'xyz','top','club','site','online','rest','icu','work','click','fit','gq','tk','ml','cf','ga',
    'men','loan','download','stream','party','cam','win','bid','review','trade','accountant','science',
    'date','faith','racing','zip','cricket','host','press','space','pw','buzz','mom','bar','uno',
    'kim','country','support','webcam','rocks','info','biz','pro','link','pics','help','ooo',
    'asia','today','live','lol','surf','fun','run','cyou','monster','store'
]

BRAND_REAL_DOMAINS = {
    'tng'    : {'tngdigital.com.my', 'touchngo.com.my', 'tng.com.my'},
    'maybank': {'maybank2u.com.my', 'maybank.com', 'etiqa.com.my'},
    'cimb'   : {'cimbclicks.com.my', 'cimb.com', 'cimbbank.com'},
}




# Trusted government / institutional TLD patterns — always pass to ML
# but never override as phishing via hard rules
TRUSTED_TLDS = {
    # Malaysian government
    'gov.my', 'edu.my', 'mil.my', 'police.gov.my',
    # International government
    'gov', 'gov.uk', 'gov.au', 'gov.sg', 'gov.bn',
    'ac.uk', 'edu', 'edu.sg', 'edu.au',
    # Other trusted institutions
    'parliament.uk', 'europa.eu',
}

def is_trusted_tld(url: str) -> bool:
    """Returns True if the URL belongs to a trusted government/edu TLD."""
    try:
        ext    = tldextract.extract(url)
        suffix = ext.suffix.lower()
        return suffix in TRUSTED_TLDS
    except:
        return False

# Free hosting platforms commonly abused for phishing
FREE_HOSTING_PLATFORMS = {
    'herokuapp.com', 'vercel.app', 'netlify.app', 'pages.dev',
    'github.io', 'gitlab.io', 'web.app', 'firebaseapp.com',
    'glitch.me', 'repl.co', 'replit.dev', 'onrender.com',
    'pythonanywhere.com', 'surge.sh', 'tiiny.site', 'carrd.co',
    'weebly.com', 'wixsite.com', 'blogspot.com', 'wordpress.com',
    'webflow.io', 'bubbleapps.io', 'softr.app', 'notion.site',
    '000webhostapp.com', 'infinityfreeapp.com', 'epizy.com',
}

# Suspicious Malay/Indonesian keywords common in local phishing lures
SUSPICIOUS_LURE_KEYWORDS = [
    'jawatan', 'percuma', 'kerja', 'pekerjaan', 'mohon', 'permohonan',
    'bantuan', 'bsh', 'sumbangan', 'pendaftaran', 'daftar', 'semak',
    'status', 'kemaskini', 'wang', 'tunai', 'rebat', 'baucar', 'voucher',
    'hadiah', 'menang', 'lucky', 'lucky-draw', 'claim', 'tuntut',
    'free', 'percuma', 'bonus', 'reward', 'giveaway',
    'login', 'verify', 'verifikasi', 'pengesahan', 'secure', 'update',
    'account', 'akaun', 'password', 'kata-laluan',
]

def check_free_hosting_abuse(url: str, hostname: str) -> tuple[bool, str]:
    """
    Flags URLs hosted on free platforms that also contain suspicious lure keywords.
    Logic: free_hosting_platform AND (lure_keyword OR random_hash_subdomain)
    """
    try:
        ext        = tldextract.extract(url)
        registered = f"{ext.domain}.{ext.suffix}".lower()
        subdomain  = ext.subdomain.lower()
        url_lower  = url.lower()

        if registered not in FREE_HOSTING_PLATFORMS:
            return False, ""

        # Check 1: suspicious lure keyword anywhere in URL
        for kw in SUSPICIOUS_LURE_KEYWORDS:
            if kw in url_lower:
                return True, f"free hosting ({registered}) + lure keyword \"{kw}\""

        # Check 2: subdomain contains a random hash-like string (8+ hex chars)
        # e.g. 6b7facafc15e in jawatan-percuma-6b7facafc15e.herokuapp.com
        import re
        if re.search(r'[0-9a-f]{8,}', subdomain):
            return True, f"free hosting ({registered}) + random hash in subdomain"

        # Check 3: subdomain is unusually long (>30 chars) — obfuscation
        if len(subdomain) > 30:
            return True, f"free hosting ({registered}) + long subdomain ({len(subdomain)} chars)"

    except:
        pass
    return False, ""

# Global brands — keyword → set of real registered domains
GLOBAL_BRANDS = {
    'amazon'    : {'amazon.com','amazon.co.uk','amazon.com.my','amazon.de','amazon.fr','amazon.ca'},
    'paypal'    : {'paypal.com','paypal.me'},
    'apple'     : {'apple.com','icloud.com'},
    'google'    : {'google.com','google.com.my','accounts.google.com'},
    'facebook'  : {'facebook.com','fb.com','meta.com'},
    'netflix'   : {'netflix.com'},
    'microsoft' : {'microsoft.com','live.com','outlook.com','office.com','microsoftonline.com'},
    'dhl'       : {'dhl.com','dhl.com.my'},
    'poslaju'   : {'pos.com.my','poslaju.com.my'},
    'shopee'    : {'shopee.com.my','shopee.com'},
    'lazada'    : {'lazada.com.my','lazada.com'},
    'grab'      : {'grab.com','grabpay.com'},
    'boost'     : {'myboost.com.my'},
    'tng'       : {'tngdigital.com.my','touchngo.com.my'},
    'maybank'   : {'maybank2u.com.my','maybank.com'},
    'cimb'      : {'cimbclicks.com.my','cimb.com'},
    'bankislam' : {'bankislam.com.my'},
    'rhbbank'   : {'rhbgroup.com','rhbbank.com.my'},
}

def check_brand_spoofing(url: str, hostname: str) -> tuple[bool, str]:
    """
    Returns (is_spoof, brand_name) if a known brand keyword appears in the
    URL but the registered domain is NOT the brand's real domain.
    Catches cases like: amazon-ish.vercel.app, paypal.support-login.com
    """
    try:
        ext        = tldextract.extract(url)
        registered = f"{ext.domain}.{ext.suffix}".lower()
        url_lower  = url.lower()
        for brand, real_domains in GLOBAL_BRANDS.items():
            if brand in url_lower:
                if not any(registered == d or registered.endswith('.' + d)
                           for d in real_domains):
                    return True, brand
    except:
        pass
    return False, ""

BRAND_KEYWORDS = {
    'touchngo': 'tng', 'tng': 'tng', 'tngdigital': 'tng',
    'maybank': 'maybank', 'maybank2u': 'maybank', 'm2u': 'maybank',
    'cimb': 'cimb', 'cimbclicks': 'cimb',
}

FEATURES_40 = [
    'url_length','n_slash','n_questionmark','n_equal','n_at',
    'n_and','n_exclamation','n_asterisk','n_hastag','n_percent',
    'dots_per_length','hyphens_per_length','is_long_url',
    'has_many_dots','has_ssl','is_cloudflare_protected',
    'special_char_density','suspicious_tld_risk','has_redirects',
    'risk_score','url_complexity',
    'url_entropy','digit_to_alpha_ratio','slash_per_length',
    'query_param_count','url_token_count','homograph_risk','padding_char_ratio',
    'has_iframe','right_click_disabled','has_popup_window',
    'has_favicon_mismatch','has_external_form_action',
    'meta_refresh_redirect','obfuscated_js_score',
    'external_link_ratio','html_form_count',
    'brand_tng_mismatch','brand_maybank_mismatch','brand_cimb_mismatch',
]

# =========================
# CACHE
# =========================
def cache_analysis_results(url, data):    cache[url] = data
def get_cached_analysis_results(url):     return cache.get(url)
def cache_virustotal_results(url, data):  cache[f"vt_{url}"] = data
def get_cached_virustotal_results(url):   return cache.get(f"vt_{url}")

# =========================
# HELPERS
# =========================
def get_redirection_count(url):
    count = 0
    try:
        for _ in range(5):
            r = requests.head(url, allow_redirects=False, timeout=3)
            if 300 <= r.status_code < 400:
                url = r.headers.get('Location', url)
                count += 1
            else:
                break
    except:
        pass
    return count

def is_using_cloudflare(url):
    try:
        r = requests.head(url, timeout=3)
        h = r.headers
        return int('cloudflare' in h.get('Server','').lower() or 'CF-RAY' in h)
    except:
        return 0

def get_domain_age(domain):
    try:
        info = whois.whois(domain)
        creation = info.creation_date
        if isinstance(creation, list): creation = creation[0]
        return (datetime.now() - creation).days
    except:
        return None

def is_ip_address(url):
    try:
        netloc = urlparse(url).netloc.split(':')[0]
        ipaddress.ip_address(netloc)
        return True
    except:
        return False

def _shannon_entropy(text):
    if not text: return 0.0
    freq = {}
    for ch in text: freq[ch] = freq.get(ch, 0) + 1
    total = len(text)
    return -sum((c/total)*math.log2(c/total) for c in freq.values())

def _brand_mismatches(hostname, url_lower):
    flags = {'tng': 0, 'maybank': 0, 'cimb': 0}
    hn = hostname.lower().replace('-','').replace('.','')
    for keyword, brand in BRAND_KEYWORDS.items():
        if keyword in hn or keyword in url_lower:
            if not any(hostname.lower().endswith(d) for d in BRAND_REAL_DOMAINS[brand]):
                flags[brand] = 1
    return flags

def _fetch_html(url, timeout=6):
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120'}
    try:
        resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True, verify=False)
        return resp.text, resp.url, len(resp.history)
    except:
        return '', url, 0

# =========================
# FEATURE EXTRACTION  — synchronized with notebook FEATURES_40
# =========================
def extract_features(url):
    parsed    = urlparse(url)
    hostname  = parsed.hostname or ''
    tld_ext   = tldextract.extract(url)
    url_lower = url.lower()

    # Group A
    url_length     = len(url)
    n_dots         = url.count('.')
    n_hypens       = url.count('-')
    n_slash        = url.count('/')
    n_questionmark = url.count('?')
    n_equal        = url.count('=')
    n_at           = url.count('@')
    n_and          = url.count('&')
    n_exclamation  = url.count('!')
    n_asterisk     = url.count('*')
    n_hastag       = url.count('#')
    n_percent      = url.count('%')
    n_underline    = url.count('_')
    n_space        = url.count(' ') + url.count('%20')
    n_tilde        = url.count('~')
    n_plus         = url.count('+')
    n_dollar       = url.count('$')
    n_redirection  = url.count('//') - 1

    # Group B
    dots_per_length        = n_dots   / (url_length + 1)
    hyphens_per_length     = n_hypens / (url_length + 1)
    is_long_url            = 1 if url_length > 75 else 0
    has_many_dots          = 1 if n_dots > 4 else 0
    has_ssl                = 1 if url.startswith('https') else 0
    is_cloudflare_protected= is_using_cloudflare(url)
    redirections           = get_redirection_count(url)
    has_redirects          = 1 if (n_redirection > 0 or redirections > 0) else 0
    suspicious_tld_risk    = 2 if tld_ext.suffix in HIGH_RISK_TLDS else 0
    special_char_density   = (n_hypens+n_underline+n_at+n_equal+n_dollar+n_percent+n_hastag) / (url_length+1)
    risk_score = (is_long_url*2.0 + has_many_dots*1.5 + special_char_density*10.0 +
                  has_redirects*3.0 - has_ssl*2.0 - is_cloudflare_protected*2.0)
    url_complexity = (url_length*0.01 + n_dots*0.50 + n_hypens*0.30 +
                      n_questionmark*0.70 + n_equal*0.70 + n_at*2.00)

    # Group C
    url_entropy          = _shannon_entropy(url)
    digit_to_alpha_ratio = sum(c.isdigit() for c in url) / (url_length + 1)
    slash_per_length     = n_slash / (url_length + 1)
    query_param_count    = len(parse_qs(parsed.query))
    url_token_count      = n_slash + n_dots + n_equal + n_questionmark
    homograph_risk       = n_at * 3 + n_percent * 0.5
    padding_char_ratio   = (n_tilde + n_plus + n_space) / (url_length + 1)

    # Group D
    html_str, _, redirect_count = _fetch_html(url)
    has_redirects = max(has_redirects, int(redirect_count > 0))
    has_iframe=right_click_disabled=has_popup_window=has_favicon_mismatch=0
    has_external_form_action=meta_refresh_redirect=obfuscated_js_score=html_form_count=0
    external_link_ratio = 0.0

    if html_str:
        soup        = BeautifulSoup(html_str, 'html.parser')
        base_domain = hostname.lower()
        has_iframe  = int(len(soup.find_all('iframe')) > 0)
        if 'oncontextmenu' in html_str.lower() and 'return false' in html_str.lower():
            right_click_disabled = 1
        if re.search(r'window\.open\s*\(', html_str, re.IGNORECASE):
            has_popup_window = 1
        for fav in soup.find_all('link', rel=lambda r: r and 'icon' in ' '.join(r).lower()):
            href = fav.get('href','')
            if href.startswith('http') and base_domain not in href.lower():
                has_favicon_mismatch = 1; break
        forms = soup.find_all('form')
        html_form_count = len(forms)
        for form in forms:
            action = form.get('action','')
            if action.startswith('http') and base_domain not in action.lower():
                has_external_form_action = 1; break
        if soup.find('meta', attrs={'http-equiv': re.compile('refresh', re.I)}):
            meta_refresh_redirect = 1
        js_text = ' '.join(s.get_text() for s in soup.find_all('script'))
        obf     = js_text.lower().count('eval(')+js_text.lower().count('atob(')+js_text.lower().count('unescape(')
        obfuscated_js_score = min(obf, 2)
        all_links = soup.find_all('a', href=True)
        if all_links:
            ext_count = sum(
                1 for a in all_links
                if a['href'].startswith('http') and base_domain not in a['href'].lower()
            )
            raw_ratio = ext_count / len(all_links)
            # Cap at 0.55 — gov/edu sites link heavily to other portals;
            # training data treats >0.6 as suspicious so we avoid false positives
            external_link_ratio = round(min(raw_ratio, 0.55), 4)

    # Group E
    brand_flags            = _brand_mismatches(hostname, url_lower)
    brand_tng_mismatch     = brand_flags['tng']
    brand_maybank_mismatch = brand_flags['maybank']
    brand_cimb_mismatch    = brand_flags['cimb']

    feature_vector = [
        url_length, n_slash, n_questionmark, n_equal, n_at,
        n_and, n_exclamation, n_asterisk, n_hastag, n_percent,
        dots_per_length, hyphens_per_length, is_long_url,
        has_many_dots, has_ssl, is_cloudflare_protected,
        special_char_density, suspicious_tld_risk, has_redirects,
        risk_score, url_complexity,
        url_entropy, digit_to_alpha_ratio, slash_per_length,
        query_param_count, url_token_count, homograph_risk, padding_char_ratio,
        has_iframe, right_click_disabled, has_popup_window,
        has_favicon_mismatch, has_external_form_action,
        meta_refresh_redirect, obfuscated_js_score,
        external_link_ratio, html_form_count,
        brand_tng_mismatch, brand_maybank_mismatch, brand_cimb_mismatch,
    ]
    assert len(feature_vector) == 40
    domain_name = f"{tld_ext.domain}.{tld_ext.suffix}"
    return feature_vector, domain_name

# =========================
# MAIN API
# =========================
@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        data = request.json
        url  = data.get('url')
        if not url:
            return jsonify({'error': 'No URL'}), 400
        if not url.startswith(('http://','https://')):
            url = 'http://' + url

        cached = get_cached_analysis_results(url)
        if cached:
            return jsonify(cached)

        # ── Hard rule 0: trusted government/edu TLD — skip all phishing hard rules ──
        if is_trusted_tld(url):
            features, domain = extract_features(url)
            scaled     = scaler.transform([features])
            prediction = model.predict(scaled)[0]
            probs      = model.predict_proba(scaled)[0]
            confidence = float(np.max(probs))
            result = {
                'analysis': {
                    'url'         : url,
                    'domain'      : urlparse(url).hostname or '',
                    'confidence'  : confidence,
                    'prediction'  : int(prediction),
                    'verdict'     : 'Legitimate' if prediction == 0 else 'Suspicious',
                    'risk_factors': [],
                }
            }
            cache_analysis_results(url, result)
            return jsonify(result)

        # ── Hard rule 1: free hosting platform abuse ─────────────────────────────
        parsed_host = urlparse(url).hostname or ''
        is_hosting_abuse, hosting_reason = check_free_hosting_abuse(url, parsed_host)
        if is_hosting_abuse:
            result = {
                'analysis': {
                    'url'         : url,
                    'domain'      : parsed_host,
                    'confidence'  : 0.97,
                    'prediction'  : 1,
                    'verdict'     : 'Phishing',
                    'risk_factors': [f'Suspicious free hosting abuse: {hosting_reason}'],
                }
            }
            cache_analysis_results(url, result)
            return jsonify(result)

        # ── Hard rule 2: brand spoofing check (catches amazon-ish.vercel.app etc.) ──
        is_spoof, spoofed_brand = check_brand_spoofing(url, parsed_host)
        if is_spoof:
            result = {
                'analysis': {
                    'url'         : url,
                    'domain'      : parsed_host,
                    'confidence'  : 0.99,
                    'prediction'  : 1,
                    'verdict'     : 'Phishing',
                    'risk_factors': [f'Brand spoofing detected: "{spoofed_brand}" in URL but not on official domain'],
                }
            }
            cache_analysis_results(url, result)
            return jsonify(result)

        features, domain = extract_features(url)
        scaled     = scaler.transform([features])
        prediction = model.predict(scaled)[0]
        probs      = model.predict_proba(scaled)[0]
        confidence = float(np.max(probs))

        if is_legit_domain(domain):
            confidence = min(confidence + 0.5, 1.0)

        if confidence < 0.6:       verdict = 'Unknown'
        elif prediction == 1:      verdict = 'Phishing'
        else:                      verdict = 'Legitimate'

        feat = dict(zip(FEATURES_40, features))
        risk_factors = []
        if is_ip_address(url):                         risk_factors.append('Uses IP address')
        if feat['is_long_url']:                         risk_factors.append('Long URL')
        if not feat['has_ssl']:                         risk_factors.append('No HTTPS')
        if feat['has_redirects']:                       risk_factors.append('Redirects detected')
        if feat['suspicious_tld_risk'] > 0:             risk_factors.append('Suspicious TLD')
        if feat['has_iframe']:                          risk_factors.append('Hidden iframe detected')
        if feat['right_click_disabled']:                risk_factors.append('Right-click disabled')
        if feat['has_external_form_action']:            risk_factors.append('External form action')
        if feat['obfuscated_js_score'] >= 2:           risk_factors.append('Obfuscated JavaScript')
        if feat['brand_tng_mismatch']:                  risk_factors.append("Touch 'n Go brand mismatch")
        if feat['brand_maybank_mismatch']:              risk_factors.append('Maybank brand mismatch')
        if feat['brand_cimb_mismatch']:                 risk_factors.append('CIMB brand mismatch')

        result = {
            'analysis': {
                'url'         : url,
                'domain'      : domain,
                'confidence'  : confidence,
                'prediction'  : int(prediction),
                'verdict'     : verdict,
                'risk_factors': risk_factors,
            }
        }
        cache_analysis_results(url, result)
        return jsonify(result)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# =========================
# RUN
# =========================
if __name__ == '__main__':
    app.run(debug=True)
