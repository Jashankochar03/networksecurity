import re, socket, ssl, whois, requests, tldextract
from urllib.parse import urlparse
from datetime import datetime
from bs4 import BeautifulSoup
import csv

shorteners = ["bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "bit.do", "shorte.st", "cutt.ly", "is.gd", "buff.ly"]

def extract_features(url):
    features = {}
    parsed = urlparse(url)
    domain = parsed.netloc
    ext = tldextract.extract(url)
    full_domain = f"{ext.domain}.{ext.suffix}"

    # 1. having_IP_Address
    features["having_IP_Address"] = 1 if re.match(r'\d{1,3}(\.\d{1,3}){3}', domain) else 0

    # 2. URL_Length
    length = len(url)
    if length < 54:
        features["URL_Length"] = 1
    elif length <= 75:
        features["URL_Length"] = 0
    else:
        features["URL_Length"] = -1


    # 3. Shortening_Service
    features["Shortining_Service"] = -1 if any(s in domain for s in shorteners) else 1

    # 4. having_At_Symbol
    features["having_At_Symbol"] = -1 if "@" in url else 1

    # 5. double_slash_redirecting
    features["double_slash_redirecting"] = 1 if url.count("//") > 1 else 0

    # 6. Prefix_Suffix
    features["Prefix_Suffix"] = 1 if "-" in domain else 0

    # 7. having_Sub_Domain
    features["having_Sub_Domain"] = domain.count('.') - 1

    # 8. SSLfinal_State
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(3)
            s.connect((domain, 443))
        features["SSLfinal_State"] = 1
    except:
        features["SSLfinal_State"] = 0

    # 9. Domain_registeration_length & 24. age_of_domain
    try:
        w = whois.whois(domain)
        if w.creation_date and w.expiration_date:
            if isinstance(w.creation_date, list):
                w.creation_date = w.creation_date[0]
            if isinstance(w.expiration_date, list):
                w.expiration_date = w.expiration_date[0]
            delta = w.expiration_date - w.creation_date
            age = datetime.now() - w.creation_date
            features["Domain_registeration_length"] = 1 if delta.days >= 365 else 0
            features["age_of_domain"] = 1 if age.days >= 180 else 0
        else:
            features["Domain_registeration_length"] = 0
            features["age_of_domain"] = 0
    except:
        features["Domain_registeration_length"] = 0
        features["age_of_domain"] = 0

    # 10. Favicon, 11. port, 12. HTTPS_token and all HTML-dependent ones
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        features["Favicon"] = 0
        for link in soup.find_all('link', rel='shortcut icon'):
            if full_domain not in link.get('href', ''):
                features["Favicon"] = 1
        features["port"] = 0 if parsed.port in [80, 443, None] else 1
        features["HTTPS_token"] = 1 if "https" in domain else 0

        # 13. Request_URL
        imgs = soup.find_all('img')
        total, externals = len(imgs), 0
        for tag in imgs:
            if full_domain not in tag.get('src', ''):
                externals += 1
        features["Request_URL"] = 1 if total and externals / total >= 0.5 else 0

        # 14. URL_of_Anchor
        anchors = soup.find_all('a')
        total, externals = len(anchors), 0
        for tag in anchors:
            href = tag.get('href', '')
            if href.startswith('#') or full_domain in href or not href:
                continue
            externals += 1
        features["URL_of_Anchor"] = 1 if total and externals / total >= 0.5 else 0

        # 15. Links_in_tags
        tags = soup.find_all(['meta', 'script', 'link'])
        total, externals = len(tags), 0
        for tag in tags:
            content = str(tag)
            if full_domain not in content:
                externals += 1
        features["Links_in_tags"] = 1 if total and externals / total >= 0.5 else 0

        # 16. SFH (Server Form Handler)
        forms = soup.find_all('form')
        suspicious = 0
        for f in forms:
            action = f.get('action', '')
            if action in ["", "about:blank"] or full_domain not in action:
                suspicious += 1
        features["SFH"] = 1 if suspicious else 0

        # 17. Submitting_to_email
        features["Submitting_to_email"] = 1 if 'mailto:' in response.text else 0

        # 18. Abnormal_URL
        try:
            w2 = whois.whois(domain)
            features["Abnormal_URL"] = 0 if w2.domain_name else 1
        except:
            features["Abnormal_URL"] = 1

        # 19. Redirect
        features["Redirect"] = 1 if len(response.history) > 1 else 0

        # 20. on_mouseover
        features["on_mouseover"] = 1 if re.search(r'onmouseover\s*=', response.text, re.I) else 0

        # 21. RightClick
        features["RightClick"] = 1 if re.search(r'event.button ?== ?2', response.text) else 0

        # 22. popUpWidnow
        features["popUpWidnow"] = 1 if re.search(r'alert\s*\(', response.text) else 0

        # 23. Iframe
        features["Iframe"] = 1 if soup.find_all('iframe') else 0

    except:
        for key in ["Favicon","port","HTTPS_token","Request_URL","URL_of_Anchor",
                    "Links_in_tags","SFH","Submitting_to_email","Abnormal_URL",
                    "Redirect","on_mouseover","RightClick","popUpWidnow","Iframe"]:
            features[key] = 0

    # 25. DNSRecord
    try:
        socket.gethostbyname(domain)
        features["DNSRecord"] = 1
    except:
        features["DNSRecord"] = 0

    # 26. web_traffic (approximate)
    try:
        r = requests.get(f"https://www.similarweb.com/website/{full_domain}/", timeout=5)
        features["web_traffic"] = 1 if r.status_code == 200 else 0
    except:
        features["web_traffic"] = 0

    # 27. Page_Rank → skip (deprecated) → set 0
    features["Page_Rank"] = 0

    # 28. Google_Index (approximate using "site:" search)
    try:
        g = requests.get(f"https://www.google.com/search?q=site:{full_domain}", headers={"User-Agent": "Mozilla/5.0"})
        features["Google_Index"] = 1 if "did not match any documents" not in g.text else 0
    except:
        features["Google_Index"] = 0

    # 29. Links_pointing_to_page → set 0 (hard to extract freely)
    features["Links_pointing_to_page"] = 0

    # 30. Statistical_report (check with PhishTank URL format)
    try:
        check_url = f"https://www.phishtank.com/phish_search.php?search={full_domain}&Submit=Search"
        r = requests.get(check_url)
        features["Statistical_report"] = 1 if "Valid phishing site" in r.text else 0
    except:
        features["Statistical_report"] = 0

    return features


import csv

# Your already-written extract_features(url) function should be defined above

def extract_features_from_file(input_file, output_file):
    with open(input_file, 'r') as file:
        urls = [line.strip() for line in file if line.strip()]

    # Define CSV header with 30 feature names
    fieldnames = [
        "having_IP_Address","URL_Length","Shortining_Service","having_At_Symbol",
        "double_slash_redirecting","Prefix_Suffix","having_Sub_Domain","SSLfinal_State",
        "Domain_registeration_length","Favicon","port","HTTPS_token","Request_URL",
        "URL_of_Anchor","Links_in_tags","SFH","Submitting_to_email","Abnormal_URL",
        "Redirect","on_mouseover","RightClick","popUpWidnow","Iframe","age_of_domain",
        "DNSRecord","web_traffic","Page_Rank","Google_Index","Links_pointing_to_page",
        "Statistical_report"
    ]

    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=["URL"] + fieldnames)
        writer.writeheader()

        for url in urls:
            try:
                features = extract_features(url)
                features["URL"] = url
                writer.writerow(features)
            except Exception as e:
                print(f"Error processing {url}: {e}")

# Call the function
extract_features_from_file("urls.txt", "phising_data.csv")
