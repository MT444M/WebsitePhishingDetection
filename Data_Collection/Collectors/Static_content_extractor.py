"""
File: content_extractor.py
Description: This module implements web crawling and
content extraction functionalities.
It comprises two sets of functions:
  (A) Static extraction using Requests and BeautifulSoup for features such as:
      - Basic URL structure: URL, LengthOfURL, HavingPath, PathLength, HavingQuery, HavingFragment, HavingAnchor
      - HTML source structural metrics: LineOfCode, LongestLineLength
      - HTML metadata & tag presence: HasTitle, HasFavicon, HasDescription, HasRobotsBlocked
      - Embedded resource counts: CntImages, CntFilesCSS, CntFilesJS, CntSelfHRef, CntEmptyRef, CntExternalRef, CntPopup, CntIFrame
      - Additional content keys: UniqueFeatureCnt, HasBankingKey, HasPaymentKey, HasCryptoKey, HasCopyrightInfoKey
"""

import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from html import unescape
import re


# -------------------------------
# (A) STATIC CONTENT EXTRACTION
# -------------------------------

def extract_url_structure(url):
    """
    Extracts basic URL structure features.
    
    Returns a dictionary with:
      - URL: the original URL.
      - LengthOfURL: total number of characters.
      - HavingPath: 1 if the URL contains a path, else 0.
      - PathLength: number of characters in the path.
      - HavingQuery: 1 if query string exists.
      - HavingFragment: 1 if fragment exists.
      - HavingAnchor: Here we equate this to HavingFragment.
    """
    features = {}
    features['URL'] = url
    features['LengthOfURL'] = len(url)
    
    parsed = urlparse(url)
    features['HavingPath'] = int(bool(parsed.path and parsed.path != "/"))
    features['PathLength'] = len(parsed.path) if parsed.path else 0
    features['HavingQuery'] = int(bool(parsed.query))
    features['HavingFragment'] = int(bool(parsed.fragment))
    # In our context, we treat "anchor" as the existence of a fragment.
    features['HavingAnchor'] = features['HavingFragment']
    
    return features


def extract_html_structure(html):
    """
    From raw HTML text, compute two structural metrics:
      - LineOfCode: Count of lines in the HTML.
      - LongestLineLength: Length of the longest line.
    """
    lines = html.splitlines()
    loc = len(lines)
    longest = max((len(line) for line in lines), default=0)
    return {'LineOfCode': loc, 'LongestLineLength': longest}


def extract_meta_and_tags(html, base_domain=None):
    """
    Parses HTML using BeautifulSoup to extract metadata, tag presence,
    and counts of embedded resources.
    
    Returns a dictionary with the following features:
      - HasTitle, HasFavicon, HasDescription, HasRobotsBlocked.
      - CntImages, CntFilesCSS, CntFilesJS, CntIFrame.
      - For anchor tags:
          * CntSelfHRef (links within the same domain),
          * CntEmptyRef (anchors with empty href or '#' only),
          * CntExternalRef (links to external sites).
      - CntPopup: Count of anchor tags that seemingly trigger pop-ups.
      
      Additional features:
      - UniqueFeatureCnt: Count of unique additional semantic keys found.
      - HasBankingKey: 1 if banking-related keyword is present.
      - HasPaymentKey: 1 if payment-related keyword is present.
      - HasCryptoKey: 1 if cryptocurrency related keyword is present.
      - HasCopyrightInfoKey: 1 if copyright information is present.
    """
    features = {}
    soup = BeautifulSoup(html, 'html.parser')
    
    # HTML metadata & tags
    features['HasTitle'] = int(soup.title is not None)
    features['HasFavicon'] = int(soup.find('link', rel=lambda x: x and 'icon' in x.lower()) is not None)
    features['HasDescription'] = int(soup.find('meta', attrs={'name': 'description'}) is not None)
    
    # Check robots meta tag for directives like 'noindex'
    robots_tag = soup.find('meta', attrs={'name': 'robots'})    
    robots_content = robots_tag.get('content', '') if robots_tag and robots_tag.get('content') else ""
    features['HasRobotsBlocked'] = int('noindex' in robots_content.lower())


    # Embedded resources counts
    features['CntImages'] = len(soup.find_all('img'))
    features['CntFilesCSS'] = len(soup.find_all('link', rel=lambda x: x and 'stylesheet' in x.lower()))
    features['CntFilesJS'] = len(soup.find_all('script', src=True))
    features['CntIFrame'] = len(soup.find_all('iframe'))
    
    # Anchor token counts
    cnt_self = 0
    cnt_external = 0
    cnt_empty = 0
    cnt_popup = 0
    for a in soup.find_all('a'):
        href = a.get('href', '').strip()
        if href in ["", "#"]:
            cnt_empty += 1
        else:
            parsed_href = urlparse(href)
            # Without a netloc, assume it's a relative (self) link.
            if not parsed_href.netloc:
                cnt_self += 1
            elif base_domain and base_domain in parsed_href.netloc:
                cnt_self += 1
            else:
                cnt_external += 1

            # Heuristic: Check for pop-up triggers (e.g., target='_blank' and inline onclick with window.open)
            if a.get('target', '').lower() == '_blank' and a.get('onclick') and 'window.open' in a.get('onclick'):
                cnt_popup += 1

    features['CntSelfHRef'] = cnt_self
    features['CntEmptyRef'] = cnt_empty
    features['CntExternalRef'] = cnt_external
    features['CntPopup'] = cnt_popup

    # -------------------------------------------
    # Additional Content-Based Feature Extraction
    # -------------------------------------------
    # Use the lower-case version of the HTML for keyword matching.
    # Convert HTML entities to their Unicode equivalents
    decoded_html = unescape(html)
    lower_html = decoded_html.lower()
    
    # Keywords lists (customize as needed)
    banking_keywords = ['bank', 'banking', 'financial']
    payment_keywords = ['payment', 'paypal', 'credit card', 'checkout']
    crypto_keywords = ['crypto', 'cryptocurrency', 'bitcoin', 'ethereum', 'blockchain']
    copyright_keywords = ['copyright', '©']
    
    
    features['HasCopyrightInfoKey '] = int(any(k in lower_html for k in copyright_keywords))
    
    features['HasBankingKey'] = int(any(k in lower_html for k in banking_keywords))
    features['HasPaymentKey'] = int(any(k in lower_html for k in payment_keywords))
    features['HasCryptoKey'] = int(any(k in lower_html for k in crypto_keywords))
    features['HasCopyrightInfoKey '] = int(any(k in lower_html for k in copyright_keywords))
    
    # UniqueFeatureCnt: Count how many of the above keys are present.
    features['UniqueFeatureCnt'] = (
        features['HasBankingKey'] +
        features['HasPaymentKey'] +
        features['HasCryptoKey'] +
        features['HasCopyrightInfoKey ']
    )
    
    return features


def extract_static_features(url):
    """
    Aggregates static features by:
      1. Getting URL structure features.
      2. Downloading the HTML via Requests.
      3. Computing HTML structure metrics.
      4. Parsing HTML to extract metadata and resource counts.
      
    Returns a dictionary of all static features, including the 'IsUnreachable' flag.
    """
    features = {}
    # URL-based features
    features.update(extract_url_structure(url))
    
    # Get HTML content
    try:
        response = requests.get(url, timeout=10)
        html = response.text
        features["IsUnreachable"] = 0
    except Exception as e:
        print(f"Error fetching URL {url}: {e}")
        features["IsUnreachable"] = 1
        return features  # Return whatever URL features we have
    
    # HTML structure metrics
    features.update(extract_html_structure(html))
    
    # For anchors counting, base_domain is needed.
    parsed = urlparse(url)
    base_domain = parsed.netloc
    
    # HTML metadata & resource counts + additional keys
    features.update(extract_meta_and_tags(html, base_domain=base_domain))
    
    return features



# Example usage:
if __name__ == "__main__":
    test_url = "https://github.com"
    static_features = extract_static_features(test_url)
    for key, value in static_features.items():
        print(f"{key}: {value}")