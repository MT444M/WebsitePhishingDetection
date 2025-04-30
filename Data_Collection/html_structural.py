# html_structural.py
# HTML Content & Structural Crawling for StealthPhisher2025 pipeline

import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin


def fetch_html(url: str, timeout: int = 5) -> tuple:
    """
    Fetches the page HTML. Returns (html_text, is_unreachable_flag).
    """
    try:
        resp = requests.get(url, timeout=timeout)
        resp.raise_for_status()
        return resp.text, 0
    except Exception:
        return "", 1


def parse_html_features(html: str, url: str) -> dict:
    """
    Parses HTML to extract structural and content features.
    Requires raw HTML and original URL for domain comparisons.
    """
    lines = html.splitlines()
    line_count = len(lines)
    longest_line = max((len(l) for l in lines), default=0)

    soup = BeautifulSoup(html, 'lxml')
    parsed = urlparse(url)
    base_netloc = parsed.netloc

    # Presence flags
    has_title   = 1 if soup.title and soup.title.string and soup.title.string.strip() else 0
    has_desc    = 1 if soup.find('meta', attrs={'name': 'description'}) else 0
    has_fav     = 1 if soup.find('link', rel=lambda x: x and 'icon' in x.lower()) else 0
    has_robots  = 1 if soup.find('meta', attrs={'name': 'robots', 'content': lambda c: c and 'noindex' in c.lower()}) else 0

    # Forms and fields
    forms = soup.find_all('form')
    form_external = 0
    for f in forms:
        action = f.get('action', '').strip()
        if action:
            action_url = urljoin(url, action)
            if urlparse(action_url).netloc != base_netloc:
                form_external = 1
                break
    has_submit  = 1 if soup.find('input', attrs={'type': 'submit'}) or soup.find('button', attrs={'type': 'submit'}) else 0
    has_hidden  = 1 if soup.find('input', attrs={'type': 'hidden'}) else 0
    has_password= 1 if soup.find('input', attrs={'type': 'password'}) else 0

    # Iframes & popups
    iframes = soup.find_all('iframe')
    has_iframe  = 1 if iframes else 0
    scripts = soup.find_all('script')
    popup_scripts = [s for s in scripts if s.string and ('alert(' in s.string or 'window.open' in s.string)]
    has_popup   = 1 if popup_scripts else 0

    # Resource counts
    cnt_images   = len(soup.find_all('img'))
    cnt_css      = len(soup.find_all('link', rel='stylesheet'))
    cnt_js       = len(soup.find_all('script', src=True))

    # Link counts
    cnt_self = cnt_external = cnt_empty = 0
    for a in soup.find_all('a', href=True):
        href = a['href'].strip()
        if not href or href == '#':
            cnt_empty += 1
        else:
            tgt = urlparse(urljoin(url, href)).netloc
            if tgt == base_netloc:
                cnt_self += 1
            else:
                cnt_external += 1

    cnt_popup = len(popup_scripts)
    cnt_iframe= len(iframes)

    return {
        "LineOfCode": line_count,
        "LongestLineLength": longest_line,
        "HasTitle": has_title,
        "HasDescription": has_desc,
        "HasFavicon": has_fav,
        "HasRobotsBlocked": has_robots,
        "IsFormSubmitExternal": form_external,
        "HasSubmitButton": has_submit,
        "HasHiddenFields": has_hidden,
        "HasPasswordFields": has_password,
        "HasIFrame": has_iframe,
        "HasPopup": has_popup,
        "CntImages": cnt_images,
        "CntFilesCSS": cnt_css,
        "CntFilesJS": cnt_js,
        "CntSelfHRef": cnt_self,
        "CntEmptyRef": cnt_empty,
        "CntExternalRef": cnt_external,
        "CntPopup": cnt_popup,
        "CntIFrame": cnt_iframe
    }


def crawl_html(url: str, timeout: int = 5) -> dict:
    """
    High-level function: fetch HTML, flag unreachable, then parse all features.
    """
    html, unreachable = fetch_html(url, timeout)
    features = parse_html_features(html, url) if not unreachable else {}
    features["IsUnreachable"] = unreachable
    return features


if __name__ == "__main__":
    test_url = "http://example.com"
    feats = crawl_html(test_url)
    print("HTML Structural Features:", feats)
