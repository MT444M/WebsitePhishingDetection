# social_brand_presence.py
# Social & Brand Presence retrieval for StealthPhisher2025 pipeline

import requests
import tldextract
from urllib.parse import urlparse

# Define standard social media URL patterns (using domain name as handle)
SOCIAL_TEMPLATES = {
    "Facebook": "https://www.facebook.com/{handle}",
    "Twitter": "https://twitter.com/{handle}",
    "LinkedIn": "https://www.linkedin.com/company/{handle}",
    "Instagram": "https://www.instagram.com/{handle}",
    "YouTube": "https://www.youtube.com/{handle}"
}                              


def extract_handle_from_domain(url: str) -> str:
    """
    Extracts a usable handle from the domain, e.g., 'example' from 'example.com'.
    """
    ext = tldextract.extract(url)
    return ext.domain


def get_social_media_pages(url: str, timeout: int = 5) -> dict:
    """
    Checks for existence of standard social media pages by sending HEAD requests.
    Returns a dict of platform -> 1/0.
    """
    handle = extract_handle_from_domain(url)
    results = {}
    for platform, template in SOCIAL_TEMPLATES.items():
        page_url = template.format(handle=handle)
        try:
            resp = requests.head(page_url, allow_redirects=True, timeout=timeout)
            exists = 1 if resp.status_code == 200 else 0
        except Exception:
            exists = 0
        results[f"Has{platform}Page"] = exists
    return results


# ------------ Twitter API (v2) example ------------
def get_twitter_profile_info(handle: str, bearer_token: str, timeout: int = 5) -> dict:
    """
    Fetches Twitter profile data using Twitter API v2.
    Returns existence flag, followers count, and tweet count (public metrics).
    Requires a valid Bearer token.
    """
    url = f"https://api.twitter.com/2/users/by/username/{handle}?user.fields=public_metrics"
    headers = {"Authorization": f"Bearer {bearer_token}"}
    try:
        resp = requests.get(url, headers=headers, timeout=timeout)
        data = resp.json().get('data', {})
        exists = 1 if resp.status_code == 200 and data else 0
        metrics = data.get('public_metrics', {}) if exists else {}
    except Exception:
        exists = 0
        metrics = {}

    return {
        "TwitterExists": exists,
        "TwitterFollowers": metrics.get('followers_count'),
        "TwitterTweetCount": metrics.get('tweet_count')
    }


# ------------ LinkedIn API stub ------------
def get_linkedin_company_info(handle: str, access_token: str) -> dict:
    """
    Placeholder for LinkedIn Company API lookup.
    Requires OAuth2 access token and correct permissions.
    Returns existence flag and basic company info.
    """
    # LinkedIn uses URNs; actual implementation requires OAuth2 and the Companies API.
    # Here we check page existence as fallback.
    page_url = SOCIAL_TEMPLATES['LinkedIn'].format(handle=handle)
    try:
        resp = requests.head(page_url, allow_redirects=True, timeout=5)
        exists = 1 if resp.status_code == 200 else 0
    except Exception:
        exists = 0

    return {
        "LinkedInExists": exists,
        # Additional fields from real API could include: 'EmployeeCount', 'Industry', etc.
    }


if __name__ == "__main__":
    test_url = "http://example.com"
    soc = get_social_media_pages(test_url)
    print("Social Pages:", soc)

    handle = extract_handle_from_domain(test_url)
    tw = get_twitter_profile_info(handle, bearer_token="YOUR_BEARER_TOKEN")
    print("Twitter Info:", tw)

    li = get_linkedin_company_info(handle, access_token="YOUR_ACCESS_TOKEN")
    print("LinkedIn Info:", li)
