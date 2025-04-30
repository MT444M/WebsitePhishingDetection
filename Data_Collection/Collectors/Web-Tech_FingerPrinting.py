import requests
from urllib.parse import urlparse
import re
from bs4 import BeautifulSoup


class LightTechDetector:
    def __init__(self, timeout=5):
        self.timeout = timeout
        self.session = requests.Session()

        # Technology signatures from your document and more.
        # Each signature can optionally include a "version_pattern".
        self.signatures = {
            "cms": {
                "wordpress": [
                    {"type": "meta", "pattern": r"wp-content|wp-includes|wordpress", "evidence": "meta tag"},
                    {"type": "header", "name": "x-powered-by", "pattern": r"wordpress", "evidence": "header: x-powered-by"}
                ],
                "drupal": [
                    {"type": "meta", "pattern": r"drupal", "evidence": "meta tag"},
                    {"type": "cookies", "name": "Drupal", "pattern": r".", "evidence": "cookie: Drupal"}
                ],
                "joomla": [
                    {"type": "meta", "pattern": r"joomla", "evidence": "meta tag"},
                    {"type": "script", "pattern": r"joomla", "evidence": "script src or inline script"}
                ],
                "magento": [
                    {"type": "script", "pattern": r"magento", "evidence": "script tag"},
                    {"type": "cookies", "name": "frontend", "pattern": r".", "evidence": "cookie: frontend"}
                ]
            },
            "javascript-framework": {
                "react": [
                    {"type": "script", "pattern": r"react\.js|react-dom", "evidence": "script src"},
                    {"type": "dom", "pattern": r"data-reactroot|__reactContainer", "evidence": "DOM attribute"}
                ],
                "vue": [
                    {"type": "script", "pattern": r"vue\.js", "evidence": "script src"},
                    {"type": "dom", "pattern": r"__vue__", "evidence": "DOM attribute"}
                ],
                "angular": [
                    {"type": "script", "pattern": r"angular\.js", "evidence": "script src"},
                    {"type": "dom", "pattern": r"ng-app|ng-controller", "evidence": "DOM attribute"}
                ],
                "jquery": [
                    {"type": "script", "pattern": r"jquery", "evidence": "script tag"}
                ]
            },
            "web-server": {
                "nginx": [
                    {"type": "header", "name": "server", "pattern": r"nginx", "evidence": "server header"}
                ],
                "apache": [
                    {"type": "header", "name": "server", "pattern": r"apache", "evidence": "server header"}
                ],
                "microsoft-iis": [
                    {"type": "header", "name": "server", "pattern": r"microsoft-iis", "evidence": "server header"}
                ]
            },
            "programming-language": {
                "php": [
                    {"type": "header", "name": "x-powered-by", "pattern": r"php", "evidence": "header x-powered-by"},
                    {"type": "cookies", "name": "PHPSESSID", "pattern": r".", "evidence": "cookie: PHPSESSID"}
                ],
                "python": [
                    {"type": "header", "name": "server", "pattern": r"python|wsgi|gunicorn|django", "evidence": "server header"},
                    {"type": "cookies", "name": "django", "pattern": r".", "evidence": "cookie: django"}
                ],
                "ruby": [
                    {"type": "header", "name": "server", "pattern": r"puma|unicorn|ruby", "evidence": "server header"},
                    {"type": "header", "name": "x-powered-by", "pattern": r"phusion|rails", "evidence": "header x-powered-by"}
                ],
                "nodejs": [
                    {"type": "header", "name": "x-powered-by", "pattern": r"express|nodejs", "evidence": "header x-powered-by"}
                ]
            },
            "cdn": {
                "cloudflare": [
                    {"type": "header", "name": "cf-ray", "pattern": r".", "evidence": "header: cf-ray"},
                    {"type": "cookies", "name": "__cfduid", "pattern": r".", "evidence": "cookie: __cfduid"}
                ],
                "fastly": [
                    {"type": "header", "name": "fastly-io", "pattern": r".", "evidence": "header: fastly-io"}
                ],
                "akamai": [
                    {"type": "header", "name": "x-akamai-transformed", "pattern": r".", "evidence": "header: x-akamai-transformed"}
                ],
                "cloudfront": [
                    {"type": "header", "name": "x-amz-cf-id", "pattern": r".", "evidence": "header: x-amz-cf-id"}
                ]
            },
            "analytics": {
                "google-analytics": [
                    {"type": "script", "pattern": r"google-analytics\.com|ga\.js|analytics\.js", "evidence": "script tag"}
                ],
                "matomo": [
                    {"type": "script", "pattern": r"matomo\.js|piwik\.js", "evidence": "script tag"}
                ]
            },
            "advertising-networks": {
                "google-adsense": [
                    {"type": "script", "pattern": r"adsbygoogle|pagead2\.googlesyndication\.com", "evidence": "script tag"}
                ],
                "media.net": [
                    {"type": "script", "pattern": r"media\.net", "evidence": "script tag"}
                ]
            },
            "ecommerce": {
                "shopify": [
                    {"type": "script", "pattern": r"shopify", "evidence": "script or meta"},
                    {"type": "meta", "pattern": r"shopify", "evidence": "meta tag"}
                ],
                "woocommerce": [
                    {"type": "script", "pattern": r"woocommerce", "evidence": "script tag"},
                    {"type": "meta", "pattern": r"woocommerce", "evidence": "meta tag"}
                ]
            },
            "font-scripts": {
                "google-fonts": [
                    {"type": "link", "pattern": r"fonts\.googleapis\.com", "evidence": "link href"}
                ],
                "font-awesome": [
                    {"type": "link", "pattern": r"font-awesome", "evidence": "link href"}
                ]
            },
            "web-framework": {
                "bootstrap": [
                    {"type": "script", "pattern": r"bootstrap", "evidence": "script or link"},
                    {"type": "link", "pattern": r"bootstrap", "evidence": "link tag"}
                ],
                "tailwind": [
                    {"type": "script", "pattern": r"tailwind", "evidence": "script tag"},
                    {"type": "meta", "pattern": r"tailwind", "evidence": "meta tag"}
                ]
            }
        }

    def add_signature(self, category, tech_name, signature_list):
        """
        Extend the signatures dictionary with custom signatures.
        signature_list should be a list of dictionaries with keys:
            - type: header, meta, script, cookies, dom, link
            - pattern
            - (optional) name (e.g., for header or cookies)
            - (optional) evidence: human-readable explanation of the pattern
        """
        if category not in self.signatures:
            self.signatures[category] = {}
        self.signatures[category][tech_name] = signature_list

    @staticmethod
    def _check_pattern(content, pattern):
        """Check if a regex pattern exists in the provided content."""
        if not content:
            return None
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            # If version extraction is possible (named capture "version"), return it.
            return match.groupdict().get("version", True)
        return None

    def _fetch_content(self, url):
        """
        Fetch the webpage content and return headers, cookies, and parsed HTML.
        """
        # Standard browser headers
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        response = self.session.get(url, headers=headers, timeout=self.timeout)
        response.raise_for_status()  # raise exception for HTTP errors

        # Standardize headers to lower-case
        response_headers = {k.lower(): v for k, v in response.headers.items()}
        cookies = {k: v for k, v in response.cookies.items()}
        html_content = response.text
        soup = BeautifulSoup(html_content, "html.parser")
        return response_headers, cookies, html_content, soup

    def detect_technologies(self, url):
        """
        Detect technologies used by a website.

        Args:
            url (str): URL to analyze

        Returns:
            dict: Detected technologies organized by category, with evidence.
        """
        result = {
            'url': url,
            'technologies': {}
        }

        try:
            headers, cookies, html_content, soup = self._fetch_content(url)

            # Extract elements using BeautifulSoup
            scripts = [script.get("src") for script in soup.find_all("script") if script.get("src")]
            links = [link.get("href") for link in soup.find_all("link") if link.get("href")]

            # For meta tags, we'll join all 'meta' tag attributes content
            meta_tags = " ".join(tag.get("content", "") for tag in soup.find_all("meta"))

            # Process categories
            for category, techs in self.signatures.items():
                detected_category = {}
                for tech_name, patterns in techs.items():
                    evidence_list = []
                    version = None
                    for pattern_info in patterns:
                        pattern_type = pattern_info.get("type")
                        pattern = pattern_info.get("pattern")
                        evidence = pattern_info.get("evidence", "unknown evidence")
                        # Default target value placeholder.
                        target_value = None

                        if pattern_type == 'header':
                            header_name = pattern_info.get("name", "").lower()
                            if header_name in headers:
                                target_value = headers[header_name]
                        elif pattern_type == 'meta':
                            target_value = meta_tags
                        elif pattern_type == 'script':
                            # Check both script src and inline script content
                            for script in scripts:
                                if (found := self._check_pattern(script, pattern)):
                                    version = version or (found if isinstance(found, str) else None)
                                    target_value = script
                                    break
                            if not target_value:
                                if (found := self._check_pattern(html_content, pattern)):
                                    version = version or (found if isinstance(found, str) else None)
                                    target_value = html_content
                        elif pattern_type == 'cookies':
                            cookie_name = pattern_info.get("name", "")
                            if cookie_name in cookies:
                                target_value = cookies[cookie_name]
                        elif pattern_type == 'dom':
                            # dom: look in the entire html for the pattern
                            target_value = html_content
                        elif pattern_type == 'link':
                            for link in links:
                                if (found := self._check_pattern(link, pattern)):
                                    version = version or (found if isinstance(found, str) else None)
                                    target_value = link
                                    break

                        # Proceed if a target value has been assigned
                        if target_value:
                            found_result = self._check_pattern(target_value, pattern)
                            if found_result:
                                evidence_list.append(evidence)
                                version = version or (found_result if isinstance(found_result, str) else None)
                                break  # use first successful evidence
                    if evidence_list:
                        detected_category[tech_name] = {
                            "detected": True,
                            "evidence": evidence_list,
                        }
                        if version and version != True:
                            detected_category[tech_name]["version"] = version
                if detected_category:
                    result["technologies"][category] = detected_category

        except Exception as e:
            result["error"] = str(e)

        return result


# Example usage
if __name__ == "__main__":
    detector = LightTechDetector(timeout=10)
    url = "https://github.com"  # Replace with the target URL
    result = detector.detect_technologies(url)  
    print(result)
    