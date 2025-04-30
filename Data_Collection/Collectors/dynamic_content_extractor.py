# -----------------------------------
# (B) DYNAMIC EXTRACTION Using Selenium
# -----------------------------------

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from urllib.parse import urlparse, urljoin
import time
from selenium.common.exceptions import TimeoutException, WebDriverException

def normalize_netloc(netloc):
    """
    Normalize a network location string by removing common prefixes 
    and converting it to lowercase.
    """
    if netloc.startswith("www."):
        netloc = netloc[4:]
    return netloc.lower().strip()

def get_web_driver():
    """Initialize and return a Chrome WebDriver instance configured for Docker environment."""
    chrome_options = Options()
    
    # Essential options for running Chrome in Docker
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--disable-gpu")
    
    # Additional security and performance options
    chrome_options.add_argument("--disable-extensions")
    chrome_options.add_argument("--disable-infobars")
    chrome_options.add_argument("--window-size=1920,1080")
    chrome_options.add_argument("--start-maximized")
    chrome_options.add_argument("--disable-blink-features=AutomationControlled")
    
    # Set user agent to avoid detection
    chrome_options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
    
    # Initialize the WebDriver
    try:
        driver = webdriver.Chrome(options=chrome_options)
        return driver
    except Exception as e:
        print(f"Error initializing Chrome WebDriver: {e}")
        return None

def extract_dynamic_features(url, timeout=30):
    """
    Uses Selenium (headless Chrome) to load the page and extract dynamic features:
      - IsResponsive: Presence of a meta viewport element.
      - IsURLRedirects: Whether the loaded URL differs from the input.
      - IsSelfRedirects: If redirected within the same domain but with a different path.
      - HasPopup: Detection based on window handles.
      - HasIFrame: Presence of iframes.
      - IsFormSubmitExternal: If any form's action points to an external domain.
      - HasSocialMediaPage: If social media links are present.
      - HasSubmitButton: If submit buttons are present.
      - HasHiddenFields: Detection of hidden input elements.
      - HasPasswordFields: Detection of password input fields.
      - ExternalLinks: A list of all external links present on the page.
      
    Returns a dictionary with these features.
    """
    # Initialize with default values in case of failure
    dynamic_features = {
        'IsResponsive': 0,
        'IsURLRedirects': 0,
        'IsSelfRedirects': 0,
        'HasPopup': 0,
        'HasIFrame': 0,
        'IsFormSubmitExternal': 0,
        'HasSocialMediaPage': 0,
        'HasSubmitButton': 0,
        'HasHiddenFields': 0,
        'HasPasswordFields': 0,
        'ExternalLinks': []
    }

    driver = None
    try:
        # Get WebDriver with Docker-compatible settings
        driver = get_web_driver()
        
        if driver is None:
            print(f"Failed to create WebDriver for URL: {url}")
            return dynamic_features
        
        print(f"Accessing URL: {url}")
        
        # Set page load timeout
        driver.set_page_load_timeout(timeout)
        
        # Normalize the original URL for comparison
        parsed_original = urlparse(url)
        original_netloc = normalize_netloc(parsed_original.netloc)
        
        # Navigate to the URL
        driver.get(url)
        
        # Wait explicitly for page elements to load
        wait = WebDriverWait(driver, 10)
        try:
            wait.until(EC.presence_of_element_located((By.TAG_NAME, "title")))
        except Exception:
            # Title might not be present, continue anyway
            pass
        
        # Optionally wait for the meta viewport tag if present
        try:
            wait.until(EC.presence_of_element_located((By.XPATH, "//meta[@name='viewport']")))
        except Exception:
            # Not all pages include a meta viewport tag
            pass
        
        # Give a minimal pause to let the DOM settle
        time.sleep(1)
        
        # --- Dynamic Features Extraction ---
        
        # 1. IsResponsive - Check for meta viewport tag presence
        meta_viewport = driver.find_elements(By.XPATH, "//meta[@name='viewport']")
        dynamic_features['IsResponsive'] = int(len(meta_viewport) > 0)
        
        # 2. IsURLRedirects - Compare the original URL with the loaded URL
        current_url = driver.current_url
        dynamic_features['IsURLRedirects'] = int(current_url != url)
        
        # 3. IsSelfRedirects - Check if the domain is the same but the path differs
        parsed_current = urlparse(current_url)
        current_netloc = normalize_netloc(parsed_current.netloc)
        dynamic_features['IsSelfRedirects'] = int(
            original_netloc == current_netloc and parsed_original.path != parsed_current.path
        )
        
        # 4. HasPopup - Count the window handles (pop-ups usually create additional windows)
        try:
            dynamic_features['HasPopup'] = int(len(driver.window_handles) > 1)
        except Exception:
            # In case of issues accessing window handles
            dynamic_features['HasPopup'] = 0
        
        # 5. HasIFrame - Detect if at least one <iframe> exists
        try:
            iframes = driver.find_elements(By.TAG_NAME, "iframe")
            dynamic_features['HasIFrame'] = int(len(iframes) > 0)
        except Exception:
            dynamic_features['HasIFrame'] = 0
        
        # 6. IsFormSubmitExternal - Check whether forms submit to external domains
        try:
            forms = driver.find_elements(By.TAG_NAME, "form")
            cnt_form_external = 0
            for form in forms:
                try:
                    action = form.get_attribute("action")
                    if action:
                        # Use urljoin to handle relative URLs
                        absolute_action = urljoin(url, action)
                        parsed_action = urlparse(absolute_action)
                        action_netloc = normalize_netloc(parsed_action.netloc)
                        if action_netloc and action_netloc != original_netloc:
                            cnt_form_external += 1
                except Exception:
                    continue
            dynamic_features['IsFormSubmitExternal'] = int(cnt_form_external > 0)
        except Exception:
            dynamic_features['IsFormSubmitExternal'] = 0
        
        # 7. HasSocialMediaPage - Scan anchor tags for known social domains
        try:
            social_media_domains = ["facebook.com", "twitter.com", "instagram.com", "linkedin.com", "pinterest.com", "youtube.com"]
            anchors = driver.find_elements(By.TAG_NAME, "a")
            has_social_link = False
            for a in anchors:
                try:
                    href = a.get_attribute("href")
                    if href:
                        parsed_href = urlparse(href)
                        netloc = normalize_netloc(parsed_href.netloc)
                        if any(social in netloc for social in social_media_domains):
                            has_social_link = True
                            break
                except Exception:
                    continue
            dynamic_features['HasSocialMediaPage'] = int(has_social_link)
        except Exception:
            dynamic_features['HasSocialMediaPage'] = 0
        
        # 8. HasSubmitButton - Look for buttons or input elements of type submit
        try:
            submit_buttons = driver.find_elements(By.XPATH, "//input[@type='submit'] | //button[@type='submit']")
            dynamic_features['HasSubmitButton'] = int(len(submit_buttons) > 0)
        except Exception:
            dynamic_features['HasSubmitButton'] = 0
        
        # 9. HasHiddenFields - Detect if there are any hidden input elements
        try:
            hidden_fields = driver.find_elements(By.XPATH, "//input[@type='hidden']")
            dynamic_features['HasHiddenFields'] = int(len(hidden_fields) > 0)
        except Exception:
            dynamic_features['HasHiddenFields'] = 0
        
        # 10. HasPasswordFields - Detect if there are any password input fields
        try:
            password_fields = driver.find_elements(By.XPATH, "//input[@type='password']")
            dynamic_features['HasPasswordFields'] = int(len(password_fields) > 0)
        except Exception:
            dynamic_features['HasPasswordFields'] = 0
        
        # 11. ExternalLinks - Retrieve a list of external links
        try:
            # Re-use the anchors list if we already collected it
            if 'anchors' not in locals():
                anchors = driver.find_elements(By.TAG_NAME, "a")
                
            external_links = set()
            for a in anchors:
                try:
                    href = a.get_attribute("href")
                    if href:
                        href = href.strip()
                        # Ignore non-URL schemes
                        if href.lower().startswith("javascript:") or href.lower().startswith("mailto:"):
                            continue
                        # Ensure we work with an absolute URL
                        absolute_href = urljoin(url, href)
                        parsed_href = urlparse(absolute_href)
                        link_netloc = normalize_netloc(parsed_href.netloc)
                        if link_netloc and link_netloc != original_netloc:
                            external_links.add(absolute_href)
                except Exception:
                    continue
            dynamic_features["ExternalLinks"] = list(external_links)
        except Exception:
            dynamic_features["ExternalLinks"] = []
        
        return dynamic_features
        
    except Exception as e:
        print(f"Error extracting dynamic features for {url}: {e}")
        return dynamic_features
    
    finally:
        # Clean up
        if driver:
            try:
                driver.quit()
            except Exception:
                pass

# Example usage
if __name__ == "__main__":
    test_url = "https://example.com"
    features = extract_dynamic_features(test_url)
    print(features)
