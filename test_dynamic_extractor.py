#!/usr/bin/env python3
"""
Test script for the dynamic_content_extractor.py module.
This script validates that Chrome WebDriver is working correctly in the Docker container.
"""

import sys
import os
import json
import argparse
from pathlib import Path

# Add the project root to the path
project_root = Path(__file__).resolve().parent
sys.path.insert(0, str(project_root))

# Import the dynamic_content_extractor module
try:
    from Data_Collection.Collectors.dynamic_content_extractor import extract_dynamic_features, get_web_driver
    print("Successfully imported extract_dynamic_features and get_web_driver")
except ImportError as e:
    print(f"Failed to import dynamic_content_extractor: {e}")
    sys.exit(1)

def test_webdriver():
    """Test if the WebDriver initializes correctly."""
    print("Testing WebDriver initialization...")
    
    driver = get_web_driver()
    
    if driver is None:
        print("ERROR: WebDriver initialization failed!")
        return False
    
    try:
        print("WebDriver initialized successfully.")
        driver.quit()
        print("WebDriver closed successfully.")
        return True
    except Exception as e:
        print(f"ERROR during WebDriver test: {e}")
        return False

def test_feature_extraction(url="https://www.example.com"):
    """Test feature extraction with a sample URL."""
    print(f"Testing dynamic feature extraction with URL: {url}")
    
    try:
        features = extract_dynamic_features(url)
        
        # Print the features in a formatted way
        print("\nExtracted features:")
        print(json.dumps(features, indent=2))
        
        # Check if we got at least some of the expected keys
        expected_keys = ['IsResponsive', 'IsURLRedirects', 'HasIFrame', 'HasPasswordFields']
        missing_keys = [key for key in expected_keys if key not in features]
        
        if missing_keys:
            print(f"WARNING: Missing expected keys: {missing_keys}")
            return False
        
        print("Feature extraction test passed successfully!")
        return True
        
    except Exception as e:
        print(f"ERROR during feature extraction: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Test dynamic content extractor")
    parser.add_argument("--url", type=str, default="https://www.example.com",
                        help="URL to test feature extraction (default: https://www.example.com)")
    parser.add_argument("--webdriver-only", action="store_true",
                        help="Only test WebDriver initialization")
    
    args = parser.parse_args()
    
    # Test WebDriver initialization
    webdriver_success = test_webdriver()
    
    if args.webdriver_only:
        sys.exit(0 if webdriver_success else 1)
    
    # Test feature extraction if WebDriver initialization succeeded
    if webdriver_success:
        extraction_success = test_feature_extraction(args.url)
        sys.exit(0 if extraction_success else 1)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()