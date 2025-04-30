# data_collection/data_collector.py

import os
import sys

# Find the directory containing the Collectors module
current_dir = os.path.dirname(os.path.abspath(__file__))  # Data_Collection directory
sys.path.append(current_dir)


# data_collection/data_collector.py
class URLFeatureCollector:
    # Consolidated required feature list for both validation and prediction.
    REQUIRED_FEATURES = [
        "LengthOfURL", "URLComplexity", "CharacterComplexity",
        "DomainLengthOfURL", "IsDomainIP", "TLD", "TLDLength",
        "LetterCntInURL", "URLLetterRatio", "DigitCntInURL", "URLDigitRatio",
        "EqualCharCntInURL", "QuesMarkCntInURL", "AmpCharCntInURL",
        "OtherSpclCharCntInURL", "URLOtherSpclCharRatio", "NumberOfHashtags",
        "NumberOfSubdomains", "HavingPath", "PathLength", "HavingQuery",
        "HavingFragment", "HavingAnchor", "HasSSL", "IsUnreachable",
        "LineOfCode", "LongestLineLength", "HasTitle", "HasFavicon",
        "HasRobotsBlocked", "IsResponsive", "IsURLRedirects", "IsSelfRedirects",
        "HasDescription", "HasPopup", "HasIFrame", "IsFormSubmitExternal",
        "HasSocialMediaPage", "HasSubmitButton", "HasHiddenFields",
        "HasPasswordFields", "HasBankingKey", "HasPaymentKey", "HasCryptoKey",
        "HasCopyrightInfoKey ", "CntImages", "CntFilesCSS", "CntFilesJS",
        "CntSelfHRef", "CntEmptyRef", "CntExternalRef", "CntPopup", "CntIFrame",
        "UniqueFeatureCnt", "ShannonEntropy", "FractalDimension",
        "KolmogorovComplexity", "HexPatternCnt", "Base64PatternCnt"
    ]

    def __init__(self, url):
        self.url = url
        self.features = {}

    def collect_all_features(self):
        """Collect all features from the URL."""
        self.collect_domain_whois()
        self.collect_ssl_hosting()
        self.collect_static_content()
        self.collect_dynamic_content()
        # self.collect_web_tech()
        # self.collect_reputation()
        # self.collect_social_presence()
        self.derive_features()
        return self.features

    def collect_domain_whois(self):
        """Collect domain WHOIS information for ML model features."""
        from Collectors.domain_whois import parse_domain
        self.features['domain_whois'] = parse_domain(self.url)
        return self.features['domain_whois']

    def collect_static_content(self):
        from Collectors.Static_content_extractor import extract_static_features
        static_feats = extract_static_features(self.url)
        self.features['static_content'] = static_feats
        return static_feats

    def collect_dynamic_content(self):
        from Collectors.dynamic_content_extractor import extract_dynamic_features
        dynamic_feats = extract_dynamic_features(self.url)
        # exclude "ExternalLinks" from dynamic features
        dynamic_feats.pop("ExternalLinks", None)
        self.features['dynamic_content'] = dynamic_feats
        return dynamic_feats

    def collect_ssl_hosting(self):
        from Collectors.ssl_hosting import get_ssl_info
        # Use "Domain" from domain_whois features if available; fallback to self.url
        domain_whois = self.features.get('domain_whois', {})
        domain = domain_whois.get("Domain", self.url)
        ssl_info = get_ssl_info(domain)
        self.features['ssl_hosting'] = {"HasSSL": ssl_info.get("HasSSL")}
        return self.features['ssl_hosting']


    def derive_features(self):
        """Derive additional features from collected raw data."""
        from feature_derivation import derive_features
        self.features['derived'] = derive_features(self.url)
        return self.features['derived']

    def flatten_features(self):
        """Flatten the nested self.features dict into a simple key-value mapping."""
        flat_features = {}
        for key, group in self.features.items():
            if isinstance(group, dict):
                flat_features.update(group)
            else:
                flat_features[key] = group
        return flat_features

    def validate_ml_features(self):
        """
        Validates that all required ML model features are present
        in the flattened self.features dict. Returns a tuple:
          (is_valid, missing_features, num_features)
        """
        flattened = self.flatten_features()
        missing = [feat for feat in URLFeatureCollector.REQUIRED_FEATURES if feat not in flattened]
        num_features = len(flattened)
        if missing:
            return False, missing, num_features
        return True, [], num_features

    def get_prediction(self, model_path="../models/model_RF.pkl", tld_freq_path="../data/tld_freq.csv"):
        """
        Loads the ML model and makes a prediction based on collected features.
        Uses a DataFrame with feature name/value pairs to match the model's expected format.
        Returns a dictionary with the prediction and associated probability scores (if available).
        """
        from joblib import load
        import pandas as pd

        # Get the flattened features.
        flat_features = self.flatten_features()

        # Read the TLD frequency mapping from CSV.
        tld_df = pd.read_csv(tld_freq_path, index_col=0)
        tld_mapping = tld_df["Frequency"].to_dict()

        # Build a dictionary with keys as feature names and values as the collected feature.
        features_dict = {}
        for key in URLFeatureCollector.REQUIRED_FEATURES:
            if key == "TLD":
                raw_tld = flat_features.get("TLD", "")
                value = tld_mapping.get(raw_tld, 0)
            else:
                value = flat_features.get(key, 0)
            features_dict[key] = value

        # Create the DataFrame with a single observation.
        input_df = pd.DataFrame([features_dict])
        # save the DataFrame to a CSV file for debugging
        input_df.to_csv("input_df.csv", index=False)

        # Load the model.
        try:
            model = load(model_path)
        except Exception as e:
            raise Exception(f"Error loading model: {e}")

        # Make a prediction using the DataFrame.
        prediction = model.predict(input_df)
        probability = model.predict_proba(input_df)[0] if hasattr(model, "predict_proba") else None

        return {"prediction": prediction[0], "probability": probability}


    def sort_features_by_class(self):
        """
        Sorts all collected (and derived) features into 4 groups:

          1. domain_url: Features computed directly from the URL and its domain.
          2. content: Features extracted from static and dynamic content.
          3. ssl: SSL-related features.
          4. advanced_features: Advanced computed features (e.g., ShannonEntropy).

        Each feature is represented by a dictionary with the following fields:
          - feature: the feature name.
          - value: the extracted value.
          - definition: a brief explanation of the feature.
          - raw feature: the originating raw source (e.g. "url", "ssl_hosting", etc.).
        """
        # Flatten the features dictionary.
        flat_features = self.flatten_features()

        # Define the grouping sets.
        domain_url_set = {
            "URL", "Domain",  # Moved from content to domain_url.
            "LengthOfURL", "URLComplexity", "CharacterComplexity",
            "DomainLengthOfURL", "IsDomainIP", "TLD", "TLDLength",
            "LetterCntInURL", "URLLetterRatio", "DigitCntInURL", "URLDigitRatio",
            "EqualCharCntInURL", "QuesMarkCntInURL", "AmpCharCntInURL",
            "OtherSpclCharCntInURL", "URLOtherSpclCharRatio", "NumberOfHashtags",
            "NumberOfSubdomains", "HavingPath", "PathLength", "HavingQuery",
            "HavingFragment", "HavingAnchor"
        }
        ssl_set = {"HasSSL"}
        advanced_set = {"ShannonEntropy", "FractalDimension", "KolmogorovComplexity", "HexPatternCnt", "Base64PatternCnt"}

        sorted_features = {
            "domain_url": [],
            "content": [],
            "ssl": [],
            "advanced_features": []
        }

        # Mapping for definitions and raw source.
        feature_defs = {
            "URL": {"definition": "The full URL string.", "raw": "url"},
            "Domain": {"definition": "The domain extracted from the URL.", "raw": "domain_whois"},
            "LengthOfURL": {"definition": "Length of the URL.", "raw": "url"},
            "URLComplexity": {"definition": "Measure of URL complexity.", "raw": "url"},
            "CharacterComplexity": {"definition": "Character distribution complexity.", "raw": "url"},
            "DomainLengthOfURL": {"definition": "Length of the domain part.", "raw": "domain_whois"},
            "IsDomainIP": {"definition": "True if the domain is an IP address.", "raw": "domain_whois"},
            "TLD": {"definition": "Top-Level Domain.", "raw": "url"},
            "TLDLength": {"definition": "Length of the TLD.", "raw": "url"},
            "LetterCntInURL": {"definition": "Count of letters in the URL.", "raw": "url"},
            "URLLetterRatio": {"definition": "Ratio of letters to total characters in the URL.", "raw": "url"},
            "DigitCntInURL": {"definition": "Count of digits in the URL.", "raw": "url"},
            "URLDigitRatio": {"definition": "Ratio of digits to total characters in the URL.", "raw": "url"},
            "EqualCharCntInURL": {"definition": "Count of repeating characters in the URL.", "raw": "url"},
            "QuesMarkCntInURL": {"definition": "Count of question marks in the URL.", "raw": "url"},
            "AmpCharCntInURL": {"definition": "Count of ampersand characters in the URL.", "raw": "url"},
            "OtherSpclCharCntInURL": {"definition": "Count of other special characters.", "raw": "url"},
            "URLOtherSpclCharRatio": {"definition": "Ratio of special characters.", "raw": "url"},
            "NumberOfHashtags": {"definition": "Number of hashtags in the URL.", "raw": "url"},
            "NumberOfSubdomains": {"definition": "Number of subdomains present.", "raw": "url"},
            "HavingPath": {"definition": "True if the URL has a path.", "raw": "url"},
            "PathLength": {"definition": "Length of the URL path.", "raw": "url"},
            "HavingQuery": {"definition": "True if there is a query string.", "raw": "url"},
            "HavingFragment": {"definition": "True if there is a fragment.", "raw": "url"},
            "HavingAnchor": {"definition": "True if an anchor is present.", "raw": "url"},
            "HasSSL": {"definition": "True if SSL is configured.", "raw": "ssl_hosting"},
            "IsUnreachable": {"definition": "True if the site is unreachable.", "raw": "static_content/dynamic_content"},
            "LineOfCode": {"definition": "Total number of lines of code.", "raw": "static_content"},
            "LongestLineLength": {"definition": "Length of the longest line.", "raw": "static_content"},
            "HasTitle": {"definition": "True if a title tag is present.", "raw": "static_content"},
            "HasFavicon": {"definition": "True if a favicon is found.", "raw": "static_content"},
            "HasRobotsBlocked": {"definition": "True if robots.txt blocks crawlers.", "raw": "static_content"},
            "IsResponsive": {"definition": "True if the page is responsive.", "raw": "static_content"},
            "IsURLRedirects": {"definition": "True if URL performs redirection.", "raw": "static_content"},
            "IsSelfRedirects": {"definition": "True if the URL redirects to itself.", "raw": "static_content"},
            "HasDescription": {"definition": "True if a meta description tag is present.", "raw": "static_content"},
            "HasPopup": {"definition": "True if popups are detected.", "raw": "static_content"},
            "HasIFrame": {"definition": "True if iframes are present.", "raw": "static_content"},
            "IsFormSubmitExternal": {"definition": "True if forms submit externally.", "raw": "static_content"},
            "HasSocialMediaPage": {"definition": "True if social media links are present.", "raw": "static_content"},
            "HasSubmitButton": {"definition": "True if a submit button is found.", "raw": "static_content"},
            "HasHiddenFields": {"definition": "True if hidden fields are present.", "raw": "static_content"},
            "HasPasswordFields": {"definition": "True if password fields exist.", "raw": "static_content"},
            "HasBankingKey": {"definition": "Indicates banking-related identifiers.", "raw": "static_content"},
            "HasPaymentKey": {"definition": "Indicates payment-related identifiers.", "raw": "static_content"},
            "HasCryptoKey": {"definition": "Indicates cryptocurrency identifiers.", "raw": "static_content"},
            "HasCopyrightInfoKey ": {"definition": "Indicates copyright information.", "raw": "static_content"},
            "CntImages": {"definition": "Count of images.", "raw": "static_content"},
            "CntFilesCSS": {"definition": "Count of CSS files linked.", "raw": "static_content"},
            "CntFilesJS": {"definition": "Count of JavaScript files linked.", "raw": "static_content"},
            "CntSelfHRef": {"definition": "Count of self-hyperlinks.", "raw": "static_content"},
            "CntEmptyRef": {"definition": "Count of empty hyperlink references.", "raw": "static_content"},
            "CntExternalRef": {"definition": "Count of external hyperlink references.", "raw": "static_content"},
            "CntPopup": {"definition": "Count of popup triggers.", "raw": "static_content"},
            "CntIFrame": {"definition": "Count of iframes.", "raw": "static_content"},
            "UniqueFeatureCnt": {"definition": "Count of unique features detected.", "raw": "static_content"},
            "ShannonEntropy": {"definition": "Entropy measuring randomness.", "raw": "derived"},
            "FractalDimension": {"definition": "Indicates structural complexity.", "raw": "derived"},
            "KolmogorovComplexity": {"definition": "Measure of algorithmic randomness.", "raw": "derived"},
            "HexPatternCnt": {"definition": "Count of hexadecimal patterns.", "raw": "derived"},
            "Base64PatternCnt": {"definition": "Count of Base64 encoded patterns.", "raw": "derived"}
        }

        # Iterate over each feature and sort according to its group.
        for feature, value in flat_features.items():
            if feature in ssl_set:
                category = "ssl"
            elif feature in advanced_set:
                category = "advanced_features"
            elif feature in domain_url_set:
                category = "domain_url"
            else:
                category = "content"

            definition = feature_defs.get(feature, {}).get("definition", "No definition available")
            raw_feature = feature_defs.get(feature, {}).get("raw", "unknown")
            sorted_features[category].append({
                "feature": feature,
                "value": value,
                "definition": definition,
                "raw feature": raw_feature
            })

        return sorted_features





# Example usage:
if __name__ == "__main__":
    url = "http://101.200.220.118:8090/ledshow2.exe"
    collector = URLFeatureCollector(url)
    all_features = collector.collect_all_features()
    # print(all_features) 
       
    # # Validate the features for the ML model
    # is_valid, missing_features, num_features = collector.validate_ml_features()
    # if is_valid:
    #     print("All required features are present.")
    #     print("Total number of features:", num_features)
    # else:
    #     print("Missing features:", missing_features)
    #     print("Total number of features:", num_features)

    # Get the prediction from the model
    prediction_result = collector.get_prediction()
    print("Prediction result:", prediction_result)

    # Sort features by class
    # sorted_features = collector.sort_features_by_class()
    # print("Sorted features:", sorted_features)

    # print feature from content
    # print("Content features:", sorted_features['content'])

    # print feature ssl
    # print("SSL features:", sorted_features['ssl'])