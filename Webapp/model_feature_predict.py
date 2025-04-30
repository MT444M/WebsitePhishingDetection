# model_features_predict.py
import pandas as pd
import os
import sys
from joblib import load

# Path configuration
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

from Data_Collection.data_collector import URLFeatureCollector


# Shared collector instance
_collector = None

def collect_features(url):
    """Handles feature collection and categorization"""
    global _collector
    try:
        # Initialize collector and get features
        _collector = URLFeatureCollector(url)
        _collector.collect_all_features()
        sorted_features = _collector.sort_features_by_class()

        # Validation check
        is_valid, missing, num_features = _collector.validate_ml_features()
        status_msg = f"✅ Collected {num_features} features"
        status_msg = f'<div style="color:#000000;">{status_msg}</div>'
        status_class = ""
        
        if not is_valid:
            status_msg = f"⚠️ Collected {num_features} features (Missing: {len(missing)})"
            status_msg = f'<div style="color:#000000;">{status_msg}</div>'  # Set color to black
            status_class = "error"
            missing_list = "<br>".join(missing)
            status_msg += f'<div style="color:#ff4444;margin-top:5px;font-size:0.9em">Missing features:<br>{missing_list}</div>'
            
        
        # Convert to DataFrames with proper formatting
        def format_feature_df(feature_list):
            df = pd.DataFrame(feature_list)
            if not df.empty:
                df = df[['feature', 'raw feature', 'value', 'definition']]
                df['value'] = df['value'].apply(lambda x: f"{x:.3f}" if isinstance(x, float) else str(x))
            return df
        
        return (
            format_feature_df(sorted_features['domain_url']),
            format_feature_df(sorted_features['content']),
            format_feature_df(sorted_features['ssl']),
            format_feature_df(sorted_features['advanced_features']),
            f'<div class="{status_class}">{status_msg}</div>'
        )
        
    except Exception as e:
        error_df = pd.DataFrame([{"feature": "Error", "raw feature": "N/A", 
                                "value": f"Collection failed: {str(e)}", "definition": "N/A"}])
        error_msg = f'<div class="error">⚠️ Feature collection failed: {str(e)}</div>'
        return error_df, error_df, error_df, error_df, error_msg
    


# Define base paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, 'data')
MODELS_DIR = os.path.join(BASE_DIR, 'models')


# Add fallback paths for Docker
if not os.path.exists(os.path.join(DATA_DIR, "tld_freq.csv")):
    DATA_DIR = "/app/data"
    MODELS_DIR = "/app/models"

def make_prediction(
    url, 
    model_path=os.path.join(MODELS_DIR, "model_RF.pkl"), 
    tld_freq_path=os.path.join(DATA_DIR, "tld_freq.csv")
):
    """Makes prediction using collected features"""
    global _collector
    try:
        # Verify files exist
        if not os.path.exists(tld_freq_path):
            raise FileNotFoundError(f"tld_freq.csv not found at {tld_freq_path}")
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"model_RF.pkl not found at {model_path}")
    
    except Exception as e:
        print(f"Error details: DATA_DIR={DATA_DIR}, file exists={os.path.exists(tld_freq_path)}")
        return f"Prediction failed: {str(e)}", "", ""
    

def format_prediction(prediction_data):
    """Formats prediction results for display"""
    pred = prediction_data["prediction"]
    proba = prediction_data["probability"]
    
    is_phishing = pred == 0
    label = "⚠️ Phishing" if is_phishing else "✅ Legitimate"
    color = "#ff4444" if is_phishing else "#44cc44"
    confidence = proba[0] if is_phishing else proba[1]
    
    bar = f"""
    <div class="confidence-bar">
        <div class="confidence-fill" style="width:{confidence*100}%; background:{color};"></div>
    </div>
    <div style="margin-top:5px; color:{color}; font-weight:bold;">
        Confidence: {confidence*100:.1f}% - {'High Risk' if is_phishing and confidence > 0.75 else 'Medium Risk' if is_phishing and confidence > 0.5 else 'Low Risk' if is_phishing else 'High Confidence' if confidence > 0.75 else 'Medium Confidence' if confidence > 0.5 else 'Low Confidence'}
    </div>
    """
    
    details = f"""
    <table class="probability-table">
        <tr><td>Phishing Probability</td><td style="color:#ff4444;font-weight:bold;">{proba[0]*100:.1f}%</td></tr>
        <tr><td>Legitimate Probability</td><td style="color:#44cc44;font-weight:bold;">{proba[1]*100:.1f}%</td></tr>
    </table>
    """
    
    return (
        f'<div class="prediction-box {"phishing" if is_phishing else "legitimate"}">'
        f'<div style="font-size:24px;margin-bottom:10px;color:#000000;">{label}</div>'  # Set color to black
        f'</div>',
        bar,
        details
    )

    

# test the function
if __name__ == "__main__":
    url = "https://example.com"

    # url_structure_df, content_html_df, security_metrics_df,advanced_metrics_df = collect_features(url)
    
    # print("URL Structure Features:")

    # print(url_structure_df)
    
    # print("\nContent/HTML Metrics:")
    # print(content_html_df)
    
    # print("\nSecurity-Related Metrics:")
    # print(security_metrics_df)
    
    # print("\nAdvanced Statistical Metrics:")
    # print(advanced_metrics_df)

    # test the prediction function
    prediction, bar, details = make_prediction(url)
    print(prediction)