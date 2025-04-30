import gradio as gr
import pandas as pd
from analyze_url import analyze_url  # Assuming analyze_url is in the same directory
from model_feature_predict import collect_features, make_prediction  # Assuming collect_features is in the same directory    


import os
import sys
# Add the project root to the path to enable imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Initialize the CSS variable
css = ""

# Add this CSS for the title
css += """
.title { 
    font-size:32px; 
    font-weight:bold; 
    text-align:center; 
    margin-bottom:20px; 
    color:#2c3e50; 
}
"""

# Add to your CSS for the info boxes
css += """
/* Summary bar container */
.summary-row {
    overflow-x: auto;
    white-space: nowrap;
    margin: 10px 0;
    padding-bottom: 10px;  /* Space for scrollbar */
}

/* Individual info boxes */
.info-box {
    display: inline-block;
    min-width: 180px;
    margin: 0 8px;
    vertical-align: top;
    flex-shrink: 0;  /* Prevent shrinking */
}

/* Content inside info boxes */
.info-box strong {
    display: block;
    margin-bottom: 5px;
}

.info-box span {
    display: block;
    padding: 3px 0;
}
"""

# Add this CSS for section titles
css += """
.section-title { 
    font-size:24px; 
    font-weight:bold; 
    color:#2980b9; 
    margin-top:15px; 
    margin-bottom:5px; 
}
"""

# Add this CSS for info boxes
css += """
.info-box { 
    flex:1; 
    border:1px solid transparent;  /* Remove the border */
    padding:10px; 
    margin:5px; 
    border-radius:5px; 
    background-color:transparent;  /* Match Gradio's background color */
    color:#ffffff;  /* Set text color to white for readability */
    text-align:center; 
}
"""

# Add this CSS for prediction boxes
css += """
.prediction-box { 
    padding: 15px; 
    border-radius: 8px; 
    margin: 10px 0;
    text-align: center;
}
.phishing { 
    background: #ffe6e6; 
    border: 2px solid #ff4444; 
}
.legitimate { 
    background: #e6ffe6; 
    border: 2px solid #44cc44; 
}
"""

# Add this CSS for confidence bars
css += """
.confidence-bar {
    height: 20px;
    border-radius: 10px;
    margin: 10px 0;
    background: #eee;
    position: relative;
}
.confidence-fill {
    height: 100%;
    border-radius: 10px;
    transition: width 0.5s ease;
}
"""

# Add this CSS for probability tables
css += """
.probability-table {
    margin: 15px auto;
    border-collapse: collapse;
}
.probability-table td {
    padding: 8px 15px;
    border: 1px solid #ddd;
}
"""

# Add this CSS for center-aligned buttons
css += """
.center-button {
    display: flex !important;
    justify-content: center !important;
    margin: 0 auto !important;
}
"""

# Add this CSS for prediction rows
css += """
.prediction-row {
    width: 80% !important;
    margin: 10px auto !important;
}
"""

# Add this CSS for feature status
css += """
.feature-status {
    border: 1px solid #ddd;
    padding: 10px;
    border-radius: 5px;
    margin: 10px auto;
    width: 80%;
    text-align: center;
    background-color: #f8f9fa;
}
.feature-status.error {
    border-color: #ff4444;
    background-color: #ffe6e6;
}
"""

# Add this CSS for Domain Whois
css += """
.whois-list {
    list-style-type: none;
    padding-left: 0;
    margin: 15px 0;
}
.whois-item {
    padding: 8px 0;
    border-bottom: 1px solid #eee;
    display: flex;
    justify-content: space-between;
}
.whois-label {
    color: #2980b9;
    font-weight: 500;
    min-width: 180px;
}
.whois-value {
    color: white;
    max-width: 70%;
    text-align: right;
}
"""

# Add this CSS for error messages
css += """
.error-message {
    color: #ff4444;
    padding: 15px;
    border: 1px solid #ff4444;
    border-radius: 5px;
    margin: 15px 0;
}
"""

# Add to CSS for DNS records
css += """
.dns-record {
    padding: 10px;
    margin: 8px 0;
    border-radius: 5px;
    background: #f8f9fa;  /* Light gray background */
    display: flex;
    justify-content: space-between;
    color: #2c3e50;  /* Dark gray text */
}

.dns-record div:first-child {
    color: #2980b9;  /* Blue for record number */
    font-weight: 500;
}

.ip-address {
    color: #495057;  /* Dark gray for IP */
    margin-right: 15px;
}

.ttl-value {
    color: #6c757d;  /* Gray for TTL */
}

.ttl-stat-item div:first-child {
    color: #2980b9;  /* Blue for stats labels */
    font-weight: 500;
}

.ttl-stat-item div:last-child {
    color: #2c3e50;  /* Dark gray for stats values */
}
"""

# Add to CSS for SSL & Hosting
css += """
.cert-detail {
    padding: 12px 0;
    border-bottom: 1px solid #eee;
    display: grid;
    grid-template-columns: 160px 1fr;
    align-items: center;
}
.cert-label {
    color: #2980b9;
    font-weight: 500;
}
.cert-value {
    color: white;
    word-break: break-word;
}
.validity-period {
    background: #e3f2fd;
    color: black;
    padding: 15px;
    border-radius: 8px;
    margin-top: 20px;
}
"""

# Add to CSS for IP Geolocation
css += """
.geo-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 15px;
    margin-top: 20px;
}
.geo-item {
    padding: 12px;
    border-radius: 8px;
    background: #f8f9fa;
}
.geo-label {
    color: #2980b9;
    font-weight: 500;
    margin-bottom: 5px;
}
.geo-value {
    color: #2c3e50;
}
"""

# Add to CSS for Content Analysis
css += """
.content-feature {
    padding: 12px 0;
    border-bottom: 1px solid #eee;
}
.content-label {
    color: #2980b9;
    font-weight: 500;
    margin-right: 15px;
    min-width: 160px;
}
.content-value {
    color: #2c3e50;
}
.external-link {
    word-break: break-all;
    margin-left: 20px;
}
"""





# --- Gradio UI Skeleton ---
with gr.Blocks(css= css) as demo:
    # Title
    gr.Markdown("<div class='title'>StealthPhisher - URL Scanner & ML Predictor</div>")

    # URL input and Analyze button
    with gr.Row():
        url_input = gr.Textbox(label="Enter URL to analyze", placeholder="https://example.com", lines=1)

    with gr.Row():
        analyze_btn = gr.Button("🔍 Analyze")

        # Error display row (hidden by default)
    with gr.Row(visible=False) as error_row:
        error_display = gr.HTML(elem_classes="error-message")
        
    with gr.Row(elem_classes="summary-row"):
        url_box = gr.HTML("""<div class="info-box">
            <strong style="color: #2980b9;">🌐 URL</strong>
            <span id="url_value"></span>
        </div>""")
        
        ip_box = gr.HTML("""<div class="info-box">
            <strong style="color: #2980b9;">🖥️ Resolved IP</strong>
            <span id="ip_value"></span>
        </div>""")
        
        country_box = gr.HTML("""<div class="info-box">
            <strong style="color: #2980b9;">🌍 Country</strong>
            <span id="country_value"></span>
        </div>""")
        
        domain_age_box = gr.HTML("""<div class="info-box">
            <strong style="color: #2980b9;">📅 Domain Age</strong>
            <span id="domain_age_value"></span>
        </div>""")

        https_box = gr.HTML("""<div class="info-box">
            <strong style="color: #2980b9;">🔒 HTTPS</strong>
            <span id="https_value"></span>
        </div>""")
        
        blacklist_box = gr.HTML("""<div class="info-box">
            <strong style="color: #2980b9;">🛡️ Blacklist</strong>
            <span id="blacklist_value"></span>
        </div>""")


    # Main navigation tabs
    with gr.Tabs():
        with gr.TabItem("Overview"):
            gr.Markdown("""
            **Overview**

            - Quick glance at URL, IP, DNS, and HTTPS status.
            - Certificate information.
            """)
        # --------------------------
        # Tab 2: Domain Whois
        # --------------------------
        with gr.TabItem("📝 Domain & WHOIS"):
            gr.Markdown("<div class='section-title'>Registration Details</div>")
            whois_html = gr.HTML()

        # --------------------------
        # Tab 5: DNS Records
        # --------------------------
        with gr.TabItem("📡 DNS"):
            gr.Markdown("<div class='section-title'>DNS Configuration</div>")
            dns_html = gr.HTML()

        # --------------------------
        # Tab 4: SSL & Hosting
        # --------------------------
        with gr.TabItem("🔐 SSL & Hosting"):
            gr.Markdown("<div class='section-title'>Certificate & Security Details</div>")
            ssl_html = gr.HTML()

        # --------------------------
        # Tab: Server Location
        # --------------------------
        with gr.TabItem("📍 Server Location"):
            gr.Markdown("<div class='section-title'>IP Geolocation Details</div>")
            geo_html = gr.HTML()
            
        # --------------------------
        # Tab: Content Analysis
        # --------------------------
        with gr.TabItem("📄 Content"):
            gr.Markdown("<div class='section-title'>Page Content & Behavior</div>")
            content_html = gr.HTML()

        # --------------------------
        # Tab: Web Technologies
        # --------------------------
        with gr.TabItem(" 🖥️ Web Technologies"):
            gr.Markdown("<div class='section-title'>Web Technologies FingerPrinting</div>")
            tech_html = gr.HTML()

        # --------------------------
        # Tab: Reputation & Threat Feeds
        # --------------------------
        with gr.TabItem("🛡️ Reputation"):
            gr.Markdown("<div class='section-title'>Reputation & Threat Feeds</div>")
             

    analyze_btn.click(
    fn=analyze_url,
    inputs=[url_input],
    outputs=[
        # Summary Bar Components (4)
        url_box, ip_box, country_box, domain_age_box, https_box,
        
        # Tab Content Components (5)
        whois_html, dns_html, ssl_html, geo_html, content_html,
        
        # Error Display (1)
        error_display
    ]
)


# ----------------------------------------------------------------------------
# Model Prediction Section
# --------------------------------------------------------------------------

    # Horizontal line before the section
    gr.Markdown("---")

    # Model Prediction Section with larger title
    gr.Markdown("<div style='font-size:32px; font-weight:bold; text-align:center; margin-bottom:20px; color:#2c3e50;'>Model Prediction</div>")

    # Centered Button to trigger feature collection with reduced width
    with gr.Row():
        with gr.Column(scale=1):
            gr.Markdown()  # Left spacer
        with gr.Column(scale=4):
            collect_features_btn = gr.Button("Collect Features", 
                                           elem_id="collect_features_btn")
        with gr.Column(scale=1):
            gr.Markdown()  # Right spacer

    # Feature status message
    feature_status = gr.Markdown(elem_classes="feature-status")

        # Model's Features Section
    with gr.Accordion("URL Structure", open=False) as url_acc:
        url_structure_df = gr.Dataframe(interactive=False, label="URL Structure Features")
    with gr.Accordion("Content/HTML Metrics", open=False) as content_acc:
        content_html_df = gr.Dataframe(interactive=False, label="Content/HTML Metrics")
    with gr.Accordion("Security-Related Metrics", open=False) as security_acc:
        security_metrics_df = gr.Dataframe(interactive=False, label="Security-Related Metrics")
    with gr.Accordion("Advanced Statistical Metrics", open=False) as advanced_acc:
        advanced_metrics_df = gr.Dataframe(interactive=False, label="Advanced Statistical Metrics")

    with gr.Row():
        # Add loading states for better UX
        # Update button connection
        collect_features_btn.click(
            fn=collect_features,
            inputs=[url_input],
            outputs=[
                url_structure_df, content_html_df, security_metrics_df, 
                advanced_metrics_df, feature_status
            ]
        )



        # Add this section below your feature collection components
    # Centered button row
    with gr.Row():
        with gr.Column(scale=1):  # Left spacer
            gr.Markdown()  
        with gr.Column(scale=4):  # Center-aligned column
            predict_btn = gr.Button("🚀 Analyze with AI Model", 
                                variant="primary",
                                elem_classes="center-button")
        with gr.Column(scale=1):  # Right spacer
            gr.Markdown()

     
    # Prediction display rows
    with gr.Row():
        prediction_output = gr.HTML(elem_classes="prediction-row")

    with gr.Row():
        confidence_bar = gr.HTML(elem_classes="prediction-row")

    with gr.Row():
        probability_details = gr.HTML(elem_classes="prediction-row")       

        predict_btn.click(
        fn=make_prediction,
        inputs=[url_input],
        outputs=[prediction_output, confidence_bar, probability_details]
    )


if __name__ == "__main__":
    # demo.launch()
    demo.launch(server_name="0.0.0.0", server_port=7860)
