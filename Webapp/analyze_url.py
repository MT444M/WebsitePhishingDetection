import html
import socket
import tldextract
import whois
import requests
from datetime import datetime, timezone

import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from Data_Collection.Collectors.domain_whois import parse_domain, get_ip_addresses, get_whois_info, get_passive_dns
from Data_Collection.Collectors.ssl_hosting import get_ssl_info, get_ip_geolocation_info
from Data_Collection.Collectors.Static_content_extractor import extract_static_features
from Data_Collection.Collectors.dynamic_content_extractor import extract_dynamic_features


import pandas as pd


#----------------------------------
# ---- Domain Whoie ----
#----------------------------------
def format_whois_for_display(whois_data: dict) -> str:
    """Formats WHOIS data into HTML with styled list items"""
    if "error" in whois_data:
        return f'<div class="error-message">⚠️ WHOIS lookup failed: {whois_data["error"]}</div>'
    
    # Helper function to format list values
    def format_value(value):
        if isinstance(value, list):
            return ", ".join(str(v) for v in value) if value else "None"
        if isinstance(value, datetime):
            return value.strftime("%Y-%m-%d %H:%M:%S UTC")
        return str(value) if value is not None else "Not Available"

    items = [
        ("🏢 Registrar", whois_data.get("Registrar")),
        ("📅 Created On", whois_data.get("CreationDate")),
        ("🔄 Last Updated", whois_data.get("UpdatedDate")),
        ("⏳ Expires On", whois_data.get("ExpirationDate")),
        ("📅 Domain Age", whois_data.get("DomainAge")),
        ("📜 Status", whois_data.get("Status")),
        ("📧 Contact Emails", whois_data.get("Emails")),
        ("🌍 Registrant Country", whois_data.get("Country")),
        ("📡 Name Servers", whois_data.get("NameServers")),
        ("🔐 DNSSEC", whois_data.get("DNSSEC")),
        ("🏛️ Registrant Org", whois_data.get("Registrant"))
    ]

    html_items = []
    for icon_label, value in items:
        label = icon_label.split(" ", 1)[1]  # Remove emoji
        formatted_value = format_value(value)
        
        html_items.append(f"""
        <li class="whois-item">
            <span class="whois-label">{label}:</span>
            <span class="whois-value style="color: white;">{formatted_value}</span>
        </li>
        """)

    return f"""
    <div class="whois-container">
        <ul class="whois-list">
            {''.join(html_items)}
        </ul>
    </div>
    """
#---------------------------------
# ---- DNS Lookup ----
#---------------------------------
def format_dns_for_display(dns_data: dict) -> str:
    """Formats DNS data into a clean HTML layout"""
    if "error" in dns_data:
        return f'<div class="error-message">⚠️ DNS lookup failed: {dns_data["error"]}</div>'
    
    records_html = []
    for i, record in enumerate(dns_data.get("A_records", []), 1):
        records_html.append(f"""
        <div class="dns-record">
            <div>🔗 A Record #{i}</div>
            <div>
                <span class="ip-address">IP: {record['address']}</span>
                <span class="ttl-value">TTL: {record['ttl']}</span>
            </div>
        </div>
        """)
    
    # Format TTL Statistics
    ttl_stats = []
    for label, value in [("📊 Average", dns_data.get("Avg_TTL")),
                         ("⬇️ Minimum", dns_data.get("Min_TTL")),
                         ("⬆️ Maximum", dns_data.get("Max_TTL"))]:
        ttl_stats.append(f"""
        <div class="ttl-stat-item">
            <div>{label}:</div>
            <div>{value if value is not None else 'N/A'}</div>
        </div>
        """)
    
    return f"""
    <div class="dns-container">
        <div style="margin-bottom: 20px; color: #2c3e50;">
            🔍 Found {dns_data.get('A_record_count', 0)} A Records
        </div>
        {''.join(records_html)}
        <div class="ttl-stats">
            <div style="color: #2980b9; margin-bottom: 10px;">⏱️ TTL Statistics</div>
            {''.join(ttl_stats)}
        </div>
    </div>
    """

#---------------------------------
# ---- SSL Lookup ----  
#---------------------------------
def format_ssl_for_display(ssl_data: dict) -> str:
    """Formats SSL certificate data into a structured layout"""
    if "error" in ssl_data:
        return f'<div class="error-message">⚠️ SSL check failed: {ssl_data["error"]}</div>'
    
    # Parse issuer information
    issuer = ssl_data.get("CertIssuer", "")
    if isinstance(issuer, tuple):
        issuer_parts = dict(issuer[0])
        issuer_str = f"{issuer_parts.get('organizationName', 'Unknown')} ({issuer_parts.get('commonName', '')})"
    else:
        issuer_str = str(issuer)

    details = [
        ("🔒 Protocol", "TLS 1.2/1.3"),  # Placeholder, needs actual protocol detection
        ("🏛️ Issuer", issuer_str),
        ("📅 Valid From", ssl_data["ValidFrom"].strftime("%Y-%m-%d")),
        ("⏳ Expires On", ssl_data["ValidTo"].strftime("%Y-%m-%d")),
        ("🔄 Days Remaining", str(ssl_data["DaysUntilExpiry"])),
    ]

    validity_html = f"""
    <div class="validity-period">
        <div style="color: #2980b9; margin-bottom: 10px;">⏳ Validity Period</div>
        <div style="color: black;">{ssl_data["ValidityPeriod"]}</div>
    </div>
    """ if ssl_data.get("ValidityPeriod") else ""

    html_chunks = []
    for label, value in details:
        html_chunks.append(f"""
        <div class="cert-detail">
            <div class="cert-label">{label}</div>
            <div class="cert-value">{value}</div>
        </div>
        """)

    return f"""
    <div class="ssl-container">
        <div style="margin-bottom: 15px; color: #2c3e50;">
            🔐 Secure Connection: {ssl_data.get('HasSSL', 0) and '✅ Valid' or '❌ Invalid'}
        </div>
        {''.join(html_chunks)}
        {validity_html}
    </div>
    """

#---------------------------------
# ---- Geolocation Lookup ----
#---------------------------------
def format_geolocation_for_display(geo_data: dict) -> str:
    """Formats geolocation data into a structured layout"""
    if "error" in geo_data:
        return f'<div class="error-message">⚠️ {geo_data["error"]}</div>'
    
    # Format IP addresses list
    ips = geo_data.get("IPAddresses", [])
    ip_count = geo_data.get("IPCount", 0)
    geo_info = geo_data.get("Geolocation", {})
    
    ip_list = ", ".join(ips) if ips else "No IPs found"
    
    # Main geolocation details with proper keys
    details = [
        ("🌍", "Country", geo_info.get("Country", "N/A")),
        ("🏙️", "Region", geo_info.get("Region", "N/A")),
        ("🏙️", "City", geo_info.get("City", "N/A")),
        ("🏢", "Organization", geo_info.get("Org", "N/A")),
        ("📡", "ASN", geo_info.get("ASN", "N/A")),
    ]

    html_chunks = [
        f'<div class="geo-item">',
        f'  <div class="geo-label">🔗 Resolved IPs ({ip_count})</div>',
        f'  <div class="geo-value">{ip_list}</div>',
        f'</div>'
    ]

    for icon, label, value in details:
        html_chunks.append(f"""
        <div class="geo-item">
            <div class="geo-label">{icon} {label}</div>
            <div class="geo-value">{value}</div>
        </div>
        """)

    return f"""
    <div class="geo-container">
        <div class="geo-grid">
            {''.join(html_chunks)}
        </div>
    </div>
    """

#---------------------------------
# ---- Content Analysis ----
#---------------------------------
def format_content_analysis(dynamic: dict, static: dict) -> str:
    """Formats content analysis results into a structured layout"""
    html = []
    
    # Redirects Section
    html.append("""
    <div class="content-section">
        <div class="content-feature">
            <span class="content-label">🔄 Redirects:</span>
            <span class="content-value">
                {redirects} {count}
            </span>
        </div>
    """.format(
        redirects="✅ Yes" if dynamic.get("IsURLRedirects") else "❌ None",
        count=f"({dynamic.get('RedirectCount', 0)} hops)" if dynamic.get("IsURLRedirects") else ""
    ))

    # Responsiveness
    html.append("""
    <div class="content-feature">
        <span class="content-label">📱 Responsive Design:</span>
        <span class="content-value">
            {responsive}
        </span>
    </div>
    """.format(responsive="✅ Yes" if dynamic.get("IsResponsive") else "❌ No"))

    # External Links
    ext_links = dynamic.get("ExternalLinks", [])
    link_list = "\n".join([
        f'<li><a href="{link}" target="_blank" class="external-link">{link}</a></li>' 
        for link in ext_links[:5]  # Show first 5 links
    ])
    html.append(f"""
    <div class="content-feature">
        <span class="content-label">🔗 External Links ({len(ext_links)}):</span>
        <ul>
            {link_list}
            {f'<li>... and {len(ext_links)-5} more</li>' if len(ext_links) > 5 else ''}
        </ul>
    </div>
    """)

    # Content Metadata
    html.append("""
    <div class="content-feature">
        <span class="content-label">📜 Page Metadata:</span>
        <div style="margin-left: 20px;">
            <div>{copyright}</div>
            <div>{description}</div>
            <div>{favicon}</div>
        </div>
    </div>
    """.format(
        copyright="©️ Copyright: " + ("✅ Detected" if static.get("HasCopyrightInfoKey") else "❌ Not found"),
        description="📝 Description: " + ("✅ Present" if static.get("HasDescription") else "❌ Missing"),
        favicon="🖼️ Favicon: " + ("✅ Found" if static.get("HasFavicon") else "❌ Missing")
    ))

    return "\n".join(html)


# ---------------------------------
# ---- Main Analysis Function ----
# ---------------------------------

def analyze_url(url: str) -> tuple:
    """Main analysis function that handles all data collection"""
    results = {
        'summary': {},
        'whois': {},
        'ssl': {},
        'dns': {},
        'content': {},
        'reputation': {},
        'errors': []
    }

    # --- Domain Parsing ---
    try:
        parsed = parse_domain(url)
        domain = parsed["Domain"]
        results['summary']['domain'] = domain
    except Exception as e:
        results['errors'].append(f"Domain parse error: {str(e)}")
        domain = url  # Fallback to original URL

    # --- WHOIS Lookup ---
    try:
        whois_info = get_whois_info(domain)
        results['whois'] = whois_info
    except Exception as e:
        results['errors'].append(f"WHOIS lookup failed: {str(e)}")
        whois_info = {"error": str(e)}

    # --- DNS Lookup ---
    try:
        dns_info = get_passive_dns(domain)
        results['dns'] = dns_info
    except Exception as e:
        results['errors'].append(f"DNS lookup failed: {str(e)}")
        dns_info = {"error": str(e)}

    # --- SSL Check ---
    try:
        ssl_info = get_ssl_info(domain)
        results['ssl'] = ssl_info
    except Exception as e:
        results['errors'].append(f"SSL check failed: {str(e)}")
        ssl_info = {"error": str(e)}
    
    # --- Geolocation Lookup ---
    try:
        geo_info = get_ip_geolocation_info(domain)  # Add your ipinfo.io token here
        results['geolocation'] = geo_info
    except Exception as e:
        results['errors'].append(f"Geolocation lookup failed: {str(e)}")
        geo_info = {"error": str(e)}

    # --- Content Analysis ---
    try:
        dynamic = extract_dynamic_features(url)
        static = extract_static_features(url)
        results['content'] = {
            'dynamic': dynamic,
            'static': static
        }
    except Exception as e:
        results['errors'].append(f"Content analysis failed: {str(e)}")
        dynamic, static = {}, {}

    # Format Outputs
    content_html = format_content_analysis(dynamic, static)
    
    
    
    # --- Format Outputs ---
    # Domain & WHOIS Tab
    whois_html = format_whois_for_display(whois_info)

    # ssl Tab
    ssl_html = format_ssl_for_display(ssl_info)
    
    # DNS Tab
    dns_html = format_dns_for_display(dns_info)
    
    # Geolocation Tab
    geo_html = format_geolocation_for_display(geo_info)

    # # Summary Bar (using existing values)
    # summary_values = {
    #     'url': url,
    #     'ip': ", ".join(results.get('dns', {}).get('IPAddresses', [])),
    #     'country': whois_info.get('Country', 'N/A'),
    #     'domain_age': whois_info.get('DomainAge', 'N/A')
    # }

    
    # Format summary values as HTML boxes
    summary_boxes = {
        'url': f"""
        <div class="info-box">
            <strong style="color: #2980b9;">🌐 URL</strong><br>
            <span id="url_value">{html.escape(url)}</span>
        </div>
        """,
        'ip': f"""
        <div class="info-box">
            <strong style="color: #2980b9;">🖥️ Resolved IP</strong><br>
            <span id="ip_value">{', '.join(ips) if (ips := results.get('dns', {}).get('IPAddresses')) else ', '.join(geo_ips) if (geo_ips := results.get('geolocation', {}).get('IPAddresses')) else 'N/A'}</span>
        </div>
        """,
        'country': f"""
        <div class="info-box">
            <strong style="color: #2980b9;">🌍 Country</strong><br>
            <span id="country_value">{html.escape(str(whois_info.get('Country', 'N/A')))}</span>
        </div>
        """,
        'domain_age': f"""
        <div class="info-box">
            <strong style="color: #2980b9;">📅 Domain Age</strong><br>
            <span id="domain_age_value">{html.escape(str(whois_info.get('DomainAge', 'N/A')))}</span>
        </div>
        """,
        'https': f"""
        <div class="info-box">
            <strong style="color: #2980b9;">🔒 HTTPS</strong><br>
            <span id="https_value">{'✅ Valid' if results['ssl'].get('HasSSL', 0) else '❌ Invalid'}</span>
        </div>
        """
    }

    # # Placeholders for other sections (to be implemented)
    # ssl_html = gr.HTML().value
    # content_html = gr.HTML().value
    # reputation_html = gr.HTML().value

    return (
        # Summary Bar Values
        summary_boxes['url'],
        summary_boxes['ip'],
        summary_boxes['country'],
        summary_boxes['domain_age'],
        summary_boxes['https'],
        
        # Tab Content
        whois_html,
        dns_html,
        ssl_html,
        geo_html,
        content_html,
        # reputation_html,
        
        # Error Display
        "\n".join(results['errors']) if results['errors'] else "No errors detected"
    )


# def analyze_url(url):
#     error_style = "color: red;"
#     results = {}

#     # Domain parsing
#     try:
#         parsed = parse_domain(url)
#         domain = parsed["Domain"]
#         results["domain"] = domain
#     except Exception as e:
#         results["domain_error"] = f"Domain parse error: {str(e)}"

#     # IP Address Resolution
#     try:
#         ip_info = get_ip_addresses(results.get("domain", url))
#         results["ips"] = ip_info.get("IPAddresses", [])
#     except Exception as e:
#         results["ip_error"] = f"IP resolution failed: {str(e)}"

#     # WHOIS Lookup
#     try:
#         whois_info = get_whois_info(results.get("domain", url))
#         results["whois"] = whois_info
#     except Exception as e:
#         results["whois_error"] = f"WHOIS lookup failed: {str(e)}"

#     # DNS Records
#     try:
#         dns_info = get_passive_dns(results.get("domain", url))
#         results["a_records"] = dns_info.get("A_records", [])
#     except Exception as e:
#         results["dns_error"] = f"DNS lookup failed: {str(e)}"

#     # Prepare outputs
#     def format_error(value, error_key):
#         return f'<span style="{error_style}">{results[error_key]}</span>' if error_key in results else value

#     # Summary boxes
#     url_value = format_error(url, "domain_error")
#     ip_value = format_error(", ".join(results.get("ips", [])), "ip_error")
#     country_value = format_error(results.get("whois", {}).get("Country", "N/A"), "whois_error")
#     a_rec_value = format_error(", ".join([r["address"] for r in results.get("a_records", [])]), "dns_error")
    
#     # WHOIS Dataframe
#     whois_df = pd.DataFrame([[
#         results.get("whois", {}).get("Registrar", "N/A"),
#         results.get("whois", {}).get("CreationDate", "N/A"),
#         results.get("whois", {}).get("ExpirationDate", "N/A"),
#         results.get("whois", {}).get("DomainAgeDays", "N/A"),
#         results.get("whois", {}).get("Country", "N/A")
#     ]], columns=["Registrar","Creation Date","Expiry Date","Domain Age (days)","Registrant Country"])

#     return (
#         # Summary boxes
#         # Summary boxes
#     f'<div class="info-box"><strong style="color: #2980b9;">URL</strong><br><span style="color: white; background-color: #27ae60; padding: 2px 5px; border-radius: 3px;">{url_value}</span></div>',
#     f'<div class="info-box"><strong style="color: #2980b9;">Resolved IP</strong><br><span style="color: white; background-color: #27ae60; padding: 2px 5px; border-radius: 3px;">{ip_value}</span></div>',
#     f'<div class="info-box"><strong style="color: #2980b9;">Country</strong><br><span style="color: white; background-color: #27ae60; padding: 2px 5px; border-radius: 3px;">{country_value}</span></div>',
#     f'<div class="info-box"><strong style="color: #2980b9;">A Records</strong><br><span style="color: white; background-color: #27ae60; padding: 2px 5px; border-radius: 3px;">{a_rec_value}</span></div>',
#     '<div class="info-box"><strong style="color: #2980b9;">MX Records</strong><br><span style="color: white; background-color: #27ae60; padding: 2px 5px; border-radius: 3px;">N/A</span></div>',  # Placeholder
#     '<div class="info-box"><strong style="color: #2980b9;">HTTPS</strong><br><span style="color: white; background-color: #27ae60; padding: 2px 5px; border-radius: 3px;">N/A</span></div>',      # Placeholder
#     '<div class="info-box"><strong style="color: #2980b9;">Cert Issuer</strong><br><span style="color: white; background-color: #27ae60; padding: 2px 5px; border-radius: 3px;">N/A</span></div>',# Placeholder
#     '<div class="info-box"><strong style="color: #2980b9;">Expiry Date</strong><br><span style="color: white; background-color: #27ae60; padding: 2px 5px; border-radius: 3px;">N/A</span></div>',# Placeholder
        
#         # Dataframes
#         whois_df,
#         pd.DataFrame([["N/A"]*5], columns=["Issuer","TLS Versions","Days to Expiry","Hosting ASN","CDN"]),
#         pd.DataFrame([["N/A"]*3], columns=["CMS","Frameworks","Libraries"]),
#         pd.DataFrame([["N/A"]*4], columns=["HTML Size (KB)","# Scripts","# External Links","# Forms"]),
#         pd.DataFrame([["N/A"]*2], columns=["Blacklist Hits","Alexa Rank"])
#     )