# ssl_hosting.py
# SSL/TLS & Hosting Metadata retrieval for StealthPhisher2025 pipeline

import socket
import ssl
import requests
from datetime import datetime, timezone
API_TOKEN = "412835848d5287"  # to remove

def format_domain_age(age_days: int) -> str:
    """
    Converts domain age in days to a human-readable format: years, months, days.
    """
    years = age_days // 365
    remaining_days = age_days % 365
    months = remaining_days // 30
    days = remaining_days % 30
    return f"{years} years, {months} months, {days} days"

def get_ssl_info(domain: str, port: int = 443, timeout: int = 5) -> dict:
    """
    Establishes an SSL connection to retrieve certificate details:
      - CertIssuer: the certificate issuer.
      - ValidFrom, ValidTo: the validity period of the certificate.
      - DaysUntilExpiry: raw number of days until expiry.
      - ValidityPeriod: the days_until_expiry converted to a human-readable format (years, months, days).
      
    If an error occurs during the connection or retrieval, the function returns a dictionary with an error message.
    """
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
    except Exception as e:
        return {"error": str(e)}

    # Parse the certificate validity dates and make them timezone-aware.
    not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)

    days_valid = (not_after - datetime.now(timezone.utc)).days
    validity_period = format_domain_age(days_valid)

    return {
        "HasSSL": 1,
        "CertIssuer": cert.get('issuer'),
        "ValidFrom": not_before,
        "ValidTo": not_after,
        "DaysUntilExpiry": days_valid,
        "ValidityPeriod": validity_period
    }



def get_ip_geolocation_info(domain: str, api_token: str=API_TOKEN) -> dict: 
    """
    Resolves a domain to its unique IP address(es) and fetches geolocation info for one IP.
    
    Process:
      - Uses socket.getaddrinfo to resolve the domain.
      - Returns a list of unique IPs and their count.
      - If at least one IP is found, fetches geolocation information for the first IP using ipinfo.io.
      
    Parameters:
      - domain: The domain to resolve.
      - api_token: Optional API token for the ipinfo.io service if required.
      
    Returns a dictionary containing:
      - "IPAddresses": List of resolved IP addresses.
      - "IPCount": The number of unique IP addresses.
      - "Geolocation": Geolocation information for the first IP address (if available).
    """
    # Resolve domain to IP addresses
    try:
        infos = socket.getaddrinfo(domain, None)
        ips = list({info[4][0] for info in infos})
    except Exception as e:
        return {"error": f"Error resolving domain: {str(e)}"}
    
    ip_count = len(ips)
    result = {
        "IPAddresses": ips,
        "IPCount": ip_count,
    }
    
    if ip_count > 0:
        # Fetch geolocation information for the first IP
        ip = ips[0]
        url = f"https://ipinfo.io/{ip}/json"
        headers = {"Authorization": f"Bearer {api_token}"} if api_token else {}
        try:
            response = requests.get(url, headers=headers, timeout=5)
            data = response.json()
        except Exception as e:
            result["Geolocation"] = {"error": f"Failed to retrieve geolocation data: {str(e)}"}
        else:
            result["Geolocation"] = {
                "IP": ip,
                "Country": data.get('country'),
                "Region": data.get('region'),
                "City": data.get('city'),
                "Org": data.get('org'),
                "ASN": data.get('org').split(' ')[0] if data.get('org') else None
            }
    
    return result



# def get_shodan_info(ip: str, api_key: str) -> dict:
#     """
#     Queries Shodan API to retrieve open ports, services, and banner info.
#     Requires a valid `api_key`.
#     """
#     url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
#     try:
#         resp = requests.get(url, timeout=5)
#         data = resp.json()
#     except Exception as e:
#         return {"error": str(e)}

#     ports = data.get('ports', [])
#     services = [s.get('product') or s.get('data') for s in data.get('data', [])]

#     return {
#         "OpenPorts": ports,
#         "Services": services,
#         "LastUpdate": data.get('last_update')
#     }


if __name__ == "__main__":
    # Example usage
    test_domain = "https://www.linkedin.com/company/researchgate/"


    ssl_info = get_ssl_info(test_domain)
    print("SSL Info:\n", ssl_info)

    # # Assume you obtained IP via DNS lookup elsewhere
    # test_ip = "93.184.216.34"
    # geo_info = get_ip_geolocation(test_ip)
    # print("Geolocation Info:", geo_info)

    # For Shodan, set your API key
    # shodan_info = get_shodan_info(test_ip, api_key="YOUR_KEY_HERE")
    # print("Shodan Info:", shodan_info)
