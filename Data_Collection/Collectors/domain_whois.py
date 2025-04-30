# domain_whois.py
# Domain & WHOIS Intelligence retrieval for StealthPhisher2025 pipeline

import tldextract
import whois
import requests
import socket
from datetime import datetime, timezone
import requests

def parse_domain(url: str) -> dict:
    """
    Extracts various domain-related features from a URL.
    
    Returns a dictionary with:
      - URL: the original URL.
      - Domain: the base domain (domain + suffix).
      - DomainLengthOfURL: length (in characters) of the domain.
      - IsDomainIP: integer flag (1 if the domain is an IP address, else 0).
      - TLD: top-level domain extracted.
      - TLDLength: length (in characters) of the TLD.
      - NumberOfSubdomains: count of subdomains present.
    """
    extracted = tldextract.extract(url)
    
    # Recombine domain and suffix to form the base domain.
    # Using filter(bool, ...) removes any empty strings.
    base_domain = ".".join(filter(bool, [extracted.domain, extracted.suffix]))
    
    # Count subdomains by splitting the subdomain string and filtering out empty parts.
    number_of_subdomains = len([s for s in extracted.subdomain.split('.') if s]) if extracted.subdomain else 0
    
    # Check if the domain is an IP address by testing if every segment is numeric.
    is_domain_ip = int(all(seg.isdigit() for seg in base_domain.split('.')))
    
    return {
        "URL": url,
        "Domain": base_domain,
        "DomainLengthOfURL": len(base_domain),
        "IsDomainIP": is_domain_ip,
        "TLD": extracted.suffix,
        "TLDLength": len(extracted.suffix) if extracted.suffix else 0,
        "NumberOfSubdomains": number_of_subdomains,
    }


def get_ip_addresses(domain: str) -> dict:
    """
    Resolves a domain to its IP address(es) using socket.
    Returns a list of unique IPs.
    """
    try:
        infos = socket.getaddrinfo(domain, None)
        ips = list({info[4][0] for info in infos})
    except Exception as e:
        return {"error": str(e)}
    return {"IPAddresses": ips}


def format_domain_age(age_days: int) -> str:
    """
    Converts domain age in days to a human-readable format: years, months, days.
    """
    years = age_days // 365
    remaining_days = age_days % 365
    months = remaining_days // 30
    days = remaining_days % 30
    return f"{years} years, {months} months, {days} days"

def get_whois_info(domain: str) -> dict:
    """
    Retrieves WHOIS record for a given domain.
    Returns:
      - Registrar: the domain registrar.
      - CreationDate: when the domain was created.
      - ExpirationDate: when the domain will expire.
      - UpdatedDate: last updated date, if available.
      - DomainAge: age in a human-readable format.
      - DomainAgeDays: raw age in days.
      - Status: the domain status.
      - Emails: contact emails from the WHOIS record.
      - NameServers: list of name servers.
      - DNSSEC: DNSSEC status.
      - Registrant: organization or registrant information.
      - Country: Country information, if provided.
    """
    try:
        w = whois.whois(domain)
    except Exception as e:
        return {"error": str(e)}

    # Handle creation, expiration and updated dates (which may be lists)
    creation = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
    expiration = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
    updated = None
    if hasattr(w, "updated_date"):
        updated = w.updated_date[0] if isinstance(w.updated_date, list) else w.updated_date

    age_days = None
    domain_age_formatted = None
    if creation:
        # If the creation date is naive, make it timezone aware.
        if creation.tzinfo is None:
            creation = creation.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - creation).days
        domain_age_formatted = format_domain_age(age_days)

    return {
        "Registrar": w.registrar,
        "CreationDate": creation,
        "ExpirationDate": expiration,
        "UpdatedDate": updated,
        "DomainAge": domain_age_formatted,
        "DomainAgeDays": age_days,
        "Status": w.status,
        "Emails": w.emails,
        "NameServers": w.name_servers if hasattr(w, "name_servers") else None,
        "DNSSEC": w.dnssec if hasattr(w, "dnssec") else None,
        "Registrant": w.org if hasattr(w, "org") else None,
        "Country": w.country if hasattr(w, "country") else None
    }

def get_passive_dns(domain: str) -> dict:
    """
    Uses Google DNS-over-HTTPS to fetch A-records and TTLs for the domain.
    Additionally, computes aggregated features including:
      - A_record_count: number of A-records.
      - Avg_TTL: average TTL of the A-records.
      - Min_TTL: minimum TTL seen.
      - Max_TTL: maximum TTL seen.
    Returns a dictionary containing the A_records and TTL statistics.
    """
    endpoint = "https://dns.google/resolve"
    params = {"name": domain, "type": "A"}
    try:
        resp = requests.get(endpoint, params=params, timeout=5)
        data = resp.json()
    except Exception as e:
        return {"error": str(e)}

    records = []
    for ans in data.get("Answer", []):
        records.append({
            "address": ans.get("data"),
            "ttl": ans.get("TTL")
        })

    # Compute TTL aggregated values if available.
    ttl_values = [record["ttl"] for record in records if record.get("ttl") is not None]
    if ttl_values:
        avg_ttl = sum(ttl_values) / len(ttl_values)
        min_ttl = min(ttl_values)
        max_ttl = max(ttl_values)
    else:
        avg_ttl = None
        min_ttl = None
        max_ttl = None

    return {
        "A_records": records,
        "A_record_count": len(records),
        "Avg_TTL": avg_ttl,
        "Min_TTL": min_ttl,
        "Max_TTL": max_ttl
    }


if __name__ == "__main__":
    # Example usage
    test_url = "https://github.com/"
    print("Test URL:", test_url)

    dom = parse_domain(test_url)
    print("Parsed Domain:", dom)

    ip_info = get_ip_addresses(dom["Domain"])

    print("IP Addresses:", ip_info)

    whois_info = get_whois_info(dom["Domain"])
    print("WHOIS Info:", whois_info)

    dns_info = get_passive_dns(dom["Domain"])
    print("Passive DNS A records:", dns_info)
