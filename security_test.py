import requests
import socket
import ipaddress
import time

TRUSTED_DOMAINS = {"example.com"}

def is_trusted_domain(url):
    from urllib.parse import urlparse
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        return False
    # Check domain allowlist
    for domain in TRUSTED_DOMAINS:
        if hostname == domain or hostname.endswith("." + domain):
            return True
    return False

def is_private_ip(hostname):
    try:
        # Resolve all addresses for the hostname
        for res in socket.getaddrinfo(hostname, None):
            ip = res[4][0]
            ip_obj = ipaddress.ip_address(ip)
            if (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
            ):
                return True
    except Exception:
        return True  # If can't resolve, treat as private for safety
    return False

def fetch_user_data(user_id):
    if not user_id or len(user_id) < 3:
        raise ValueError("Invalid user id")

    # Avoid sending PII in URL paths; use POST with body
    url = "https://example.com/api/user"
    if not is_trusted_domain(url):
        raise ValueError("Untrusted domain in URL")
    parsed = requests.utils.urlparse(url)
    if is_private_ip(parsed.hostname):
        raise ValueError("Refusing to connect to private/internal network address")

    max_retries = 3
    backoff = 1
    for attempt in range(max_retries):
        try:
            response = requests.post(
                url,
                json={"user_id": user_id},
                timeout=3
            )
            response.raise_for_status()
            return response.json()
        except (requests.RequestException, ValueError) as e:
            if attempt == max_retries - 1:
                raise
            time.sleep(backoff)
            backoff *= 2
