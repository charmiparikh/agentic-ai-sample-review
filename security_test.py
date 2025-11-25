import requests
import ipaddress
from urllib.parse import urlparse

TRUSTED_DOMAINS = {"example.com"}

def is_safe_domain(url):
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False
        # Check if hostname is an IP address
        try:
            ip = ipaddress.ip_address(hostname)
            # Block private/internal networks
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return False
        except ValueError:
            # Not an IP, check domain allowlist
            # Only allow trusted domains
            domain_parts = hostname.split('.')
            for trusted in TRUSTED_DOMAINS:
                if hostname == trusted or hostname.endswith('.' + trusted):
                    return True
            return False
        return True
    except Exception:
        return False

def fetch_user_data(user_id):
    if not user_id or len(user_id) < 3:
        raise ValueError("Invalid user id")

    # Avoid including PII in URL, use POST and mask user_id
    url = "https://example.com/api/userdata"
    if not is_safe_domain(url):
        raise ValueError("Unsafe URL or domain")

    # Mask user_id (e.g., hash or partial)
    masked_user_id = user_id[:2] + "***"

    response = requests.post(
        url,
        json={"user_id": masked_user_id},
        timeout=10
    )
    return response
