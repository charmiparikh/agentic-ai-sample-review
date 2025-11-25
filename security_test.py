import os
import requests
import re
from urllib.parse import urljoin
from ipaddress import ip_address, IPv4Address, IPv6Address

# Allowlist of trusted domains
TRUSTED_DOMAINS = {"example.com"}

def is_private_ip(host):
    try:
        ip = ip_address(host)
        # Check for private, loopback, link-local addresses
        return (
            ip.is_private or
            ip.is_loopback or
            ip.is_link_local
        )
    except ValueError:
        return False

def is_trusted_domain(host):
    # Only allow exact matches to trusted domains
    return host in TRUSTED_DOMAINS

def mask_user_id(user_id):
    # Mask all but last 4 characters
    if len(user_id) <= 4:
        return "*" * len(user_id)
    return "*" * (len(user_id) - 4) + user_id[-4:]

def get_data(user_id, api_token=None):
    """
    Fetch data for a user from a trusted API endpoint.

    Args:
        user_id (str): The user identifier (will be masked).
        api_token (str, optional): Bearer token for authentication.

    Returns:
        dict: The JSON response from the API.

    Raises:
        ValueError: If the domain is not trusted or IP is private/internal.
    """
    # Mask user_id before transmission
    masked_user_id = mask_user_id(user_id)

    # Build the URL securely
    base_url = "https://example.com/api/"
    url = urljoin(base_url, masked_user_id)

    # Extract host for validation
    host_match = re.match(r"https://([^/]+)/", url)
    if not host_match:
        raise ValueError("Invalid URL constructed.")
    host = host_match.group(1)

    # Validate against allowlist and block private/internal networks
    if not is_trusted_domain(host):
        raise ValueError("Untrusted domain.")
    if is_private_ip(host):
        raise ValueError("Blocked private/internal network address.")

    headers = {}
    # Add authentication if provided
    if api_token:
        headers["Authorization"] = f"Bearer {api_token}"

    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()
