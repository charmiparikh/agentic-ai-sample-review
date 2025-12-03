import re
import requests
import socket
from urllib.parse import urlparse

TRUSTED_DOMAIN = "example.com"
USER_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{3,32}$")  # strict pattern, adjust as needed

def is_private_ip(hostname):
    try:
        ip = socket.gethostbyname(hostname)
        # Check for private/internal IPs
        if ip.startswith("127.") or ip.startswith("169.254.") or ip == "::1":
            return True
        # Check for IPv6 loopback
        if ip == "0:0:0:0:0:0:0:1":
            return True
        return False
    except Exception:
        return True  # treat resolution errors as unsafe

def fetch_user_data(user_id, user_authenticated=False, user_authorized=False):
    # Validate authentication and authorization
    if not user_authenticated or not user_authorized:
        raise PermissionError("User not authenticated or authorized.")

    # Validate user_id
    if not user_id or len(user_id) < 3:
        raise ValueError("Invalid user id")
    if not USER_ID_PATTERN.fullmatch(user_id):
        raise ValueError("User id contains invalid characters or format.")

    # Mask user_id (simple pseudonymization example)
    masked_user_id = re.sub(r'(?<=.{2}).', '*', user_id)

    # Build and validate URL
    url = f"https://{TRUSTED_DOMAIN}/api/{masked_user_id}"
    parsed = urlparse(url)
    if parsed.hostname != TRUSTED_DOMAIN:
        raise ValueError("Untrusted domain in URL.")
    if is_private_ip(parsed.hostname):
        raise ValueError("Refusing to connect to private/internal network.")

    try:
        response = requests.get(
            url,
            timeout=3  # Reduced timeout
        )
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        # Log error, mask details in production
        raise RuntimeError("Failed to fetch user data from API.") from None
