import requests
import logging
import socket
import ipaddress
import time

# Trusted domains allowlist
TRUSTED_DOMAINS = {"example.com"}

# Configure audit logger
audit_logger = logging.getLogger("audit")
audit_logger.setLevel(logging.INFO)
handler = logging.FileHandler("audit.log")
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
handler.setFormatter(formatter)
audit_logger.addHandler(handler)

def is_trusted_domain(url):
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False
        # Check if domain is in allowlist
        domain = hostname.lower()
        for trusted in TRUSTED_DOMAINS:
            if domain == trusted or domain.endswith("." + trusted):
                return True
        return False
    except Exception:
        return False

def is_private_ip(hostname):
    try:
        # Resolve hostname to IP
        ip = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip)
        # Check for private/internal IP ranges
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            return True
        return False
    except Exception:
        return True  # Treat resolution errors as private for safety

def mask_user_id(user_id):
    # Simple pseudonymization: hash the user_id
    import hashlib
    return hashlib.sha256(user_id.encode()).hexdigest()

def fetch_user_data(user_id, current_user):
    if not user_id or len(user_id) < 3:
        # Handle errors gracefully, avoid exposing internal details
        raise ValueError("Invalid user id provided.")

    # Authentication and authorization check
    if not current_user or not current_user.is_authenticated or not current_user.has_permission("fetch_user_data"):
        raise PermissionError("Unauthorized access.")

    # Mask user_id before transmitting
    masked_user_id = mask_user_id(user_id)

    url = f"https://example.com/api/{masked_user_id}"

    # Validate URL against allowlist
    if not is_trusted_domain(url):
        raise ValueError("Untrusted domain in URL.")

    # Block requests to private/internal networks
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if is_private_ip(parsed.hostname):
        raise ValueError("Blocked request to private/internal network.")

    # Audit logging
    audit_logger.info(f"API call: fetch_user_data for masked_user_id={masked_user_id} by user={getattr(current_user, 'username', 'unknown')}")

    # Retry logic with exponential backoff
    max_retries = 3
    backoff = 1
    for attempt in range(max_retries):
        try:
            response = requests.get(
                url,
                timeout=3  # Reduced timeout
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            if attempt == max_retries - 1:
                # Handle errors gracefully, avoid exposing internal details
                raise RuntimeError("Failed to fetch user data from external service.") from None
            time.sleep(backoff)
            backoff *= 2
