import requests
import logging
import socket
import ipaddress
from urllib.parse import urlparse

# Configure audit logging
logging.basicConfig(
    filename='audit.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s'
)

TRUSTED_DOMAINS = {"example.com"}

def is_private_address(hostname):
    try:
        # Resolve the hostname to an IP address
        ip = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip)
        # Check for private, loopback, or link-local addresses
        return (
            ip_obj.is_private or
            ip_obj.is_loopback or
            ip_obj.is_link_local
        )
    except Exception:
        return True  # If resolution fails, treat as unsafe

def is_trusted_domain(url):
    try:
        parsed = urlparse(url)
        domain = parsed.hostname
        return domain in TRUSTED_DOMAINS
    except Exception:
        return False

def anonymize_user_id(user_id):
    # Simple anonymization: hash the user_id (for demonstration)
    import hashlib
    return hashlib.sha256(user_id.encode()).hexdigest()

def has_permission(user_id):
    # Placeholder for real access control logic
    # For demonstration, allow all users with anonymized id
    return True

def fetch_user_data(user_id):
    if not user_id or len(user_id) < 3:
        raise ValueError("Invalid user id")

    # Audit log the access attempt
    logging.info(f"User data fetch requested for user_id: {user_id}")

    # Anonymize user_id before transmission
    anon_user_id = anonymize_user_id(user_id)

    # Access control check
    if not has_permission(user_id):
        logging.warning(f"Unauthorized access attempt for user_id: {user_id}")
        raise PermissionError("Unauthorized access")

    url = f"https://example.com/api/{anon_user_id}"

    # Validate URL
    parsed_url = urlparse(url)
    if not is_trusted_domain(url) or is_private_address(parsed_url.hostname):
        logging.error(f"Blocked request to untrusted or private address: {url}")
        raise ValueError("Request to untrusted or private address is not allowed")

    try:
        response = requests.get(
            url,
            timeout=3  # Reduced timeout to 3 seconds
        )
        response.raise_for_status()
        # Audit log successful fetch
        logging.info(f"Successfully fetched data for user_id: {user_id}")
        return response.json()
    except requests.RequestException as e:
        logging.error(f"Failed to fetch data for user_id: {user_id}: {e}")
        # Implement simple retry logic (1 retry)
        try:
            response = requests.get(
                url,
                timeout=3
            )
            response.raise_for_status()
            logging.info(f"Retry successful for user_id: {user_id}")
            return response.json()
        except requests.RequestException as e2:
            logging.error(f"Retry failed for user_id: {user_id}: {e2}")
            raise RuntimeError("Failed to fetch user data after retry") from e2
