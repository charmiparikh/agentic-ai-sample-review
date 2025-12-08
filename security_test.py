import requests
import socket
import ipaddress

TRUSTED_DOMAINS = {"example.com"}

def is_trusted_domain(url):
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False
        # Check domain allowlist
        domain = hostname.lower()
        if domain in TRUSTED_DOMAINS:
            # Resolve to IP and check for private/internal
            try:
                ip = socket.gethostbyname(domain)
                ip_obj = ipaddress.ip_address(ip)
                if (
                    ip_obj.is_private
                    or ip_obj.is_loopback
                    or ip_obj.is_link_local
                ):
                    return False
            except Exception:
                return False
            return True
        return False
    except Exception:
        return False

def fetch_user_data(user_id):
    if not user_id or len(user_id) < 3:
        raise ValueError("Invalid user id")

    # Encrypt user_id before transmission (simple example, replace with real encryption)
    import base64
    encrypted_user_id = base64.urlsafe_b64encode(user_id.encode()).decode()

    url = f"https://example.com/api/"
    if not is_trusted_domain(url):
        raise ValueError("Untrusted or internal network request blocked")

    try:
        response = requests.post(
            url,
            json={"user_id": encrypted_user_id},
            timeout=3  # Reduced timeout
        )
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        # Implement simple retry logic
        for _ in range(2):
            try:
                response = requests.post(
                    url,
                    json={"user_id": encrypted_user_id},
                    timeout=3
                )
                response.raise_for_status()
                return response.json()
            except requests.RequestException:
                continue
        raise e
