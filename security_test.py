import re
import requests

TRUSTED_DOMAINS = {"example.com"}

def is_trusted_domain(url):
    # Extract domain from URL
    match = re.match(r"https?://([^/]+)/", url)
    if not match:
        return False
    domain = match.group(1)
    # Remove port if present
    domain = domain.split(":")[0]
    return domain in TRUSTED_DOMAINS

def is_private_ip(user_id):
    # Block requests to private/internal networks by user_id
    # Since user_id is used in the URL, ensure it's not an IP in private ranges
    # Only allow alphanumeric user_ids
    if not re.match(r"^[a-zA-Z0-9_-]+$", user_id):
        return True
    return False

def fetch_user_data(user_id):
    if not user_id or len(user_id) < 3:
        raise ValueError("Invalid user id")

    if is_private_ip(user_id):
        raise ValueError("Potential SSRF or invalid user id detected")

    url = f"https://example.com/api/"
    if not is_trusted_domain(url):
        raise ValueError("Untrusted domain in URL")

    # Do not include PII in URL paths; send user_id in POST body
    try:
        response = requests.post(
            url,
            json={"user_id": user_id},
            timeout=3  # Reduced timeout
        )
        response.raise_for_status()
    except requests.RequestException as e:
        # Implement simple retry logic
        try:
            response = requests.post(
                url,
                json={"user_id": user_id},
                timeout=3
            )
            response.raise_for_status()
        except requests.RequestException as e2:
            raise RuntimeError(f"Failed to fetch user data: {e2}") from e2

    return response.json()
