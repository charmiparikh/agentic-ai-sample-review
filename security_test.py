import re
import requests
import logging

TRUSTED_API_DOMAIN = "example.com"
USER_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{3,32}$")  # strict pattern, adjust as needed

def is_private_network(host):
    # Check for private/internal IPs and localhost
    private_patterns = [
        r"^127\.",         # IPv4 localhost
        r"^169\.254\.",    # IPv4 link-local
        r"^::1$",          # IPv6 localhost
        r"^localhost$",    # localhost
    ]
    for pat in private_patterns:
        if re.match(pat, host):
            return True
    return False

def mask_user_id(user_id):
    # Simple pseudonymization: hash or mask, here we just mask all but last 2 chars
    if len(user_id) > 2:
        return "*" * (len(user_id) - 2) + user_id[-2:]
    return "*" * len(user_id)

def fetch_user_data(user_id, auth_token=None):
    try:
        if not user_id or len(user_id) < 3:
            raise ValueError("Invalid user id")

        # Strict validation of user_id
        if not USER_ID_PATTERN.match(user_id):
            raise ValueError("User id format not allowed")

        # Mask user_id for logging
        masked_id = mask_user_id(user_id)

        # Audit logging
        logging.info(f"API access requested for user_id: {masked_id}")

        # Build URL safely
        api_url = f"https://{TRUSTED_API_DOMAIN}/api/{user_id}"

        # Parse host for SSRF protection
        from urllib.parse import urlparse
        parsed = urlparse(api_url)
        host = parsed.hostname
        if is_private_network(host):
            raise ValueError("Blocked request to private/internal network")

        # Authentication/Authorization check
        if not auth_token or not isinstance(auth_token, str) or len(auth_token) < 10:
            raise PermissionError("Missing or invalid authentication token")

        # Retry logic with exponential backoff
        import time
        max_retries = 3
        backoff = 0.5
        for attempt in range(max_retries):
            try:
                response = requests.get(
                    api_url,
                    timeout=3,  # Reduced timeout
                    headers={"Authorization": f"Bearer {auth_token}"}
                )
                response.raise_for_status()
                return response.json()
            except requests.RequestException as e:
                if attempt < max_retries - 1:
                    time.sleep(backoff)
                    backoff *= 2
                    continue
                logging.error(f"API request failed for user_id {masked_id}: {e}")
                raise RuntimeError("Failed to fetch user data. Please try again later.")
    except Exception as ex:
        # Graceful error handling, no stack trace exposure
        logging.error(f"Error in fetch_user_data: {ex}")
        return {"error": "Unable to process request."}
