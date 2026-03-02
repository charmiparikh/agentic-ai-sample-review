import os
import requests

def get_data(user_id):
    if not user_id or len(user_id) < 3:
        raise ValueError("Invalid user id")

    response = requests.get(
        f"https://example.com/api/{user_id}",
        timeout=10
    )
    return response.json()
