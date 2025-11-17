import os
import requests

def get_data(user_id):
    response = requests.get("http://example.com/api/" + user_id)
    return response.json()
