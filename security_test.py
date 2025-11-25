import os

def get_password():
    pwd = os.environ.get('ADMIN_PASSWORD')
    if pwd is None:
        raise ValueError("ADMIN_PASSWORD environment variable not set")
    return pwd
