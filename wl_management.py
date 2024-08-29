import requests
import json
import os
import hashlib
import configparser

BASE_URL = os.environ.get('API_BASE_URL', 'https://api.hosting.kinode.net')
CLIENT_ID = os.environ.get('API_CLIENT_ID', '2')
CONFIG_FILE = 'config.ini'

def load_config():
    config = configparser.ConfigParser()
    if os.path.exists(CONFIG_FILE):
        config.read(CONFIG_FILE)
        return config.get('AUTH', 'TOKEN', fallback=None)
    return None

def save_config(token):
    config = configparser.ConfigParser()
    config['AUTH'] = {'TOKEN': token}
    with open(CONFIG_FILE, 'w') as configfile:
        config.write(configfile)

TOKEN = load_config()

def make_authenticated_request(method, endpoint, data=None, auth_required=True):
    url = f"{BASE_URL}{endpoint}"
    headers = {
        'client_id': CLIENT_ID,
        'Content-Type': 'application/json'
    }
    if auth_required:
        if not TOKEN:
            print("No token available. Please log in first.")
            return None
        headers['authorization'] = f'bearer {TOKEN}'
    
    response = requests.request(method, url, headers=headers, json=data)
    if response.ok:
        return response.json()
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return None

def sha256_hash(password):
    return '0x' + hashlib.sha256(password.encode()).hexdigest()

def operator_login():
    global TOKEN
    email = input("Enter your email: ")
    password = input("Enter your password: ")
    hashed_password = sha256_hash(password)
    
    data = {
        'email': email,
        'password': hashed_password
    }
    
    result = make_authenticated_request('POST', '/operator/login', data, auth_required=False)
    if result and 'token' in result:
        TOKEN = result['token']
        save_config(TOKEN)
        print("Login successful. Token updated.")
    else:
        print("Login failed.")

def get_active_users():
    return make_authenticated_request('GET', '/operator/active-users')

def get_whitelisted_users():
    return make_authenticated_request('GET', '/operator/whitelisted-users')

def add_whitelisted_user(twitter_name):
    return make_authenticated_request('POST', '/operator/add-whitelisted-user', {'twitterName': twitter_name})

def update_whitelisted_user(user_id, twitter_name):
    return make_authenticated_request('PUT', f'/operator/update-whitelisted-user/{user_id}', {'twitterName': twitter_name})

def delete_whitelisted_user(user_id):
    return make_authenticated_request('DELETE', f'/operator/delete-whitelisted-user/{user_id}')

def print_users(users):
    if users:
        print(json.dumps(users, indent=2))
    else:
        print("No users found or unable to fetch users.")

def main():
    while True:
        print("\nWhitelist Management")
        print("1. View active users")
        print("2. View whitelisted users")
        print("3. Add user to whitelist")
        print("4. Update whitelisted user")
        print("5. Delete user from whitelist")
        print("6. Operator Login")
        print("7. Exit")

        choice = input("Enter your choice (1-7): ")

        if choice == '1':
            users = get_active_users()
            print_users(users)
        elif choice == '2':
            users = get_whitelisted_users()
            print_users(users)
        elif choice == '3':
            twitter_name = input("Enter the Twitter name to add: ")
            result = add_whitelisted_user(twitter_name)
            if result:
                print("User added successfully:")
                print(json.dumps(result, indent=2))
            else:
                print("Failed to add user")
        elif choice == '4':
            user_id = input("Enter the user ID to update: ")
            twitter_name = input("Enter the new Twitter name: ")
            result = update_whitelisted_user(user_id, twitter_name)
            if result:
                print("User updated successfully:")
                print(json.dumps(result, indent=2))
            else:
                print("Failed to update user")
        elif choice == '5':
            user_id = input("Enter the user ID to delete: ")
            result = delete_whitelisted_user(user_id)
            if result:
       
