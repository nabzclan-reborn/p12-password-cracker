#!/usr/bin/env python3
"""
P12 Password Cracker & Changer - A tool to crack and change passwords for P12/PKCS#12 certificate files
utilizing the Nabzclan Developer API. 

This script allows users to:
1. Crack P12 file passwords using:
   - Smart mode (common P12 passwords)
   - Single password verification
   - Custom wordlist from a local file or URL
2. Change P12 file passwords after finding the correct password
"""

import argparse
import json
import sys
import os
import requests
from dotenv import load_dotenv
from colorama import init, Fore, Style

init(autoreset=True)
load_dotenv()

API_BASE_URL = "https://developer.nabzclan.vip/api"
VERIFY_ENDPOINT = f"{API_BASE_URL}/p12-verify"
CRACK_ENDPOINT = f"{API_BASE_URL}/p12-crack"
CHANGE_ENDPOINT = f"{API_BASE_URL}/p12passwordchanger"
USER_ENDPOINT = f"{API_BASE_URL}/user"

API_KEY = os.getenv("API_KEY")
if not API_KEY:
    print(f"{Fore.YELLOW}[!] Warning: API_KEY not found in .env file.")



def display_banner():
    """Display an attractive banner when the script starts."""
    banner = f"""
{Fore.CYAN}╔════════════════════════════════════════════════════════╗
{Fore.CYAN}║                                                        ║
{Fore.CYAN}║  {Fore.YELLOW}P12 Password Cracker & Changer {Fore.GREEN}v2.0               {Fore.CYAN}    ║
{Fore.CYAN}║  {Fore.WHITE}Powered by Nabzclan Developer API                     {Fore.CYAN}║
{Fore.CYAN}║                                                        ║
{Fore.CYAN}║                                                        ║
{Fore.CYAN}╚════════════════════════════════════════════════════════╝
"""
    print(banner)


def get_user_profile():
    """
    Get the authenticated user's profile and plan status.
    
    Returns:
        dict: User profile data including plan info, or None if failed
    """
    headers = {
        'Authorization': f'Bearer {API_KEY}',
        'Accept': 'application/json',
        'User-Agent': 'P12PasswordCracker/2.0'
    }
    
    try:
        response = requests.get(USER_ENDPOINT, headers=headers, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            print(f"{Fore.RED}[!] Authentication failed. Please check your API key.")
        else:
            print(f"{Fore.RED}[!] Failed to get user profile: {e}")
        return None
    except Exception as e:
        print(f"{Fore.RED}[!] Error getting user profile: {e}")
        return None


def is_vip_user():
    """
    Check if the current user has a VIP plan.
    
    Returns:
        tuple: (is_vip boolean, plan_name string or None)
    """
    profile = get_user_profile()
    if profile and 'plan' in profile:
        plan_name = profile['plan'].get('name', 'Free')
        is_vip = 'vip' in plan_name.lower()
        return is_vip, plan_name
    return False, None


def show_usage_info():
    """Display the user's current API usage information."""
    profile = get_user_profile()
    if profile:
        plan = profile.get('plan', {})
        usage = profile.get('usage', {})
        
        today = usage.get('today', 0)
        limit = usage.get('limit', 0)
        remaining = usage.get('remaining', 0)
        
        # Handle unlimited plans (VIP 4 returns -1)
        limit_display = "Unlimited" if limit == -1 else str(limit)
        remaining_display = "Unlimited" if remaining == -1 else str(remaining)
        
        print(f"{Fore.CYAN}[*] User: {profile.get('name', 'Unknown')}")
        print(f"{Fore.CYAN}[*] Nabzclan ID: {profile.get('nabzclan_user_id', 'N/A')}")
        print(f"{Fore.CYAN}[*] Plan: {plan.get('name', 'Free')}")
        print(f"{Fore.CYAN}[*] Daily Limit: {limit_display}")
        print(f"{Fore.CYAN}[*] Used Today: {today}")
        print(f"{Fore.CYAN}[*] Remaining: {remaining_display}")
        return True
    return False



def verify_p12_password(p12_file_path, password):
    """
    Verify a single password for a P12 file using the Nabzclan Developer API.
    
    Args:
        p12_file_path (str): Path to the local P12 file
        password (str): Password to verify
        
    Returns:
        tuple: (success boolean, password string or None, error message or None)
    """
    headers = {
        'Authorization': f'Bearer {API_KEY}',
        'User-Agent': 'P12PasswordCracker/2.0'
    }
    
    print(f"{Fore.CYAN}[*] Verifying password...")
    print(f"{Fore.CYAN}[*] Password: {password[:15]}{'...' if len(password) > 15 else ''}")
    
    try:
        with open(p12_file_path, 'rb') as f:
            files = {'file': (os.path.basename(p12_file_path), f, 'application/x-pkcs12')}
            data = {'password': password}
            
            print(f"{Fore.YELLOW}[*] Sending request to Nabzclan API...")
            response = requests.post(VERIFY_ENDPOINT, headers=headers, files=files, data=data, timeout=120)
            response.raise_for_status()
            
            result = response.json()
            
            if result.get('success') is True and result.get('valid') is True:
                print(f"\n{Fore.GREEN}[+] PASSWORD FOUND: {Fore.WHITE}{result.get('password')}")
                return True, result.get('password'), None
            elif result.get('success') is True and result.get('valid') is False:
                print(f"\n{Fore.YELLOW}[-] Password is incorrect")
                return False, None, {'message': "Password is incorrect", 'valid': False}
            
            print(f"\n{Fore.BLUE}[*] Complete API Response:")
            print(f"{Fore.WHITE}{json.dumps(result, indent=4)}")
            return False, None, "Unexpected response format"
            
    except FileNotFoundError:
        error_msg = f"P12 file not found: {p12_file_path}"
        print(f"{Fore.RED}[!] {error_msg}")
        return False, None, error_msg
        
    except requests.exceptions.HTTPError as e:
        return handle_http_error(e)
        
    except (requests.exceptions.RequestException, json.JSONDecodeError, Exception) as e:
        error_msg = f"Error: {str(e)}"
        print(f"{Fore.RED}[!] {error_msg}")
        return False, None, error_msg


def crack_p12_password(p12_file_path, mode="smart", wordlist=None, wordlist_url=None, 
                       charset=None, min_length=None, max_length=None):
    """
    Attempt to crack the P12 file password using the Nabzclan Developer API.
    
    Args:
        p12_file_path (str): Path to the local P12 file
        mode (str): Cracking mode - 'smart', 'dictionary', or 'brute_force'
        wordlist (list or str): Password list or path to wordlist file
        wordlist_url (str): URL to download wordlist from
        charset (str): Characters for brute force
        min_length (int): Min password length for brute force
        max_length (int): Max password length for brute force
        
    Returns:
        tuple: (success boolean, password string or None, error message or None)
    """
    headers = {
        'Authorization': f'Bearer {API_KEY}',
        'User-Agent': 'P12PasswordCrackernabzclangithub/2.0'
    }
    
    print(f"{Fore.CYAN}[*] Starting password cracking attempt...")
    print(f"{Fore.CYAN}[*] Mode: {mode}")
    
    try:
        with open(p12_file_path, 'rb') as f:
            files = {'file': (os.path.basename(p12_file_path), f, 'application/x-pkcs12')}
            data = {'mode': mode}
            
            # Add wordlist data based on mode
            if mode == 'dictionary':
                if wordlist_url:
                    data['wordlist_url'] = wordlist_url
                    print(f"{Fore.CYAN}[*] Using wordlist URL: {wordlist_url}")
                elif isinstance(wordlist, list):
                    # Pass as array
                    for pw in wordlist:
                        if 'wordlist[]' not in data:
                            data['wordlist[]'] = []
                    print(f"{Fore.CYAN}[*] Using password array with {len(wordlist)} passwords")
                elif wordlist and os.path.exists(wordlist):
                    # Upload wordlist file - need to reopen in the files dict
                    files['wordlist'] = (os.path.basename(wordlist), open(wordlist, 'rb'), 'text/plain')
                    print(f"{Fore.CYAN}[*] Uploading wordlist file: {wordlist}")
            
            # Add brute force params
            if mode == 'brute_force':
                if charset:
                    data['charset'] = charset
                    print(f"{Fore.CYAN}[*] Charset: {charset}")
                if min_length:
                    data['min_length'] = min_length
                if max_length:
                    data['max_length'] = max_length
                print(f"{Fore.CYAN}[*] Length range: {min_length or 1}-{max_length or 4}")
            
            print(f"{Fore.YELLOW}[*] Sending request to Nabzclan API...")
            
            # Handle wordlist array differently
            if mode == 'dictionary' and isinstance(wordlist, list):
                # Need to use special format for array
                response = requests.post(
                    CRACK_ENDPOINT, 
                    headers=headers, 
                    files=files, 
                    data=[('mode', mode)] + [('wordlist[]', pw) for pw in wordlist],
                    timeout=300
                )
            else:
                response = requests.post(CRACK_ENDPOINT, headers=headers, files=files, data=data, timeout=300)
            
            response.raise_for_status()
            
            result = response.json()
            
            if result.get('success') is True and result.get('found') is True:
                print(f"\n{Fore.GREEN}[+] PASSWORD FOUND: {Fore.WHITE}{result.get('password')}")
                print(f"{Fore.GREEN}[+] Attempts: {result.get('attempts', 'unknown')}")
                print(f"{Fore.GREEN}[+] Time taken: {result.get('elapsed_seconds', 'unknown')} seconds")
                print(f"{Fore.GREEN}[+] Speed: {result.get('speed_per_second', 'unknown')} passwords/sec")
                return True, result.get('password'), None
            elif result.get('success') is True and result.get('found') is False:
                print(f"\n{Fore.YELLOW}[-] Password not found")
                print(f"{Fore.YELLOW}[-] Attempts: {result.get('attempts', 'unknown')}")
                return False, None, "Password not found"
            
            # Check for error responses
            if result.get('error'):
                error_msg = result.get('error')
                print(f"\n{Fore.RED}[!] Error: {error_msg}")
                return False, None, result
            
            print(f"\n{Fore.BLUE}[*] Complete API Response:")
            print(f"{Fore.WHITE}{json.dumps(result, indent=4)}")
            return False, None, "Unexpected response format"
            
    except FileNotFoundError:
        error_msg = f"P12 file not found: {p12_file_path}"
        print(f"{Fore.RED}[!] {error_msg}")
        return False, None, error_msg
        
    except requests.exceptions.HTTPError as e:
        return handle_http_error(e)
    
    except requests.exceptions.Timeout:
        error_msg = "Request timed out. The server may be processing a large request."
        print(f"{Fore.RED}[!] {error_msg}")
        print(f"{Fore.YELLOW}[*] Tip: For brute force, try reducing --max-length (max: 6)")
        return False, None, error_msg
    
    except requests.exceptions.ConnectionError:
        error_msg = "Connection error. Please check your internet connection."
        print(f"{Fore.RED}[!] {error_msg}")
        return False, None, error_msg
    
    except json.JSONDecodeError as e:
        error_msg = f"Invalid response from API: {str(e)}"
        print(f"{Fore.RED}[!] {error_msg}")
        print(f"{Fore.YELLOW}[*] The server may have returned an empty or invalid response.")
        print(f"{Fore.YELLOW}[*] This can happen with large brute force requests. Try --max-length 6 or less.")
        return False, None, error_msg
        
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        print(f"{Fore.RED}[!] {error_msg}")
        return False, None, error_msg


def handle_http_error(e):
    """Handle HTTP errors from API requests."""
    status_code = e.response.status_code
    error_msg = None
    
    try:
        error_data = e.response.json()
    except:
        error_data = {}
    
    if status_code == 401:
        error_msg = "Authentication failed. Please check your API key."
        print(f"{Fore.RED}[!] {error_msg}")
        
    elif status_code == 403:
        error_type = error_data.get('error', '')
        
        if error_type == 'feature_not_available':
            error_msg = error_data.get('message', 'This feature requires a VIP subscription')
            print(f"{Fore.RED}[!] {error_msg}")
            allowed = error_data.get('allowed_modes', [])
            if allowed:
                print(f"{Fore.YELLOW}[*] Allowed modes for your plan: {', '.join(allowed)}")
            print(f"{Fore.YELLOW}[*] Upgrade at: https://developer.nabzclan.vip")
            
        elif error_type == 'limit_exceeded':
            error_msg = error_data.get('message', 'Plan limit exceeded')
            print(f"{Fore.RED}[!] {error_msg}")
            limit = error_data.get('limit')
            provided = error_data.get('provided')
            if limit and provided:
                print(f"{Fore.YELLOW}[*] Limit: {limit}, You provided: {provided}")
            print(f"{Fore.YELLOW}[*] Upgrade at: https://developer.nabzclan.vip")
            
        elif error_type == 'policy_agreement_required':
            error_msg = error_data.get('message', 'Policy agreement required')
            print(f"{Fore.RED}[!] {error_msg}")
            agreement_url = error_data.get('agreement_url', 'https://developer.nabzclan.vip/dashboard/policy')
            print(f"{Fore.YELLOW}[*] Please visit: {agreement_url}")
            
        else:
            error_msg = error_data.get('message', 'Access denied')
            print(f"{Fore.RED}[!] {error_msg}")
        
    elif status_code == 429:
        error_msg = error_data.get('message', 'Rate limit exceeded. Please try again later.')
        print(f"{Fore.RED}[!] {error_msg}")
        print(f"{Fore.YELLOW}[*] Upgrade your plan for higher limits: https://developer.nabzclan.vip/plans")
        error_data['error'] = 'rate_limit_exceeded'
        
    elif status_code == 400:
        error_msg = error_data.get('error') or error_data.get('message', 'Bad request')
        print(f"{Fore.RED}[!] {error_msg}")
        
    elif status_code == 500:
        error_msg = "Server error. Please try again later."
        print(f"{Fore.RED}[!] {error_msg}")
        
    else:
        error_msg = f"HTTP Error {status_code}: {e}"
        print(f"{Fore.RED}[!] {error_msg}")
        try:
            print(f"{Fore.RED}[!] Response: {e.response.text[:500]}")
        except:
            pass
    
    if error_data:
        if 'message' not in error_data and error_msg:
             error_data['message'] = error_msg
        return False, None, error_data
        
    return False, None, {'message': error_msg}


def change_p12_password(p12_file_path, old_password, new_password, interactive=True):
    """
    Change P12 password using Nabzclan API
    
    Args:
        p12_file_path (str): Path to P12 file
        old_password (str): Current password
        new_password (str): New password
        interactive (bool): Whether to ask for download input (CLI mode)
        
    Returns:
        tuple: (success boolean, download_url or None, error message or None)
    """
    headers = {
        'Authorization': f'Bearer {API_KEY}',
        'Accept': 'application/json',
        'User-Agent': 'P12PasswordChanger/2.0'
    }
    
    print(f"{Fore.CYAN}[*] Attempting to change P12 password...")
    print(f"{Fore.CYAN}[*] P12 file: {p12_file_path}")
    
    try:
        with open(p12_file_path, 'rb') as f:
            files = {'p12_file': (os.path.basename(p12_file_path), f, 'application/x-pkcs12')}
            data = {
                'old_password': old_password,
                'new_password': new_password
            }
            
            print(f"{Fore.YELLOW}[*] Sending request to Nabzclan API...")
            response = requests.post(CHANGE_ENDPOINT, headers=headers, files=files, data=data, timeout=120)
            response.raise_for_status()
            
            result = response.json()
            
            if result.get('success') is True:
                data_obj = result.get('data', {})
                download_url = data_obj.get('download_url')
                print(f"\n{Fore.GREEN}[+] Password changed successfully!")
                print(f"{Fore.GREEN}[+] Modified P12 file available at: {Fore.WHITE}{download_url}")
                print(f"{Fore.GREEN}[+] New filename: {data_obj.get('filename', 'unknown')}")
                
                if data_obj.get('warning'):
                    print(f"{Fore.YELLOW}[!] Warning: {data_obj.get('warning')}")
                
                if interactive:
                    download_choice = input(f"{Fore.YELLOW}[?] Do you want to download the modified P12 file? (y/n): ").lower().strip()
                    if download_choice == 'y':
                        filename = data_obj.get('filename', 'modified_certificate.p12')
                        download_file(download_url, filename)
                    
                return True, download_url, None
            else:
                error_msg = result.get('error', 'Unknown error')
                print(f"\n{Fore.RED}[!] Failed to change password: {error_msg}")
                return False, None, result
        
    except FileNotFoundError:
        error_msg = f"P12 file not found: {p12_file_path}"
        print(f"{Fore.RED}[!] {error_msg}")
        return False, None, error_msg
        
    except requests.exceptions.HTTPError as e:
        status_code = e.response.status_code
        error_msg = None
        
        if status_code == 401:
            error_msg = "Authentication failed. Please check your API token."
        elif status_code == 400:
            try:
                error_data = e.response.json()
                error_msg = error_data.get('error', 'Bad request - check old password')
            except:
                error_msg = f"Bad request: {e.response.text}"
        elif status_code == 500:
            try:
                error_data = e.response.json()
                error_msg = error_data.get('error', 'Internal server error')
            except:
                error_msg = f"Server error: {e.response.text}"
        else:
            error_msg = f"HTTP Error occurred: {e}"
        
        print(f"{Fore.RED}[!] {error_msg}")
        return False, None, error_msg
        
    except (requests.exceptions.RequestException, json.JSONDecodeError, Exception) as e:
        error_msg = f"Error: {str(e)}"
        print(f"{Fore.RED}[!] {error_msg}")
        return False, None, error_msg


def validate_url(url):
    """Validate if the provided URL is accessible and exists."""
    try:
        response = requests.head(url, timeout=10)
        if response.status_code >= 400:
            print(f"{Fore.RED}[!] Warning: The URL {url} returned status code {response.status_code}")
            return False
        return True
    except requests.exceptions.RequestException:
        print(f"{Fore.RED}[!] Warning: The URL {url} is not accessible")
        return False


def is_local_file(path):
    """
    Check if a path is a local file rather than a URL.

    Args:
        path (str): Path to check

    Returns:
        bool: True if it's a local file, False if it's a URL
    """
    return os.path.exists(path) and not path.startswith(('http://', 'https://'))


def validate_p12_file(p12_path):
    """
    Validate that the P12 file exists and is a valid file.
    
    Args:
        p12_path (str): Path to the P12 file
    
    Returns:
        str: The absolute path to the P12 file
    """
    if not os.path.exists(p12_path):
        print(f"{Fore.RED}[!] Error: P12 file not found: {p12_path}")
        sys.exit(1)
    
    if not os.path.isfile(p12_path):
        print(f"{Fore.RED}[!] Error: Path is not a file: {p12_path}")
        sys.exit(1)
        
    if not p12_path.lower().endswith(('.p12', '.pfx')):
        print(f"{Fore.YELLOW}[!] Warning: File does not have .p12 or .pfx extension")
        proceed = input(f"{Fore.YELLOW}Do you want to proceed anyway? (y/n): ").lower().strip()
        if proceed != 'y':
            sys.exit(1)
    
    print(f"{Fore.CYAN}[*] P12 file validated: {p12_path}")
    return os.path.abspath(p12_path)




def download_file(url, output_path):
    """Download a file from a URL to a local path."""
    try:
        print(f"{Fore.CYAN}[*] Downloading file from {url}...")
        response = requests.get(url, stream=True, timeout=60)
        response.raise_for_status()

        total_size = int(response.headers.get('content-length', 0))
        block_size = 1024
        downloaded = 0

        with open(output_path, 'wb') as file:
            for data in response.iter_content(block_size):
                file.write(data)
                downloaded += len(data)

                if total_size > 0:
                    percent = (downloaded / total_size) * 100
                    progress = f"{Fore.CYAN}[*] Download progress: {percent:.1f}%"
                    print(progress, end='\r')

        print(f"\n{Fore.GREEN}[+] File downloaded successfully to {output_path}")
        return True
    except Exception as e:
        print(f"{Fore.RED}[!] Error downloading file: {e}")
        return False


def check_api_key():
    """Check if the API key is set and prompt the user if it's not or has the default value."""
    global API_KEY

    if not API_KEY or API_KEY.strip() == "" or API_KEY == "YOUR_API_KEY_HERE":
        print(f"{Fore.RED}[!] Error: API key is not set or is using the default placeholder value")
        print(f"{Fore.YELLOW}[*] You need to set your API key in the script.")
        print(f"{Fore.YELLOW}[*] Open the script file and look for the API_KEY variable.")
        print(f"{Fore.YELLOW}[*] Example: API_KEY = \"your_api_key_here\"")
        print(f"{Fore.YELLOW}[*] You can get your API key from: https://developer.nabzclan.vip")
        sys.exit(1)


def main():
    """Main function to parse arguments and execute the password operations."""
    parser = argparse.ArgumentParser(
        description='P12 Password Cracker & Changer - A tool for P12/PKCS#12 certificate files',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    subparsers = parser.add_subparsers(dest='command', help='Command to execute')

    # Crack subcommand
    crack_parser = subparsers.add_parser('crack', help='Crack a P12 file password')
    crack_parser.add_argument('-p', '--p12', metavar='P12_FILE', required=True,
                           help='Path to local P12 file to crack')

    # Attack mode selection
    method_group = crack_parser.add_mutually_exclusive_group(required=False)
    method_group.add_argument('-s', '--single', metavar='PASSWORD',
                            help='Verify a single password (Example: -s "mypassword")')
    method_group.add_argument('-l', '--list', metavar='WORDLIST_PATH',
                            help='Use a custom wordlist from a local file or URL')
    method_group.add_argument('--smart', action='store_true',
                            help='Use smart mode with common P12 passwords (default)')
    method_group.add_argument('-b', '--brute', action='store_true',
                            help='Use brute force mode (VIP only ⭐️)')
    method_group.add_argument('-a', '--array', metavar='PASSWORDS', nargs='+',
                            help='Try multiple passwords inline (Example: -a pass1 pass2 pass3)')
    
    # Brute force options
    crack_parser.add_argument('--charset', metavar='CHARS',
                            help='Characters to use for brute force (default: a-z0-9)')
    crack_parser.add_argument('--min-length', type=int, default=1, metavar='N',
                            help='Minimum password length for brute force (default: 1, max: 6)')
    crack_parser.add_argument('--max-length', type=int, default=4, metavar='N',
                            help='Maximum password length for brute force (default: 4, max: 6)')
    
    crack_parser.add_argument('-c', '--change', metavar='NEW_PASSWORD',
                           help='Change the password if cracking succeeds')

    # Change subcommand
    change_parser = subparsers.add_parser('change', help='Change a P12 file password')
    change_parser.add_argument('-p', '--p12', metavar='P12_FILE', required=True,
                            help='Path to local P12 file')
    change_parser.add_argument('-o', '--old', metavar='OLD_PASSWORD', required=True,
                            help='Current password of the P12 file')
    change_parser.add_argument('-n', '--new', metavar='NEW_PASSWORD', required=True,
                            help='New password to set for the P12 file')

    # Status subcommand
    subparsers.add_parser('status', help='View your API usage and plan information')

    parser.add_argument('-v', '--verbose', action='store_true',
                      help='Enable verbose output')

    args = parser.parse_args()

    display_banner()

    check_api_key()

    if not args.command:
        parser.print_help()
        print(f"\n{Fore.YELLOW}[*] Usage examples:")
        print(f"{Fore.WHITE}  # Try a single password on a P12 file:")
        print(f"{Fore.WHITE}  python {sys.argv[0]} crack -p cert.p12 -s \"password123\"")
        print(f"{Fore.WHITE}  # Use smart mode (default):")
        print(f"{Fore.WHITE}  python {sys.argv[0]} crack -p cert.p12 --smart")
        print(f"{Fore.WHITE}  # Use a wordlist file:")
        print(f"{Fore.WHITE}  python {sys.argv[0]} crack -p cert.p12 -l wordlist.txt")
        print(f"{Fore.WHITE}  # Use brute force mode (VIP only ⭐️):")
        print(f"{Fore.WHITE}  python {sys.argv[0]} crack -p cert.p12 -b --charset abc123 --max-length 4")
        print(f"{Fore.WHITE}  # Try multiple passwords inline:")
        print(f"{Fore.WHITE}  python {sys.argv[0]} crack -p cert.p12 -a password1 password2 password3")
        print(f"{Fore.WHITE}  # Change password after finding it:")
        print(f"{Fore.WHITE}  python {sys.argv[0]} change -p cert.p12 -o \"oldpass\" -n \"newpass\"")
        print(f"{Fore.WHITE}  # View your API usage and plan:")
        print(f"{Fore.WHITE}  python {sys.argv[0]} status")
        sys.exit(1)

    # Handle status command first (before other commands)
    if args.command == 'status':
        show_usage_info()
        sys.exit(0)

    if args.command == 'crack':
        p12_file = validate_p12_file(args.p12)

        success = False
        password = None

        if args.single:

            print(f"{Fore.CYAN}[*] Mode: Single Password Verification")
            success, password, _ = verify_p12_password(p12_file, args.single)

        elif args.list:

            print(f"{Fore.CYAN}[*] Mode: Dictionary Attack")

            is_vip, _ = is_vip_user()
            if not is_vip:
                print(f"{Fore.YELLOW}[*] Limits: Free=1,000 passwords, VIP=50MB. See: https://developer.nabzclan.vip/docs/endpoints/p12-cracker")
            if is_local_file(args.list):

                success, password, _ = crack_p12_password(p12_file, mode='dictionary', wordlist=args.list)
            else:

                if not validate_url(args.list):
                    proceed = input(f"{Fore.YELLOW}Do you want to proceed anyway? (y/n): ").lower().strip()
                    if proceed != 'y':
                        sys.exit(1)
                success, password, _ = crack_p12_password(p12_file, mode='dictionary', wordlist_url=args.list)

        elif args.brute:
            print(f"{Fore.CYAN}[*] Mode: Brute Force Attack (VIP only ⭐️)")
            
            if args.max_length > 6:
                print(f"{Fore.RED}[!] Error: Maximum password length for brute force is 6")
                print(f"{Fore.YELLOW}[*] You specified: {args.max_length}")
                print(f"{Fore.YELLOW}[*] Tip: Use dictionary mode (-l) for longer passwords")
                sys.exit(1)
            
            is_vip, plan_name = is_vip_user()
            if not is_vip:
                print(f"{Fore.RED}[!] Error: Brute force mode requires a VIP subscription")
                print(f"{Fore.YELLOW}[*] Your current plan: {plan_name or 'Free'}")
                print(f"{Fore.YELLOW}[*] Upgrade at: https://developer.nabzclan.vip/plans")
                sys.exit(1)
            
            print(f"{Fore.GREEN}[+] VIP status confirmed: {plan_name}")
            success, password, _ = crack_p12_password(
                p12_file, 
                mode='brute_force',
                charset=args.charset,
                min_length=args.min_length,
                max_length=args.max_length
            )

        elif args.array:

            print(f"{Fore.CYAN}[*] Mode: Password Array Attack")
            print(f"{Fore.CYAN}[*] Trying {len(args.array)} passwords...")

            if len(args.array) > 100:
                is_vip, _ = is_vip_user()
                if not is_vip:
                    print(f"{Fore.YELLOW}[!] Note: Free plan limit is 100 passwords. See: https://developer.nabzclan.vip/docs/endpoints/p12-cracker")
            success, password, _ = crack_p12_password(p12_file, mode='dictionary', wordlist=args.array)

        else:

            print(f"{Fore.CYAN}[*] Mode: Smart Attack (using common P12 passwords)")
            success, password, _ = crack_p12_password(p12_file, mode='smart')

        if success and password and args.change:
            print(f"\n{Fore.CYAN}[*] Proceeding to change password...")
            change_p12_password(p12_file, password, args.change)

    elif args.command == 'change':
        p12_file = validate_p12_file(args.p12)

        change_p12_password(p12_file, args.old, args.new)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Operation cancelled by user")
        sys.exit(0)
