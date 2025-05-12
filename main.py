#!/usr/bin/env python3
"""
P12 Password Cracker & Changer - A tool to crack and change passwords for P12/PKCS#12 certificate files
utilizing the API-Aries services. 

This script allows users to:
1. Crack P12 file passwords using:
   - Single password attempt
   - Custom wordlist from a local file or URL
2. Change P12 file passwords after finding the correct password
"""

import argparse
import json
import sys
import os
import requests
from colorama import init, Fore, Style

init(autoreset=True)


API_BASE_URL = "https://api.api-aries.com/v2"
CRACK_ENDPOINT = f"{API_BASE_URL}/cracking/p12-password/"
CHANGE_ENDPOINT = f"{API_BASE_URL}/p12password-changer/"
UPLOAD_URL = "https://cdn.nabzclan.vip/public/p12cracker-github/upload/"
# Your API key can be obtained from: https://api-aries.com/dashboard
API_KEY = "YOUR_API_KEY_HERE"  # Replace with your API key from the panel pls.


def display_banner():
    """Display an attractive banner when the script starts."""
    banner = f"""
{Fore.CYAN}╔════════════════════════════════════════════════════════╗
{Fore.CYAN}║                                                        ║
{Fore.CYAN}║  {Fore.YELLOW}P12 Password Cracker & Changer {Fore.GREEN}v1.4               {Fore.CYAN}    ║
{Fore.CYAN}║  {Fore.WHITE}Powered by API-Aries & nabzclan.vip                  {Fore.CYAN} ║
{Fore.CYAN}║                                                        ║
{Fore.CYAN}║                                                        ║
{Fore.CYAN}╚════════════════════════════════════════════════════════╝
"""
    print(banner)


def crack_p12_password(url, p12_file_url, method, value=None):
    """
    Attempt to crack the P12 file password using the API-Aries service.
    
    Args:
        url (str): The complete API URL to use
        p12_file_url (str): URL to the P12 file
        method (str): The cracking method being used (for display purposes)
        value (str, optional): The specific value being used with the method
        
    Returns:
        tuple: (success boolean, password string or None, error message or None)
    """
    headers = {
        'X-API-KEY': API_KEY,
        'User-Agent': 'P12PasswordCrackernabzclangithub/1.3'
    }
    
    print(f"{Fore.CYAN}[*] Starting password cracking attempt...")
    print(f"{Fore.CYAN}[*] Working with uploaded P12 file...")
    print(f"{Fore.CYAN}[*] Method: {method}" + (f" with value: {value}" if value else ""))
    
    try:
        print(f"{Fore.YELLOW}[*] Sending request to API-Aries to crack.")
        response = requests.get(url, headers=headers, timeout=300)
        response.raise_for_status()
        
        result = response.json()
        
        if result.get('success') is True and result.get('password'):
            print(f"\n{Fore.GREEN}[+] PASSWORD FOUND: {Fore.WHITE}{result.get('password')}")
            print(f"{Fore.GREEN}[+] Time taken: {result.get('time_taken', 'unknown')} seconds")
            return True, result.get('password'), None
        elif result.get('success') is False:
            error_msg = result.get('message', 'unknown')
            print(f"\n{Fore.YELLOW}[-] Password not found. Reason: {error_msg}")
            return False, None, error_msg
        
        print(f"\n{Fore.BLUE}[*] Complete API Response:")
        print(f"{Fore.WHITE}{json.dumps(result, indent=4)}")
        return False, None, "No success information in response"
        
    except requests.exceptions.HTTPError as e:
        status_code = e.response.status_code
        error_msg = None
        
        if status_code == 401:
            error_msg = "Authentication failed. Please check your API key."
        elif status_code == 429:
            error_msg = "Rate limit exceeded. Please try again later."
        else:
            error_msg = f"HTTP Error occurred: {e}"
            
        print(f"{Fore.RED}[!] {error_msg}")
        try:
            error_details = e.response.json()
            print(f"{Fore.RED}[!] Error details: {json.dumps(error_details, indent=4)}")
        except:
            print(f"{Fore.RED}[!] Response content: {e.response.text}")
        
        return False, None, error_msg
                
    except requests.exceptions.ConnectionError:
        error_msg = "Connection Error: Could not connect to the API service."
        print(f"{Fore.RED}[!] {error_msg}")
        print(f"{Fore.RED}[!] Please check your internet connection and try again.")
        return False, None, error_msg
        
    except requests.exceptions.Timeout:
        error_msg = "Request timed out. The cracking process may be taking longer than expected."
        print(f"{Fore.RED}[!] {error_msg}")
        print(f"{Fore.RED}[!] Consider using a single password or checking the API status.")
        return False, None, error_msg
        
    except requests.exceptions.RequestException as e:
        error_msg = f"Request error occurred: {e}"
        print(f"{Fore.RED}[!] {error_msg}")
        return False, None, error_msg
        
    except json.JSONDecodeError:
        error_msg = "Could not parse the API response as JSON."
        print(f"{Fore.RED}[!] {error_msg}")
        print(f"{Fore.RED}[!] Raw response: {response.text[:200]}...")
        return False, None, error_msg
        
    except Exception as e:
        error_msg = f"An unexpected error occurred: {e}"
        print(f"{Fore.RED}[!] {error_msg}")
        return False, None, error_msg


def change_p12_password(p12_url, old_password, new_password):
    """
    Change the password of a P12 file using the API-Aries service.
    
    Args:
        p12_url (str): URL to the P12 file
        old_password (str): Current password of the P12 file
        new_password (str): New password to set for the P12 file
    
    Returns:
        tuple: (success boolean, download_url string or None, error message or None)
    """
    headers = {
        'APITOKEN': API_KEY,
        'User-Agent': 'P12PasswordChanger/1.4'
    }
    
    url = f"{CHANGE_ENDPOINT}?p12={p12_url}&old_password={old_password}&new_password={new_password}"
    
    print(f"{Fore.CYAN}[*] Attempting to change P12 password...")
    print(f"{Fore.CYAN}[*] Working with uploaded P12 file...")
    
    try:
        print(f"{Fore.YELLOW}[*] Sending request to API-Aries...")
        response = requests.get(url, headers=headers, timeout=120)
        response.raise_for_status()
        
        result = response.json()
        
        if result.get('success') is True:
            download_url = result.get('download_url')
            print(f"\n{Fore.GREEN}[+] Password changed successfully!")
            print(f"{Fore.GREEN}[+] Modified P12 file available at: {Fore.WHITE}{download_url}")
            print(f"{Fore.GREEN}[+] Timestamp: {result.get('timestamp', 'unknown')}")
            
            download_choice = input(f"{Fore.YELLOW}[?] Do you want to download the modified P12 file? (y/n): ").lower().strip()
            if download_choice == 'y':
                filename = download_url.split('/')[-1]
                download_file(download_url, filename)
                
            return True, download_url, None
        else:
            error_msg = result.get('message', 'Unknown error')
            print(f"\n{Fore.RED}[!] Failed to change password: {error_msg}")
            return False, None, error_msg
        
    except requests.exceptions.HTTPError as e:
        status_code = e.response.status_code
        error_msg = None
        
        if status_code == 401:
            error_msg = "Authentication failed. Please check your API token."
        elif status_code == 400:
            try:
                error_data = e.response.json()
                error_code = error_data.get('error_code', 'unknown')
                error_msg = f"Error {error_code}: {error_data.get('message', 'Unknown error')}"
                
                error_explanations = {
                    "ERR001": "Invalid or non-HTTPS URL provided for .p12 file.",
                    "ERR002": "Only .p12 files are allowed.",
                    "ERR003": "Failed to download the .p12 file.",
                    "ERR004": "Incorrect old password provided.",
                    "ERR005": "An error occurred while processing the .p12 file.",
                    "ERR006": "The modified .p12 file was not generated.",
                    "ERR007": "Missing required parameters: p12, old_password, or new_password."
                }
                
                if error_code in error_explanations:
                    print(f"{Fore.YELLOW}[i] {error_explanations[error_code]}")
            except:
                error_msg = f"Bad request: {e.response.text}"
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


def process_input_path(p12_path):
    if os.path.exists(p12_path) and not p12_path.startswith(('http://', 'https://')):
        print(f"{Fore.YELLOW}[*] Detected local file. Uploading {p12_path} first...")
        p12_url = upload_p12(p12_path)
        if not p12_url:
            print(f"{Fore.RED}[!] Error: Failed to upload file")
            sys.exit(1)
        return p12_url
    elif not p12_path.startswith(('http://', 'https://')):
        print(f"{Fore.RED}[!] Error: File path must be a valid local file or start with http:// or https://")
        sys.exit(1)


    if not validate_url(p12_path):
        proceed = input(f"{Fore.YELLOW}Do you want to proceed anyway? (y/n): ").lower().strip()
        if proceed != 'y':
            sys.exit(1)

    return p12_path


def upload_p12(file_path):
    """Upload a P12 file to the server and return the URL."""
    print(f"{Fore.CYAN}[*] Uploading P12 file: {file_path}...")

    try:
        with open(file_path, 'rb') as f:
            files = {'file': f}
            headers = {'User-Agent': 'P12PasswordCrackernabzclangithub/1.3'}

            response = requests.post(UPLOAD_URL, files=files, headers=headers)

            if response.status_code == 200:
                try:
                    result = response.json()
                    if 'path' in result:
                        print(f"{Fore.GREEN}[+] File uploaded successfully!")
                        print(f"{Fore.GREEN}[+] {result.get('file_expiry', 'File will expire after some time')}")
                        return result['path']
                    else:
                        print(f"{Fore.RED}[!] Upload successful but no path returned in response: {response.text}")
                except json.JSONDecodeError:
                    print(f"{Fore.RED}[!] Failed to parse server response: {response.text}")
            else:
                print(f"{Fore.RED}[!] Upload failed with status code: {response.status_code}")
                print(f"{Fore.RED}[!] Server response: {response.text}")

    except Exception as e:
        print(f"{Fore.RED}[!] Error uploading file: {e}")

    return None


def process_local_wordlist(p12_url, wordlist_path):
    """
    Process a local wordlist file by trying each password against the P12 file.

    Args:
        p12_url (str): URL to the P12 file
        wordlist_path (str): Path to the local wordlist file

    Returns:
        tuple: (success boolean, password string or None, error message or None)
    """
    try:
        if not os.path.exists(wordlist_path):
            print(f"{Fore.RED}[!] Error: Wordlist file {wordlist_path} does not exist")
            return False, None, "Wordlist file not found"

        print(f"{Fore.CYAN}[*] Processing local wordlist: {wordlist_path}")


        total_lines = sum(1 for _ in open(wordlist_path, 'r', errors='ignore'))
        print(f"{Fore.CYAN}[*] Found {total_lines} passwords to try")

        with open(wordlist_path, 'r', errors='ignore') as f:
            for i, line in enumerate(f, 1):
                password = line.strip()
                if not password: 
                    continue

                if i % 10 == 0 or i == 1 or i == total_lines:
                    print(f"{Fore.CYAN}[*] Trying password {i}/{total_lines}: {password[:15]}{'...' if len(password) > 15 else ''}")

                url = f"{CRACK_ENDPOINT}?p12={p12_url}&password={password}"
                headers = {
                    'X-API-KEY': API_KEY,
                    'User-Agent': 'P12PasswordCrackernabzclangithub/1.3'
                }

                try:
                    response = requests.get(url, headers=headers, timeout=30)
                    if response.status_code == 200:
                        result = response.json()

                        if result.get('success') is True and result.get('password'):
                            print(f"\n{Fore.GREEN}[+] PASSWORD FOUND: {Fore.WHITE}{result.get('password')}")
                            print(f"{Fore.GREEN}[+] Found on attempt {i}/{total_lines}")
                            return True, result.get('password'), None
                except Exception as e:
                    if i % 50 == 0:
                        print(f"{Fore.YELLOW}[!] Error on attempt {i}: {str(e)[:50]}")
                    continue

        print(f"\n{Fore.YELLOW}[-] Tried all {total_lines} passwords but none worked")
        return False, None, "No password found in wordlist"

    except Exception as e:
        error_msg = f"Error processing wordlist: {e}"
        print(f"{Fore.RED}[!] {error_msg}")
        return False, None, error_msg


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
        print(f"{Fore.YELLOW}[*] You can get your API key from: https://api-aries.com/dashboard")
        sys.exit(1)


def main():
    """Main function to parse arguments and execute the password operations."""
    parser = argparse.ArgumentParser(
        description='P12 Password Cracker & Changer - A tool for P12/PKCS#12 certificate files',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    subparsers = parser.add_subparsers(dest='command', help='Command to execute')

    crack_parser = subparsers.add_parser('crack', help='Crack a P12 file password')
    crack_parser.add_argument('-p', '--p12', metavar='P12_FILE_OR_URL', required=True,
                           help='Path to local P12 file or URL to remote P12 file to crack')

    method_group = crack_parser.add_mutually_exclusive_group(required=True)
    method_group.add_argument('-s', '--single', metavar='PASSWORD',
                            help='Try a single password (Example: -s "mypassword")')
    method_group.add_argument('-l', '--list', metavar='WORDLIST_PATH',
                            help='Use a custom wordlist from a local file or URL (Example: -l wordlist.txt or -l https://example.com/passwords.txt)')

    crack_parser.add_argument('-c', '--change', metavar='NEW_PASSWORD',
                           help='Change the password if cracking succeeds')

    change_parser = subparsers.add_parser('change', help='Change a P12 file password')
    change_parser.add_argument('-p', '--p12', metavar='P12_FILE_OR_URL', required=True,
                            help='Path to local P12 file or URL to remote P12 file')
    change_parser.add_argument('-o', '--old', metavar='OLD_PASSWORD', required=True,
                            help='Current password of the P12 file')
    change_parser.add_argument('-n', '--new', metavar='NEW_PASSWORD', required=True,
                            help='New password to set for the P12 file')

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
        print(f"{Fore.WHITE}  # Use a wordlist file:")
        print(f"{Fore.WHITE}  python {sys.argv[0]} crack -p cert.p12 -l wordlist.txt")
        print(f"{Fore.WHITE}  # Change password after finding it:")
        print(f"{Fore.WHITE}  python {sys.argv[0]} change -p cert.p12 -o \"oldpass\" -n \"newpass\"")
        sys.exit(1)

    if args.command == 'crack':
        p12_file_url = process_input_path(args.p12)

        success = False
        password = None

        if args.single:
            method = "Single Password"
            url = f"{CRACK_ENDPOINT}?p12={p12_file_url}&password={args.single}"
            success, password, _ = crack_p12_password(url, p12_file_url, method, args.single)

        elif args.list:
            method = "Custom Wordlist"
            if is_local_file(args.list):
                print(f"{Fore.CYAN}[*] Using local wordlist file: {args.list}")
                success, password, _ = process_local_wordlist(p12_file_url, args.list)
            else:
                if not validate_url(args.list):
                    proceed = input(f"{Fore.YELLOW}Do you want to proceed anyway? (y/n): ").lower().strip()
                    if proceed != 'y':
                        sys.exit(1)
                url = f"{CRACK_ENDPOINT}?p12={p12_file_url}&list={args.list}"
                success, password, _ = crack_p12_password(url, p12_file_url, method, args.list)

        else:
            print(f"{Fore.RED}[!] Error: You must specify a cracking method (-s or -l)")
            sys.exit(1)

        if success and password and args.change:
            print(f"\n{Fore.CYAN}[*] Proceeding to change password...")
            change_p12_password(p12_file_url, password, args.change)

    elif args.command == 'change':
        p12_file_url = process_input_path(args.p12)

        change_p12_password(p12_file_url, args.old, args.new)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Operation cancelled by user")
        sys.exit(0)
