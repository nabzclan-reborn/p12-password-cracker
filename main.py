#!/usr/bin/env python3
"""
P12 Password Cracker & Changer - A tool to crack and change passwords for P12/PKCS#12 certificate files
utilizing the API-Aries services.

This script allows users to:
1. Crack P12 file passwords using:
   - Single password attempt
   - Custom wordlist from a URL
   - Default wordlist from API-Aries (also runs when no method is specified)
2. Change P12 file passwords after finding the correct password
"""

import argparse
import json
import sys
import requests
from colorama import init, Fore, Style

init(autoreset=True)


API_BASE_URL = "https://api.api-aries.com/v2"
CRACK_ENDPOINT = f"{API_BASE_URL}/cracking/p12-password/"
CHANGE_ENDPOINT = f"{API_BASE_URL}/p12password-changer/"
# Your API key can be obtained from: https://api-aries.com/dashboard
API_KEY = "YOUR_API_KEY_HERE"  # Replace with your API key from the panel pls.


def display_banner():
    """Display an attractive banner when the script starts."""
    banner = f"""
{Fore.CYAN}╔════════════════════════════════════════════════════════╗
{Fore.CYAN}║                                                        ║
{Fore.CYAN}║  {Fore.YELLOW}P12 Password Cracker & Changer {Fore.GREEN}v1.2               {Fore.CYAN}║
{Fore.CYAN}║  {Fore.WHITE}Powered by API-Aries                                {Fore.CYAN}║
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
        'User-Agent': 'P12PasswordCracker/1.3'
    }
    
    print(f"{Fore.CYAN}[*] Starting password cracking attempt...")
    print(f"{Fore.CYAN}[*] P12 File: {p12_file_url}")
    print(f"{Fore.CYAN}[*] Method: {method}" + (f" with value: {value}" if value else ""))
    
    try:
        print(f"{Fore.YELLOW}[*] Sending request to API-Aries. This may take some time...")
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
        'User-Agent': 'P12PasswordChanger/1.3'
    }
    
    url = f"{CHANGE_ENDPOINT}?p12={p12_url}&old_password={old_password}&new_password={new_password}"
    
    print(f"{Fore.CYAN}[*] Attempting to change P12 password...")
    print(f"{Fore.CYAN}[*] P12 File: {p12_url}")
    
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


def main():
    """Main function to parse arguments and execute the password operations."""
    parser = argparse.ArgumentParser(
        description='P12 Password Cracker & Changer - A tool for P12/PKCS#12 certificate files',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    crack_parser = subparsers.add_parser('crack', help='Crack a P12 file password')
    crack_parser.add_argument('-p', '--p12', metavar='P12_URL', required=True,
                           help='URL to the P12 file to crack')
    
    method_group = crack_parser.add_mutually_exclusive_group(required=False)
    method_group.add_argument('-s', '--single', metavar='PASSWORD',
                            help='Try a single password (Example: -s "mypassword")')
    method_group.add_argument('-l', '--list', metavar='WORDLIST_URL',
                            help='Use a custom wordlist from a URL (Example: -l https://example.com/passwords.txt)')
    method_group.add_argument('-d', '--default', action='store_true',
                            help='Use the default wordlist from API-Aries (this is the default if no method is specified)')
    
    crack_parser.add_argument('-k', '--key', metavar='API_KEY',
                           help='Specify API key (overrides the default)')
    crack_parser.add_argument('-c', '--change', metavar='NEW_PASSWORD',
                           help='Change the password if cracking succeeds')
    
    change_parser = subparsers.add_parser('change', help='Change a P12 file password')
    change_parser.add_argument('-p', '--p12', metavar='P12_URL', required=True,
                            help='URL to the P12 file')
    change_parser.add_argument('-o', '--old', metavar='OLD_PASSWORD', required=True,
                            help='Current password of the P12 file')
    change_parser.add_argument('-n', '--new', metavar='NEW_PASSWORD', required=True,
                            help='New password to set for the P12 file')
    change_parser.add_argument('-k', '--key', metavar='API_KEY',
                            help='Specify API key (overrides the default)')
    
    parser.add_argument('p12_url', metavar='P12_URL', nargs='?',
                      help='URL to the P12 file (for quick default cracking)')
    
    parser.add_argument('-k', '--key', metavar='API_KEY',
                      help='Specify API key (overrides the default)')
    parser.add_argument('-v', '--verbose', action='store_true',
                      help='Enable verbose output')
    
    args = parser.parse_args()
    
    display_banner()
    
    global API_KEY
    if hasattr(args, 'key') and args.key:
        API_KEY = args.key
    
    if API_KEY == "YOUR_API_KEY_HERE":
        print(f"{Fore.RED}[!] Error: You must set your API key in the script or use the -k option")
        sys.exit(1)
    
    if args.p12_url and not args.command:
        p12_file_url = args.p12_url
        if not p12_file_url.startswith(('http://', 'https://')):
            print(f"{Fore.RED}[!] Error: P12 file URL must start with http:// or https://")
            sys.exit(1)
        
        if not validate_url(p12_file_url):
            proceed = input(f"{Fore.YELLOW}Do you want to proceed anyway? (y/n): ").lower().strip()
            if proceed != 'y':
                sys.exit(1)
        
        print(f"{Fore.YELLOW}[*] Running in simple mode with default wordlist...")
        method = "Default Wordlist"
        url = f"{CRACK_ENDPOINT}?p12={p12_file_url}"
        crack_p12_password(url, p12_file_url, method)
        return
    
    if not args.command and not args.p12_url:
        parser.print_help()
        print(f"\n{Fore.YELLOW}[*] Quick usage examples:")
        print(f"{Fore.WHITE}  # Quick crack with default wordlist:")
        print(f"{Fore.WHITE}  python {sys.argv[0]} https://example.com/file.p12")
        print(f"{Fore.WHITE}  # Crack with specific options:")
        print(f"{Fore.WHITE}  python {sys.argv[0]} crack -p https://example.com/file.p12 -s \"password123\"")
        print(f"{Fore.WHITE}  # Change password:")
        print(f"{Fore.WHITE}  python {sys.argv[0]} change -p https://example.com/file.p12 -o \"oldpass\" -n \"newpass\"")
        sys.exit(1)
    
    if args.command == 'crack':
        p12_file_url = args.p12
        if not p12_file_url.startswith(('http://', 'https://')):
            print(f"{Fore.RED}[!] Error: P12 file URL must start with http:// or https://")
            sys.exit(1)
        
        if not validate_url(p12_file_url):
            proceed = input(f"{Fore.YELLOW}Do you want to proceed anyway? (y/n): ").lower().strip()
            if proceed != 'y':
                sys.exit(1)
        
        success = False
        password = None
        
        if args.single:
            method = "Single Password"
            url = f"{CRACK_ENDPOINT}?p12={p12_file_url}&password={args.single}"
            success, password, _ = crack_p12_password(url, p12_file_url, method, args.single)
            
        elif args.list:
            method = "Custom Wordlist"
            if not validate_url(args.list):
                proceed = input(f"{Fore.YELLOW}Do you want to proceed anyway? (y/n): ").lower().strip()
                if proceed != 'y':
                    sys.exit(1)
            url = f"{CRACK_ENDPOINT}?p12={p12_file_url}&list={args.list}"
            success, password, _ = crack_p12_password(url, p12_file_url, method, args.list)
            
        else:
            method = "Default Wordlist"
            url = f"{CRACK_ENDPOINT}?p12={p12_file_url}"
            success, password, _ = crack_p12_password(url, p12_file_url, method)
        
        if success and password and args.change:
            print(f"\n{Fore.CYAN}[*] Proceeding to change password...")
            change_p12_password(p12_file_url, password, args.change)
    
    elif args.command == 'change':
        p12_file_url = args.p12
        if not p12_file_url.startswith(('http://', 'https://')):
            print(f"{Fore.RED}[!] Error: P12 file URL must start with http:// or https://")
            sys.exit(1)
        
        if not validate_url(p12_file_url):
            proceed = input(f"{Fore.YELLOW}Do you want to proceed anyway? (y/n): ").lower().strip()
            if proceed != 'y':
                sys.exit(1)
        
        change_p12_password(p12_file_url, args.old, args.new)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Operation cancelled by user")
        sys.exit(0)
