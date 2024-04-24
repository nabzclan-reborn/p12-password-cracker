import argparse
import requests
import json
from colorama import init, Fore, Style

init(autoreset=True)

def crack_p12_password(url, token_type, api_key):
    headers = {
        'APITOKEN': api_key,
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status() 

        formatted_response = json.dumps(response.json(), indent=4)
        print(Fore.GREEN + "Response:")
        print(Fore.WHITE + formatted_response)

    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"Error occurred: {e}")

    except Exception as e:
        print(Fore.RED + f"An error occurred: {e}")

parser = argparse.ArgumentParser(description='P12 Password Cracker')
parser.add_argument('-s', '--single', metavar='PASSWORD', help='Use a single password - Example: python3 main.py -s password here')
parser.add_argument('-L', '--list', metavar='CUSTOM_LIST_URL', help='Use a custom list of words - Example: python3 main.py -L https://example.com/passwords.txt')
parser.add_argument('-d', '--default', action='store_true', help='Use default list of words from API Aries - Example: python3 main.py -d')
args = parser.parse_args()

# REQUIRED
p12_file_url = "https://cloud.nabzclan.vip/file/2Tw/Sunshine_Insurance_Group_Co.p12"  #sample direct file download url using https://cloud.nabzclan.vip 

if args.single:
   password_option = f"https://api.api-aries.online/v2/cracking/p12-password/?p12={p12_file_url}&password={args.single}"
elif args.list:
    password_option = f"https://api.api-aries.online/v2/cracking/p12-password/?p12={p12_file_url}&list={args.list}"
elif args.default:
    password_option = f"https://api.api-aries.online/v2/cracking/p12-password/?p12={p12_file_url}"
else:
    print(Fore.RED + "Please provide an option:")
    print("  -s, --single PASSWORD\t\tUse a single password - Example: python3 main.py -s password here")
    print("  -L, --list CUSTOM_LIST_URL\tUse a custom list of words - Example: python3 main.py -L https://example.com/passwords.txt")
    print("  -d, --default\t\t\tUse default list of words from API Aries - Example: python3 main.py -d")
    exit()

# REQUIRED
api_key = "1111-1111-111"  #API Token : https://support.api-aries.online/hc/articles/1/3/13/p12-password-cracker

url = password_option if (args.list or args.single or args.default) else ""

crack_p12_password(url, token_type, api_key)
