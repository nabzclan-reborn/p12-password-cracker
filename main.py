import requests
import json
from colorama import init, Fore, Style

init(autoreset=True)

def crack_p12_password(p12_file_url, token_type, api_key, list_param=None):
    base_url = "https://api.api-aries.online/v2/cracking/p12-password/?p12="
    url = base_url + p12_file_url

    if list_param:
        url += f"&list={list_param}"

    headers = {
        'Type': token_type,
        'APITOKEN': api_key
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

p12_file_url = "https://cloud.nabzclan.vip/file/2Tl/Throughtek_Co-Ltd.p12" #sample direct file download url using https://cloud.nabzclan.vip 
token_type = "1" # token type :  https://support.api-aries.online/hc/articles/1/3/13/p12-password-cracker#token-types-required
api_key = "1111-1111-111" #API Token : https://support.api-aries.online/hc/articles/1/3/13/p12-password-cracker
list_param = "https://raw.githubusercontent.com/nabclan-reborn/p12-password-cracker/main/passwords.txt"  # List of passwords learn more: https://support.api-aries.online/hc/articles/1/3/13/p12-password-cracker#custom-list-format

crack_p12_password(p12_file_url, token_type, api_key, list_param)
