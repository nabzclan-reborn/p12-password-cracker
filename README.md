# P12 Password Cracker & Changer

A powerful tool for cracking and changing passwords for P12/PKCS#12 certificate files using the API-Aries service.

![Version](https://img.shields.io/badge/version-1.4-blue)
![Python](https://img.shields.io/badge/python-3.6%2B-green)
![License](https://img.shields.io/badge/license-MIT-orange)

## Features

- **Crack P12 Passwords** using:
  - Single password attempt
  - Custom wordlist (local file or URL)
- **Change P12 Passwords** once found or with known password
- **Automatic local file upload** for processing without having to get your own link to add to api aries.

## Installation
```bash
# Clone repository
git clone https://github.com/nabzclan-reborn/p12-password-cracker.git
cd p12-password-cracker

# Install required dependencies
pip3 install -r requirements.txt
```

## Configuration

Before using the tool, configure your API key in one of the following ways:
- Edit the script and replace `YOUR_API_KEY_HERE` with your actual API key - Get Key 'https://api-aries.com/dashboard'

## Usage Examples

```bash
# Try a single password
python3 main.py crack -p cert.p12 -s "password123"

# Use a local wordlist file
python3 main.py crack -p cert.p12 -l wordlist.txt

# Use a wordlist from URL
python3 main.py crack -p cert.p12 -l https://example.com/wordlist.txt

# Crack password and then change it
python3 main.py crack -p cert.p12 -s "password123" -c "newpassword123"

# Change password (when you know the current password)
python3 main.py change -p cert.p12 -o "oldpassword" -n "newpassword"
```

## Changelog

### v1.4
- Removed default wordlist feature
- Eliminated the requirement for a direct P12 download link - the system now handles file management automatically via naqbzclan cdn server and stores P12 files for only 2 hours
- Rewrote several features for improved performance

### v1.3
- API update with enhanced capabilities
- Added support for P12 Password Changing
- Expanded default wordlist to 20+ million passwords
- Added simple mode for quick usage
- Improved error handling with detailed messages
- Auto-download option for modified P12 files

### v1.2
- Completely remade the script for better performance
- Added 3 new features for improved functionality
- Enhanced user interface with colorful output

### v1.1
- Initial public release

## API Documentation

For more information about the API used by this tool, visit:
[API-Aries P12 Password Cracker Documentation](https://support.api-aries.online/hc/articles/1/3/13/p12-password-cracker)

## Online Tools

Try our web-based tools for convenience:

- [Online P12 Cracker (Advanced)](https://tools.nabzclan.vip)
- [Online P12 Cracker (Standard)](https://tools.nabzclan.vip)
- [Online P12 Password Changer](https://tools.nabzclan.vip)

## Requirements

- Python 3.6 or higher
- Internet connection
- Valid API-Aries API key

## License

This project is licensed under the MIT License - see the LICENSE file for details.
