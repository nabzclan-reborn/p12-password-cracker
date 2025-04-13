# P12 Password Cracker & Changer

A powerful tool for cracking and changing passwords for P12/PKCS#12 certificate files using the API-Aries service.

![Version](https://img.shields.io/badge/version-1.3-blue)
![Python](https://img.shields.io/badge/python-3.6%2B-green)
![License](https://img.shields.io/badge/license-MIT-orange)

## Features

- **Crack P12 Passwords** using:
  - Single password attempt
  - Custom wordlist from a URL
  - Default wordlist with 20+ million passwords
- **Change P12 Passwords** once found
- **Colorful Interface** with progress information
- **Simple & Advanced Modes** for different use cases

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
- Use the `-k` or `--key` option when running the script

## Usage Examples

### Quick Usage (Default Wordlist)

```bash
# Simplest way to use - just provide the P12 URL
python3 p12_tool.py https://example.com/certificate.p12
```

### Advanced Usage

```bash
# Try a single password
python3 p12_tool.py crack -p https://example.com/certificate.p12 -s "password123"

# Use a custom wordlist from URL
python3 p12_tool.py crack -p https://example.com/certificate.p12 -l https://example.com/wordlist.txt

# Use default wordlist (20+ million passwords)
python3 p12_tool.py crack -p https://example.com/certificate.p12 -d

# Crack password and then change it
python3 p12_tool.py crack -p https://example.com/certificate.p12 -d -c "newpassword123"

# Change password (when you know the current password)
python3 p12_tool.py change -p https://example.com/certificate.p12 -o "oldpassword" -n "newpassword"
```

## Changelog

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
