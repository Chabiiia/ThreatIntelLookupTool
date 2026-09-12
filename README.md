# ThreatIntelLookupTool

A simple command-line tool that looks up IP addresses or file hashes (MD5 / SHA1 / SHA256) on **VirusTotal** and **AbuseIPDB**.

## Features

- IP address lookup (VirusTotal + AbuseIPDB)
- File hash lookup (MD5 / SHA1 / SHA256 → VirusTotal)
- Colored terminal output
- Automatic input type detection

## Installation

```bash
git clone https://github.com/Chabiiia/ThreatIntelLookupTool.git
cd ThreatIntelLookupTool

# Recommended: create a virtual environment
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

pip install -r requirements.txt
Requirements

Python 3.8+
VirusTotal API Key
AbuseIPDB API Key

Getting API Keys
VirusTotalhttps://www.virustotal.com/gui/join-us500 requests / day
AbuseIPDBhttps://www.abuseipdb.com/register1000 requests / day

Configuration
Copy the example environment file and add your keys:
Bashcp .env.example .env
Edit .env:
envVT_API_KEY=your_virustotal_api_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
Usage
Bash# Lookup an IP address
python main.py 8.8.8.8

# Lookup a file hash
python main.py d41d8cd98f00b204e9800998ecf8427e
python main.py e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
Example Output
text=== Intel Lookup: 8.8.8.8 (IP) ===

[VirusTotal]
  Malicious:   0
  Suspicious:  0
  Harmless:    72
  Undetected:  14
  Country:     US
  AS Owner:    Google LLC

[AbuseIPDB]
  Abuse score: 0/100
  Reports:     0
  Country:     US
  ISP:         Google LLC
  Whitelisted: True
Project Structure
textThreatIntelLookupTool/
├── main.py                 # Entry point
├── detect.py               # IP / Hash type detection
├── vt_client.py            # VirusTotal API client
├── abuseipdb_client.py     # AbuseIPDB API client
├── formatter.py            # Colored output formatter
├── .env.example
├── requirements.txt
└── README.md
Notes

Hash lookups only use VirusTotal.
IP lookups query both VirusTotal and AbuseIPDB.
Never commit your API keys. The .env file is already listed in .gitignore.

License
MIT
textYou can paste this directly into a new `README.md` file in the repository.
