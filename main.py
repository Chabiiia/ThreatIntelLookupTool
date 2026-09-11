import argparse
import os
import sys

from dotenv import load_dotenv
import abuseipdb_client, detect, formatter, vt_client

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Look up the IP address or file hash on VirusTotal / AbuseIPDB."
    )
    parser.add_argument("target",help="IP or Hash(MD5/SHA1/SHA256) to Look up")
    return parser.parse_args()

def main() -> int:
    load_dotenv()
    vt_key=os.getenv("VT_API_KEY")
    abuseipdb_key=os.getenv("ABUSEIPDB_API_KEY")

    if not vt_key or not abuseipdb_key:
        print("Error: You should have VT_API_KEY or ABUSEIPDB_API_KEY file in your .env .")
        print("Tip: Copy .env.example to .env and add your keys.")
        return 1

    args = parse_args()
    target= args.target.strip()
    target_type= detect.detect_input_type(target)

    if target_type == "unknown":
        print(f"Error: '{target}' does not appear to be a valid IP address or hash.")
        return 1

    formatter.print_header(target,target_type)

    if target_type == "ip":
        try:
            vt_result = vt_client.lookup_ip(target,vt_key)
            formatter.print_vt_ip_result(vt_result)
        except vt_client.VTError as e:
            formatter.print_error("Virus Total",str(e))

        try:
            abuse_result= abuseipdb_client.lookup_ip(target,abuseipdb_key)
            formatter.print_abuseipdb_result(abuse_result)
        except abuseipdb_client.IPDBError as e:
            formatter.print_error("AbuseIPDB",str(e))


    elif target_type == "hash":
        try:
            vt_result= vt_client.lookup_hash(target,vt_key)
            formatter.print_vt_hash_result(vt_result)
        except vt_client.VTError as e:
            formatter.print_error("Virus Total",str(e))


    return 0

if __name__ =="__main__":
    sys.exit(main())