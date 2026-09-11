RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RESET = "\033[0m"
BOLD = "\033[1m"


def _verdict_color(malicious: int, suspicious: int = 0) -> str:
    if malicious > 0:
        return RED
    if suspicious > 0:
        return YELLOW
    return GREEN


def print_header(target: str, target_type: str) -> None:
    print(f"\n{BOLD}=== Intel Lookup: {target} ({target_type.upper()}) ==={RESET}\n")


def print_vt_ip_result(result: dict) -> None:
    print(f"{BOLD}[VirusTotal]{RESET}")
    if not result.get("found"):
        print("  No records found.\n")
        return

    color = _verdict_color(result["malicious"], result["suspicious"])
    print(f"  Malicious:   {color}{result['malicious']}{RESET}")
    print(f"  Suspicious:  {result['suspicious']}")
    print(f"  Harmless:    {result['harmless']}")
    print(f"  Undetected:  {result['undetected']}")
    print(f"  Country:     {result['country']}")
    print(f"  AS Owner:    {result['as_owner']}\n")


def print_vt_hash_result(result: dict) -> None:
    print(f"{BOLD}[VirusTotal]{RESET}")
    if not result.get("found"):
        print("  No records found.\n")
        return

    color = _verdict_color(result["malicious"], result["suspicious"])
    print(f"  Malicious:   {color}{result['malicious']}{RESET}")
    print(f"  Suspicious:  {result['suspicious']}")
    print(f"  Harmless:    {result['harmless']}")
    print(f"  Undetected:  {result['undetected']}")
    print(f"  File type:   {result['type_description']}")
    print(f"  File name:   {result['meaningful_name']}\n")


def print_abuseipdb_result(result: dict) -> None:
    print(f"{BOLD}[AbuseIPDB]{RESET}")
    score = result["abuse_confidence_score"]
    color = RED if score >= 50 else (YELLOW if score > 0 else GREEN)

    print(f"  Abuse score: {color}{score}/100{RESET}")
    print(f"  Reports:     {result['total_reports']}")
    print(f"  Country:     {result['country_code']}")
    print(f"  ISP:         {result['isp']}")
    print(f"  Whitelisted: {result['is_whitelisted']}")
    if result.get("last_reported_at"):
        print(f"  Last report: {result['last_reported_at']}")
    print()


def print_error(source: str, message: str) -> None:
    print(f"{RED}[{source}] Error: {message}{RESET}\n")