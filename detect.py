import ipaddress
import re

HASH_PATTERNS={
    "MD5": re.compile(r"^[a-fA-F0-9]{32}$"),
    "SHA1": re.compile(r"^[a-fA-F0-9]{40}$"),
    "SHA256": re.compile(r"^[a-fA-F0-9]{64}$")
}

def is_ip(value:str)-> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def get_hash_type(value:str)-> str | None:
    for hash_type,pattern in HASH_PATTERNS.items():
        if pattern.match(value):
            return hash_type
    return None

def detect_input_type(value:str)-> str:
    if is_ip(value):
        return "ip"
    if get_hash_type(value):
        return "hash"
    return "unknown"
