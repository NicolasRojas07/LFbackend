import base64

def base64url_decode(input_str: str) -> bytes:
    rem = len(input_str) % 4
    if rem:
        input_str += '=' * (4 - rem)
    return base64.urlsafe_b64decode(input_str.encode('utf-8'))

def base64url_encode(input_bytes: bytes) -> str:
    return base64.urlsafe_b64encode(input_bytes).rstrip(b'=').decode('utf-8')
