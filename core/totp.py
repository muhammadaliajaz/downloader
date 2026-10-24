import hmac
import hashlib
import time
import struct
import base64
import secrets
import json
import io
import urllib.parse
from werkzeug.security import generate_password_hash, check_password_hash

def generate_base32_secret(length=20) -> str:
    """Generates a cryptographically random Base32 secret for TOTP authenticator apps."""
    random_bytes = secrets.token_bytes(length)
    return base64.b32encode(random_bytes).decode('utf-8').rstrip('=').upper()

def get_totp_code(secret_b32: str, current_time: float = None, interval: int = 30) -> str:
    """Computes standard RFC 6238 TOTP 6-digit code using HMAC-SHA1."""
    if current_time is None:
        current_time = time.time()
    
    # Pad secret if padding was stripped
    secret_clean = secret_b32.strip().upper()
    missing_padding = len(secret_clean) % 8
    if missing_padding:
        secret_clean += '=' * (8 - missing_padding)

    key = base64.b32decode(secret_clean)
    counter = int(current_time // interval)
    msg = struct.pack('>Q', counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0f
    code = (struct.unpack('>I', digest[offset:offset+4])[0] & 0x7fffffff) % 1000000
    return f"{code:06d}"

def verify_totp_code(secret_b32: str, code_input: str, interval: int = 30, window: int = 2) -> bool:
    """
    Verifies submitted 6-digit code against TOTP algorithm with clock drift tolerance.
    Window of 2 checks [current - 60s, current - 30s, current, current + 30s, current + 60s]
    to prevent false rejections due to minor mobile or server clock skew.
    """
    if not secret_b32 or not code_input:
        return False

    code_clean = ''.join(c for c in str(code_input).strip() if c.isdigit())
    if len(code_clean) != 6:
        return False

    now = time.time()
    for w in range(-window, window + 1):
        candidate_time = now + (w * interval)
        expected = get_totp_code(secret_b32, candidate_time, interval)
        if secrets.compare_digest(expected, code_clean):
            return True
    return False

def generate_qr_code_data_uri(secret_b32: str, username: str = "", issuer: str = "StellarStudio") -> str:
    """Generates an embedded PNG Base64 data URI of the Authenticator QR code."""
    # Defensive guard: if arguments were accidentally swapped (e.g. username first, secret second)
    if len(username) > len(secret_b32) and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=' for c in username.upper()):
        secret_b32, username = username, secret_b32

    secret_clean = secret_b32.strip().upper()
    issuer_clean = issuer.replace(' ', '')
    user_clean = username.strip() or "admin"
    
    # Standard RFC 6238 Key URI format (Google Authenticator / Authy / Microsoft Authenticator)
    otp_uri = f"otpauth://totp/{issuer_clean}:{user_clean}?secret={secret_clean}&issuer={issuer_clean}&algorithm=SHA1&digits=6&period=30"
    try:
        import qrcode
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=5,
            border=2,
        )
        qr.add_data(otp_uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="#102421", back_color="#ffffff")
        
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        b64_str = base64.b64encode(buf.getvalue()).decode('utf-8')
        return f"data:image/png;base64,{b64_str}"
    except Exception as e:
        # Graceful fallback: return empty string so 2FA page still works and shows manual secret key
        return ""

def generate_backup_scratch_codes(count=8):
    """
    Generates single-use emergency backup scratch codes.
    Returns (plain_codes: list, hashed_codes_json: str)
    """
    plain = []
    hashed = []
    for _ in range(count):
        part1 = secrets.token_hex(2).upper()
        part2 = secrets.token_hex(2).upper()
        code = f"{part1}-{part2}"
        plain.append(code)
        hashed.append(generate_password_hash(code))
    return plain, json.dumps(hashed)

def verify_and_consume_backup_code(backup_codes_json: str, code_input: str):
    """
    Checks if code matches one of the one-time backup codes and consumes it.
    Returns (is_valid: bool, updated_backup_codes_json: str)
    """
    if not backup_codes_json or not code_input:
        return False, backup_codes_json

    try:
        hashed_list = json.loads(backup_codes_json)
    except Exception:
        return False, backup_codes_json

    clean_input = code_input.strip().upper()
    for idx, h in enumerate(hashed_list):
        if check_password_hash(h, clean_input):
            # Consume single-use code
            hashed_list.pop(idx)
            return True, json.dumps(hashed_list)

    return False, backup_codes_json

def generate_emergency_recovery_key():
    """
    Generates a master emergency account recovery key (e.g. REC-XXXX-XXXX-XXXX-XXXX).
    Returns (plain_key: str, hashed_key: str)
    """
    parts = [secrets.token_hex(2).upper() for _ in range(4)]
    plain_key = f"REC-{'-'.join(parts)}"
    hashed_key = generate_password_hash(plain_key)
    return plain_key, hashed_key

def verify_emergency_recovery_key(stored_hash: str, key_input: str) -> bool:
    """Verifies emergency recovery key against stored hash."""
    if not stored_hash or not key_input:
        return False
    clean_input = key_input.strip().upper()
    return check_password_hash(stored_hash, clean_input)
