import json
import jwt
from flask import current_app
from app.utils import base64url

class JWTService:

    @staticmethod
    def decode_token_no_verify(token: str):
        parts = token.split('.')
        if len(parts) != 3:
            raise ValueError("Malformed token: must contain 3 parts separated by '.'")

        header_b = base64url.base64url_decode(parts[0])
        payload_b = base64url.base64url_decode(parts[1])
        try:
            header = json.loads(header_b.decode('utf-8'))
            payload = json.loads(payload_b.decode('utf-8'))
        except Exception as e:
            raise ValueError(f"Invalid JSON structure: {e}")

        return {
            "header": header,
            "payload": payload,
            "signature_b64url": parts[2]
        }

    @staticmethod
    def verify_signature(token: str, secret: str, algorithms=None) -> bool:
        if algorithms is None:
            algorithms = current_app.config.get("ALLOWED_ALGORITHMS", ["HS256"])
        try:
            jwt.decode(token, secret, algorithms=algorithms, options={"verify_exp": False})
            return True
        except (jwt.InvalidSignatureError, jwt.DecodeError):
            return False
        except Exception:
            return False

    @staticmethod
    def create_token(header: dict, payload: dict, secret: str, algorithm: str = "HS256") -> str:
        if algorithm not in current_app.config.get("ALLOWED_ALGORITHMS", ["HS256"]):
            raise ValueError("Algorithm not allowed")
        return jwt.encode(payload, secret, algorithm=algorithm, headers=header)

    @staticmethod
    def validate_semantics(header: dict, payload: dict):
        errors = []
        if not isinstance(header, dict):
            errors.append("Header must be a JSON object")
        if not isinstance(payload, dict):
            errors.append("Payload must be a JSON object")
        if "alg" not in header:
            errors.append("Missing 'alg' in header")
        if "typ" not in header:
            errors.append("Missing 'typ' in header")
        if "exp" in payload and not isinstance(payload["exp"], (int, float)):
            errors.append("'exp' must be numeric (timestamp)")
        if "iat" in payload and not isinstance(payload["iat"], (int, float)):
            errors.append("'iat' must be numeric (timestamp)")
        return (len(errors) == 0, errors)
