import json
import jwt  # PyJWT
from flask import current_app
from ..utils import base64url

class JWTService:
    """
    Service class for decoding, verifying, and creating JWTs.
    """

    @staticmethod
    def decode_token_no_verify(token: str):
        """
        Decode a JWT without verifying the signature.
        Returns header and payload as Python dicts.
        """
        parts = token.split('.')
        if len(parts) != 3:
            raise ValueError("Malformed token: must contain 3 parts separated by '.'")

        header_b = base64url.base64url_decode(parts[0])
        payload_b = base64url.base64url_decode(parts[1])
        try:
            header = json.loads(header_b)
            payload = json.loads(payload_b)
        except Exception as e:
            raise ValueError(f"Invalid JSON structure: {e}")

        return {
            "header": header,
            "payload": payload,
            "signature_b64url": parts[2]
        }

    @staticmethod
    def verify_signature(token: str, secret: str, algorithms=None) -> bool:
        """
        Verify token signature using PyJWT.
        Returns True if valid, False otherwise.
        """
        if algorithms is None:
            algorithms = current_app.config.get("ALLOWED_ALGORITHMS", ["HS256"])

        try:
            jwt.decode(token, secret, algorithms=algorithms, options={"verify_exp": False})
            return True
        except jwt.InvalidSignatureError:
            return False
        except jwt.DecodeError:
            return False
        except Exception:
            return False

    @staticmethod
    def create_token(header: dict, payload: dict, secret: str, algorithm: str = "HS256") -> str:
        """
        Create a JWT using PyJWT.
        """
        if algorithm not in current_app.config.get("ALLOWED_ALGORITHMS", ["HS256"]):
            raise ValueError("Algorithm not allowed")

        token = jwt.encode(payload, secret, algorithm=algorithm, headers=header)
        return token.decode('utf-8') if isinstance(token, bytes) else token

    @staticmethod
    def validate_semantics(header: dict, payload: dict):
        """
        Perform basic semantic checks on header and payload.
        Returns (is_valid, list_of_errors)
        """
        errors = []

        if "alg" not in header:
            errors.append("Missing 'alg' in header")
        if "typ" not in header:
            errors.append("Missing 'typ' in header")

        if "exp" in payload and not isinstance(payload["exp"], (int, float)):
            errors.append("'exp' must be numeric (timestamp)")
        if "iat" in payload and not isinstance(payload["iat"], (int, float)):
            errors.append("'iat' must be numeric (timestamp)")

        if not isinstance(header, dict):
            errors.append("Header must be a JSON object")
        if not isinstance(payload, dict):
            errors.append("Payload must be a JSON object")

        return (len(errors) == 0, errors)
