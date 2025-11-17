"""
JWT Semantic Analyzer
Phase 3: Semantic Analysis

Validations:
1. Required fields in header (typ, alg)
2. Standard claims in payload (exp, nbf, iat, iss, sub, aud)
3. Data type validation
4. Temporal validation (exp, nbf, iat)
5. Symbol table (claims registry)
"""
import json
import base64
from datetime import datetime, timezone
from typing import Dict, List, Any, Tuple


class SymbolTable:
    """Symbol table to store claims and their information"""
    def __init__(self):
        self.symbols: Dict[str, Dict] = {}
    
    def add_symbol(self, name: str, value: Any, claim_type: str, scope: str):
        """Adds a symbol (claim) to the table"""
        self.symbols[name] = {
            "name": name,
            "value": value,
            "type": type(value).__name__,
            "claim_type": claim_type,  # "standard", "public", "private"
            "scope": scope  # "header", "payload"
        }
    
    def get_symbol(self, name: str) -> Dict:
        """Gets information about a symbol"""
        return self.symbols.get(name)
    
    def to_dict(self) -> List[Dict]:
        """Converts table to list of dictionaries"""
        return list(self.symbols.values())


class JWTSemanticAnalyzer:
    """
    JWT Semantic Analyzer
    
    Validates:
    - Required and optional fields
    - Correct data types
    - Semantic restrictions
    - Temporal validation
    """
    
    # Registered standard claims (RFC 7519)
    STANDARD_CLAIMS = {
        "iss": {"type": str, "description": "Issuer", "required": False},
        "sub": {"type": str, "description": "Subject", "required": False},
        "aud": {"type": (str, list), "description": "Audience", "required": False},
        "exp": {"type": int, "description": "Expiration Time", "required": False},
        "nbf": {"type": int, "description": "Not Before", "required": False},
        "iat": {"type": int, "description": "Issued At", "required": False},
        "jti": {"type": str, "description": "JWT ID", "required": False}
    }
    
    # Required header fields
    REQUIRED_HEADER_FIELDS = {
        "typ": {"type": str, "description": "Token Type", "expected": "JWT"},
        "alg": {"type": str, "description": "Algorithm", "allowed": ["HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "none"]}
    }
    
    def __init__(self, header: Dict, payload: Dict):
        self.header = header
        self.payload = payload
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.symbol_table = SymbolTable()
    
    def analyze(self) -> Dict:
        """
        Performs complete semantic analysis
        """
        # Build symbol table
        self._build_symbol_table()
        
        # Validate header
        header_valid = self._validate_header()
        
        # Validate payload
        payload_valid = self._validate_payload()
        
        # Validate data types
        types_valid = self._validate_types()
        
        # Validate temporal restrictions
        temporal_valid = self._validate_temporal()
        
        success = len(self.errors) == 0
        
        return {
            "phase": "Semantic Analysis",
            "success": success,
            "validations": {
                "header": header_valid,
                "payload": payload_valid,
                "types": types_valid,
                "temporal": temporal_valid
            },
            "symbol_table": self.symbol_table.to_dict(),
            "errors": self.errors,
            "warnings": self.warnings,
            "statistics": {
                "total_claims": len(self.symbol_table.symbols),
                "standard_claims": len([s for s in self.symbol_table.symbols.values() if s["claim_type"] == "standard"]),
                "private_claims": len([s for s in self.symbol_table.symbols.values() if s["claim_type"] == "private"])
            }
        }
    
    def _build_symbol_table(self):
        """Builds symbol table with all claims"""
        # Add header symbols
        for key, value in self.header.items():
            claim_type = "standard" if key in ["typ", "alg", "kid"] else "private"
            self.symbol_table.add_symbol(key, value, claim_type, "header")
        
        # Add payload symbols
        for key, value in self.payload.items():
            claim_type = "standard" if key in self.STANDARD_CLAIMS else "private"
            self.symbol_table.add_symbol(key, value, claim_type, "payload")
    
    def _validate_header(self) -> bool:
        """Validates required fields and header structure"""
        valid = True
        
        # Validate 'typ' field
        if "typ" not in self.header:
            self.warnings.append("Missing 'typ' field in header (recommended: 'JWT')")
        elif self.header["typ"] != "JWT":
            self.warnings.append(f"Field 'typ' has value '{self.header['typ']}', expected 'JWT'")
        
        # Validate 'alg' field (REQUIRED)
        if "alg" not in self.header:
            self.errors.append("Required field 'alg' missing in header")
            valid = False
        else:
            alg = self.header["alg"]
            allowed_algs = self.REQUIRED_HEADER_FIELDS["alg"]["allowed"]
            if alg not in allowed_algs:
                self.errors.append(f"Algorithm '{alg}' not recognized. Valid algorithms: {allowed_algs}")
                valid = False
        
        return valid
    
    def _validate_payload(self) -> bool:
        """Validates structure and payload claims"""
        valid = True
        
        # Validate non-empty payload
        if not self.payload:
            self.warnings.append("Empty payload: contains no claims")
        
        # Validate present standard claims
        for claim, info in self.STANDARD_CLAIMS.items():
            if claim in self.payload:
                expected_type = info["type"]
                actual_value = self.payload[claim]
                
                # Validate type
                if isinstance(expected_type, tuple):
                    if not isinstance(actual_value, expected_type):
                        self.errors.append(f"Claim '{claim}' has incorrect type: {type(actual_value).__name__}, expected {expected_type}")
                        valid = False
                else:
                    if not isinstance(actual_value, expected_type):
                        self.errors.append(f"Claim '{claim}' has incorrect type: {type(actual_value).__name__}, expected {expected_type.__name__}")
                        valid = False
        
        return valid
    
    def _validate_types(self) -> bool:
        """Validates data types of all claims"""
        valid = True
        
        # Validate types in header
        for key, value in self.header.items():
            if key in self.REQUIRED_HEADER_FIELDS:
                expected_type = self.REQUIRED_HEADER_FIELDS[key]["type"]
                if not isinstance(value, expected_type):
                    self.errors.append(f"Header.{key} has incorrect type: {type(value).__name__}, expected {expected_type.__name__}")
                    valid = False
        
        # Validate temporal claim types
        for temporal_claim in ["exp", "nbf", "iat"]:
            if temporal_claim in self.payload:
                value = self.payload[temporal_claim]
                if not isinstance(value, int):
                    self.errors.append(f"Temporal claim '{temporal_claim}' must be int (Unix timestamp), found {type(value).__name__}")
                    valid = False
        
        return valid
    
    def _validate_temporal(self) -> bool:
        """Validates temporal restrictions (exp, nbf, iat)"""
        valid = True
        now = datetime.now(timezone.utc).timestamp()
        
        # Validate expiration (exp)
        if "exp" in self.payload:
            exp = self.payload["exp"]
            if isinstance(exp, int):
                if exp < now:
                    self.errors.append(f"Token expired: exp={exp}, now={int(now)}")
                    valid = False
            else:
                self.errors.append(f"Claim 'exp' must be a Unix timestamp (int), found {type(exp).__name__}")
                valid = False
        else:
            self.warnings.append("Token without 'exp' claim: cannot validate expiration")
        
        # Validate not before (nbf)
        if "nbf" in self.payload:
            nbf = self.payload["nbf"]
            if isinstance(nbf, int):
                if nbf > now:
                    self.errors.append(f"Token not yet valid: nbf={nbf}, now={int(now)}")
                    valid = False
            else:
                self.errors.append(f"Claim 'nbf' must be a Unix timestamp (int), found {type(nbf).__name__}")
                valid = False
        
        # Validate issued at (iat)
        if "iat" in self.payload:
            iat = self.payload["iat"]
            if isinstance(iat, int):
                if iat > now:
                    self.warnings.append(f"Claim 'iat' is in the future: iat={iat}, now={int(now)}")
            else:
                self.errors.append(f"Claim 'iat' must be a Unix timestamp (int), found {type(iat).__name__}")
                valid = False
        
        # Validate temporal order: iat < nbf < exp
        if all(k in self.payload for k in ["iat", "nbf", "exp"]):
            iat = self.payload["iat"]
            nbf = self.payload["nbf"]
            exp = self.payload["exp"]
            
            if isinstance(iat, int) and isinstance(nbf, int) and isinstance(exp, int):
                if not (iat <= nbf <= exp):
                    self.errors.append(f"Invalid temporal order: must satisfy iat <= nbf <= exp, found iat={iat}, nbf={nbf}, exp={exp}")
                    valid = False
        
        return valid
    
    def get_semantic_rules(self) -> Dict:
        """Returns applied semantic rules"""
        return {
            "header_rules": {
                "required_fields": list(self.REQUIRED_HEADER_FIELDS.keys()),
                "typ_expected": "JWT",
                "alg_allowed": self.REQUIRED_HEADER_FIELDS["alg"]["allowed"]
            },
            "payload_rules": {
                "standard_claims": list(self.STANDARD_CLAIMS.keys()),
                "temporal_claims": ["exp", "nbf", "iat"],
                "temporal_order": "iat <= nbf <= exp"
            },
            "type_rules": {
                "exp": "int (Unix timestamp)",
                "nbf": "int (Unix timestamp)",
                "iat": "int (Unix timestamp)",
                "iss": "string",
                "sub": "string",
                "aud": "string or array",
                "jti": "string"
            }
        }
