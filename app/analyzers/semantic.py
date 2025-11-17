"""
Analizador Semántico para JWT
Fase 3: Análisis Semántico

Validaciones:
1. Campos obligatorios en header (typ, alg)
2. Claims estándar en payload (exp, nbf, iat, iss, sub, aud)
3. Validación de tipos de datos
4. Validación temporal (exp, nbf, iat)
5. Tabla de símbolos (claims registry)
"""
import json
import base64
from datetime import datetime, timezone
from typing import Dict, List, Any, Tuple


class SymbolTable:
    """Tabla de símbolos para almacenar claims y su información"""
    def __init__(self):
        self.symbols: Dict[str, Dict] = {}
    
    def add_symbol(self, name: str, value: Any, claim_type: str, scope: str):
        """Agrega un símbolo (claim) a la tabla"""
        self.symbols[name] = {
            "name": name,
            "value": value,
            "type": type(value).__name__,
            "claim_type": claim_type,  # "standard", "public", "private"
            "scope": scope  # "header", "payload"
        }
    
    def get_symbol(self, name: str) -> Dict:
        """Obtiene información de un símbolo"""
        return self.symbols.get(name)
    
    def to_dict(self) -> List[Dict]:
        """Convierte la tabla a lista de diccionarios"""
        return list(self.symbols.values())


class JWTSemanticAnalyzer:
    """
    Analizador Semántico para JWT
    
    Valida:
    - Campos obligatorios y opcionales
    - Tipos de datos correctos
    - Restricciones semánticas
    - Validación temporal
    """
    
    # Claims estándar registrados (RFC 7519)
    STANDARD_CLAIMS = {
        "iss": {"type": str, "description": "Issuer", "required": False},
        "sub": {"type": str, "description": "Subject", "required": False},
        "aud": {"type": (str, list), "description": "Audience", "required": False},
        "exp": {"type": int, "description": "Expiration Time", "required": False},
        "nbf": {"type": int, "description": "Not Before", "required": False},
        "iat": {"type": int, "description": "Issued At", "required": False},
        "jti": {"type": str, "description": "JWT ID", "required": False}
    }
    
    # Campos obligatorios en header
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
        Realiza análisis semántico completo
        """
        # Construir tabla de símbolos
        self._build_symbol_table()
        
        # Validar header
        header_valid = self._validate_header()
        
        # Validar payload
        payload_valid = self._validate_payload()
        
        # Validar tipos de datos
        types_valid = self._validate_types()
        
        # Validar restricciones temporales
        temporal_valid = self._validate_temporal()
        
        success = len(self.errors) == 0
        
        return {
            "phase": "Análisis Semántico",
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
        """Construye la tabla de símbolos con todos los claims"""
        # Agregar símbolos del header
        for key, value in self.header.items():
            claim_type = "standard" if key in ["typ", "alg", "kid"] else "private"
            self.symbol_table.add_symbol(key, value, claim_type, "header")
        
        # Agregar símbolos del payload
        for key, value in self.payload.items():
            claim_type = "standard" if key in self.STANDARD_CLAIMS else "private"
            self.symbol_table.add_symbol(key, value, claim_type, "payload")
    
    def _validate_header(self) -> bool:
        """Valida campos obligatorios y estructura del header"""
        valid = True
        
        # Validar campo 'typ'
        if "typ" not in self.header:
            self.warnings.append("Campo 'typ' faltante en header (recomendado: 'JWT')")
        elif self.header["typ"] != "JWT":
            self.warnings.append(f"Campo 'typ' tiene valor '{self.header['typ']}', se esperaba 'JWT'")
        
        # Validar campo 'alg' (OBLIGATORIO)
        if "alg" not in self.header:
            self.errors.append("Campo obligatorio 'alg' faltante en header")
            valid = False
        else:
            alg = self.header["alg"]
            allowed_algs = self.REQUIRED_HEADER_FIELDS["alg"]["allowed"]
            if alg not in allowed_algs:
                self.errors.append(f"Algoritmo '{alg}' no reconocido. Algoritmos válidos: {allowed_algs}")
                valid = False
        
        return valid
    
    def _validate_payload(self) -> bool:
        """Valida estructura y claims del payload"""
        valid = True
        
        # Validar que el payload no esté vacío
        if not self.payload:
            self.warnings.append("Payload vacío: no contiene claims")
        
        # Validar claims estándar presentes
        for claim, info in self.STANDARD_CLAIMS.items():
            if claim in self.payload:
                expected_type = info["type"]
                actual_value = self.payload[claim]
                
                # Validar tipo
                if isinstance(expected_type, tuple):
                    if not isinstance(actual_value, expected_type):
                        self.errors.append(f"Claim '{claim}' tiene tipo incorrecto: {type(actual_value).__name__}, se esperaba {expected_type}")
                        valid = False
                else:
                    if not isinstance(actual_value, expected_type):
                        self.errors.append(f"Claim '{claim}' tiene tipo incorrecto: {type(actual_value).__name__}, se esperaba {expected_type.__name__}")
                        valid = False
        
        return valid
    
    def _validate_types(self) -> bool:
        """Valida tipos de datos de todos los claims"""
        valid = True
        
        # Validar tipos en header
        for key, value in self.header.items():
            if key in self.REQUIRED_HEADER_FIELDS:
                expected_type = self.REQUIRED_HEADER_FIELDS[key]["type"]
                if not isinstance(value, expected_type):
                    self.errors.append(f"Header.{key} tiene tipo incorrecto: {type(value).__name__}, se esperaba {expected_type.__name__}")
                    valid = False
        
        # Validar tipos de claims temporales
        for temporal_claim in ["exp", "nbf", "iat"]:
            if temporal_claim in self.payload:
                value = self.payload[temporal_claim]
                if not isinstance(value, int):
                    self.errors.append(f"Claim temporal '{temporal_claim}' debe ser int (Unix timestamp), se encontró {type(value).__name__}")
                    valid = False
        
        return valid
    
    def _validate_temporal(self) -> bool:
        """Valida restricciones temporales (exp, nbf, iat)"""
        valid = True
        now = datetime.now(timezone.utc).timestamp()
        
        # Validar expiración (exp)
        if "exp" in self.payload:
            exp = self.payload["exp"]
            if isinstance(exp, int):
                if exp < now:
                    self.errors.append(f"Token expirado: exp={exp}, now={int(now)}")
                    valid = False
            else:
                self.errors.append(f"Claim 'exp' debe ser un timestamp Unix (int), se encontró {type(exp).__name__}")
                valid = False
        else:
            self.warnings.append("Token sin claim 'exp': no se puede validar expiración")
        
        # Validar not before (nbf)
        if "nbf" in self.payload:
            nbf = self.payload["nbf"]
            if isinstance(nbf, int):
                if nbf > now:
                    self.errors.append(f"Token aún no válido: nbf={nbf}, now={int(now)}")
                    valid = False
            else:
                self.errors.append(f"Claim 'nbf' debe ser un timestamp Unix (int), se encontró {type(nbf).__name__}")
                valid = False
        
        # Validar issued at (iat)
        if "iat" in self.payload:
            iat = self.payload["iat"]
            if isinstance(iat, int):
                if iat > now:
                    self.warnings.append(f"Claim 'iat' está en el futuro: iat={iat}, now={int(now)}")
            else:
                self.errors.append(f"Claim 'iat' debe ser un timestamp Unix (int), se encontró {type(iat).__name__}")
                valid = False
        
        # Validar orden temporal: iat < nbf < exp
        if all(k in self.payload for k in ["iat", "nbf", "exp"]):
            iat = self.payload["iat"]
            nbf = self.payload["nbf"]
            exp = self.payload["exp"]
            
            if isinstance(iat, int) and isinstance(nbf, int) and isinstance(exp, int):
                if not (iat <= nbf <= exp):
                    self.errors.append(f"Orden temporal inválido: debe cumplirse iat <= nbf <= exp, se encontró iat={iat}, nbf={nbf}, exp={exp}")
                    valid = False
        
        return valid
    
    def get_semantic_rules(self) -> Dict:
        """Retorna las reglas semánticas aplicadas"""
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
