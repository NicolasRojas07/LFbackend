"""
Analizador Léxico para JWT
Fase 1: Análisis Léxico

Alfabeto Base64URL: Σ = {A-Z, a-z, 0-9, _, -}
Delimitadores: {.}
Tokens: HEADER, DOT, PAYLOAD, DOT, SIGNATURE
"""
import re
from typing import List, Dict, Tuple
from enum import Enum


class TokenType(Enum):
    """Tipos de tokens en un JWT"""
    HEADER = "HEADER"
    PAYLOAD = "PAYLOAD"
    SIGNATURE = "SIGNATURE"
    DOT = "DOT"
    INVALID = "INVALID"
    EOF = "EOF"


class Token:
    """Representa un token identificado por el analizador léxico"""
    def __init__(self, token_type: TokenType, value: str, position: int):
        self.type = token_type
        self.value = value
        self.position = position
    
    def to_dict(self):
        return {
            "type": self.type.value,
            "value": self.value,
            "position": self.position,
            "length": len(self.value)
        }
    
    def __repr__(self):
        return f"Token({self.type.value}, '{self.value[:20]}...', pos={self.position})"


class JWTLexer:
    """
    Analizador Léxico para JWT
    
    Expresión Regular Base64URL: ^[A-Za-z0-9_-]+$
    Alfabeto: Σ = {A-Z, a-z, 0-9, _, -} (64 símbolos)
    Delimitadores: {.}
    """
    
    # Expresión regular para validar caracteres Base64URL
    BASE64URL_PATTERN = re.compile(r'^[A-Za-z0-9_-]+$')
    
    # Alfabeto válido Base64URL
    ALPHABET = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-')
    
    def __init__(self, jwt_string: str):
        self.input = jwt_string
        self.position = 0
        self.tokens: List[Token] = []
        self.errors: List[str] = []
    
    def tokenize(self) -> Tuple[List[Token], List[str]]:
        """
        Realiza el análisis léxico completo del JWT
        
        Returns:
            Tuple[List[Token], List[str]]: Lista de tokens y lista de errores
        """
        parts = self.input.split('.')
        current_pos = 0
        
        if len(parts) < 3:
            self.errors.append(f"JWT incompleto: se esperaban 3 partes, se encontraron {len(parts)}")
            return self.tokens, self.errors
        
        if len(parts) > 3:
            self.errors.append(f"JWT con formato inválido: se encontraron {len(parts)} partes, se esperaban 3")
        
        # Tokenizar HEADER
        header_part = parts[0]
        if self._is_valid_base64url(header_part):
            self.tokens.append(Token(TokenType.HEADER, header_part, current_pos))
        else:
            self.tokens.append(Token(TokenType.INVALID, header_part, current_pos))
            invalid_chars = self._find_invalid_chars(header_part)
            self.errors.append(f"HEADER contiene caracteres inválidos en posición {current_pos}: {invalid_chars}")
        
        current_pos += len(header_part)
        
        # Primer DOT
        self.tokens.append(Token(TokenType.DOT, '.', current_pos))
        current_pos += 1
        
        # Tokenizar PAYLOAD
        payload_part = parts[1]
        if self._is_valid_base64url(payload_part):
            self.tokens.append(Token(TokenType.PAYLOAD, payload_part, current_pos))
        else:
            self.tokens.append(Token(TokenType.INVALID, payload_part, current_pos))
            invalid_chars = self._find_invalid_chars(payload_part)
            self.errors.append(f"PAYLOAD contiene caracteres inválidos en posición {current_pos}: {invalid_chars}")
        
        current_pos += len(payload_part)
        
        # Segundo DOT
        self.tokens.append(Token(TokenType.DOT, '.', current_pos))
        current_pos += 1
        
        # Tokenizar SIGNATURE
        signature_part = parts[2]
        if self._is_valid_base64url(signature_part):
            self.tokens.append(Token(TokenType.SIGNATURE, signature_part, current_pos))
        else:
            self.tokens.append(Token(TokenType.INVALID, signature_part, current_pos))
            invalid_chars = self._find_invalid_chars(signature_part)
            self.errors.append(f"SIGNATURE contiene caracteres inválidos en posición {current_pos}: {invalid_chars}")
        
        current_pos += len(signature_part)
        
        # EOF
        self.tokens.append(Token(TokenType.EOF, '', current_pos))
        
        return self.tokens, self.errors
    
    def _is_valid_base64url(self, text: str) -> bool:
        """
        Valida si el texto cumple con la expresión regular Base64URL
        Expresión: ^[A-Za-z0-9_-]+$
        """
        if not text:
            return False
        return bool(self.BASE64URL_PATTERN.match(text))
    
    def _find_invalid_chars(self, text: str) -> str:
        """Encuentra caracteres que no pertenecen al alfabeto Base64URL"""
        invalid = [ch for ch in text if ch not in self.ALPHABET]
        return str(set(invalid)) if invalid else "ninguno"
    
    def get_alphabet_info(self) -> Dict:
        """Retorna información sobre el alfabeto Base64URL"""
        return {
            "name": "Base64URL",
            "size": len(self.ALPHABET),
            "symbols": {
                "uppercase": "A-Z (26 símbolos)",
                "lowercase": "a-z (26 símbolos)",
                "digits": "0-9 (10 símbolos)",
                "special": "_ - (2 símbolos)"
            },
            "alphabet": sorted(list(self.ALPHABET)),
            "regex": "^[A-Za-z0-9_-]+$"
        }
    
    def analyze(self) -> Dict:
        """
        Realiza análisis léxico completo y retorna resultado estructurado
        """
        tokens, errors = self.tokenize()
        
        return {
            "phase": "Análisis Léxico",
            "success": len(errors) == 0,
            "tokens": [t.to_dict() for t in tokens],
            "token_count": len(tokens),
            "errors": errors,
            "alphabet": self.get_alphabet_info(),
            "statistics": {
                "header_length": len(self.tokens[0].value) if len(self.tokens) > 0 else 0,
                "payload_length": len(self.tokens[2].value) if len(self.tokens) > 2 else 0,
                "signature_length": len(self.tokens[4].value) if len(self.tokens) > 4 else 0,
                "total_length": len(self.input)
            }
        }
