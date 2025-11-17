"""
JWT Lexical Analyzer
Phase 1: Lexical Analysis

Base64URL Alphabet: Σ = {A-Z, a-z, 0-9, _, -}
Delimiters: {.}
Tokens: HEADER, DOT, PAYLOAD, DOT, SIGNATURE
"""
import re
from typing import List, Dict, Tuple
from enum import Enum


class TokenType(Enum):
    """Token types in a JWT"""
    HEADER = "HEADER"
    PAYLOAD = "PAYLOAD"
    SIGNATURE = "SIGNATURE"
    DOT = "DOT"
    INVALID = "INVALID"
    EOF = "EOF"


class Token:
    """Represents a token identified by the lexical analyzer"""
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
    JWT Lexical Analyzer
    
    Base64URL Regular Expression: ^[A-Za-z0-9_-]+$
    Alphabet: Σ = {A-Z, a-z, 0-9, _, -} (64 symbols)
    Delimiters: {.}
    """
    
    # Regular expression to validate Base64URL characters
    BASE64URL_PATTERN = re.compile(r'^[A-Za-z0-9_-]+$')
    
    # Valid Base64URL alphabet
    ALPHABET = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-')
    
    def __init__(self, jwt_string: str):
        self.input = jwt_string
        self.position = 0
        self.tokens: List[Token] = []
        self.errors: List[str] = []
    
    def tokenize(self) -> Tuple[List[Token], List[str]]:
        """
        Performs complete lexical analysis of JWT
        
        Returns:
            Tuple[List[Token], List[str]]: List of tokens and list of errors
        """
        parts = self.input.split('.')
        current_pos = 0
        
        if len(parts) < 3:
            self.errors.append(f"Incomplete JWT: expected 3 parts, found {len(parts)}")
            return self.tokens, self.errors
        
        if len(parts) > 3:
            self.errors.append(f"Invalid JWT format: found {len(parts)} parts, expected 3")
        
        # Tokenize HEADER
        header_part = parts[0]
        if self._is_valid_base64url(header_part):
            self.tokens.append(Token(TokenType.HEADER, header_part, current_pos))
        else:
            self.tokens.append(Token(TokenType.INVALID, header_part, current_pos))
            invalid_chars = self._find_invalid_chars(header_part)
            self.errors.append(f"HEADER contains invalid characters at position {current_pos}: {invalid_chars}")
        
        current_pos += len(header_part)
        
        # First DOT
        self.tokens.append(Token(TokenType.DOT, '.', current_pos))
        current_pos += 1
        
        # Tokenize PAYLOAD
        payload_part = parts[1]
        if self._is_valid_base64url(payload_part):
            self.tokens.append(Token(TokenType.PAYLOAD, payload_part, current_pos))
        else:
            self.tokens.append(Token(TokenType.INVALID, payload_part, current_pos))
            invalid_chars = self._find_invalid_chars(payload_part)
            self.errors.append(f"PAYLOAD contains invalid characters at position {current_pos}: {invalid_chars}")
        
        current_pos += len(payload_part)
        
        # Second DOT
        self.tokens.append(Token(TokenType.DOT, '.', current_pos))
        current_pos += 1
        
        # Tokenize SIGNATURE
        signature_part = parts[2]
        if self._is_valid_base64url(signature_part):
            self.tokens.append(Token(TokenType.SIGNATURE, signature_part, current_pos))
        else:
            self.tokens.append(Token(TokenType.INVALID, signature_part, current_pos))
            invalid_chars = self._find_invalid_chars(signature_part)
            self.errors.append(f"SIGNATURE contains invalid characters at position {current_pos}: {invalid_chars}")
        
        current_pos += len(signature_part)
        
        # EOF
        self.tokens.append(Token(TokenType.EOF, '', current_pos))
        
        return self.tokens, self.errors
    
    def _is_valid_base64url(self, text: str) -> bool:
        """
        Validates if text matches Base64URL regular expression
        Expression: ^[A-Za-z0-9_-]+$
        """
        if not text:
            return False
        return bool(self.BASE64URL_PATTERN.match(text))
    
    def _find_invalid_chars(self, text: str) -> str:
        """Finds characters that don't belong to Base64URL alphabet"""
        invalid = [ch for ch in text if ch not in self.ALPHABET]
        return str(set(invalid)) if invalid else "none"
    
    def get_alphabet_info(self) -> Dict:
        """Returns information about Base64URL alphabet"""
        return {
            "name": "Base64URL",
            "size": len(self.ALPHABET),
            "symbols": {
                "uppercase": "A-Z (26 symbols)",
                "lowercase": "a-z (26 symbols)",
                "digits": "0-9 (10 symbols)",
                "special": "_ - (2 symbols)"
            },
            "alphabet": sorted(list(self.ALPHABET)),
            "regex": "^[A-Za-z0-9_-]+$"
        }
    
    def analyze(self) -> Dict:
        """
        Performs complete lexical analysis and returns structured result
        """
        tokens, errors = self.tokenize()
        
        return {
            "phase": "Lexical Analysis",
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
