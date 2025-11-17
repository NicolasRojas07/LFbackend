"""
JWT Syntactic Analyzer
Phase 2: Syntactic Analysis

Context-Free Grammar:
G = (V, Σ, P, S)

V (Variables): {JWT, HEADER, PAYLOAD, SIGNATURE, BASE64URL_STRING}
Σ (Terminals): {[A-Za-z0-9_-], .}
S (Start symbol): JWT

Productions (P):
1. JWT → HEADER . PAYLOAD . SIGNATURE
2. HEADER → BASE64URL_STRING
3. PAYLOAD → BASE64URL_STRING
4. SIGNATURE → BASE64URL_STRING
5. BASE64URL_STRING → [A-Za-z0-9_-]+
"""
from typing import Dict, List, Tuple
from app.analyzers.lexer import JWTLexer, TokenType, Token


class ParseNode:
    """Parse tree node"""
    def __init__(self, symbol: str, value: str = "", children: List['ParseNode'] = None):
        self.symbol = symbol  # Non-terminal or terminal
        self.value = value    # Token value (for terminals)
        self.children = children or []
    
    def to_dict(self):
        return {
            "symbol": self.symbol,
            "value": self.value,
            "children": [child.to_dict() for child in self.children],
            "is_terminal": len(self.children) == 0
        }


class JWTParser:
    """
    Recursive Descent Syntactic Analyzer for JWT
    
    Implements an LL(1) parser that validates JWT syntactic structure
    according to the defined context-free grammar.
    """
    
    def __init__(self, tokens: List[Token]):
        self.tokens = tokens
        self.current = 0
        self.errors: List[str] = []
        self.parse_tree: ParseNode = None
    
    def parse(self) -> Tuple[ParseNode, List[str], bool]:
        """
        Performs complete syntactic analysis
        
        Returns:
            Tuple[ParseNode, List[str], bool]: Parse tree, errors, success
        """
        self.parse_tree = self._parse_jwt()
        success = len(self.errors) == 0 and self.parse_tree is not None
        return self.parse_tree, self.errors, success
    
    def _current_token(self) -> Token:
        """Returns current token"""
        if self.current < len(self.tokens):
            return self.tokens[self.current]
        return Token(TokenType.EOF, '', -1)
    
    def _consume(self, expected_type: TokenType) -> Token:
        """Consumes a token of expected type"""
        token = self._current_token()
        if token.type != expected_type:
            self.errors.append(
                f"Syntax error at position {token.position}: "
                f"expected {expected_type.value}, found {token.type.value}"
            )
            return None
        self.current += 1
        return token
    
    def _parse_jwt(self) -> ParseNode:
        """
        Production 1: JWT → HEADER . PAYLOAD . SIGNATURE
        Start symbol of grammar
        """
        jwt_node = ParseNode("JWT", "")
        
        # HEADER
        header_node = self._parse_header()
        if header_node is None:
            return None
        jwt_node.children.append(header_node)
        
        # First DOT
        dot1 = self._consume(TokenType.DOT)
        if dot1 is None:
            self.errors.append("Missing first separator '.' after HEADER")
            return None
        jwt_node.children.append(ParseNode("DOT", "."))
        
        # PAYLOAD
        payload_node = self._parse_payload()
        if payload_node is None:
            return None
        jwt_node.children.append(payload_node)
        
        # Second DOT
        dot2 = self._consume(TokenType.DOT)
        if dot2 is None:
            self.errors.append("Missing second separator '.' after PAYLOAD")
            return None
        jwt_node.children.append(ParseNode("DOT", "."))
        
        # SIGNATURE
        signature_node = self._parse_signature()
        if signature_node is None:
            return None
        jwt_node.children.append(signature_node)
        
        # Verify EOF
        eof = self._consume(TokenType.EOF)
        if eof is None:
            self.errors.append("Found additional characters after valid JWT")
            return None
        
        return jwt_node
    
    def _parse_header(self) -> ParseNode:
        """
        Production 2: HEADER → BASE64URL_STRING
        """
        token = self._current_token()
        if token.type == TokenType.INVALID:
            self.errors.append(f"Invalid HEADER at position {token.position}: contains non-Base64URL characters")
            self.current += 1
            return None
        
        if token.type != TokenType.HEADER:
            self.errors.append(f"Expected HEADER, found {token.type.value}")
            return None
        
        self.current += 1
        header_node = ParseNode("HEADER", "")
        base64_node = ParseNode("BASE64URL_STRING", token.value)
        header_node.children.append(base64_node)
        return header_node
    
    def _parse_payload(self) -> ParseNode:
        """
        Production 3: PAYLOAD → BASE64URL_STRING
        """
        token = self._current_token()
        if token.type == TokenType.INVALID:
            self.errors.append(f"Invalid PAYLOAD at position {token.position}: contains non-Base64URL characters")
            self.current += 1
            return None
        
        if token.type != TokenType.PAYLOAD:
            self.errors.append(f"Expected PAYLOAD, found {token.type.value}")
            return None
        
        self.current += 1
        payload_node = ParseNode("PAYLOAD", "")
        base64_node = ParseNode("BASE64URL_STRING", token.value)
        payload_node.children.append(base64_node)
        return payload_node
    
    def _parse_signature(self) -> ParseNode:
        """
        Production 4: SIGNATURE → BASE64URL_STRING
        """
        token = self._current_token()
        if token.type == TokenType.INVALID:
            self.errors.append(f"Invalid SIGNATURE at position {token.position}: contains non-Base64URL characters")
            self.current += 1
            return None
        
        if token.type != TokenType.SIGNATURE:
            self.errors.append(f"Expected SIGNATURE, found {token.type.value}")
            return None
        
        self.current += 1
        signature_node = ParseNode("SIGNATURE", "")
        base64_node = ParseNode("BASE64URL_STRING", token.value)
        signature_node.children.append(base64_node)
        return signature_node
    
    def get_grammar_info(self) -> Dict:
        """Returns grammar information"""
        return {
            "type": "Context-Free Grammar (CFG)",
            "parser_type": "Recursive Descent LL(1)",
            "start_symbol": "JWT",
            "non_terminals": ["JWT", "HEADER", "PAYLOAD", "SIGNATURE", "BASE64URL_STRING"],
            "terminals": ["[A-Za-z0-9_-]", "."],
            "productions": [
                "JWT → HEADER . PAYLOAD . SIGNATURE",
                "HEADER → BASE64URL_STRING",
                "PAYLOAD → BASE64URL_STRING",
                "SIGNATURE → BASE64URL_STRING",
                "BASE64URL_STRING → [A-Za-z0-9_-]+"
            ]
        }
    
    def analyze(self) -> Dict:
        """
        Performs complete syntactic analysis and returns structured result
        """
        parse_tree, errors, success = self.parse()
        
        return {
            "phase": "Syntactic Analysis",
            "success": success,
            "grammar": self.get_grammar_info(),
            "parse_tree": parse_tree.to_dict() if parse_tree else None,
            "errors": errors,
            "tokens_consumed": self.current
        }
