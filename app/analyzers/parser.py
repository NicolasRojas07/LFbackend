"""
Analizador Sintáctico para JWT
Fase 2: Análisis Sintáctico

Gramática Libre de Contexto:
G = (V, Σ, P, S)

V (Variables): {JWT, HEADER, PAYLOAD, SIGNATURE, BASE64URL_STRING}
Σ (Terminales): {[A-Za-z0-9_-], .}
S (Símbolo inicial): JWT

Producciones (P):
1. JWT → HEADER . PAYLOAD . SIGNATURE
2. HEADER → BASE64URL_STRING
3. PAYLOAD → BASE64URL_STRING
4. SIGNATURE → BASE64URL_STRING
5. BASE64URL_STRING → [A-Za-z0-9_-]+
"""
from typing import Dict, List, Tuple
from app.analyzers.lexer import JWTLexer, TokenType, Token


class ParseNode:
    """Nodo del árbol de derivación"""
    def __init__(self, symbol: str, value: str = "", children: List['ParseNode'] = None):
        self.symbol = symbol  # No terminal o terminal
        self.value = value    # Valor del token (para terminales)
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
    Analizador Sintáctico Descendente Recursivo para JWT
    
    Implementa un parser LL(1) que valida la estructura sintáctica del JWT
    según la gramática libre de contexto definida.
    """
    
    def __init__(self, tokens: List[Token]):
        self.tokens = tokens
        self.current = 0
        self.errors: List[str] = []
        self.parse_tree: ParseNode = None
    
    def parse(self) -> Tuple[ParseNode, List[str], bool]:
        """
        Realiza el análisis sintáctico completo
        
        Returns:
            Tuple[ParseNode, List[str], bool]: Árbol de derivación, errores, éxito
        """
        self.parse_tree = self._parse_jwt()
        success = len(self.errors) == 0 and self.parse_tree is not None
        return self.parse_tree, self.errors, success
    
    def _current_token(self) -> Token:
        """Retorna el token actual"""
        if self.current < len(self.tokens):
            return self.tokens[self.current]
        return Token(TokenType.EOF, '', -1)
    
    def _consume(self, expected_type: TokenType) -> Token:
        """Consume un token del tipo esperado"""
        token = self._current_token()
        if token.type != expected_type:
            self.errors.append(
                f"Error sintáctico en posición {token.position}: "
                f"se esperaba {expected_type.value}, se encontró {token.type.value}"
            )
            return None
        self.current += 1
        return token
    
    def _parse_jwt(self) -> ParseNode:
        """
        Producción 1: JWT → HEADER . PAYLOAD . SIGNATURE
        Símbolo inicial de la gramática
        """
        jwt_node = ParseNode("JWT", "")
        
        # HEADER
        header_node = self._parse_header()
        if header_node is None:
            return None
        jwt_node.children.append(header_node)
        
        # Primer DOT
        dot1 = self._consume(TokenType.DOT)
        if dot1 is None:
            self.errors.append("Falta el primer separador '.' después del HEADER")
            return None
        jwt_node.children.append(ParseNode("DOT", "."))
        
        # PAYLOAD
        payload_node = self._parse_payload()
        if payload_node is None:
            return None
        jwt_node.children.append(payload_node)
        
        # Segundo DOT
        dot2 = self._consume(TokenType.DOT)
        if dot2 is None:
            self.errors.append("Falta el segundo separador '.' después del PAYLOAD")
            return None
        jwt_node.children.append(ParseNode("DOT", "."))
        
        # SIGNATURE
        signature_node = self._parse_signature()
        if signature_node is None:
            return None
        jwt_node.children.append(signature_node)
        
        # Verificar EOF
        eof = self._consume(TokenType.EOF)
        if eof is None:
            self.errors.append("Se encontraron caracteres adicionales después del JWT válido")
            return None
        
        return jwt_node
    
    def _parse_header(self) -> ParseNode:
        """
        Producción 2: HEADER → BASE64URL_STRING
        """
        token = self._current_token()
        if token.type == TokenType.INVALID:
            self.errors.append(f"HEADER inválido en posición {token.position}: contiene caracteres no Base64URL")
            self.current += 1
            return None
        
        if token.type != TokenType.HEADER:
            self.errors.append(f"Se esperaba HEADER, se encontró {token.type.value}")
            return None
        
        self.current += 1
        header_node = ParseNode("HEADER", "")
        base64_node = ParseNode("BASE64URL_STRING", token.value)
        header_node.children.append(base64_node)
        return header_node
    
    def _parse_payload(self) -> ParseNode:
        """
        Producción 3: PAYLOAD → BASE64URL_STRING
        """
        token = self._current_token()
        if token.type == TokenType.INVALID:
            self.errors.append(f"PAYLOAD inválido en posición {token.position}: contiene caracteres no Base64URL")
            self.current += 1
            return None
        
        if token.type != TokenType.PAYLOAD:
            self.errors.append(f"Se esperaba PAYLOAD, se encontró {token.type.value}")
            return None
        
        self.current += 1
        payload_node = ParseNode("PAYLOAD", "")
        base64_node = ParseNode("BASE64URL_STRING", token.value)
        payload_node.children.append(base64_node)
        return payload_node
    
    def _parse_signature(self) -> ParseNode:
        """
        Producción 4: SIGNATURE → BASE64URL_STRING
        """
        token = self._current_token()
        if token.type == TokenType.INVALID:
            self.errors.append(f"SIGNATURE inválida en posición {token.position}: contiene caracteres no Base64URL")
            self.current += 1
            return None
        
        if token.type != TokenType.SIGNATURE:
            self.errors.append(f"Se esperaba SIGNATURE, se encontró {token.type.value}")
            return None
        
        self.current += 1
        signature_node = ParseNode("SIGNATURE", "")
        base64_node = ParseNode("BASE64URL_STRING", token.value)
        signature_node.children.append(base64_node)
        return signature_node
    
    def get_grammar_info(self) -> Dict:
        """Retorna información sobre la gramática"""
        return {
            "type": "Gramática Libre de Contexto (CFG)",
            "parser_type": "Descendente Recursivo LL(1)",
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
        Realiza análisis sintáctico completo y retorna resultado estructurado
        """
        parse_tree, errors, success = self.parse()
        
        return {
            "phase": "Análisis Sintáctico",
            "success": success,
            "grammar": self.get_grammar_info(),
            "parse_tree": parse_tree.to_dict() if parse_tree else None,
            "errors": errors,
            "tokens_consumed": self.current
        }
