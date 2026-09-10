from typing import Never

from authz_analyzer.expressions import (
    And,
    Atom,
    Constant,
    Equiv,
    Expression,
    Implies,
    Not,
    Or,
    Xor,
)
from authz_analyzer.lexer import ExpressionSyntaxError, Token, TokenKind, tokenize


class _Parser:
    def __init__(self, source: str) -> None:
        self.source = source
        self.tokens = tokenize(source)
        self.position = 0

    @property
    def current(self) -> Token:
        return self.tokens[self.position]

    def take(self, kind: TokenKind) -> Token | None:
        if self.current.kind is not kind:
            return None
        token = self.current
        self.position += 1
        return token

    def parse(self) -> Expression:
        expression = self.parse_equiv()
        if self.current.kind is not TokenKind.EOF:
            self.fail(f"unexpected token {self.current.value!r}")
        return expression

    def parse_equiv(self) -> Expression:
        expression = self.parse_implies()
        while self.take(TokenKind.EQUIV):
            expression = Equiv(expression, self.parse_implies())
        return expression

    def parse_implies(self) -> Expression:
        expression = self.parse_or()
        if self.take(TokenKind.IMPLIES):
            return Implies(expression, self.parse_implies())
        return expression

    def parse_or(self) -> Expression:
        args = [self.parse_xor()]
        while self.take(TokenKind.OR):
            args.append(self.parse_xor())
        return args[0] if len(args) == 1 else Or(tuple(args))

    def parse_xor(self) -> Expression:
        args = [self.parse_and()]
        while self.take(TokenKind.XOR):
            args.append(self.parse_and())
        return args[0] if len(args) == 1 else Xor(tuple(args))

    def parse_and(self) -> Expression:
        args = [self.parse_not()]
        while self.take(TokenKind.AND):
            args.append(self.parse_not())
        return args[0] if len(args) == 1 else And(tuple(args))

    def parse_not(self) -> Expression:
        if self.take(TokenKind.NOT):
            return Not(self.parse_not())
        return self.parse_primary()

    def parse_primary(self) -> Expression:
        if token := self.take(TokenKind.ATOM):
            return Atom(token.value)
        if self.take(TokenKind.TRUE):
            return Constant(True)
        if self.take(TokenKind.FALSE):
            return Constant(False)
        if left_paren := self.take(TokenKind.LEFT_PAREN):
            expression = self.parse_equiv()
            if not self.take(TokenKind.RIGHT_PAREN):
                self.fail("expected ')'", start=left_paren.start)
            return expression
        self.fail("expected an atom, constant, or '('")

    def fail(self, message: str, *, start: int | None = None) -> Never:
        token = self.current
        raise ExpressionSyntaxError(
            message,
            self.source,
            token.start if start is None else start,
            token.end,
        )


def parse(source: str) -> Expression:
    return _Parser(source).parse()


__all__ = ["parse"]
