"""Decorator-based parser registry."""

from __future__ import annotations

from typing import Callable

from security_gym.parsers.base import Parser


class ParserRegistry:
    """Registry mapping parser names to Parser classes."""

    _parsers: dict[str, type[Parser]] = {}

    @classmethod
    def register(cls, name: str) -> Callable:
        """Decorator to register a parser class under a name."""
        def decorator(parser_cls: type[Parser]) -> type[Parser]:
            parser_cls.name = name
            cls._parsers[name] = parser_cls
            return parser_cls
        return decorator

    @classmethod
    def get(cls, name: str) -> Parser:
        """Instantiate and return a registered parser by name."""
        if name not in cls._parsers:
            raise KeyError(f"Unknown parser: {name!r}. Available: {cls.available()}")
        return cls._parsers[name]()

    @classmethod
    def available(cls) -> list[str]:
        """Return list of registered parser names."""
        return sorted(cls._parsers.keys())
