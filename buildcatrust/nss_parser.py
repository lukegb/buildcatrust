# SPDX-FileCopyrightText: 2021 Luke Granger-Brown <git@lukegb.com>
#
# SPDX-License-Identifier: MIT

from collections.abc import Iterable
import enum
import re
from typing import Union

from . import enums


class ParserState(enum.Enum):
    AWAITING_DATA = enum.auto()
    OBJECT_AWAIT_ATTRIBUTE = enum.auto()
    OBJECT_AWAIT_TYPE = enum.auto()
    OBJECT_AWAIT_VALUE = enum.auto()
    OBJECT_AWAIT_MULTILINE_OCTAL_VALUE = enum.auto()


class ParseError(Exception):
    pass


ParsedValue = Union[bool, enums.ObjectType, str, bytes, enums.TrustType]
ParsedObject = dict[bytes, ParsedValue]


def _value_to_python(ck_type: bytes, ck_value: bytes) -> ParsedValue:
    if ck_type == b"CK_BBOOL":
        if ck_value == b"CK_FALSE":
            return False
        elif ck_value == b"CK_TRUE":
            return True
        raise ParseError(f"unknown value {ck_value} for type {ck_type}")
    elif ck_type == b"CK_OBJECT_CLASS":
        if not ck_value.startswith(b"CKO_"):
            raise ParseError(
                f"CK_OBJECT_CLASS value {ck_value} doesn't begin with CKO_"
            )
        return enums.ObjectType[ck_value[len("CKO_") :].decode("utf-8")]
    elif ck_type == b"UTF8":
        return ck_value.decode("utf-8")
    elif ck_type == b"CK_CERTIFICATE_TYPE":
        if ck_value != b"CKC_X_509":
            raise ParseError(f"unknown value {ck_value} for type {ck_type}")
        return ck_value
    elif ck_type == b"CK_TRUST":
        if not ck_value.startswith(b"CKT_NSS_"):
            raise ParseError(f"CK_TRUST value {ck_value} doesn't begin with CKT_NSS_")
        return enums.TrustType[ck_value[len("CKT_NSS_") :].decode("utf-8")]
    elif ck_type == b"MULTILINE_OCTAL":
        return ck_value.decode("unicode-escape").encode("latin1")
    else:
        raise ParseError(f"unknown type {ck_type} (value: {ck_value})")


class Parser:
    def __init__(self):
        self.objects = []  # type: list[ParsedObject]
        self.state = ParserState.AWAITING_DATA

        self._current_object = None  # type: ParsedObject | None
        self._current_attribute = None  # type: bytes | None
        self._current_type = None  # type: bytes | None
        self._current_value = None  # type: ParsedValue | None

    @staticmethod
    def _split_line(ln: bytes) -> Iterable[bytes]:
        # Consume either:
        # Whitespace
        # "quoted string with \" "
        # non-space token
        for m in re.finditer(
            rb'((?P<space>\s+)|(?P<quoted_string>"(?:\\"|.)*?")|(?P<token>[^"\s][^\s]+))',
            ln,
        ):
            if m.group("space"):
                continue
            elif m.group("quoted_string"):
                yield m.group("quoted_string")[1:-1].replace(rb"\"", b'"')
            elif m.group("token"):
                yield m.group("token")

    def _new_object(self) -> Iterable[ParsedObject]:
        if self._current_object:
            yield self._current_object
        self._current_object = {}
        self._new_attribute()

    def _new_attribute(self) -> None:
        if self._current_attribute:
            # Parse the type to turn it into something useful.
            self._current_object[self._current_attribute] = _value_to_python(
                self._current_type, self._current_value
            )
        self._current_attribute = None
        self._current_type = None
        self._current_value = None

    def parse_token(self, token: bytes) -> Iterable[ParsedObject]:
        if self.state == ParserState.AWAITING_DATA:
            if token == b"BEGINDATA":
                yield from self._new_object()
                self.state = ParserState.OBJECT_AWAIT_ATTRIBUTE
        elif self.state == ParserState.OBJECT_AWAIT_ATTRIBUTE:
            if token == b"CKA_CLASS":
                yield from self._new_object()
            self._current_attribute = token
            self.state = ParserState.OBJECT_AWAIT_TYPE
        elif self.state == ParserState.OBJECT_AWAIT_TYPE:
            self._current_type = token
            if token == b"MULTILINE_OCTAL":
                self.state = ParserState.OBJECT_AWAIT_MULTILINE_OCTAL_VALUE
            else:
                self.state = ParserState.OBJECT_AWAIT_VALUE
        elif self.state == ParserState.OBJECT_AWAIT_VALUE:
            self._current_value = token
            self._new_attribute()
            self.state = ParserState.OBJECT_AWAIT_ATTRIBUTE
        elif self.state == ParserState.OBJECT_AWAIT_MULTILINE_OCTAL_VALUE:
            if token == b"END":
                self._current_value = self._current_value
                self._new_attribute()
                self.state = ParserState.OBJECT_AWAIT_ATTRIBUTE
            elif not self._current_value:
                self._current_value = token
            else:
                self._current_value += token

    def parse_lines(self, line_iterator: Iterable[bytes]) -> Iterable[ParsedObject]:
        for ln in line_iterator:
            ln = ln.strip()
            if ln.startswith(b"#"):
                continue
            for token in self._split_line(ln):
                yield from self.parse_token(token)
        yield from self._new_object()
