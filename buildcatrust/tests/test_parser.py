# SPDX-FileCopyrightText: 2021 Luke Granger-Brown <git@lukegb.com>
#
# SPDX-License-Identifier: MIT

import os

import pytest

from buildcatrust import enums
from buildcatrust import nss_parser


def _parse(s: str):
    return list(nss_parser.Parser().parse_lines(s.encode("utf-8").split(b"\n")))


def test_parses_root_list_obj():
    objs = _parse(
        """\
# Some comments
BEGINDATA
CKA_CLASS CK_OBJECT_CLASS CKO_NSS_BUILTIN_ROOT_LIST
CKA_TOKEN CK_BBOOL CK_TRUE
CKA_PRIVATE CK_BBOOL CK_FALSE
CKA_MODIFIABLE CK_BBOOL CK_FALSE
CKA_LABEL UTF8 "Happy Flappy"
"""
    )
    assert objs == [
        {
            b"CKA_CLASS": enums.ObjectType.NSS_BUILTIN_ROOT_LIST,
            b"CKA_TOKEN": True,
            b"CKA_PRIVATE": False,
            b"CKA_MODIFIABLE": False,
            b"CKA_LABEL": "Happy Flappy",
        }
    ]


def test_parses_cert_obj():
    with open(
        os.path.join(os.path.dirname(__file__), "testdata", "certdata-certumec384.txt"),
        "r",
    ) as f:
        objs = _parse(f.read())
    assert objs[1] == {
        b"CKA_CERTIFICATE_TYPE": b"CKC_X_509",
        b"CKA_CLASS": enums.ObjectType.CERTIFICATE,
        b"CKA_ID": "0",
        b"CKA_ISSUER": (
            b"0t1\x0b0\t\x06\x03U\x04\x06\x13\x02PL1!0\x1f\x06\x03U\x04\n"
            b"\x13\x18Asseco Data Systems S.A.1'0%\x06\x03U\x04\x0b\x13"
            b"\x1eCertum Certification Authority1\x190\x17\x06"
            b"\x03U\x04\x03\x13\x10Certum EC-384 CA"
        ),
        b"CKA_LABEL": "Certum EC-384 CA",
        b"CKA_MODIFIABLE": False,
        b"CKA_NSS_EMAIL_DISTRUST_AFTER": False,
        b"CKA_NSS_MOZILLA_CA_POLICY": True,
        b"CKA_NSS_SERVER_DISTRUST_AFTER": False,
        b"CKA_PRIVATE": False,
        b"CKA_SERIAL_NUMBER": b"\x02\x10x\x8f'\\\x81\x12R \xa5\x04\xd0-\xdd\xbas\xf4",
        b"CKA_SUBJECT": (
            b"0t1\x0b0\t\x06\x03U\x04\x06\x13\x02PL1!0\x1f\x06\x03U\x04\n"
            b"\x13\x18Asseco Data Systems S.A.1'0%\x06\x03U\x04\x0b\x13"
            b"\x1eCertum Certification Authority1\x190\x17\x06"
            b"\x03U\x04\x03\x13\x10Certum EC-384 CA"
        ),
        b"CKA_TOKEN": True,
        b"CKA_VALUE": (
            b"0\x82\x02e0\x82\x01\xeb\xa0\x03\x02\x01\x02\x02\x10x"
            b"\x8f'\\\x81\x12R \xa5\x04\xd0-\xdd\xbas\xf40\n\x06\x08*"
            b"\x86H\xce=\x04\x03\x030t1\x0b0\t\x06\x03U\x04\x06\x13\x02PL1!"
            b"0\x1f\x06\x03U\x04\n\x13\x18Asseco Data Systems S.A.1'0"
            b"%\x06\x03U\x04\x0b\x13\x1eCertum Certification Authority1\x19"
            b"0\x17\x06\x03U\x04\x03\x13\x10Certum EC-384 CA0\x1e\x17\r180"
            b"326072454Z\x17\r430326072454Z0t1\x0b0\t\x06\x03U\x04\x06"
            b"\x13\x02PL1!0\x1f\x06\x03U\x04\n\x13\x18Asseco Data Systems S"
            b".A.1'0%\x06\x03U\x04\x0b\x13\x1eCertum Certification Autho"
            b"rity1\x190\x17\x06\x03U\x04\x03\x13\x10Certum EC-384 CA0"
            b'v0\x10\x06\x07*\x86H\xce=\x02\x01\x06\x05+\x81\x04\x00"\x03'
            b"b\x00\x04\xc4(\x8e\xab\x18[j\xbend7c\xe4\xcd\xec\xab:"
            b"\xf7\xcc\xa1\xb8\x0e\x82I\xd7\x86)\x9f\xa1\x94\xf2\xe3`"
            b"x\x98\x81x\x06M\xf2\xec\x9a\x0eW`\x83\x9f\xb4\xe6"
            b"\x17/\x1a\xb3]\x02[\x89#<\xc2\x11\x05*\xa7\x88\x13\x18\xf3P"
            b"\x84\xd7\xbd4,'\x89U\xff\xceL\xe7\xdf\xa6\x1f(\xc4\xf0T\xc3"
            b"\xb9|\xb7S\xad\xeb\xc2\xa3B0@0\x0f\x06\x03U\x1d\x13\x01\x01"
            b"\xff\x04\x050\x03\x01\x01\xff0\x1d\x06\x03U\x1d\x0e\x04"
            b"\x16\x04\x14\x8d\x06ft$v:\xf3\x89\xf7\xbc\xd6\xbdG}/\xbc"
            b"\x10_K0\x0e\x06\x03U\x1d\x0f\x01\x01\xff\x04\x04\x03"
            b"\x02\x01\x060\n\x06\x08*\x86H\xce=\x04\x03\x03\x03h\x000e"
            b"\x020\x03U-\xa6\xe6\x18\xc4|\xef\xc9Pn\xc1'\x0f\x9c\x87\xaf"
            b"n\xd5\x1b\x08\x18\xbd\x92)\xc1\xef\x94\x91x\xd2:\x1c"
            b"U\x89b\xe5\x1b\t\x1e\xbadk\xf1v\xb4\xd4\x021\x00\xb4B\x84"
            b"\x99\xff\xab\xe7\x9e\xfb\x91\x97']\xdc\xb0[0q\xce^8\x1aj"
            b"\xd9%\xe7\xea\xf7a\x92V\xf8\xea\xda6\xc2\x87e\x96.r%/"
            b"\x7f\xdf\xc3\x13\xc9"
        ),
    }


def test_parses_trust_obj():
    objs = _parse(
        r"""\
BEGINDATA
CKA_CLASS CK_OBJECT_CLASS CKO_NSS_TRUST
CKA_TOKEN CK_BBOOL CK_TRUE
CKA_PRIVATE CK_BBOOL CK_FALSE
CKA_MODIFIABLE CK_BBOOL CK_FALSE
CKA_LABEL UTF8 "Explicitly Distrust DigiNotar Root CA"
CKA_CERT_SHA1_HASH MULTILINE_OCTAL
\301\167\313\113\340\264\046\216\365\307\317\105\231\042\271\260
\316\272\041\057
END
CKA_CERT_MD5_HASH MULTILINE_OCTAL
\012\244\325\314\272\264\373\243\131\343\346\001\335\123\331\116
END
CKA_ISSUER MULTILINE_OCTAL
\060\137\061\013\060\011\006\003\125\004\006\023\002\116\114\061
\022\060\020\006\003\125\004\012\023\011\104\151\147\151\116\157
\164\141\162\061\032\060\030\006\003\125\004\003\023\021\104\151
\147\151\116\157\164\141\162\040\122\157\157\164\040\103\101\061
\040\060\036\006\011\052\206\110\206\367\015\001\011\001\026\021
\151\156\146\157\100\144\151\147\151\156\157\164\141\162\056\156
\154
END
CKA_SERIAL_NUMBER MULTILINE_OCTAL
\002\020\017\377\377\377\377\377\377\377\377\377\377\377\377\377
\377\377
END
CKA_TRUST_SERVER_AUTH CK_TRUST CKT_NSS_NOT_TRUSTED
CKA_TRUST_EMAIL_PROTECTION CK_TRUST CKT_NSS_NOT_TRUSTED
CKA_TRUST_CODE_SIGNING CK_TRUST CKT_NSS_NOT_TRUSTED
CKA_TRUST_STEP_UP_APPROVED CK_BBOOL CK_FALSE
"""
    )
    assert objs == [
        {
            b"CKA_CERT_MD5_HASH": (
                b"\n\xa4\xd5\xcc\xba\xb4\xfb\xa3Y\xe3\xe6\x01\xddS\xd9N"
            ),
            b"CKA_CERT_SHA1_HASH": (
                b'\xc1w\xcbK\xe0\xb4&\x8e\xf5\xc7\xcfE\x99"\xb9\xb0\xce\xba!/'
            ),
            b"CKA_CLASS": enums.ObjectType.NSS_TRUST,
            b"CKA_ISSUER": (
                b"0_1\x0b0\t\x06\x03U\x04\x06\x13\x02NL1\x120\x10\x06"
                b"\x03U\x04\n\x13\tDigiNotar1\x1a0\x18\x06\x03U\x04\x03"
                b"\x13\x11DigiNotar Root CA1 0\x1e\x06\t*\x86H\x86\xf7\r\x01"
                b"\t\x01\x16\x11info@diginotar.nl"
            ),
            b"CKA_LABEL": "Explicitly Distrust DigiNotar Root CA",
            b"CKA_MODIFIABLE": False,
            b"CKA_PRIVATE": False,
            b"CKA_SERIAL_NUMBER": (
                b"\x02\x10\x0f\xff\xff\xff\xff\xff\xff\xff\xff\xff"
                b"\xff\xff\xff\xff\xff\xff"
            ),
            b"CKA_TOKEN": True,
            b"CKA_TRUST_CODE_SIGNING": enums.TrustType.NOT_TRUSTED,
            b"CKA_TRUST_EMAIL_PROTECTION": enums.TrustType.NOT_TRUSTED,
            b"CKA_TRUST_SERVER_AUTH": enums.TrustType.NOT_TRUSTED,
            b"CKA_TRUST_STEP_UP_APPROVED": False,
        },
    ]


def test_fails_invalid_bool():
    with pytest.raises(nss_parser.ParseError):
        _parse(
            r"""\
BEGINDATA
CKA_BAZ CK_BBOOL CKT_NSS_NOT_TRUSTED
"""
        )


def test_fails_bad_object_class():
    with pytest.raises(nss_parser.ParseError):
        _parse(
            r"""\
BEGINDATA
CKA_BAZ CK_OBJECT_CLASS WHAT
"""
        )
    with pytest.raises(KeyError):
        _parse(
            r"""\
BEGINDATA
CKA_BAZ CK_OBJECT_CLASS CKO_STILL_BAD
"""
        )


def test_fails_bad_certificate_type():
    with pytest.raises(nss_parser.ParseError):
        _parse(
            r"""\
BEGINDATA
CKA_SOMETHING CK_CERTIFICATE_TYPE CKC_PKCS23
"""
        )


def test_fails_bad_trust_type():
    with pytest.raises(nss_parser.ParseError):
        _parse(
            r"""\
BEGINDATA
CKA_SOMETHING CK_TRUST SOMETHING
"""
        )
    with pytest.raises(nss_parser.ParseError):
        _parse(
            r"""\
BEGINDATA
CKA_SOMETHING CK_TRUST CKT_SOMETHING
"""
        )


def test_fails_unknown_type():
    with pytest.raises(nss_parser.ParseError):
        _parse(
            r"""\
BEGINDATA
CKA_SOMETHING CK_MY_RANDOM_UNKNOWN CK_OOPS
"""
        )
