# SPDX-FileCopyrightText: 2021 Luke Granger-Brown <git@lukegb.com>
#
# SPDX-License-Identifier: MIT

import dataclasses

from buildcatrust import der_x509


def test_object_id():
    c = der_x509.ObjectID.from_str("Hello", "1.2.3.4.2554")
    assert str(c) == "1.2.3.4.2554"
    assert repr(c) == "1.2.3.4.2554"
    assert c.as_der() == b"\x06\x05\x2a\x03\x04\x93\x7a"
    assert der_x509.ObjectID.from_der(c.as_der()) == (
        dataclasses.replace(c, name=None),
        b"",
    )
    assert der_x509.ObjectID.from_der(c.as_der() + b"foo") == (
        dataclasses.replace(c, name=None),
        b"foo",
    )


def test_encode_long_length():
    c = der_x509.ObjectID(name="", oid=list(range(0x100)))
    assert c.as_der()[:4] == b"\x06\x82\x01\x7f"


def test_extended_key_usages():
    c = der_x509.ExtendedKeyUsages(
        oids=[
            der_x509.ObjectID.from_str("Hello", "2.1.3.4"),
            der_x509.ObjectID.from_str("Hello", "1.2.3.4.2554"),
        ]
    )
    assert c.as_der() == b"\x30\x0c\x06\x03\x51\x03\x04\x06\x05\x2a\x03\x04\x93\x7a"


def test_cert_extension_noncritical():
    c = der_x509.CertExtension(
        ext_id=der_x509.ObjectID.from_str("Hello", "2.1.3.4"),
        critical=False,
        extension=der_x509.ExtendedKeyUsages(
            oids=[der_x509.ObjectID.from_str("Hello", "1.2.3.4.2554")],
        ),
    )
    assert (
        c.as_der()
        == b"\x30\x10\x06\x03\x51\x03\x04\x04\x09\x30\x07\x06\x05\x2a\x03\x04\x93\x7a"
    )


def test_cert_extension_critical():
    c = der_x509.CertExtension(
        ext_id=der_x509.ObjectID.from_str("Hello", "2.1.3.4"),
        critical=True,
        extension=der_x509.ExtendedKeyUsages(
            oids=[der_x509.ObjectID.from_str("Hello", "1.2.3.4.2554")],
        ),
    )
    assert (
        c.as_der()
        == b"\x30\x13\x06\x03\x51\x03\x04\x01\x01\xff\x04\x09\x30\x07\x06\x05\x2a\x03\x04\x93\x7a"
    )


def test_openssl_cert_aux_empty():
    c = der_x509.OpenSSLCertAux(trust=[], reject=[])
    assert c.as_der() == b"\x30\x02\x30\x00"


def test_openssl_cert_aux_trust_only():
    c = der_x509.OpenSSLCertAux(
        trust=[
            der_x509.ObjectID.from_str("Hello", "1.2.3.4.2554"),
        ],
        reject=[],
    )
    assert c.as_der() == b"\x30\x09\x30\x07\x06\x05\x2a\x03\x04\x93\x7a"


def test_openssl_cert_aux_reject_only():
    c = der_x509.OpenSSLCertAux(
        trust=[],
        reject=[
            der_x509.ObjectID.from_str("Hello", "1.2.3.4.2554"),
        ],
    )
    assert c.as_der() == b"\x30\x0b\x30\x00\xa0\x07\x06\x05\x2a\x03\x04\x93\x7a"


def test_openssl_cert_aux_trust_and_reject():
    c = der_x509.OpenSSLCertAux(
        trust=[
            der_x509.ObjectID.from_str("Hello", "1.2.3.4.2553"),
        ],
        reject=[
            der_x509.ObjectID.from_str("Hello", "1.2.3.4.2554"),
        ],
    )
    assert (
        c.as_der()
        == b"\x30\x12\x30\x07\x06\x05\x2a\x03\x04\x93\x79\xa0\x07\x06\x05\x2a\x03\x04\x93\x7a"
    )


def test_pemblock():
    pem = der_x509.PEMBlock(
        name="TEST BLOCK", content=bytes.fromhex("85e965a30a2b95df")
    )
    assert (
        pem.encode()
        == """\
-----BEGIN TEST BLOCK-----
helloworld8=
-----END TEST BLOCK-----
"""
    )

    assert der_x509.PEMBlock.decode(pem.encode()) == ("", pem, "")


def test_encode_decode_int():
    i = 10
    assert der_x509._decode_int(der_x509._encode_int(i)) == (i, bytearray())

    i = 1 << 20
    assert der_x509._decode_int(der_x509._encode_int(i)) == (i, bytearray())


def test_parse_openssl_cert():
    cert_bytes = bytes.fromhex(
        """\
30820265308201eba0030201020210788f275c81125220a504d02dddba73
f4300a06082a8648ce3d0403033074310b300906035504061302504c3121
301f060355040a131841737365636f20446174612053797374656d732053
2e412e31273025060355040b131e43657274756d20436572746966696361
74696f6e20417574686f7269747931193017060355040313104365727475
6d2045432d333834204341301e170d3138303332363037323435345a170d
3433303332363037323435345a3074310b300906035504061302504c3121
301f060355040a131841737365636f20446174612053797374656d732053
2e412e31273025060355040b131e43657274756d20436572746966696361
74696f6e20417574686f7269747931193017060355040313104365727475
6d2045432d3338342043413076301006072a8648ce3d020106052b810400
2203620004c4288eab185b6abe6e643763e4cdecab3af7cca1b80e8249d7
86299fa194f2e36078988178064df2ec9a0e5760839fb4e6172f1ab35d02
5b89233cc211052aa7881318f35084d7bd342c278955ffce4ce7dfa61f28
c4f054c3b97cb753adebc2a3423040300f0603551d130101ff0405300301
01ff301d0603551d0e041604148d06667424763af389f7bcd6bd477d2fbc
105f4b300e0603551d0f0101ff040403020106300a06082a8648ce3d0403
030368003065023003552da6e618c47cefc9506ec1270f9c87af6ed51b08
18bd9229c1ef949178d23a1c558962e51b091eba646bf176b4d4023100b4
428499ffabe79efb9197275ddcb05b3071ce5e381a6ad925e7eaf7619256
f8eada36c28765962e72252f7fdfc313c9
"""
    )
    cert_aux = der_x509.OpenSSLCertAux(
        trust=[der_x509.ObjectID.from_str(None, "1.2.3.4")],
        reject=[der_x509.ObjectID.from_str(None, "1.2.3.9")],
    )
    trusted_cert = der_x509.to_trusted_certificate(cert_bytes, cert_aux)
    got_cert_bytes, got_cert_aux, trailing = der_x509.parse_trusted_certificate(
        trusted_cert
    )

    assert got_cert_bytes == cert_bytes
    assert got_cert_aux == cert_aux
    assert trailing == b""


def test_distinguished_name():
    test_dn = bytes.fromhex(
        "3074310b300906035504061302504c3121301f060355040a131841737365636f20446174612053797374656d7320532e412e31273025060355040b131e43657274756d2043657274696669636174696f6e20417574686f72697479311930170603550403131043657274756d2045432d333834204341"
    )
    dn, rem = der_x509.DistinguishedName.from_der(test_dn)
    assert not rem
    assert (
        str(dn)
        == "c=PL,o=Asseco Data Systems S.A.,ou=Certum Certification Authority,cn=Certum EC-384 CA"
    )


def test_distinguished_name_multiple():
    test_dn = bytes.fromhex(
        "3081A5310B3009060355040613025349311A3018060355040A1311737461746520617574686F7269746965733110300E060355040B13077365727665727331683010060355040713094C6A75626C6A616E6130110603550403130A76706E2E676F762E73693011060B2B0601040182373C0201031302534930140603550405130D313233373731393731333031303018060355040F1311476F7665726E6D656E7420456E74697479"
    )
    dn, rem = der_x509.DistinguishedName.from_der(test_dn)
    assert not rem
    assert (
        str(dn)
        == "c=SI,o=state authorities,ou=servers,{l=Ljubljana,cn=vpn.gov.si,jurisdictionOfIncorporationCountryName=SI,serialNumber=1237719713010,businessCategory=Government Entity}"
    )
