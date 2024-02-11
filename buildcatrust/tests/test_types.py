# SPDX-FileCopyrightText: 2021 Luke Granger-Brown <git@lukegb.com>
#
# SPDX-License-Identifier: MIT

import os

from buildcatrust import enums
from buildcatrust import nss_parser
from buildcatrust import types
from buildcatrust import x509_consts


def test_certificate():
    with open(
        os.path.join(os.path.dirname(__file__), "testdata", "certdata-certumec384.txt"),
        "rb",
    ) as f:
        objs = list(nss_parser.Parser().parse_lines(f))

    cert = types.Certificate.from_parser_object(objs[1])
    assert cert.label == "Certum EC-384 CA"
    assert cert.id == "0"
    assert cert.mozilla_ca_policy
    assert cert.server_distrust_after is None
    assert cert.email_distrust_after is None
    assert cert.sha1_fingerprint == "f33e783cacdff4a2ccac67556956d7e5163ce1ed"
    assert (
        cert.sha256_fingerprint
        == "6b328085625318aa50d173c98d8bda09d57e27413d114cf787a0f5d06c030cf6"
    )

    assert cert.clean_filename == "Certum_EC-384_CA:788f275c81125220a504d02dddba73f4"

    assert (
        cert.public_key_pem().encode()
        == """\
-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAExCiOqxhbar5uZDdj5M3sqzr3zKG4DoJJ
14Ypn6GU8uNgeJiBeAZN8uyaDldgg5+05hcvGrNdAluJIzzCEQUqp4gTGPNQhNe9
NCwniVX/zkzn36YfKMTwVMO5fLdTrevC
-----END PUBLIC KEY-----
"""
    )
    assert (
        cert.as_pem().encode()
        == """\
-----BEGIN CERTIFICATE-----
MIICZTCCAeugAwIBAgIQeI8nXIESUiClBNAt3bpz9DAKBggqhkjOPQQDAzB0MQsw
CQYDVQQGEwJQTDEhMB8GA1UEChMYQXNzZWNvIERhdGEgU3lzdGVtcyBTLkEuMScw
JQYDVQQLEx5DZXJ0dW0gQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxGTAXBgNVBAMT
EENlcnR1bSBFQy0zODQgQ0EwHhcNMTgwMzI2MDcyNDU0WhcNNDMwMzI2MDcyNDU0
WjB0MQswCQYDVQQGEwJQTDEhMB8GA1UEChMYQXNzZWNvIERhdGEgU3lzdGVtcyBT
LkEuMScwJQYDVQQLEx5DZXJ0dW0gQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxGTAX
BgNVBAMTEENlcnR1bSBFQy0zODQgQ0EwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAATE
KI6rGFtqvm5kN2PkzeyrOvfMobgOgknXhimfoZTy42B4mIF4Bk3y7JoOV2CDn7Tm
Fy8as10CW4kjPMIRBSqniBMY81CE1700LCeJVf/OTOffph8oxPBUw7l8t1Ot68Kj
QjBAMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFI0GZnQkdjrzife81r1HfS+8
EF9LMA4GA1UdDwEB/wQEAwIBBjAKBggqhkjOPQQDAwNoADBlAjADVS2m5hjEfO/J
UG7BJw+ch69u1RsIGL2SKcHvlJF40jocVYli5RsJHrpka/F2tNQCMQC0QoSZ/6vn
nvuRlydd3LBbMHHOXjgaatkl5+r3YZJW+OraNsKHZZYuciUvf9/DE8k=
-----END CERTIFICATE-----
"""
    )


def test_trust():
    with open(
        os.path.join(os.path.dirname(__file__), "testdata", "certdata-certumec384.txt"),
        "rb",
    ) as f:
        objs = list(nss_parser.Parser().parse_lines(f))
    trust = types.Trust.from_parser_object(objs[2])

    assert trust.label == "Certum EC-384 CA"

    assert not trust.distrusted

    assert trust.trust_server_auth == enums.TrustType.TRUSTED_DELEGATOR
    assert trust.trust_client_auth == enums.TrustType.UNKNOWN
    assert trust.trust_code_signing == enums.TrustType.MUST_VERIFY_TRUST

    # Expected to be same as certificate above!
    assert trust.clean_filename == "Certum_EC-384_CA:788f275c81125220a504d02dddba73f4"


def test_trust_as_distrusted():
    with open(
        os.path.join(os.path.dirname(__file__), "testdata", "certdata-certumec384.txt"),
        "rb",
    ) as f:
        objs = list(nss_parser.Parser().parse_lines(f))
    trust = types.Trust.from_parser_object(objs[2])
    distrusted_trust = trust.as_distrusted()

    assert not trust.distrusted
    assert distrusted_trust.distrusted

    assert trust.label == distrusted_trust.label
    assert trust.issuer == distrusted_trust.issuer
    assert trust.serial_number == distrusted_trust.serial_number

    assert distrusted_trust.trusted_key_usages == []
    assert sorted(distrusted_trust.untrusted_key_usages) == sorted(
        p.object_id for p in x509_consts.PURPOSES
    )


def test_certdb():
    certdb = types.CertDB()
    with open(
        os.path.join(os.path.dirname(__file__), "testdata", "certdata-certumec384.txt"),
        "rb",
    ) as f:
        certdb.add_nss_objs(nss_parser.Parser().parse_lines(f))

    assert "Certum_EC-384_CA:788f275c81125220a504d02dddba73f4" in certdb.certmap
    assert "Certum_EC-384_CA:788f275c81125220a504d02dddba73f4" in certdb.trustmap
