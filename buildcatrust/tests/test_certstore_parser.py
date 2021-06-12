# SPDX-FileCopyrightText: 2021 Luke Granger-Brown <git@lukegb.com>
#
# SPDX-License-Identifier: MIT

import io

from buildcatrust import certstore_parser
from buildcatrust import enums
from buildcatrust import types

CERTUM_NAME = "cn=Certum_EC-384_CA:6b328085:788f275c81125220a504d02dddba73f4"


def test_read_certificates_raw_pem():
    certum_pem = """\
some garbage
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
    fp = io.StringIO(certum_pem)
    certs = certstore_parser.read_certificates(fp)
    assert len(certs) == 1

    certdb = types.CertDB()
    certdb.add_certs(certs)

    assert CERTUM_NAME in certdb.certmap
    assert CERTUM_NAME in certdb.trustmap

    trust = certdb.trustmap[CERTUM_NAME]
    assert not trust.trust_step_up_approved
    assert trust.trust_server_auth == enums.TrustType.TRUSTED_DELEGATOR
    assert trust.trust_client_auth == enums.TrustType.TRUSTED_DELEGATOR
    assert trust.trust_ipsec_user == enums.TrustType.UNKNOWN


def test_read_certificates_openssl_trusted():
    certum_pem = """\
more garbage
-----BEGIN TRUSTED CERTIFICATE-----
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
nvuRlydd3LBbMHHOXjgaatkl5+r3YZJW+OraNsKHZZYuciUvf9/DE8kwGDAKBggr
BgEFBQcDAaAKBggrBgEFBQcDBw==
-----END TRUSTED CERTIFICATE-----
"""
    fp = io.StringIO(certum_pem)
    certs = certstore_parser.read_certificates(fp)
    assert len(certs) == 1

    certdb = types.CertDB()
    certdb.add_certs(certs)

    assert CERTUM_NAME in certdb.certmap
    assert CERTUM_NAME in certdb.trustmap

    trust = certdb.trustmap[CERTUM_NAME]
    assert not trust.trust_step_up_approved
    assert trust.trust_server_auth == enums.TrustType.TRUSTED_DELEGATOR
    assert trust.trust_client_auth == enums.TrustType.UNKNOWN
    assert trust.trust_ipsec_user == enums.TrustType.NOT_TRUSTED
