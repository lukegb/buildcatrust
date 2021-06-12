# SPDX-FileCopyrightText: 2021 Luke Granger-Brown <git@lukegb.com>
#
# SPDX-License-Identifier: MIT

import io
import os

import pytest

from buildcatrust import certstore_output
from buildcatrust import nss_parser
from buildcatrust import types
from buildcatrust import x509_consts


@pytest.fixture
def certum():
    certdb = types.CertDB()
    with open(
        os.path.join(os.path.dirname(__file__), "testdata", "certdata-certumec384.txt"),
        "rb",
    ) as f:
        certdb.add_nss_objs(nss_parser.Parser().parse_lines(f))

    cert = certdb.certmap["Certum_EC-384_CA:788f275c81125220a504d02dddba73f4"]
    trust = certdb.trustmap["Certum_EC-384_CA:788f275c81125220a504d02dddba73f4"]
    return cert, trust


def test_certificate(certum):
    cert, trust = certum

    buf = io.StringIO()

    certstore_output.CertStoreOutput(buf).output(cert, trust)

    assert (
        buf.getvalue()
        == """\
Certum EC-384 CA
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

Trusted for:
  - 1.3.6.1.5.5.7.3.1 (RFC5280: serverAuth key usage)
  - 1.3.6.1.5.5.7.3.4 (RFC5280: emailProtection key usage)
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
nvuRlydd3LBbMHHOXjgaatkl5+r3YZJW+OraNsKHZZYuciUvf9/DE8kwFjAUBggr
BgEFBQcDAQYIKwYBBQUHAwQ=
-----END TRUSTED CERTIFICATE-----

"""
    )


def test_distrusted_certificate(certum):
    cert, trust = certum

    buf = io.StringIO()

    certstore_output.CertStoreOutput(buf).output(cert, trust.as_distrusted())

    assert (
        buf.getvalue()
        == """\
Certum EC-384 CA
Traditional PEM block omitted: this certificate is not trusted for authenticating servers.
Rejected for:
  - 1.3.6.1.5.5.7.3.1 (RFC5280: serverAuth key usage)
  - 1.3.6.1.5.5.7.3.2 (RFC5280: clientAuth key usage)
  - 1.3.6.1.5.5.7.3.3 (RFC5280: codeSigning key usage)
  - 1.3.6.1.5.5.7.3.4 (RFC5280: emailProtection key usage)
  - 1.3.6.1.5.5.7.3.8 (RFC5280: timeStamping key usage)
  - 1.3.6.1.5.5.7.3.5 (RFC2459: ipsecEndSystem key usage)
  - 1.3.6.1.5.5.7.3.6 (RFC2459: ipsecTunnel key usage)
  - 1.3.6.1.5.5.7.3.7 (RFC2459: ipsecUser key usage)
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
nvuRlydd3LBbMHHOXjgaatkl5+r3YZJW+OraNsKHZZYuciUvf9/DE8kwVDAAoFAG
CCsGAQUFBwMBBggrBgEFBQcDAgYIKwYBBQUHAwMGCCsGAQUFBwMEBggrBgEFBQcD
CAYIKwYBBQUHAwUGCCsGAQUFBwMGBggrBgEFBQcDBw==
-----END TRUSTED CERTIFICATE-----

"""
    )


def test_no_certificate(certum):
    # Some trusts are trust-only and have no certificate.
    cert, trust = certum

    buf = io.StringIO()

    certstore_output.CertStoreOutput(buf).output(None, trust)

    assert buf.getvalue() == ""
