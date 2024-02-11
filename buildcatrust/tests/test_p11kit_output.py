# SPDX-FileCopyrightText: 2021 Luke Granger-Brown <git@lukegb.com>
#
# SPDX-License-Identifier: MIT

import dataclasses
import io
import os

import pytest

from buildcatrust import enums
from buildcatrust import nss_parser
from buildcatrust import p11kit_output
from buildcatrust import types


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

    p11kit_output.P11KitOutput(buf).output(cert, trust)

    assert (
        buf.getvalue()
        == """\
# Certum_EC-384_CA:788f275c81125220a504d02dddba73f4
[p11-kit-object-v1]
label: "Certum EC-384 CA"
modifiable: false
trusted: true
nss-mozilla-ca-policy: true
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

# RFC5280: Extended Key Usage X.509 extension
# value = [1.3.6.1.5.5.7.3.1 (RFC5280: serverAuth key usage), 1.3.6.1.5.5.7.3.4 (RFC5280: emailProtection key usage)]
[p11-kit-object-v1]
label: "Certum EC-384 CA"
modifiable: false
class: x-certificate-extension
object-id: 2.5.29.37
value: "0 %06%03U%1D%25%01%01%FF%04%160%14%06%08%2B%06%01%05%05%07%03%01%06%08%2B%06%01%05%05%07%03%04"
-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAExCiOqxhbar5uZDdj5M3sqzr3zKG4DoJJ
14Ypn6GU8uNgeJiBeAZN8uyaDldgg5+05hcvGrNdAluJIzzCEQUqp4gTGPNQhNe9
NCwniVX/zkzn36YfKMTwVMO5fLdTrevC
-----END PUBLIC KEY-----

"""
    )


def test_certificate_just_included_not_ca(certum):
    cert, trust = certum

    buf = io.StringIO()

    # Make cert locally-trusted only, not as a CA.
    cert = dataclasses.replace(cert, mozilla_ca_policy=False)
    trust = dataclasses.replace(
        trust, **{k: enums.TrustType.TRUSTED for k in trust.TRUST_ATTRS}
    )

    p11kit_output.P11KitOutput(buf).output(cert, trust)

    assert (
        buf.getvalue()
        == """\
# Certum_EC-384_CA:788f275c81125220a504d02dddba73f4
[p11-kit-object-v1]
label: "Certum EC-384 CA"
modifiable: false
trusted: false
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


def test_distrust_after_certificate(certum):
    cert, trust = certum

    buf = io.StringIO()

    # Make cert locally-trusted only, not as a CA.
    cert = dataclasses.replace(
        cert,
        server_distrust_after=b"210301000000Z",
        email_distrust_after=b"210301000000Z",
    )

    p11kit_output.P11KitOutput(buf).output(cert, trust)

    assert (
        buf.getvalue()
        == """\
# Certum_EC-384_CA:788f275c81125220a504d02dddba73f4
[p11-kit-object-v1]
label: "Certum EC-384 CA"
modifiable: false
trusted: true
nss-mozilla-ca-policy: true
nss-server-distrust-after: "210301000000Z"
nss-email-distrust-after: "210301000000Z"
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

# RFC5280: Extended Key Usage X.509 extension
# value = [1.3.6.1.5.5.7.3.1 (RFC5280: serverAuth key usage), 1.3.6.1.5.5.7.3.4 (RFC5280: emailProtection key usage)]
[p11-kit-object-v1]
label: "Certum EC-384 CA"
modifiable: false
class: x-certificate-extension
object-id: 2.5.29.37
value: "0 %06%03U%1D%25%01%01%FF%04%160%14%06%08%2B%06%01%05%05%07%03%01%06%08%2B%06%01%05%05%07%03%04"
-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAExCiOqxhbar5uZDdj5M3sqzr3zKG4DoJJ
14Ypn6GU8uNgeJiBeAZN8uyaDldgg5+05hcvGrNdAluJIzzCEQUqp4gTGPNQhNe9
NCwniVX/zkzn36YfKMTwVMO5fLdTrevC
-----END PUBLIC KEY-----

"""
    )


def test_distrusted_certificate(certum):
    cert, trust = certum

    buf = io.StringIO()

    p11kit_output.P11KitOutput(buf).output(cert, trust.as_distrusted())

    assert (
        buf.getvalue()
        == """\
# Certum_EC-384_CA:788f275c81125220a504d02dddba73f4
[p11-kit-object-v1]
label: "Certum EC-384 CA"
modifiable: false
x-distrusted: true
nss-mozilla-ca-policy: true
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

# p11kit OpenSSL reject extension
# value = [1.3.6.1.5.5.7.3.1 (RFC5280: serverAuth key usage), 1.3.6.1.5.5.7.3.2 (RFC5280: clientAuth key usage), 1.3.6.1.5.5.7.3.3 (RFC5280: codeSigning key usage), 1.3.6.1.5.5.7.3.4 (RFC5280: emailProtection key usage), 1.3.6.1.5.5.7.3.8 (RFC5280: timeStamping key usage), 1.3.6.1.5.5.7.3.5 (RFC2459: ipsecEndSystem key usage), 1.3.6.1.5.5.7.3.6 (RFC2459: ipsecTunnel key usage), 1.3.6.1.5.5.7.3.7 (RFC2459: ipsecUser key usage)]
[p11-kit-object-v1]
label: "Certum EC-384 CA"
modifiable: false
class: x-certificate-extension
object-id: 1.3.6.1.4.1.3319.6.10.1
value: "0c%06%0A%2B%06%01%04%01%99w%06%0A%01%01%01%FF%04R0P%06%08%2B%06%01%05%05%07%03%01%06%08%2B%06%01%05%05%07%03%02%06%08%2B%06%01%05%05%07%03%03%06%08%2B%06%01%05%05%07%03%04%06%08%2B%06%01%05%05%07%03%08%06%08%2B%06%01%05%05%07%03%05%06%08%2B%06%01%05%05%07%03%06%06%08%2B%06%01%05%05%07%03%07"
-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAExCiOqxhbar5uZDdj5M3sqzr3zKG4DoJJ
14Ypn6GU8uNgeJiBeAZN8uyaDldgg5+05hcvGrNdAluJIzzCEQUqp4gTGPNQhNe9
NCwniVX/zkzn36YfKMTwVMO5fLdTrevC
-----END PUBLIC KEY-----

# RFC5280: Extended Key Usage X.509 extension
# value = [1.3.6.1.4.1.3319.6.10.16 (p11kit reserved key purpose)]
[p11-kit-object-v1]
label: "Certum EC-384 CA"
modifiable: false
class: x-certificate-extension
object-id: 2.5.29.37
value: "0%18%06%03U%1D%25%01%01%FF%04%0E0%0C%06%0A%2B%06%01%04%01%99w%06%0A%10"
-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAExCiOqxhbar5uZDdj5M3sqzr3zKG4DoJJ
14Ypn6GU8uNgeJiBeAZN8uyaDldgg5+05hcvGrNdAluJIzzCEQUqp4gTGPNQhNe9
NCwniVX/zkzn36YfKMTwVMO5fLdTrevC
-----END PUBLIC KEY-----

"""
    )


def test_no_certificate(certum):
    # Some trusts are trust-only and have no certificate.
    cert, trust = certum

    buf = io.StringIO()

    p11kit_output.P11KitOutput(buf).output(None, trust.as_distrusted())

    assert (
        buf.getvalue()
        == """\
# Certum_EC-384_CA:788f275c81125220a504d02dddba73f4
[p11-kit-object-v1]
label: "Certum EC-384 CA"
class: certificate
certificate-type: x-509
modifiable: false
issuer: "0t1%0B0%09%06%03U%04%06%13%02PL1%210%1F%06%03U%04%0A%13%18Asseco Data Systems S.A.1%270%25%06%03U%04%0B%13%1ECertum Certification Authority1%190%17%06%03U%04%03%13%10Certum EC-384 CA"
serial-number: "%02%10x%8F%27%5C%81%12R %A5%04%D0-%DD%BAs%F4"
x-distrusted: true

"""
    )
