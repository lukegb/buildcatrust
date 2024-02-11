# SPDX-FileCopyrightText: 2021 Luke Granger-Brown <git@lukegb.com>
#
# SPDX-License-Identifier: MIT


from . import helpers


def test_main(tmp_path):
    want_p11kit = """\
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
    want_ca = """\
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
    helpers.check_output_main(
        tmp_path,
        want_p11kit,
        want_ca,
        {"certdata_input": helpers.TESTDATA_DIR / "certdata-certumec384.txt"},
    )


def test_blocklist(tmp_path):
    want_p11kit = """\
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
    want_ca = """\
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
    helpers.check_output_main(
        tmp_path,
        want_p11kit,
        want_ca,
        {
            "certdata_input": helpers.TESTDATA_DIR / "certdata-certumec384.txt",
            "blocklist_input": helpers.TESTDATA_DIR / "blocklist-certumec384.txt",
        },
    )
