# SPDX-FileCopyrightText: 2021 Luke Granger-Brown <git@lukegb.com>
#
# SPDX-License-Identifier: MIT

import dataclasses

from . import der_x509


@dataclasses.dataclass(frozen=True)
class Purpose:
    eku_name: str
    object_id: der_x509.ObjectID
    trust_name: str


PURPOSES = [
    # RFC 5280
    Purpose(
        "serverAuth",
        der_x509.ObjectID.from_str(
            "RFC5280: serverAuth key usage", "1.3.6.1.5.5.7.3.1"
        ),
        "server_auth",
    ),
    Purpose(
        "clientAuth",
        der_x509.ObjectID.from_str(
            "RFC5280: clientAuth key usage", "1.3.6.1.5.5.7.3.2"
        ),
        "client_auth",
    ),
    Purpose(
        "codeSigning",
        der_x509.ObjectID.from_str(
            "RFC5280: codeSigning key usage", "1.3.6.1.5.5.7.3.3"
        ),
        "code_signing",
    ),
    Purpose(
        "emailProtection",
        der_x509.ObjectID.from_str(
            "RFC5280: emailProtection key usage", "1.3.6.1.5.5.7.3.4"
        ),
        "email_protection",
    ),
    Purpose(
        "timeStamping",
        der_x509.ObjectID.from_str(
            "RFC5280: timeStamping key usage", "1.3.6.1.5.5.7.3.8"
        ),
        "time_stamping",
    ),
    # RFC 2459
    Purpose(
        "ipsecEndSystem",
        der_x509.ObjectID.from_str(
            "RFC2459: ipsecEndSystem key usage", "1.3.6.1.5.5.7.3.5"
        ),
        "ipsec_end_system",
    ),
    Purpose(
        "ipsecTunnel",
        der_x509.ObjectID.from_str(
            "RFC2459: ipsecTunnel key usage", "1.3.6.1.5.5.7.3.6"
        ),
        "ipsec_tunnel",
    ),
    Purpose(
        "ipsecUser",
        der_x509.ObjectID.from_str("RFC2459: ipsecUser key usage", "1.3.6.1.5.5.7.3.7"),
        "ipsec_user",
    ),
]


EXTENDED_KEY_USAGE_OID = der_x509.ObjectID.from_str(
    "RFC5280: Extended Key Usage X.509 extension", "2.5.29.37"
)

ATTRIBUTES = {
    str(a): a
    for a in [
        der_x509.ObjectID.from_str("c", "2.5.4.6"),
        der_x509.ObjectID.from_str("l", "2.5.4.7"),
        der_x509.ObjectID.from_str("cn", "2.5.4.3"),
        der_x509.ObjectID.from_str("o", "2.5.4.10"),
        der_x509.ObjectID.from_str("ou", "2.5.4.11"),
        der_x509.ObjectID.from_str("organizationIdentifier", "2.5.4.97"),
        der_x509.ObjectID.from_str("name", "2.5.4.41"),
        der_x509.ObjectID.from_str("givenName", "2.5.4.42"),
        der_x509.ObjectID.from_str("serialNumber", "2.5.4.5"),
        der_x509.ObjectID.from_str("businessCategory", "2.5.4.15"),
        der_x509.ObjectID.from_str(
            "jurisdictionOfIncorporationCountryName", "1.3.6.1.4.1.311.60.2.1.3"
        ),
    ]
}
