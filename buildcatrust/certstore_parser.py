# SPDX-FileCopyrightText: 2021 Luke Granger-Brown <git@lukegb.com>
#
# SPDX-License-Identifier: MIT

from typing import Dict, List, TextIO, Tuple

from . import der_x509
from . import enums
from . import types
from . import x509_consts


def _cert_bytes_to_cert_and_trust(
    b: bytes, trust_attrs: Dict[str, enums.TrustType]
) -> Tuple[types.Certificate, types.Trust]:
    x509_cert, trailing = der_x509.Certificate.from_der(b)
    if trailing:
        raise Exception("got trailing garbage parsing X509 certificate")
    cert = types.Certificate.from_x509(b, x509_cert)
    trust = types.Trust(
        label=cert.label,
        issuer=cert.issuer,
        serial_number=cert.serial_number,
        trust_step_up_approved=False,
        **trust_attrs,
    )
    return cert, trust


def read_certificates(fp: TextIO) -> List[Tuple[types.Certificate, types.Trust]]:
    certs = []
    while True:
        data = der_x509.PEMBlock.decode_from_file(fp)
        if not data:
            if fp.read(1) == "":
                # EOF
                break
            else:
                raise IOError("something went wrong")
        _, pem_block = data
        if pem_block.name == "CERTIFICATE":
            certs.append(
                _cert_bytes_to_cert_and_trust(
                    pem_block.content,
                    {
                        attr: enums.TrustType.TRUSTED_DELEGATOR
                        if attr in types.Trust.CORE_TRUST_ATTRS
                        else enums.TrustType.UNKNOWN
                        for attr in types.Trust.TRUST_ATTRS
                    },
                )
            )
        elif pem_block.name == "TRUSTED CERTIFICATE":
            cert_bytes, cert_aux, trailing = der_x509.parse_trusted_certificate(
                pem_block
            )
            if trailing:
                raise Exception("got trailing garbage parsing trusted certificate")

            trust_attrs = {
                attr: enums.TrustType.UNKNOWN for attr in types.Trust.TRUST_ATTRS
            }
            for purpose in x509_consts.PURPOSES:
                trust_name = f"trust_{purpose.trust_name}"
                assert trust_name in trust_attrs
                if purpose.object_id in cert_aux.trust:
                    trust_attrs[trust_name] = enums.TrustType.TRUSTED_DELEGATOR
                elif purpose.object_id in cert_aux.reject:
                    trust_attrs[trust_name] = enums.TrustType.NOT_TRUSTED

            certs.append(_cert_bytes_to_cert_and_trust(cert_bytes, trust_attrs))
    return certs
