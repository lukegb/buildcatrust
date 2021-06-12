# SPDX-FileCopyrightText: 2021 Luke Granger-Brown <git@lukegb.com>
#
# SPDX-License-Identifier: MIT

from typing import Optional, TextIO

from . import der_x509
from . import enums
from . import types


class CertStoreOutput:
    def __init__(self, fp: TextIO):
        self.fp = fp

    def output(self, cert: Optional[types.Certificate], trust: types.Trust) -> None:
        if not cert:
            return

        print(cert.label, file=self.fp)

        if trust.trust_server_auth == enums.TrustType.TRUSTED_DELEGATOR:
            # Output the "plain" version for applications expecting just plain CERTIFICATE entries.
            # We only do this if the cert is affirmatively trusted for being a CA for server-side auth.
            print(cert.as_pem().encode(), file=self.fp)
        else:
            print(
                "Traditional PEM block omitted: this certificate is not trusted for authenticating servers.",
                file=self.fp,
            )

        # Output OpenSSL-style TRUSTED CERTIFICATE entries.
        if trust.trusted_key_usages:
            print("Trusted for:", file=self.fp)
            for usage in trust.trusted_key_usages:
                print(f"  - {str(usage)} ({usage.name})", file=self.fp)
        if trust.untrusted_key_usages:
            print("Rejected for:", file=self.fp)
            for usage in trust.untrusted_key_usages:
                print(f"  - {str(usage)} ({usage.name})", file=self.fp)
        cert_aux = der_x509.OpenSSLCertAux(
            trust=trust.trusted_key_usages,
            reject=trust.untrusted_key_usages,
        ).as_der()
        pem_block = der_x509.PEMBlock(
            name="TRUSTED CERTIFICATE", content=cert.value + cert_aux
        )
        print(pem_block.encode(), file=self.fp)
