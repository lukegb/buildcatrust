# SPDX-FileCopyrightText: 2021 Luke Granger-Brown <git@lukegb.com>
#
# SPDX-License-Identifier: MIT

from typing import List, Optional, TextIO, Union
import urllib.parse

from . import der_x509
from . import types
from . import x509_consts

_P11KIT_REJECT_OID = der_x509.ObjectID.from_str(
    "p11kit OpenSSL reject extension", "1.3.6.1.4.1.3319.6.10.1"
)
_P11KIT_DUMMY_KEY_USAGE_OID = der_x509.ObjectID.from_str(
    "p11kit reserved key purpose", "1.3.6.1.4.1.3319.6.10.16"
)


def _quote(s: Union[bytes, str]) -> str:
    quoted = urllib.parse.quote(s, safe="/ ")
    return f'"{quoted}"'


class P11KitOutput:
    def __init__(self, fp: TextIO):
        self.fp = fp

    def output(self, cert: Optional[types.Certificate], trust: types.Trust) -> None:
        self.fp.write(f"# {trust.clean_filename}\n")
        if cert:
            self._cert_and_trust(cert, trust)
        else:
            self._trustonly(trust)

    def _trust_attributes(self, trust: types.Trust) -> str:
        attrs = []
        if trust.distrusted:
            attrs.append("x-distrusted: true")
        elif trust.trusted_key_usages:
            attrs.append("trusted: true")
        else:
            # We're neutral about this.
            attrs.append("trusted: false")
        if attrs:
            attrs.append("")
        return "\n".join(attrs)

    def _cert_attributes(self, cert: types.Certificate) -> str:
        attrs = []
        if cert.mozilla_ca_policy:
            attrs.append("nss-mozilla-ca-policy: true")
        if cert.server_distrust_after:
            attrs.append(
                f"nss-server-distrust-after: {_quote(cert.server_distrust_after)}"
            )
        if cert.email_distrust_after:
            attrs.append(
                f"nss-email-distrust-after: {_quote(cert.email_distrust_after)}"
            )
        if attrs:
            attrs.append("")
        return "\n".join(attrs)

    def _write_ku_extension(
        self,
        cert: types.Certificate,
        oid: der_x509.ObjectID,
        key_usages: List[der_x509.ObjectID],
    ) -> None:
        """Write out a X.509 extension override in p11-kit object format."""
        ce_bytes = _quote(
            der_x509.CertExtension(
                ext_id=oid,
                critical=True,
                extension=der_x509.ExtendedKeyUsages(
                    oids=key_usages,
                ),
            ).as_der()
        )
        friendly_value = ", ".join(f"{str(u)} ({u.name})" for u in key_usages)
        self.fp.write(
            f"""\
# {oid.name}
# value = [{friendly_value}]
[p11-kit-object-v1]
label: {_quote(cert.label)}
modifiable: false
class: x-certificate-extension
object-id: {str(oid)}
value: {ce_bytes}
{cert.public_key_pem().encode()}
"""
        )

    def _cert_and_trust(self, cert: types.Certificate, trust: types.Trust) -> None:
        """Write out a CA and its trust attributes in p11-kit format."""
        self.fp.write(
            f"""\
[p11-kit-object-v1]
label: {_quote(trust.label)}
modifiable: false
{self._trust_attributes(trust)}\
{self._cert_attributes(cert)}\
{cert.as_pem().encode()}
"""
        )
        trusted_to_delegate_for = trust.trusted_key_usages
        distrusted_for = trust.untrusted_key_usages
        if distrusted_for:
            self._write_ku_extension(cert, _P11KIT_REJECT_OID, distrusted_for)

        if trusted_to_delegate_for:
            self._write_ku_extension(
                cert, x509_consts.EXTENDED_KEY_USAGE_OID, trusted_to_delegate_for
            )
        elif distrusted_for:
            # We don't trust this for anything, and we distrust it.
            # Therefore, we overwrite the EKU.
            # Note that we don't do this without a distrust, because we want to
            # leave the EKU bits alone if someone's just put an intermediate
            # cert into the pool without trusting it as a CA for anything.

            # We want to override the EKU with the empty set,
            # but we need to specify something, since "empty" is not permitted.
            # Fortunately, P11Kit defines a dummy extension explicitly for this purpose.
            self._write_ku_extension(
                cert, x509_consts.EXTENDED_KEY_USAGE_OID, [_P11KIT_DUMMY_KEY_USAGE_OID]
            )

    def _trustonly(self, trust: types.Trust) -> None:
        """Write out trust information in p11-kit format without full certificate data."""
        # We should only get here if we distrusted the cert: otherwise, we should have the full certificate.
        assert trust.distrusted
        self.fp.write(
            f"""\
[p11-kit-object-v1]
label: {_quote(trust.label)}
class: certificate
certificate-type: x-509
modifiable: false
issuer: {_quote(trust.issuer.as_der())}
serial-number: {_quote(trust.serial_number)}
{self._trust_attributes(trust)}
"""
        )
