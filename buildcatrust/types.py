# SPDX-FileCopyrightText: 2021 Luke Granger-Brown <git@lukegb.com>
#
# SPDX-License-Identifier: MIT

from collections.abc import Iterable
import dataclasses
import hashlib

from . import der_x509
from . import enums
from . import nss_parser
from . import x509_consts


def _dn_from_der(b: bytes) -> der_x509.DistinguishedName:
    dn, rem = der_x509.DistinguishedName.from_der(b)
    assert not rem
    return dn


@dataclasses.dataclass(frozen=True)
class Certificate:
    label: str
    subject: der_x509.DistinguishedName
    id: bytes
    issuer: der_x509.DistinguishedName
    serial_number: bytes
    value: bytes
    mozilla_ca_policy: bool
    server_distrust_after: bytes | None
    email_distrust_after: bytes | None

    sha1_fingerprint: str
    sha256_fingerprint: str

    @classmethod
    def from_parser_object(cls, obj: nss_parser.ParsedObject) -> "Certificate":
        return cls(
            label=obj[b"CKA_LABEL"],
            subject=_dn_from_der(obj[b"CKA_SUBJECT"]),
            id=obj[b"CKA_ID"],
            issuer=_dn_from_der(obj[b"CKA_ISSUER"]),
            serial_number=obj[b"CKA_SERIAL_NUMBER"],
            value=obj[b"CKA_VALUE"],
            mozilla_ca_policy=obj.get(b"CKA_NSS_MOZILLA_CA_POLICY", False),
            server_distrust_after=obj.get(b"CKA_NSS_SERVER_DISTRUST_AFTER", None)
            or None,
            email_distrust_after=obj.get(b"CKA_NSS_EMAIL_DISTRUST_AFTER", None) or None,
            sha1_fingerprint=hashlib.sha1(obj[b"CKA_VALUE"]).hexdigest(),
            sha256_fingerprint=hashlib.sha256(obj[b"CKA_VALUE"]).hexdigest(),
        )

    @classmethod
    def from_x509(cls, b: bytes, obj: der_x509.Certificate) -> "Certificate":
        tbs = obj.tbs_certificate
        sha256_fingerprint = hashlib.sha256(b).hexdigest()
        subject = _dn_from_der(tbs.subject)
        if subject.bits:
            label = f"{subject.last_part()}:{sha256_fingerprint[:8]}"
        else:
            label = sha256_fingerprint
        return cls(
            label=label,
            subject=subject,
            id=b"0",
            issuer=_dn_from_der(tbs.issuer),
            serial_number=tbs.serial_number,
            value=b,
            mozilla_ca_policy=False,
            server_distrust_after=None,
            email_distrust_after=None,
            sha1_fingerprint=hashlib.sha1(b).hexdigest(),
            sha256_fingerprint=sha256_fingerprint,
        )

    @property
    def clean_filename(self) -> str:
        return _to_filename(self)

    def public_key_pem(self) -> der_x509.PEMBlock:
        der_cert, trailing = der_x509.Certificate.from_der(self.value)
        assert not trailing
        return der_cert.public_key_pem()

    def as_pem(self) -> der_x509.PEMBlock:
        return der_x509.PEMBlock(
            name="CERTIFICATE",
            content=self.value,
        )


@dataclasses.dataclass(frozen=True)
class Trust:
    label: str
    issuer: der_x509.DistinguishedName
    serial_number: bytes

    trust_step_up_approved: bool

    trust_server_auth: enums.TrustType
    trust_client_auth: enums.TrustType
    trust_code_signing: enums.TrustType

    trust_digital_signature: enums.TrustType
    trust_non_repudiation: enums.TrustType
    trust_key_encipherment: enums.TrustType
    trust_data_encipherment: enums.TrustType
    trust_key_agreement: enums.TrustType
    trust_key_cert_sign: enums.TrustType
    trust_crl_sign: enums.TrustType
    trust_email_protection: enums.TrustType
    trust_ipsec_end_system: enums.TrustType
    trust_ipsec_tunnel: enums.TrustType
    trust_ipsec_user: enums.TrustType
    trust_time_stamping: enums.TrustType

    CORE_TRUST_ATTRS = [
        "trust_server_auth",
        "trust_client_auth",
        "trust_code_signing",
    ]

    TRUST_ATTRS = CORE_TRUST_ATTRS + [
        "trust_digital_signature",
        "trust_non_repudiation",
        "trust_key_encipherment",
        "trust_data_encipherment",
        "trust_key_agreement",
        "trust_key_cert_sign",
        "trust_crl_sign",
        "trust_email_protection",
        "trust_ipsec_end_system",
        "trust_ipsec_tunnel",
        "trust_ipsec_user",
        "trust_time_stamping",
    ]

    def as_distrusted(self) -> "Trust":
        # Generate a new version of this Trust where we distrust everything.
        return dataclasses.replace(
            self, **{k: enums.TrustType.NOT_TRUSTED for k in self.TRUST_ATTRS}
        )

    @classmethod
    def from_parser_object(cls, obj: nss_parser.ParsedObject):
        return cls(
            label=obj[b"CKA_LABEL"],
            issuer=_dn_from_der(obj[b"CKA_ISSUER"]),
            serial_number=obj[b"CKA_SERIAL_NUMBER"],
            trust_step_up_approved=obj[b"CKA_TRUST_STEP_UP_APPROVED"],
            # We expect these to be present
            trust_server_auth=obj[b"CKA_TRUST_SERVER_AUTH"],
            trust_code_signing=obj[b"CKA_TRUST_CODE_SIGNING"],
            trust_email_protection=obj[b"CKA_TRUST_EMAIL_PROTECTION"],
            # These vary and probably aren't set.
            trust_digital_signature=obj.get(
                b"CKA_TRUST_DIGITAL_SIGNATURE", enums.TrustType.UNKNOWN
            ),
            trust_non_repudiation=obj.get(
                b"CKA_TRUST_NON_REPUDIATION", enums.TrustType.UNKNOWN
            ),
            trust_key_encipherment=obj.get(
                b"CKA_TRUST_KEY_ENCIPHERMENT", enums.TrustType.UNKNOWN
            ),
            trust_data_encipherment=obj.get(
                b"CKA_TRUST_DATA_ENCIPHERMENT", enums.TrustType.UNKNOWN
            ),
            trust_key_agreement=obj.get(
                b"CKA_TRUST_KEY_AGREEMENT", enums.TrustType.UNKNOWN
            ),
            trust_key_cert_sign=obj.get(
                b"CKA_TRUST_KEY_CERT_SIGN", enums.TrustType.UNKNOWN
            ),
            trust_crl_sign=obj.get(b"CKA_TRUST_CRL_SIGN", enums.TrustType.UNKNOWN),
            trust_client_auth=obj.get(
                b"CKA_TRUST_CLIENT_AUTH", enums.TrustType.UNKNOWN
            ),
            trust_ipsec_end_system=obj.get(
                b"CKA_TRUST_IPSEC_END_SYSTEM", enums.TrustType.UNKNOWN
            ),
            trust_ipsec_tunnel=obj.get(
                b"CKA_TRUST_IPSEC_TUNNEL", enums.TrustType.UNKNOWN
            ),
            trust_ipsec_user=obj.get(b"CKA_TRUST_IPSEC_USER", enums.TrustType.UNKNOWN),
            trust_time_stamping=obj.get(
                b"CKA_TRUST_TIME_STAMPING", enums.TrustType.UNKNOWN
            ),
        )

    @property
    def distrusted(self) -> bool:
        # We distrust the cert if it is untrusted for *anything*.
        return bool(self.untrusted_key_usages)

    def _key_usages(self, trust_state: enums.TrustType) -> list[der_x509.ObjectID]:
        oids = []
        for purpose in x509_consts.PURPOSES:
            if getattr(self, f"trust_{purpose.trust_name}") == trust_state:
                oids.append(purpose.object_id)
        return oids

    @property
    def trusted_key_usages(self) -> list[der_x509.ObjectID]:
        return self._key_usages(enums.TrustType.TRUSTED_DELEGATOR)

    @property
    def untrusted_key_usages(self) -> list[der_x509.ObjectID]:
        return self._key_usages(enums.TrustType.NOT_TRUSTED)

    @property
    def clean_filename(self) -> str:
        return _to_filename(self)


def _to_filename(obj: Certificate | Trust) -> str:
    serial, _, serial_rem = der_x509.der_int_to_python(obj.serial_number)
    assert not serial_rem
    return "{clean_label}:{serial_hex}".format(
        clean_label=obj.label.translate(
            str.maketrans(
                {
                    "/": "_",
                    " ": "_",
                    ",": "_",
                    "(": "=",
                    ")": "=",
                }
            )
        ),
        serial_hex=hex(serial)[2:],
    )


@dataclasses.dataclass(frozen=True)
class CertDB:
    certmap: dict[str, Certificate] = dataclasses.field(default_factory=dict)
    trustmap: dict[str, Trust] = dataclasses.field(default_factory=dict)

    def add_nss_objs(self, objs: Iterable[nss_parser.ParsedObject]) -> None:
        for obj in objs:
            pobj = _parser_object_to_python(obj)
            if isinstance(pobj, Certificate):
                self.certmap[pobj.clean_filename] = pobj
            elif isinstance(pobj, Trust):
                self.trustmap[pobj.clean_filename] = pobj

    def add_certs(self, objs: Iterable[tuple[Certificate, Trust]]) -> None:
        for cert, trust in objs:
            assert cert.label == trust.label
            assert cert.issuer == trust.issuer
            assert cert.serial_number == trust.serial_number
            self.certmap[cert.clean_filename] = cert
            self.trustmap[trust.clean_filename] = trust


def _parser_object_to_python(
    obj: nss_parser.ParsedObject,
) -> Certificate | Trust | None:
    if obj[b"CKA_CLASS"] == enums.ObjectType.NSS_BUILTIN_ROOT_LIST:
        return None
    elif obj[b"CKA_CLASS"] == enums.ObjectType.CERTIFICATE:
        return Certificate.from_parser_object(obj)
    elif obj[b"CKA_CLASS"] == enums.ObjectType.NSS_TRUST:
        return Trust.from_parser_object(obj)
