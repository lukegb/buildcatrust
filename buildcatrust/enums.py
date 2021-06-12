# SPDX-FileCopyrightText: 2021 Luke Granger-Brown <git@lukegb.com>
#
# SPDX-License-Identifier: MIT

import enum


class ObjectType(enum.Enum):
    NSS_BUILTIN_ROOT_LIST = enum.auto()
    CERTIFICATE = enum.auto()
    NSS_TRUST = enum.auto()


class TrustType(enum.Enum):
    TRUSTED_DELEGATOR = enum.auto()
    MUST_VERIFY_TRUST = enum.auto()
    NOT_TRUSTED = enum.auto()

    # We shouldn't see these, but they're included for completeness.
    TRUSTED = enum.auto()
    UNKNOWN = enum.auto()
