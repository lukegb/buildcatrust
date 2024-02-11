#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2021 Luke Granger-Brown <git@lukegb.com>
#
# SPDX-License-Identifier: MIT

import base64
import csv
import sys
from typing import List

from buildcatrust import der_x509
from buildcatrust import types


def process_path(path: str) -> None:
    with open(path, "r", newline="") as f:
        csvr = csv.reader(f)
        for row in csvr:
            log_url, log_index = row[0:2]
            cert_der_b64, all_domains = row[3:5]
            try:
                cert_der = base64.b64decode(cert_der_b64)
                x509_cert, trailer = der_x509.Certificate.from_der(cert_der)
                assert not trailer
                assert types.Certificate.from_x509(cert_der, x509_cert)
            except Exception as ex:
                print(
                    f"while parsing {log_url} idx {log_index} - {all_domains}: {repr(ex)}",
                    file=sys.stderr,
                )


def main(argv: List[str]) -> int:
    for path in argv:
        process_path(path)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
