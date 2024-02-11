#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2021 the buildcatrust authors
#
# SPDX-License-Identifier: MIT

import argparse
import os.path
import sys

from . import certstore_output
from . import certstore_parser
from . import nss_parser
from . import p11kit_output
from . import types


def output_to_file(db: types.CertDB, args, arg_name: str, output_cls) -> bool:
    file_name = getattr(args, arg_name)
    if not file_name:
        return False
    with open(file_name, "w") as fp:
        out = output_cls(fp)
        for key in sorted(db.trustmap.keys()):
            out.output(db.certmap.get(key, None), db.trustmap[key])
    return True


def output_to_dir(
    db: types.CertDB, args, arg_name: str, output_cls, extension: str
) -> bool:
    dir_name = getattr(args, arg_name)
    if not dir_name:
        return False
    for key in sorted(db.trustmap.keys()):
        with open(os.path.join(dir_name, f"{key}{extension}"), "w") as fp:
            output_cls(fp).output(db.certmap.get(key, None), db.trustmap[key])
    return True


def load_blocklist(path: str) -> set[str]:
    block = set()
    with open(path) as f:
        for ln in f:
            ln = ln.strip()
            if not ln or ln.startswith("#"):
                continue
            block.add(ln)
    return block


def _parse_args(args):
    argparser = argparse.ArgumentParser()
    argparser.add_argument(
        "--p11kit_output", help="Path to output p11kit-compatible output to."
    )
    argparser.add_argument(
        "--ca_bundle_output", help="Path to output certificate bundle output to."
    )
    argparser.add_argument(
        "--ca_standard_bundle_output",
        help="Path to output the PEM-standard certificate bundle output to.",
    )
    argparser.add_argument(
        "--ca_unpacked_output", help="Path to output certificate unbundled output to."
    )

    argparser.add_argument(
        "--certdata_input",
        help="Path to the certdata.txt in NSS-compatible format.",
        nargs="*",
    )
    argparser.add_argument(
        "--ca_bundle_input",
        help="Path to a cert bundle or directory to trust. This can either be plain PEM files, in which case they will be trusted for all 'standard' uses, or OpenSSL-style TRUSTED CERTIFICATE files, in which case those trust bits will be used.",
        nargs="*",
    )
    argparser.add_argument(
        "--blocklist_input",
        help="Path to a new-line separated blocklist of certificates from the provided certstore to distrust. Can be either the label in the NSS store, or the internal key (which is output alongside the certificate in the available output formats).",
    )

    return argparser, argparser.parse_args(args)


def cli_main(raw_args):
    argparser, args = _parse_args(raw_args)
    if not (args.certdata_input or args.ca_bundle_input):
        argparser.print_help()
        return 1

    db = types.CertDB()
    for certdata_path in args.certdata_input or []:
        with open(certdata_path, "rb") as certdata_fp:
            db.add_nss_objs(nss_parser.Parser().parse_lines(certdata_fp))
    for bundle_path in args.ca_bundle_input or []:
        if os.path.isfile(bundle_path):
            bundle_files = [bundle_path]
        elif os.path.isdir(bundle_path):
            bundle_files = [
                os.path.join(bundle_path, f) for f in os.listdir(bundle_path)
            ]
            bundle_files = [f for f in bundle_files if os.path.isfile(f)]
        else:
            raise FileNotFoundError(f"Bundle not found: {bundle_path}")
        for f in bundle_files:
            with open(f) as ca_bundle_fp:
                db.add_certs(certstore_parser.read_certificates(ca_bundle_fp))

    blocklist = frozenset()
    if args.blocklist_input:
        blocklist = load_blocklist(args.blocklist_input)

    certs_without_trusts = set(db.certmap.keys()) - db.trustmap.keys()
    if certs_without_trusts:
        print(f"Certs without trusts: {certs_without_trusts}", file=sys.stderr)
        return 2

    # Remove all trust from any certs in blocklist.
    # We will allow either the trustmap key, or just the plain label.
    saw_blocklist = set()
    for key in sorted(db.trustmap.keys()):
        if key in blocklist:
            saw_blocklist.add(key)
            db.trustmap[key] = db.trustmap[key].as_distrusted()
        elif db.trustmap[key].label in blocklist:
            saw_blocklist.add(db.trustmap[key].label)
            db.trustmap[key] = db.trustmap[key].as_distrusted()
    unseen_blocklist = blocklist - saw_blocklist
    if unseen_blocklist:
        print(
            f"Certs in blocklist but not in cert store: {unseen_blocklist}",
            file=sys.stderr,
        )
        return 3

    did_output = False
    outputs = {
        "p11kit_output": (output_to_file, p11kit_output.P11KitOutput),
        "ca_bundle_output": (output_to_file, certstore_output.OpenSSLCertStoreOutput),
        "ca_unpacked_output": (
            output_to_dir,
            certstore_output.OpenSSLCertStoreOutput,
            ".crt",
        ),
        "ca_standard_bundle_output": (
            output_to_file,
            certstore_output.StandardCertStoreOutput,
        ),
    }
    for k, v in outputs.items():
        did_output = v[0](db, args, k, *v[1:]) or did_output

    if not did_output:
        argparser.print_help()
        return 1
    return 0


def main():
    sys.exit(cli_main(sys.argv[1:]) or 0)


if __name__ == "__main__":
    main()
