# SPDX-FileCopyrightText: 2021 Luke Granger-Brown <git@lukegb.com>
#
# SPDX-License-Identifier: MIT

import pathlib

from buildcatrust import cli

TESTDATA_DIR = pathlib.Path(__file__).parent / "testdata"


def run_main(**kwargs):
    args = [f"--{k}={v}" for k, v in kwargs.items()]
    return cli.cli_main(args)


def check_output_main(tmp_path, want_p11kit, want_ca, main_args):
    ca_unpacked_output = tmp_path / "ca_unpacked"
    ca_unpacked_output.mkdir(exist_ok=True)
    p11kit_output = tmp_path / "p11kit.p11"
    ca_bundle_output = tmp_path / "cabundle.crt"

    assert (
        run_main(
            p11kit_output=p11kit_output,
            ca_unpacked_output=ca_unpacked_output,
            ca_bundle_output=ca_bundle_output,
            **main_args,
        )
        == 0
    )

    with open(p11kit_output) as p11kit_fp:
        p11kit_data = p11kit_fp.read()
        assert p11kit_data == want_p11kit

    with open(ca_bundle_output) as ca_bundle_fp:
        ca_bundle_data = ca_bundle_fp.read()
        assert ca_bundle_data == want_ca

    ca_unpacked_files = [
        f
        for f in ca_unpacked_output.iterdir()
        if f.name.endswith(".crt") and f.is_file()
    ]
    assert [f.name for f in ca_unpacked_files] == [
        "Certum_EC-384_CA:788f275c81125220a504d02dddba73f4.crt"
    ]
    with open(ca_unpacked_files[0]) as ca_unpacked_fp:
        ca_unpacked_data = ca_unpacked_fp.read()
        assert ca_unpacked_data == want_ca
