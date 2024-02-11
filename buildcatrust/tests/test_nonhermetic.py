# SPDX-FileCopyrightText: 2021 Luke Granger-Brown <git@lukegb.com>
#
# SPDX-License-Identifier: MIT

"""These tests intentionally rely on artifacts and binaries that are not included in the repo."""

import shutil
import tarfile
import urllib.request

import pytest

from . import helpers

LOCAL_TESTDATA_DIR = helpers.TESTDATA_DIR / "local"


def _download_file_to_path(url, path):
    with urllib.request.urlopen(url) as response, open(path, "wb") as out:
        shutil.copyfileobj(response, out)


@pytest.fixture(scope="session")
def nss_certdata_path():
    LOCAL_TESTDATA_DIR.mkdir(exist_ok=True)
    nss_certdata_path = LOCAL_TESTDATA_DIR / "nss-certdata.txt"
    if not nss_certdata_path.exists():
        nss_path = LOCAL_TESTDATA_DIR / "nss.tar.gz"
        if not nss_path.exists():
            _download_file_to_path(
                "https://ftp.mozilla.org/pub/security/nss/releases/NSS_3_66_RTM/src/nss-3.66.tar.gz",
                nss_path,
            )
        with tarfile.open(nss_path, "r:*") as tf, open(nss_certdata_path, "wb") as fp:
            shutil.copyfileobj(
                tf.extractfile("nss-3.66/nss/lib/ckfw/builtins/certdata.txt"), fp
            )
    return nss_certdata_path


def test_nss_certdata_parse(nss_certdata_path, tmp_path):
    ca_unpacked_output = tmp_path / "ca_unpacked"
    ca_unpacked_output.mkdir(exist_ok=True)
    p11kit_output = tmp_path / "p11kit.p11"
    ca_bundle_output = tmp_path / "cabundle.crt"
    assert (
        helpers.run_main(
            p11kit_output=p11kit_output,
            ca_bundle_output=ca_bundle_output,
            ca_unpacked_output=ca_unpacked_output,
            certdata_input=nss_certdata_path,
        )
        == 0
    )
    assert p11kit_output.exists()
    assert ca_bundle_output.exists()
    assert (
        len(
            [
                f
                for f in ca_unpacked_output.iterdir()
                if f.name.endswith(".crt") and f.is_file()
            ]
        )
        > 20
    )
