# SPDX-FileCopyrightText: 2021 the buildcatrust authors
#
# SPDX-License-Identifier: MIT

{ pkgs ? import <nixpkgs> {
    # overlays = [ (self: super: { }) ];
  }
}:

let
  python = pkgs.python3;
  importlab = python.pkgs.buildPythonPackage rec {
    pname = "importlab";
    version = "0.6.1";

    src = python.pkgs.fetchPypi {
      inherit pname version;
      sha256 = "sha256:0gpq9za0ykq4b2x8i4ykj6nj11m15824idd4j5i8zfpiklr06r85";
    };

    propagatedBuildInputs = with python.pkgs; [
      networkx
    ];

    # Tries to use Python2?
    doCheck = false;
  };
  ninjaPy = python.pkgs.buildPythonPackage rec {
    pname = "ninja";
    version = "1.10.0.post2";

    src = pkgs.fetchFromGitHub {
      owner = "ninja-build";
      repo = pname;
      rev = "v1.10.0";
      sha256 = "sha256:1fbzl7mrcrwp527sgkc1npfl3k6bbpydpiq98xcf1a1hkrx0z5x4";
    };

    configurePhase = ''
      cat <<EOF >setup.py
      from setuptools import setup

      setup(
          name = "${pname}",
          version = "${version}",
          packages = ['ninja'],
      )
      EOF

      mkdir ninja/
      cp misc/ninja_syntax.py ninja/ninja_syntax.py
      cat <<EOF >ninja/__init__.py
      import os.path
      import subprocess
      import sys

      __version__ = "${version}"

      BIN_DIR = "${pkgs.ninja}/bin"

      def _program(name, args):
        return subprocess.call([os.path.join(BIN_DIR, name)] + args)

      def ninja():
        raise SystemExit(_program('ninja', sys.argv[1:]))
      EOF
      cat <<EOF >ninja/__main__.py
      from ninja import ninja

      if __name__ == '__main__':
        ninja()
      EOF
    '';
  };
  pytype = python.pkgs.buildPythonPackage rec {
    pname = "pytype";
    version = "2021.5.25";

    src = python.pkgs.fetchPypi {
      inherit pname version;
      sha256 = "sha256:1am113x1rla8vfyvcibahyxnydw2maxv8qvihrwwqp1lvnp9q0ih";
    };

    doCheck = false;  # tries to parse Python2 things

    propagatedBuildInputs = with python.pkgs; [
      attrs
      importlab
      ninjaPy
      pylint
      pyyaml
      six
      toml
      typed-ast
      pybind11
    ];
  };
  myPython = python.withPackages (pm: with pm; [
    # for pre-commit
    black
    isort
    pytest
    pytype

    # for misc local testing
    pytest-cov
    pyasn1

    flit
  ]);
in
pkgs.mkShell {
  buildInputs = with pkgs; [
    pre-commit
    myPython
    openssl
    ninja
    reuse
  ];
}
