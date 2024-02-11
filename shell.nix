# SPDX-FileCopyrightText: 2021 the buildcatrust authors
#
# SPDX-License-Identifier: MIT

{ pkgs ? import <nixpkgs> {
    # overlays = [ (self: super: { }) ];
  }
}:

let
  python = pkgs.python3;
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
  pycnite = python.pkgs.buildPythonPackage rec {
    pname = "pycnite";
    version = "2023.10.11";
    pyproject = true;

    src = python.pkgs.fetchPypi {
      inherit pname version;
      sha256 = "sha256:18car2rh02ayrf299hryfgvb2i5hw27sm68917r3kk7f5fc1d1md";
    };

    buildInputs = with python.pkgs; [
      setuptools
    ];
  };
  pytype = python.pkgs.buildPythonPackage rec {
    pname = "pytype";
    version = "2024.2.9";

    src = python.pkgs.fetchPypi {
      inherit pname version;
      sha256 = "sha256:106dma6qjsgqyh5ky7czfnp1vy5kzi5mfxz2lpw413pyrcxxwfj9";
    };

    doCheck = false;  # tries to parse Python2 things

    propagatedBuildInputs = with python.pkgs; [
      attrs
      importlab
      jinja2
      libcst
      networkx
      ninjaPy
      pybind11
      pycnite
      pydot
      pylint
      tabulate
      toml
      typing-extensions
    ];
  };
  myPython = python.withPackages (pm: with pm; [
    # for pre-commit
    pytest
    pytype

    # for misc local testing
    pytest-cov
    pyasn1
    pyupgrade

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
    ruff
  ];
}
