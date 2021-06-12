# SPDX-FileCopyrightText: 2021 Luke Granger-Brown <git@lukegb.com>
#
# SPDX-License-Identifier: MIT

{ pkgs ? import <nixpkgs> {
    overlays = [ (self: super: rec {
      python39 = super.python39.override {
        packageOverrides = self: super: {
          attrs = super.attrs.overridePythonAttrs (oldAttrs: rec {
            version = "21.2.0";
            src = super.fetchPypi {
              pname = "attrs";
              inherit version;
              sha256 = "sha256:1yzmwi5d197p0qhl7rl4xi9q1w8mk9i3zn6hrl22knbcrb1slspg";
            };
          });
          typed-ast = super.typed-ast.overridePythonAttrs (oldAttrs: rec {
            version = "1.4.3";
            src = super.fetchPypi {
              pname = "typed_ast";
              inherit version;
              sha256 = "sha256:0rgcynvicc614fyzq1bdq9c864wrkhwq21ypxnfa5pish2nbw6zv";
            };
          });
          pyasn1 = super.pyasn1.overridePythonAttrs (old: rec {
            version = "unstable-20200320";
            src = pkgs.fetchFromGitHub {
              owner = "etingof";
              repo = "pyasn1";
              rev = "db8f1a7930c6b5826357646746337dafc983f953";
              sha256 = "sha256:05ss2l1d9zrl9c4cf1r5xfiwrp955l982w61588qhgvk9y3mxi0x";
            };
          });
        };
      };
    }) ];
  }
}:

let
  python = pkgs.python39;
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

    checkInputs = [ pkgs.python2 ];
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
    pre-commit

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
    myPython
    openssl
    ninja
    (reuse.override { python3Packages = myPython.pkgs; })
  ];
}
