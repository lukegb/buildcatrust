<!--
SPDX-FileCopyrightText: 2024 the buildcatrust authors <buildcatrust@lukegb.com>

SPDX-License-Identifier: CC0-1.0
-->

# buildcatrust

buildcatrust is a tool for turning trust stores into other trust stores.

In particular, it's intended for use within [NixOS](https://www.nixos.org), for
turning the Mozilla NSS cert store into a format that can be used by various
downstream systems (see below).

## Why

The original author (lukegb) was not particularly happy with any of the
existing options: they tend to lose some of the semantic meaning of the input
NSS store, and this is undesirable.

In particular, there's a [well
documented](https://utcc.utoronto.ca/~cks/space/blog/linux/CARootStoreTrustProblem)
that Linux distributions have in general with distrusting certificates. This package
does not itself solve this 100% (because the nuance _still_ isn't readily encodable),
but the goal is to not make things worse. That is, running Firefox on a system
configured to use a buildcatrust-built certificate store should not drop
distrust dates. Other software may vary, depending on support for
distrust-after.

## Goals

* Have no runtime dependencies outside of the Python standard library
  - This is because this complicates packaging, particularly on NixOS, where
    buildcatrust is part of the bootstrap path for building everything else.
* Have decent test coverage
* Convey as many trust bits from the source system to downstream systems as
  possible
  - In some cases, this means using software-specific hacks (such as for
    OpenSSL)

## Contributing & Developing

Users are expected to abide by [the Contributor Covenant, version
2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

The best answer for developing this software is to use Nix, which will provide
dependencies for you automatically (at least on Linux-based distributions).

You should be able to run `nix-shell` in the root of this repo to get a working
shell containing a Python interpreter with `ruff`, `pytest`, `pytype`, and so
on.

It is also suggested to run `pre-commit` when making changes; you can install
its hook using `pre-commit install` which will ensure that things are correctly
formatted before permitting a commit.

However, because this software aims to have no dependencies outside of the
Python stdlib, it should be possible to at least make changes and run the
software without needing Nix or any other software installed. I do suggest that
you install `pytest` and `ruff` though, because then you can ensure a baseline
level of correctness before letting GitHub Actions judge your PR.
