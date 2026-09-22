# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# `tools/meister-ca`, as a program with its two dependencies in its own PATH.
#
# It stays a bash script and it stays readable, and that is the whole point of
# it: it is the one tool an operator has to be able to read line by line
# before trusting it with a CA key, and `openssl` is its only real
# prerequisite. What this derivation adds is that the prerequisite is no
# longer somebody's `nix shell nixpkgs#openssl` — the script checks for
# `openssl` on PATH and dies with a sentence when it is not there, and
# `meister-deploy keys issue` looks up a bare `meister-ca` on PATH.
#
# So: an OPERATOR-side package (`nix run .#meister-ca`, or on the path of the
# machine an operator issues certificates from), and deliberately not part of
# `meisterstack-runtime`. The runtime is what a managed host's units exec, and
# a managed host has no CA key on it — the key stays with the operator (D10),
# a node makes its own key and sends a request. A CA in a fleet host's closure
# would be a CA on seventy machines that must never have one.
{ lib
, stdenvNoCC
, makeWrapper
, bash
, openssl
, coreutils
}:
stdenvNoCC.mkDerivation {
  pname = "meister-ca";
  version = "0.1.0";
  src = ../../tools/meister-ca;
  dontUnpack = true;
  nativeBuildInputs = [ makeWrapper ];
  installPhase = ''
    runHook preInstall
    install -Dm755 $src $out/bin/meister-ca
    # The interpreter out of the store, so the script does not depend on
    # whatever /usr/bin/env finds.
    substituteInPlace $out/bin/meister-ca \
      --replace-fail '#!/usr/bin/env bash' '#!${bash}/bin/bash'
    # `openssl` and the handful of coreutils it uses (mktemp, mkdir, cat,
    # cut, dirname, rm), and NOTHING else on the PATH: a CA script that
    # picked up a program from the caller's environment would be a CA script
    # whose behaviour depends on who ran it.
    wrapProgram $out/bin/meister-ca \
      --set PATH ${lib.makeBinPath [ openssl coreutils ]}
    runHook postInstall
  '';
  # The marker the wrapper must not have swallowed: the script refuses to run
  # without openssl, and after this it can never be without it.
  doInstallCheck = true;
  installCheckPhase = ''
    env -i $out/bin/meister-ca --help > help.txt
    grep -q -- '--sign-csr' help.txt \
      || { echo "the wrapped script does not offer --sign-csr"; exit 1; }
    grep -q -- '--cloud' help.txt \
      || { echo "the wrapped script printed something else entirely"; cat help.txt; exit 1; }
  '';
  meta = {
    description = "The lab's certificate authority: openssl, in one readable script";
    license = lib.licenses.mit;
    mainProgram = "meister-ca";
    platforms = lib.platforms.unix;
  };
}
