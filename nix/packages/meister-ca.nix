# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Package the operator-side CA script with a fixed Bash interpreter and PATH
# containing OpenSSL and coreutils. Keep it outside the host runtime package.
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
  # Check that the wrapped command exposes its certificate-issuance interface.
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
