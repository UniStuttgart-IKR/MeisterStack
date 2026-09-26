# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Build the RDMA latency and bandwidth tools used alongside rdma-core.
# rdma.nix selects this package only for enabled agents.
{ lib
, stdenv
, fetchFromGitHub
, autoconf
, automake
, libtool
, pkg-config
, rdma-core
, pciutils
}:

stdenv.mkDerivation rec {
  pname = "perftest";
  # Pin benchmark results to a release tag.
  version = "26.04.17";

  src = fetchFromGitHub {
    owner = "linux-rdma";
    repo = "perftest";
    rev = version;
    hash = "sha256-oNvzQubmslZ4JUNww/wvWd54JDsDLamCDlorHWlNtaY=";
  };

  nativeBuildInputs = [ autoconf automake libtool pkg-config ];
  buildInputs = [ rdma-core pciutils ];

  # The tarball ships no `configure`; upstream's own build starts here.
  preConfigure = "./autogen.sh";

  meta = {
    description = "InfiniBand/RoCE latency and bandwidth benchmarks (ib_send_lat, ib_write_bw)";
    homepage = "https://github.com/linux-rdma/perftest";
    license = lib.licenses.gpl2Only;
    platforms = lib.platforms.linux;
  };
}
