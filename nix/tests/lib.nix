# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Helpers of the evaluation-only checks (gpu-profile, leandro-series): they
# decide at evaluation and the check's shell script only reports the result.
{ lib }:
rec {
  # One shell step of a check: nothing when `ok`, else the reason and a failing exit.
  require = ok: reason:
    lib.optionalString (!ok) "echo ${lib.escapeShellArg "-> ${reason}"}; exit 1";

  # The tag a message of this stack's own assertions and warnings starts with
  # ("[driver] ..." is "driver"), or null for one without. Checks match the tag and never
  # the prose after it, so the prose is free to change.
  tagOf = message:
    if lib.hasPrefix "[" message
    then lib.removePrefix "[" (lib.head (lib.splitString "]" message))
    else null;

  # The tags of the failed assertions of a NixOS configuration. Untagged ones are the
  # module system's and other modules', which a host carries as well.
  failedOf = config: lib.filter (tag: tag != null)
    (map (a: tagOf a.message) (lib.filter (a: !a.assertion) config.assertions));

  # Whether a configuration fails exactly one of the tagged assertions, the one tagged `tag`.
  failsOnly = config: tag: failedOf config == [ tag ];
}
