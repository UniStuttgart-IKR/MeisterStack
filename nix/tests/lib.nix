# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Helpers of the evaluation-only checks (leandro-series): they decide at
# evaluation and the check's shell script only reports the result.
{ lib }:
{
  # One shell step of a check: nothing when `ok`, else the reason and a failing exit.
  require = ok: reason:
    lib.optionalString (!ok) "echo ${lib.escapeShellArg "-> ${reason}"}; exit 1";
}
