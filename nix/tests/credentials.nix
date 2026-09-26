# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Check ordinary key files, ownership, restrictive modes, and reboot enforcement.
# This test uses an untrusted certificate to distinguish file-access checks from
# TLS validation; keys.nix covers successful authenticated sessions.
{ nixpkgs, lib, pkgs, system, self }:

pkgs.testers.runNixOSTest {
  name = "meister-credentials";

  nodes.machine = { ... }: {
    imports = [ self.nixosModules.services self.nixosModules.managed ];
    meisterstack.roles = [ "agent" ];
    meisterstack.managed.enable = true;
    meisterstack.managed.trustedPublicKeys = [
      "credentials-test:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    ];
    # The whole point of this test: the agent runs as `meister` and not as
    # root, so the key it opens has to be readable by `meister` and by
    # nobody else.
    meisterstack.agent.unprivileged = true;
    # Neither belongs to this question, and both are kernel modules a test
    # VM would have to carry.
    meisterstack.agent.frr.enable = false;
    meisterstack.agent.nvmeTcp.enable = false;
    # A controller to talk to, and nothing listening there. Without an
    # address the agent opens no session at all and therefore never opens
    # its identity key — which would make this test about a loader that is
    # never asked. Where the address points does not matter: the key is
    # loaded to BUILD the session, before anything is dialled.
    meisterstack.agent.settings.controller_addrs = [ "https://127.0.0.1:50051" ];

    environment.systemPackages = [ pkgs.openssl ];
    boot.loader.grub.enable = false;
    virtualisation.writableStore = true;
    virtualisation.memorySize = 2048;
  };

  testScript = ''
    machine.start()
    machine.wait_for_unit("multi-user.target")

    pki = "/var/lib/meisterstack/pki"

    def mode_of(path):
        return machine.succeed(f"stat -c '%a %U:%G' {path}").strip()

    def agent_said():
        return machine.succeed(
            "journalctl -u meister-agent.service --no-pager | tail -40"
        )

    # --- no systemd credential anywhere ---------------------------------
    unit = machine.succeed("systemctl cat meister-agent.service")
    assert "LoadCredential" not in unit, unit
    assert "SetCredential" not in unit, unit
    assert "/run/credentials" not in unit, unit
    # The unit runs as the user whose key it opens.
    assert "User=meister" in unit, unit
    # And it waits, visibly, for key material it has not been given yet.
    assert f"ConditionPathExists={pki}/ca.crt" in unit, unit
    machine.succeed(f"test -d {pki}")

    # --- an identity, as a bootstrap would deliver it --------------------
    #
    # Self-signed, because what is being measured here is the MODE and not
    # the trust chain: a certificate nobody signed is exactly as readable as
    # one a CA did.
    machine.succeed(
        f"openssl req -x509 -newkey rsa:2048 -nodes -days 1 "
        f"-subj '/CN=system:node:machine' -keyout {pki}/identity.key "
        f"-out {pki}/identity.crt 2>/dev/null"
    )
    machine.succeed(f"cp {pki}/identity.crt {pki}/ca.crt")
    machine.succeed(f"chown meister:meister {pki}/identity.key {pki}/identity.crt")
    machine.succeed(f"chmod 600 {pki}/identity.key")
    machine.succeed(f"chmod 644 {pki}/identity.crt {pki}/ca.crt")
    assert mode_of(f"{pki}/identity.key") == "600 meister:meister"

    # --- 0600 gets past the loader ---------------------------------------
    #
    # The agent will not come up — there is no controller to register with
    # and nobody signed this certificate — but WHY it does not come up is
    # the question. "too open" is the loader's refusal, and it must not be
    # in there.
    machine.succeed("systemctl restart meister-agent.service || true")
    machine.sleep(3)
    said = agent_said()
    print(said)
    assert "too open" not in said, said

    # --- 0640 is refused, in the loader's own words ----------------------
    machine.succeed(f"chmod 640 {pki}/identity.key")
    machine.succeed("systemctl restart meister-agent.service || true")
    machine.wait_until_succeeds(
        "journalctl -u meister-agent.service --no-pager | grep -q 'too open'", timeout=60
    )
    said = machine.succeed(
        "journalctl -u meister-agent.service --no-pager | grep 'too open' | tail -1"
    )
    print(said)
    assert "permissions 0640" in said, said
    assert f"{pki}/identity.key" in said, said
    assert "chmod 600" in said, said
    # It is the group bit that does it, not the world: 0604 would be refused
    # just the same, and 0600 is the only mode that is not.
    assert machine.succeed(f"stat -c %a {pki}/identity.key").strip() == "640"

    # --- and the mode survives a reboot ----------------------------------
    #
    # `z <pki.dir>/identity.key 0600 meister meister` in nix/agent.nix is a
    # tmpfiles rule that ENFORCES the mode at every boot rather than only
    # creating the file. A key that a chmod had loosened is therefore tight
    # again after a reboot — which is the half of this that a comment could
    # not promise.
    machine.shutdown()
    machine.start()
    machine.wait_for_unit("multi-user.target")
    assert mode_of(f"{pki}/identity.key") == "600 meister:meister", (
        "the tmpfiles rule did not put the key back to 0600 meister:meister"
    )
    machine.succeed("systemctl restart meister-agent.service || true")
    machine.sleep(3)
    said = agent_said()
    assert "too open" not in said, said

    # And the key is still a FILE the machine's own tools can see — not a
    # credential inside a unit's namespace, which is what M0 probe S11
    # measured and what this fleet decided against.
    machine.succeed(f"test -f {pki}/identity.key")
    machine.fail("test -e /run/credentials/meister-agent.service")

    print("a key on a managed host is meister:meister 0600, and the loader says so")
  '';
}
