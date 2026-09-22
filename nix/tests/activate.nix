# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# What `meister-activate` does to a real machine, in a real machine.
#
# Every other test of the helper is a command line a fake runner recorded.
# This one moves an actual system profile, runs an actual
# `switch-to-configuration`, and waits for an actual systemd timer to fire —
# because the one guarantee M2 exists to give is "a host that nobody
# confirms comes back by itself", and a guarantee about a timer is worth
# exactly as much as the machine it has run on.
#
# Two systems, A and B, and they are two NODES of this test rather than two
# hand-built closures. The reason is the test driver: it talks to the
# machine through `backdoor.service`, and a system that did not carry that
# unit would be a system the driver cannot reach after the switch. Both
# nodes are full test machines that differ in one `environment.etc` entry,
# so the switch between them changes a file and no unit at all.
#
# What this test does NOT prove is the boot-mode fallback: this VM boots
# with `-kernel` and has no ESP, so there is no `bootctl` to set a one-shot
# entry with. What it proves instead is that the helper REFUSES boot mode
# there, with the sentence D5 asks for. nix/tests/activate-boot.nix is the
# other half.
{ nixpkgs, lib, pkgs, system, self }:

let
  # The half of a managed host that both systems share. No roles: this test
  # is about the profile and the transaction, and a control plane in it
  # would only be a slower boot.
  common = { ... }: {
    imports = [ self.nixosModules.services self.nixosModules.managed ];
    # No `nixpkgs.pkgs` here: `pkgs.testers.runNixOSTest` gives its nodes the
    # pkgs it was called on, which is this flake's overlayed one, and a
    # second definition of it is a conflict rather than a repetition.
    meisterstack.managed.enable = true;
    # Required by nix/managed.nix, and never used here: nothing is copied
    # into this machine (that is nix/tests/update.nix).
    meisterstack.managed.trustedPublicKeys = [ "activate-test:not-a-real-key" ];
    # A test machine does not carry `switch-to-configuration` by default —
    # nixos-test-base turns it off so that Hydra does not rebuild every test
    # when it changes. A machine a deployment activates on HAS to have it:
    # it is the program that makes a store path the running system.
    system.switch.enable = true;
    # …and it must not try to install a boot loader while it is at it: this
    # VM is started with `-kernel` and has no disk to install one on, so
    # grub-install fails and takes the whole switch with it. A real managed
    # host has a loader; nix/tests/activate-boot.nix is the VM that does.
    boot.loader.grub.enable = false;
    # `nix-env --set` and `nix-collect-garbage` write the store.
    virtualisation.writableStore = true;
    virtualisation.memorySize = 2048;
  };
in
pkgs.testers.runNixOSTest {
  name = "meister-activate-semantics";

  nodes = {
    machine = { nodes, ... }: {
      imports = [ common ];
      environment.etc."meister-generation".text = "A";
      # System B has to be IN this machine's store before anything can
      # activate it. `additionalPaths` is what a test has instead of the
      # `nix copy` a rollout does.
      virtualisation.additionalPaths = [ nodes.other.system.build.toplevel ];
    };

    # Never started. It exists for its toplevel, which is system B: the same
    # machine with one file changed.
    other = { ... }: {
      imports = [ common ];
      environment.etc."meister-generation".text = "B";
    };
  };

  testScript = { nodes, ... }:
    let
      systemB = nodes.other.system.build.toplevel;
    in
    ''
      import json

      machine.start()
      machine.wait_for_unit("multi-user.target")

      def status():
          return json.loads(machine.succeed("meister-activate status --json"))

      def generation_file():
          return machine.succeed("cat /etc/meister-generation").strip()

      # --- the starting point ------------------------------------------
      #
      # A test machine boots with `-kernel` and has no system profile, so
      # generation 1 is made here — which is also the first thing a real
      # host has, from `nixos-install`.
      systemA = machine.succeed("readlink -f /run/current-system").strip()
      machine.succeed(f"nix-env -p /nix/var/nix/profiles/system --set {systemA}")

      before = status()
      print(json.dumps(before, indent=2))
      assert before["current_system"] == systemA, before
      assert before["generation"] == 1, before
      assert before["open_txns"] == [], before
      assert before["lock"] is None, before
      assert before["kernel_booted"] is not None, "the booted kernel is readable"
      assert generation_file() == "A"

      # The contract 2A's probe merges: what this program prints IS
      # `meister-deploy schema activate-status`, and the schema says so.
      assert before["schema"] == "meister-deploy/activate-status/1", before

      # --- stage: it is here, whole, and it is a system ------------------
      machine.succeed("meister-activate stage ${systemB}")
      machine.fail("meister-activate stage /nix/store/00000000000000000000000000000000-not-here")

      # --- an activation nobody confirms comes back by itself ------------
      machine.succeed(
          "meister-activate activate --txn t1 --toplevel ${systemB} "
          "--mode switch --confirm-within 20 --run run-a"
      )
      assert generation_file() == "B", "the switch did not take"
      during = status()
      assert len(during["open_txns"]) == 1, during
      assert during["open_txns"][0]["state"] == "pending", during
      assert during["open_txns"][0]["deadline"] is not None, during
      # The way back is armed, and it is a unit somebody can look at.
      machine.succeed("systemctl is-active meister-revert-t1.timer")

      # A second activation on top of an open one is refused, and says which.
      refused = machine.fail(
          "meister-activate activate --txn t2 --toplevel ${systemB} "
          "--mode switch --confirm-within 20 --run run-a 2>&1"
      )
      assert "already has the transaction t1 open" in refused, refused

      # Nobody says anything. The timer fires.
      machine.wait_until_succeeds("test \"$(cat /etc/meister-generation)\" = A", timeout=90)
      machine.wait_until_fails("systemctl is-active meister-revert-t1.timer", timeout=30)
      # The record is written when the way back is FINISHED, not when the
      # /etc symlink moved — so this waits for the program rather than for
      # the file it swapped first. (Measured: the first run of this test
      # read the record while switch-to-configuration was still reloading
      # units, and found it pending, which it was.)
      machine.wait_until_succeeds(
          "meister-activate --json txn show --txn t1 | grep -q '\"reverted\"'", timeout=60
      )
      after = status()
      assert after["current_system"] == systemA, after
      assert after["open_txns"] == [], "a reverted transaction is not open any more"
      reverted = json.loads(machine.succeed("meister-activate --json txn show --txn t1"))
      assert reverted["state"] == "reverted", reverted
      assert "nobody confirmed" in reverted["reason"], reverted
      # And the journal of the machine says who did it.
      machine.succeed("journalctl -u meister-revert-t1.service --no-pager | tail -5")

      # --- an activation somebody confirms stays -------------------------
      machine.succeed(
          "meister-activate activate --txn t3 --toplevel ${systemB} "
          "--mode switch --confirm-within 20 --run run-a"
      )
      assert generation_file() == "B"
      machine.succeed("meister-activate confirm --txn t3")
      machine.fail("systemctl is-active meister-revert-t3.timer")
      confirmed = json.loads(machine.succeed("meister-activate --json txn show --txn t3"))
      assert confirmed["state"] == "confirmed", confirmed
      # Well past the deadline it would have had.
      machine.sleep(30)
      assert generation_file() == "B", "a confirmed activation was taken back anyway"
      assert status()["current_system"] != systemA

      # A confirmed transaction is not reverted afterwards.
      refused = machine.fail("meister-activate revert --txn t3 2>&1")
      assert "was confirmed" in refused, refused

      # --- the lock is one door -----------------------------------------
      machine.succeed(
          "meister-activate lock acquire --run run-a --operator silas@manacor --pid 4711"
      )
      refused = machine.fail(
          "meister-activate lock acquire --run run-b --operator somebody@else --pid 1 2>&1"
      )
      assert "held by the run run-a" in refused, refused
      assert "never expires by itself" in refused, refused
      # Only the holder gives it back, and the read-only probe of lane 2A
      # reads the same file.
      assert machine.fail("meister-activate lock release --run run-b 2>&1")
      owner = json.loads(machine.succeed("cat /var/lib/meisterstack/deploy/lock/owner.json"))
      assert owner["run_id"] == "run-a", owner
      assert sorted(owner.keys()) == ["acquired_at", "operator", "pid", "run_id"], owner
      assert status()["lock"]["run_id"] == "run-a"
      machine.succeed("meister-activate lock release --run run-a")
      assert status()["lock"] is None

      # --- an activation on a host somebody else holds --------------------
      machine.succeed(
          "meister-activate lock acquire --run run-other --operator somebody@else --pid 2"
      )
      refused = machine.fail(
          "meister-activate activate --txn t4 --toplevel ${systemB} "
          "--mode switch --confirm-within 20 --run run-a 2>&1"
      )
      assert "held by the run run-other" in refused, refused
      assert "Nothing was changed" in refused, refused
      machine.succeed("meister-activate lock release --run run-other")

      # --- boot mode, on a machine that has no boot menu ------------------
      #
      # This VM is started with `-kernel` and has no ESP, so `bootctl` can
      # say nothing about a one-shot entry. The helper refuses rather than
      # activating something whose way back it cannot arrange — which is
      # exactly the documented limit of D5 for a grub host.
      refused = machine.fail(
          "meister-activate activate --txn t5 --toplevel ${systemB} "
          "--mode boot --confirm-within 60 --run run-a 2>&1"
      )
      assert "no boot fallback" in refused, refused
      assert "--mode switch" in refused, refused
      assert status()["open_txns"] == [], "a refused activation left a record"

      # --- gc keeps what a rollback needs ---------------------------------
      #
      # A retired record first: a finished transaction is retired by the run
      # that owns it, and until then it is what makes the next plan refuse to
      # start over.
      machine.succeed("meister-activate txn retire --txn t3 --run run-a")
      machine.succeed("meister-activate txn retire --txn t1")
      assert machine.succeed("meister-activate --json txn list").strip() == "[]"

      generations = machine.succeed("nix-env -p /nix/var/nix/profiles/system --list-generations")
      print(generations)
      assert len(generations.strip().splitlines()) >= 3, generations
      machine.succeed("meister-activate gc --keep 1")
      left = machine.succeed("nix-env -p /nix/var/nix/profiles/system --list-generations")
      print(left)
      # The running one, the one it booted, and one to go back to.
      assert len(left.strip().splitlines()) <= 3, left
      assert "(current)" in left, left
      # And the system it is running is still there to run.
      machine.succeed("test -e /run/current-system/init")
      assert generation_file() == "B"

      # A gc while something is pending is refused, because the generation it
      # would roll back to must not be collected.
      machine.succeed(
          "meister-activate activate --txn t6 --toplevel ${systemB} "
          "--mode switch --confirm-within 120 --run run-a"
      )
      refused = machine.fail("meister-activate gc --keep 1 2>&1")
      assert "must not be collected" in refused, refused
      machine.succeed("meister-activate confirm --txn t6")

      print("meister-activate: the semantics hold on a real machine")
    '';
}
