# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# A guest small enough to be a test and reproducible enough to be evidence.
#
# The verification suites of M4 need a guest that boots, says one thing and
# goes away again. Until now that guest was four files in
# /mnt/vmstore/MeisterStack/images — `vmlinux.elf`, `tiny-initrd`,
# `tiny-volume.raw`, `m51-initrd` — built by hand, carried by
# `deploy/push.sh` out of `MEISTER_GUEST_ASSETS`, and reproducible by nobody:
# M0 probe S14 looked for a build script and found exactly one, for a
# different guest (`claude/input-e2e-guest/{init.c,build.sh}` in the journal,
# which is the template for the initramfs below). A release that names a
# guest kernel it cannot rebuild is a release whose `guest_artifacts` mean
# nothing, so this package is the answer to that and nothing more.
#
# Two decisions worth reading before changing it:
#
# * **The console is the SERIAL port, not virtio-console.** 8250 is built
#   into the pinned nixpkgs kernel; virtio_console is a MODULE there (as are
#   all the virtio drivers), so a guest that talks over virtio has to insmod
#   before it can say anything — and then a broken insmod looks exactly like
#   a guest that did not boot. `--serial tty --console off` and the marker is
#   the first thing on the wire.
# * **Poweroff is honoured, and how is visible.** The ACPI power button
#   reaches userspace as an input event, so busybox' acpid plus `evdev.ko`
#   out of the same kernel is what turns a power button press into a clean
#   shutdown — and in the pinned nixpkgs kernel evdev is built in, so no
#   module is needed at all. Either way init SAYS on the console whether it
#   can hear the button, instead of looking like a guest that ignores a
#   shutdown.
{ lib
, stdenvNoCC
, runCommand
, writeText
, linuxPackages
, pkgsStatic
, cpio
, gzip
, xz
}:

let
  kernel = linuxPackages.kernel;
  # nixpkgs splits a kernel into three outputs, and the modules are not in
  # the one that holds the bzImage.
  modules = kernel.modules or kernel;
  busybox = pkgsStatic.busybox;

  # The line the suites wait for. One string, in one place: the agent's own
  # console contract is `MS-S0-*` (components/agent/tests/stufe3_ch.rs), and
  # this guest keeps that prefix so a suite can grep for one family of lines.
  marker = "MS-S0-TINY-OK";

  init = writeText "guest-tiny-init" ''
    #!/bin/sh
    # The whole userspace of this guest.
    # /var/log because busybox' acpid opens /var/log/acpid.log unless it is
    # logging to stderr, and dies with "No such file or directory" if the
    # directory is missing — measured, and it looked exactly like a guest
    # that ignores the power button.
    /bin/busybox mkdir -p /proc /sys /dev /var/log
    /bin/busybox mount -t proc proc /proc 2>/dev/null
    /bin/busybox mount -t sysfs sys /sys 2>/dev/null
    /bin/busybox mount -t devtmpfs dev /dev 2>/dev/null

    echo "${marker}"
    echo "MS-S0-KERNEL: $(/bin/busybox uname -r)"
    echo "MS-S0-NICS: $(/bin/busybox ls /sys/class/net 2>/dev/null | /bin/busybox tr '\n' ' ')"

    # `ms_tiny=poweroff` on the kernel command line is how the build-time
    # boot proof ends: print, then leave. Anything else stays up and waits
    # for the button, which is what a lifecycle suite needs.
    if /bin/busybox grep -q 'ms_tiny=poweroff' /proc/cmdline 2>/dev/null; then
      echo "MS-S0-DONE"
      /bin/busybox poweroff -f
      /bin/busybox sleep 30
    fi

    # Both are MODULES in the pinned nixpkgs kernel — measured:
    # CONFIG_INPUT_EVDEV=m and CONFIG_ACPI_BUTTON=m — so the power button
    # has no input node until they are loaded. evdev first, because it is
    # the handler that creates the node the button then appears as.
    for m in evdev button; do
      [ -f /lib/modules/$m.ko ] && /bin/busybox insmod /lib/modules/$m.ko
    done
    if [ -e /dev/input/event0 ]; then
      # In the FOREGROUND, as a job of init, and never as a daemon: measured,
      # a daemonized busybox acpid answers the very same button press with
      # nothing at all (the press is accepted by the hypervisor, HTTP 204,
      # and the guest stays up), while `-f` powers the guest down every
      # time. As a job its own messages also land on the console, which is
      # the only diagnostic channel a guest this small has.
      # `ms_tiny=debug` adds acpid's own event logging on top.
      dbg=""
      /bin/busybox grep -q 'ms_tiny=debug' /proc/cmdline 2>/dev/null && dbg="-d"
      /bin/busybox acpid -f $dbg -c /etc/acpi &
      echo "MS-S0-ACPI: listening on $(/bin/busybox cat /sys/class/input/event0/device/name 2>/dev/null)"
    else
      echo "MS-S0-ACPI: no input node for the power button; it will not be seen"
    fi

    echo "MS-S0-DONE"
    # PID 1 must not return: a kernel whose init exits panics, and a panic
    # after a green line would be read as the guest having crashed.
    while true; do /bin/busybox sleep 3600; done
  '';

  # busybox' acpid with `-c CONFDIR` looks for ONE path per event:
  # `<confdir>/<device>/<code>`. Measured with `ms_tiny=debug`, which is why
  # that switch exists: a press arrives as `acpid: PWRF/00000080`, and
  # anything else in the directory is never looked at. The classic
  # `event=`/`action=` rule files are the OTHER acpid's format and are
  # silently ignored here.
  powerHandler = writeText "guest-tiny-power" ''
    #!/bin/sh
    echo "MS-S0-POWEROFF"
    /bin/busybox poweroff -f
  '';

  initrd = runCommand "guest-tiny-initrd"
    {
      nativeBuildInputs = [ cpio gzip xz ];
      passthru = { inherit marker; };
    } ''
    root=$PWD/root
    mkdir -p $root/bin $root/lib/modules $root/etc/acpi/PWRF $root/proc $root/sys $root/dev $root/var/log

    cp ${busybox}/bin/busybox $root/bin/busybox
    chmod +x $root/bin/busybox
    # `sh` by name, because /init and the button handler are scripts with a
    # shebang. Everything else goes through `busybox <applet>` so that the
    # set of names here stays reviewable.
    ln -s busybox $root/bin/sh

    install -m0755 ${init} $root/init
    install -m0755 ${powerHandler} $root/etc/acpi/PWRF/00000080

    # The two modules this guest loads, out of the SAME kernel it boots — a
    # module from anywhere else would not load, and a guest that cannot hear
    # the power button says so on its console rather than hanging. They live
    # in the kernel's `modules` output, not next to the bzImage.
    for m in drivers/input/evdev drivers/acpi/button; do
      src=${modules}/lib/modules/${kernel.modDirVersion}/kernel/$m
      name=$(basename $m).ko
      if [ -f "$src.ko.xz" ]; then
        xz -dc "$src.ko.xz" > $root/lib/modules/$name
      elif [ -f "$src.ko" ]; then
        cp "$src.ko" $root/lib/modules/$name
      else
        echo "this kernel has neither $src.ko nor $src.ko.xz" >&2
        exit 1
      fi
    done

    ( cd $root && find . -print0 | cpio --null -o -H newc --quiet ) | gzip -9 > initrd.gz
    install -Dm0644 initrd.gz $out
  '';
in
stdenvNoCC.mkDerivation {
  pname = "guest-tiny";
  version = kernel.version;

  dontUnpack = true;
  dontConfigure = true;
  dontBuild = true;

  installPhase = ''
    runHook preInstall
    mkdir -p $out
    # The two files a hypervisor is handed, under fixed names: a suite that
    # has the store path has the guest, and does not have to know how a
    # kernel package is laid out.
    ln -s ${kernel}/bzImage $out/bzImage
    ln -s ${initrd} $out/initrd
    echo "${marker}" > $out/marker
    runHook postInstall
  '';

  passthru = {
    inherit kernel initrd marker;
    kernelVersion = kernel.version;
  };

  meta = {
    description = "A busybox guest that boots on a serial console, says ${marker} and honours the power button";
    license = lib.licenses.mit;
    platforms = [ "x86_64-linux" ];
  };
}
