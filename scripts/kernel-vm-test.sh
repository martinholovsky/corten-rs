#!/usr/bin/env bash
# Runs corten-sandbox's broker tests on a pinned newer kernel under QEMU, so
# the Landlock rights CI's own kernel lacks (ResolveUnix, ABI v9, Linux 7.1;
# UDP, ABI v10, Linux 7.2) are exercised, not only their below-ABI branches.
#
# Usage: scripts/kernel-vm-test.sh KERNEL_DEB ROOTFS_TAR TEST_BIN SANDBOX_BIN EXPECT_KERNEL
#   KERNEL_DEB     an Ubuntu mainline linux-image .deb (its SHA-256 checked by the caller)
#   ROOTFS_TAR     a filesystem export with the same glibc as the test build, plus iproute2
#   TEST_BIN       the compiled broker test binary (tests/broker.rs), absolute path
#   SANDBOX_BIN    the corten-sandbox binary the tests name, absolute path
#   EXPECT_KERNEL  the release prefix the VM must report, e.g. 7.3.5
# Exits with the tests' status; 1 when the VM booted another kernel or never
# reported a status (a crash or a timeout is a failure, never a pass).
# Uses KVM when /dev/kvm is usable, else software emulation (slower).
set -euo pipefail
[ "$#" -eq 5 ] || { sed -n '4,12p' "$0" >&2; exit 2; }
kernel_deb=$1 rootfs_tar=$2 test_bin=$3 sandbox_bin=$4 expect=$5
for f in "$kernel_deb" "$rootfs_tar" "$test_bin" "$sandbox_bin"; do
    [ -f "$f" ] || { echo "kernel-vm-test: not a file: $f" >&2; exit 2; }
done
for b in "$test_bin" "$sandbox_bin"; do
    case "$b" in /*) ;; *) echo "kernel-vm-test: not an absolute path: $b" >&2; exit 2 ;; esac
done
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/root" "$work/kernel"
# Device nodes are not needed (the VM mounts devtmpfs) and cannot be created
# without privilege.
tar -xf "$rootfs_tar" -C "$work/root" --exclude='dev/*'
for b in "$test_bin" "$sandbox_bin"; do
    mkdir -p "$work/root$(dirname "$b")"
    cp "$b" "$work/root$b"
done
install -m 0755 "$here/kernel-vm-init" "$work/root/init"
(cd "$work/root" && find . | cpio -o -H newc --quiet | gzip -1) > "$work/initrd.gz"
dpkg-deb -x "$kernel_deb" "$work/kernel"
vmlinuz=$(find "$work/kernel/boot" -name 'vmlinuz-*' -type f | head -1)
[ -n "$vmlinuz" ] || { echo "kernel-vm-test: no vmlinuz in $kernel_deb" >&2; exit 2; }
accel=(-accel tcg)
if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    accel=(-accel kvm -cpu host)
fi
echo "kernel-vm-test: booting $(basename "$vmlinuz") with ${accel[1]}, initrd $(wc -c < "$work/initrd.gz") bytes"
log="$work/console.log"
timeout 2400 qemu-system-x86_64 "${accel[@]}" -m 3072 -smp 2 -nographic -no-reboot \
    -kernel "$vmlinuz" -initrd "$work/initrd.gz" \
    -append "console=ttyS0 rdinit=/init panic=-1 lsm=landlock,lockdown,yama,integrity,apparmor VM_TEST_BIN=$test_bin" \
    > "$log" 2>&1 || echo "kernel-vm-test: qemu exited with $?"
# The tests' own output, for the job log.
grep -aE '^(VM_|test |test result|failures:|---- )' "$log" | sed 's/\x1b\[[0-9;]*m//g' || true
booted=$(sed -n 's/^VM_KERNEL=//p' "$log" | tr -d '\r' | head -1)
case "$booted" in
    "$expect"*) ;;
    *) echo "kernel-vm-test: expected kernel $expect, VM reported '${booted}'" >&2; tail -40 "$log" >&2; exit 1 ;;
esac
rc=$(sed -n 's/^VM_TEST_RC=//p' "$log" | tr -d '\r' | head -1)
if [ -z "$rc" ]; then
    echo "kernel-vm-test: the VM never reported a test status" >&2
    tail -40 "$log" >&2
    exit 1
fi
exit "$rc"
