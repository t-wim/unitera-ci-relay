#!/usr/bin/busybox sh
# Marketing Python-VM guest init. Trusted controller supplies /ci-config and /plan
# inside the per-job initrd overlay. No marketing source, credentials, host shares
# or network downloads are part of this image; source arrives only via the
# digest-verified ext4 workspace disk.
export PATH=/usr/bin:/usr/sbin:/bin:/sbin HOME=/ws/work
export TZ=UTC CI=true NO_COLOR=1 LANG=C.UTF-8
export TMPDIR=/ws/work/tmp PYTHONUNBUFFERED=1
/usr/bin/busybox --install -s /usr/bin
if [ "$1" != stage2 ]; then
  mkdir -p /newroot
  mount -t tmpfs -o size=768m tmpfs /newroot || /usr/bin/exit-failure
  for entry in /*; do
    [ "$entry" = /newroot ] || cp -a "$entry" /newroot/
  done
  exec switch_root /newroot /init stage2
fi
mkdir -p /proc /sys /dev /run /tmp /root /sys/fs/cgroup /ws/work/tmp /fixtures
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs tmpfs /run
mount -t tmpfs tmpfs /tmp
mount -t cgroup2 none /sys/fs/cgroup
hostname marketing-python-vm
echo 'root:x:0:0:ci:/root:/usr/bin/sh' > /etc/passwd
echo 'root:!:0:' > /etc/group
echo '127.0.0.1 localhost marketing-python-vm' > /etc/hosts
echo 'hosts: files' > /etc/nsswitch.conf
failures=0
check() {
  name="$1"; shift
  if "$@"; then echo "CHECK $name PASS"; else echo "CHECK $name FAIL"; failures=$((failures+1)); fi
}
absent() { test ! -e "$1"; }
socket_absent() { test ! -e "$1" && test ! -e "$2"; }
denied() { ! timeout 2 nc -w 1 "$1" "$2" </dev/null >/dev/null 2>&1; }
no_shares() { ! grep -E ' - (9p|virtiofs|cifs|nfs) ' /proc/self/mountinfo; }
# Only probe paths/addresses and expected counts cross this boundary; never canary contents.
. /ci-config
modprobe virtio_net 2>/dev/null || true
modprobe virtio_blk 2>/dev/null || true
modprobe virtio_pci 2>/dev/null || true
modprobe ext4 2>/dev/null || true
ip link set lo up
nic=$(ls /sys/class/net | grep -v '^lo$' | head -1)
ip link set "$nic" up
ip addr add 10.0.2.15/24 dev "$nic"
ip route add default via 10.0.2.2
check live_virtual_link ping -c 1 -W 2 10.0.2.2
check protected_host_canary absent "$HOST_CANARY_PATH"
check review_canary absent "$REVIEW_CANARY_PATH"
check status_canary absent "$STATUS_CANARY_PATH"
check credential_environment_absent sh -c 'test -z "$SYNTHETIC_REVIEW_CANARY" && test -z "$SYNTHETIC_STATUS_CANARY"'
check host_docker_socket_absent socket_absent /run/docker.sock "$SOCKET_CANARY_PATH"
check no_host_mounts no_shares
check host_service_denied denied 10.0.2.2 "$HOST_PORT"
check lan_denied denied "$LAN_PROBE" "$HOST_PORT"
check metadata_denied denied 169.254.169.254 80
check ipv6_host_denied denied fe80::2 "$HOST_PORT"
check ipv6_metadata_denied denied fd00:ec2::254 80
check no_agent_forwarding sh -c 'test -z "$SSH_AUTH_SOCK" && test ! -e /run/host-services/ssh-auth.sock'
check previous_file_absent absent /tmp/previous-job-state
check previous_process_absent sh -c '! grep -a -l "[m]arketing-previous-process" /proc/[0-9]*/cmdline 2>/dev/null'
echo synthetic > /tmp/previous-job-state
sh -c 'while :; do sleep 60; done # marketing-previous-process' &
previous_pid=$!
check synthetic_process_created kill -0 "$previous_pid"
check synthetic_file_created test -f /tmp/previous-job-state
mount -t ext4 -o rw /dev/vda /ws || { echo "CHECK c1_source_integrity FAIL"; echo SRC_MOUNT_FAILED; /usr/bin/exit-failure; }
mkdir -p /ws/work/tmp /ws/work/logs
src_count=$(find /ws/src -type f | wc -l)
echo "DIAG src_file_count $src_count expected $EXPECTED_FILE_COUNT"
c1=0
(cd /ws/src && sha256sum -c /inventory.sha256 > /ws/work/c1.log 2>&1) || c1=1
[ "$src_count" -eq "$EXPECTED_FILE_COUNT" ] || c1=1
if [ "$c1" -eq 0 ]; then echo "CHECK c1_source_integrity PASS"; else echo "CHECK c1_source_integrity FAIL"; tail -c 2048 /ws/work/c1.log | sed 's/^/DIAG c1 /'; failures=$((failures+1)); fi
c2=0
sha256sum -c /toolchain.sha256 > /ws/work/c2.log 2>&1 || c2=1
python_version=$(python3 --version 2>/dev/null)
[ "$python_version" = "Python $PYTHON_VERSION" ] || c2=1
python3 -c 'import json, email, hashlib, ssl, sqlite3, unittest, urllib.request' >> /ws/work/c2.log 2>&1 || c2=1
if [ "$c2" -eq 0 ]; then echo "CHECK c2_toolchain_validation PASS"; else echo "CHECK c2_toolchain_validation FAIL"; tail -c 2048 /ws/work/c2.log | sed 's/^/DIAG c2 /'; failures=$((failures+1)); fi
echo SRC_READY
if [ "$MODE" = hold ]; then
  while :; do sleep 5; done
fi
while IFS='|' read -r name tmo plan_cwd rest; do
  case "$name" in ''|'#'*) continue ;; esac
  cd "$plan_cwd" || { echo "EXIT $name 77"; echo "TMO $name 0"; echo "CHECK $name FAIL"; failures=$((failures+1)); continue; }
  oldifs=$IFS
  IFS=$(printf '\037')
  set -f
  # $rest carries a controller-built argv with unit-separator fields, never a shell string.
  set -- $rest
  set +f
  IFS=$oldifs
  rc=0
  timeout "$tmo" "$@" > "/ws/work/log-$name.log" 2>&1 || rc=$?
  tmo_hit=0
  [ "$rc" -eq 124 ] && tmo_hit=1
  echo "EXIT $name $rc"
  echo "TMO $name $tmo_hit"
  if [ "$rc" -eq 0 ]; then
    echo "CHECK $name PASS"
  else
    echo "CHECK $name FAIL"
    failures=$((failures+1))
  fi
  echo "LOGDIGEST $name $(sha256sum "/ws/work/log-$name.log" | cut -d' ' -f1)"
  # Marketing logs are small text transcripts; emit in full within a hard budget.
  log_bytes=$(wc -c < "/ws/work/log-$name.log")
  if [ "$log_bytes" -le 262144 ]; then
    sed "s/^/LOG $name /" "/ws/work/log-$name.log"
  else
    echo "LOGBUDGET $name $log_bytes"
    failures=$((failures+1))
  fi
done < /plan
if [ "$failures" -ne 0 ]; then
  echo GUEST_ASSERTIONS_FAILED
  /usr/bin/exit-failure
fi
echo GUEST_ALL_CHECKS_PASSED
/usr/bin/exit-success
