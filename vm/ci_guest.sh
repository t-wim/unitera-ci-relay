#!/usr/bin/busybox sh
# Source-CI guest init. Trusted controller supplies /ci-config and /plan inside the job initrd.
# No application code, credentials, host shares or network downloads are part of this image.
export PATH=/usr/bin:/usr/sbin:/bin:/sbin HOME=/ws/work
export NODE_OPTIONS=--max-old-space-size=2048 TZ=UTC CI=true NO_COLOR=1
export TMPDIR=/ws/work/tmp
/usr/bin/busybox --install -s /usr/bin
if [ "$1" != stage2 ]; then
  mkdir -p /newroot
  mount -t tmpfs -o size=1792m tmpfs /newroot || /usr/bin/exit-failure
  for entry in /*; do
    [ "$entry" = /newroot ] || cp -a "$entry" /newroot/
  done
  exec switch_root /newroot /init stage2
fi
mkdir -p /proc /sys /dev /run /tmp /root /sys/fs/cgroup /ws/work/tmp /pnpm /fixtures
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs tmpfs /run
mount -t tmpfs tmpfs /tmp
mount -t cgroup2 none /sys/fs/cgroup
hostname ci-executor-vm
echo 'root:x:0:0:ci:/root:/usr/bin/sh' > /etc/passwd
echo 'root:!:0:' > /etc/group
echo '127.0.0.1 localhost ci-executor-vm' > /etc/hosts
echo 'hosts: files' > /etc/nsswitch.conf
failures=0
check() {
  name="$1"; shift
  if "$@"; then echo "CHECK $name PASS"; else echo "CHECK $name FAIL"; failures=$((failures+1)); fi
}
absent() { test ! -e "$1"; }
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
check docker_canary absent "$DOCKER_CANARY_PATH"
check credential_environment_absent sh -c 'test -z "$SYNTHETIC_REVIEW_CANARY" && test -z "$SYNTHETIC_STATUS_CANARY"'
check host_docker_socket_absent absent /run/docker.sock
check no_host_mounts no_shares
check host_service_denied denied 10.0.2.2 "$HOST_PORT"
check lan_denied denied "$LAN_PROBE" "$HOST_PORT"
check metadata_denied denied 169.254.169.254 80
check ipv6_host_denied denied fe80::2 "$HOST_PORT"
check ipv6_metadata_denied denied fd00:ec2::254 80
check no_agent_forwarding sh -c 'test -z "$SSH_AUTH_SOCK" && test ! -e /run/host-services/ssh-auth.sock'
check previous_file_absent absent /tmp/previous-job-state
check previous_process_absent sh -c '! grep -a -l "[c]i-previous-process" /proc/[0-9]*/cmdline 2>/dev/null'
echo synthetic > /tmp/previous-job-state
sh -c 'while :; do sleep 60; done # ci-previous-process' &
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
node_version=$(node --version 2>/dev/null)
[ "$node_version" = "v$NODE_VERSION" ] || c2=1
if [ "$c2" -eq 0 ]; then echo "CHECK c2_toolchain_validation PASS"; else echo "CHECK c2_toolchain_validation FAIL"; failures=$((failures+1)); fi
if [ -n "$EXPECTED_TREE_SHA" ]; then
  # baum-os profile: typed tree custody. The materialized work tree (regular files,
  # exec bits, symlinks) is re-indexed with git inside this disposable guest; the
  # gitlink entries are added from controller data; git write-tree must reproduce the
  # exact commit tree SHA. Any content, mode, symlink or gitlink drift breaks the tree.
  export npm_config_store_dir=/ws/store npm_config_offline=true npm_config_frozen_lockfile=true
  export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TEMPLATE_DIR=/nonexistent
  export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0=/ws/src
  c1b=0
  sl_seen=0
  while IFS="$(printf '\t')" read -r sl_path sl_target; do
    [ -n "$sl_path" ] || continue
    sl_seen=$((sl_seen+1))
    [ "$(readlink "/ws/src/$sl_path" 2>/dev/null)" = "$sl_target" ] || c1b=1
  done < /symlinks.txt
  [ "$sl_seen" -eq "$EXPECTED_SYMLINK_COUNT" ] || c1b=1
  gl_seen=0
  while IFS="$(printf '\t')" read -r gl_sha gl_path; do
    [ -n "$gl_sha" ] || continue
    gl_seen=$((gl_seen+1))
  done < /gitlinks.txt
  [ "$gl_seen" -eq "$EXPECTED_GITLINK_COUNT" ] || c1b=1
  ( cd /ws/src && git init -q . && git add -A -f . && \
    while IFS="$(printf '\t')" read -r gl_sha gl_path; do
      [ -n "$gl_sha" ] || continue
      git update-index --add --cacheinfo 160000,"$gl_sha","$gl_path" || exit 1
    done < /gitlinks.txt && git write-tree ) > /ws/work/c1b.log 2>&1
  c1b_rc=$?
  c1b_tree=$(tail -n 1 /ws/work/c1b.log 2>/dev/null)
  { [ "$c1b_rc" -eq 0 ] && [ "$c1b_tree" = "$EXPECTED_TREE_SHA" ]; } || c1b=1
  if [ "$c1b" -eq 0 ]; then
    echo "CHECK c1b_git_tree_identity PASS"
  else
    echo "CHECK c1b_git_tree_identity FAIL"
    echo "DIAG c1b_tree $c1b_tree expected $EXPECTED_TREE_SHA"
    tail -c 2048 /ws/work/c1b.log 2>/dev/null | sed 's/^/DIAG c1b /'
    failures=$((failures+1))
  fi
fi
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
  tail -c 65536 "/ws/work/log-$name.log" | sed "s/^/LOG $name /"
done < /plan/commands
if [ "$failures" -ne 0 ]; then
  echo GUEST_ASSERTIONS_FAILED
  /usr/bin/exit-failure
fi
echo GUEST_ALL_CHECKS_PASSED
/usr/bin/exit-success
