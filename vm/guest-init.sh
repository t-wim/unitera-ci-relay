#!/usr/bin/busybox sh
# Synthetic guest init. No application code, credentials or network downloads.
export PATH=/usr/bin:/usr/sbin:/bin:/sbin HOME=/root
export DOCKER_HOST=unix:///run/docker.sock
/usr/bin/busybox --install -s /usr/bin
if [ "$1" != stage2 ]; then
  mkdir -p /newroot
  mount -t tmpfs -o size=512m tmpfs /newroot || /usr/bin/exit-failure
  for entry in /*; do
    [ "$entry" = /newroot ] || cp -a "$entry" /newroot/
  done
  exec switch_root /newroot /init stage2
fi
mkdir -p /proc /sys /dev /run /tmp /root /sys/fs/cgroup /var/lib/docker /etc
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs tmpfs /run
mount -t tmpfs tmpfs /tmp
mount -t cgroup2 none /sys/fs/cgroup
hostname synthetic-vm
echo 'root:x:0:0:synthetic:/root:/usr/bin/sh' > /etc/passwd
echo 'root:!:0:' > /etc/group
echo '127.0.0.1 localhost synthetic-vm' > /etc/hosts
echo 'hosts: files' > /etc/nsswitch.conf
failures=0
check() {
  name="$1"; shift
  if "$@"; then echo "CHECK $name PASS"; else echo "CHECK $name FAIL"; failures=$((failures+1)); fi
}
absent() { test ! -e "$1"; }
denied() { ! timeout 2 nc -w 1 "$1" "$2" </dev/null >/dev/null 2>&1; }
no_shares() { ! grep -E ' - (9p|virtiofs|cifs|nfs) ' /proc/self/mountinfo; }
# Only paths/addresses of synthetic probes are supplied; never canary contents.
. /probe-config
modprobe virtio_net
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
check previous_file_absent absent /tmp/previous-job-state
check previous_process_absent sh -c '! grep -a -l "[s]ynthetic-previous-process" /proc/[0-9]*/cmdline 2>/dev/null'
check no_agent_forwarding sh -c 'test -z "$SSH_AUTH_SOCK" && test ! -e /run/host-services/ssh-auth.sock'
echo synthetic > /tmp/previous-job-state
sh -c 'while :; do sleep 60; done # synthetic-previous-process' &
previous_pid=$!
check synthetic_process_created kill -0 "$previous_pid"
check synthetic_file_created test -f /tmp/previous-job-state
# Only this guest owns this Docker socket. No host Docker API is called.
dockerd --host=unix:///run/docker.sock --data-root=/var/lib/docker --storage-driver=vfs \
  --iptables=false --ip6tables=false --bridge=none --ip-forward=false --ip-masq=false \
  --userland-proxy=false --exec-opt native.cgroupdriver=cgroupfs > /tmp/docker.log 2>&1 &
for i in $(seq 1 50); do docker info >/dev/null 2>&1 && break; sleep 0.2; done
check guest_docker_ready docker info
mkdir -p /tmp/synthetic-root/bin
cp /usr/bin/busybox /tmp/synthetic-root/bin/busybox
tar -C /tmp/synthetic-root -cf /tmp/synthetic-root.tar .
docker import /tmp/synthetic-root.tar synthetic-local >/tmp/import.log 2>&1
check guest_container docker run --rm --network=none synthetic-local /bin/busybox sh -c \
  'test ! -e /run/docker.sock && test ! -e /tmp/previous-job-state && echo synthetic-container-ok'
if [ "$failures" -ne 0 ]; then tail -30 /tmp/docker.log; echo GUEST_ASSERTIONS_FAILED; /usr/bin/exit-failure; fi
echo SYNTHETIC_READY
case "$MODE" in
  success) echo OUTCOME_SUCCESS; /usr/bin/exit-success ;;
  failure) false; echo OUTCOME_FAILURE; /usr/bin/exit-failure ;;
  hold) while :; do sleep 1; done ;;
  *) /usr/bin/exit-failure ;;
esac
