#!/bin/sh
set -eu

# Bootstrap an already-booted Kali/Raspberry Pi sensor over SSH.
# Usage: ./piannaple-sensor-bootstrap.sh user@host [hostname]

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "usage: $0 user@host [hostname]" >&2
    exit 2
fi

TARGET=$1
HOSTNAME=${2:-netsensor}
KEY=${PIANNAPLE_SSH_KEY:-$HOME/.ssh/piannaple-sensor_ed25519}

umask 077
if [ ! -f "$KEY" ]; then
    ssh-keygen -t ed25519 -f "$KEY" -N '' -C 'piannaple-sensor' </dev/null
fi

echo "Installing public key on $TARGET..."
ssh-copy-id -i "$KEY.pub" "$TARGET"

ssh -i "$KEY" "$TARGET" "sudo env PIANNAPLE_HOSTNAME='$HOSTNAME' bash -s" <<'REMOTE'
set -eu
hostnamectl set-hostname "$PIANNAPLE_HOSTNAME"
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    avahi-daemon openssh-server nmap arpwatch tcpdump tshark
systemctl enable --now avahi-daemon ssh
install -d -m 0755 /etc/avahi/services
cat >/etc/avahi/services/piannaple-sensor.service <<'SERVICE'
<?xml version="1.0" standalone="no"?>
<!DOCTYPE service-group SYSTEM "avahi-service.dtd">
<service-group>
  <name replace-wildcards="yes">Piannaple network sensor on %h</name>
  <service>
    <type>_ssh._tcp</type>
    <port>22</port>
  </service>
  <service>
    <type>_piannaple-sensor._tcp</type>
    <port>22</port>
  </service>
</service-group>
SERVICE
systemctl restart avahi-daemon
printf 'Piannaple sensor ready: %s.local\n' "$PIANNAPLE_HOSTNAME"
REMOTE

echo "Sensor bootstrap complete. Use: ssh -i '$KEY' $HOSTNAME.local"
