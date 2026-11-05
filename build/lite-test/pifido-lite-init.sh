#!/bin/bash
set -eu
modprobe dwc2 dr_mode=peripheral || true
modprobe libcomposite
modprobe usb_f_hid
mountpoint -q /sys/kernel/config || mount -t configfs none /sys/kernel/config
G=/sys/kernel/config/usb_gadget/pifido
mkdir -p "$G"
echo 0x1209 > "$G/idVendor"
echo 0xf1d0 > "$G/idProduct"
mkdir -p "$G/strings/0x409"
echo Tails1154 > "$G/strings/0x409/manufacturer"
echo FIDO2 > "$G/strings/0x409/product"
echo PIFIDO-LITE-TEST > "$G/strings/0x409/serialnumber"
mkdir -p "$G/functions/hid.usb0"
echo 1 > "$G/functions/hid.usb0/protocol"
echo 1 > "$G/functions/hid.usb0/subclass"
echo 64 > "$G/functions/hid.usb0/report_length"
printf '\x06\xd0\xf1\x09\x01\xa1\x01\x09\x20\x15\x00\x26\xff\x00\x75\x08\x95\x40\x81\x02\x95\x40\x91\x02\xc0' > "$G/functions/hid.usb0/report_desc"
mkdir -p "$G/configs/c.1/strings/0x409"
echo 120 > "$G/configs/c.1/MaxPower"
ln -sf "$G/functions/hid.usb0" "$G/configs/c.1/"
UDC=$(ls /sys/class/udc | head -n1)
echo "$UDC" > "$G/UDC"
exec /usr/lib/zulu/bin/java -Djava.io.tmpdir=/tmp -Dpifido.requireButton=true -jar /usr/lib/pifido/pifido.jar
