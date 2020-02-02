#!/bin/bash

# Remove second interface (currently the VirtualBox Host Only Adapter)
if [ -f /etc/sysconfig/network-scripts/ifcfg-eth1 ]
then
  echo "Removing second interface (VirtualBox Host Only Adapter)..."
  rm /etc/sysconfig/network-scripts/ifcfg-eth1
fi

# TODO: get the network adapter name from OS
device=eth0
# Get the first entry
ipaddr=$(hostname -i | cut -d' ' -f1)
# In a VirtualBox NAT service network the gateway has always 1 in the last octet
gateway=$(echo ${ipaddr} | cut -d'.' -f-3).1
dns1=${gateway}
# Configure first interface (currently the VirtualBox NAT Adapter)
# as the original second one (after reboot this will be the VirtualBox NAT service adapter)
cat > /etc/sysconfig/network-scripts/ifcfg-${device} <<-_EOF
NM_CONTROLLED=yes
BOOTPROTO=none
ONBOOT=yes
IPADDR=${ipaddr}
NETMASK=255.255.255.0
DEVICE=${device}
PEERDNS=no
GATEWAY=${gateway}
DNS1=${dns1}
_EOF
