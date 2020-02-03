#!/bin/bash

vagrant_conf="${VAGRANT_CONF:-vagrant-conf.yml}"
template=./packer/template.json

echo "Using Vagrant configuration file: ${vagrant_conf}"

# Get box name for packer to base build on
if grep "^packer_box:" ${vagrant_conf} > /dev/null 2>&1
then
  box=$(grep "^packer_box:" ${vagrant_conf} | awk '{ print $2 }' | tr -d '"')
  echo "Using box image: ${box}"
else
  box=centos/7
  echo "Using default box image: ${box}"
fi

# Generate packer input file - https://www.packer.io/docs/builders/vagrant.html
sed -e "s#_BOX_#${box}#g" ${template}.tmpl > ${template}

# Validate before building
packer validate ${template}

# Shoew components of build
packer inspect ${template}

# Actual building of box
packer build -force ${template}
