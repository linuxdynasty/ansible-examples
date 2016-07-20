#!/bin/bash

user=ansible

if ! id -u $user 2>&1 > /dev/null; then
  usermod  -l $user ubuntu
  groupmod -n $user ubuntu
  usermod  -d /home/$user -m $user
  usermod -a -G docker $user
  if [ -f /etc/sudoers.d/90-cloudimg-ubuntu ]; then
    mv /etc/sudoers.d/90-cloudimg-ubuntu /etc/sudoers.d/90-cloud-init-users
  fi
  sed -i "s/ubuntu/${user}/g" /etc/sudoers.d/90-cloud-init-users
  echo "ansible user created."
else
  usermod -a -G docker $user
  echo "ansible user already exist."
fi

if ! id -u ubuntu 2>&1 > /dev/null; then
  userdel -f ubuntu
exit 0
