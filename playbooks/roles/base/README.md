base
--------------------------------
Installs the base packages and dependencies that is required by all of our systems.

## Role Actions.
This role has 3 different actions:

* pre_reboot
* reboot
* post_reboot

The pre_reboot action performs the following tasks:

1. cp rename_user.sh into /etc/rc.local (Moves the Ubuntu user to Ansible)
2. Add monitoring into cron.
3. Add the docker repository.
4. Install linux-image-extra-virtual and update all of the current packages.

The reboot action performs the following tasks:

1. Stop the EC2 instance.
2. Start the EC2 instance.
3. Wait for SSH to come up.
4. Try to SSH as the Ansible user.

The post_reboot action performs the following tasks:

1. Installs docker-engine and docker-py 
2. Sets the DOCKER_OPTS for AUFS.
3. Pull down Ubuntu 14.04 and anki/busybox image

## Variables this role is dependent on.
**No variables set for this role as of yet**
