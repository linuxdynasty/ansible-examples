users role
==========

Creates users and groups based on hashed to allow [hash merging](http://docs.ansible.com/intro_configuration.html#hash-behaviour) and data only management.

Based on [users](https://galaxy.ansible.com/list#/roles/51) by [Mark Harrison](https://github.com/mivok)

Role configuration
-----------------

* users_create_per_user_group (default: true) - when creating users, also
  create a group with the same username and make that the user's primary
  group.
* users_group (default: users) - if users_create_per_user_group is _not_ set,
  then this is the primary group for all created users.
* users_default_shell (default: /bin/bash) - the default shell if none is
  specified for the user.
* users_create_homedirs (default: true) - create home directories for new
  users. Set this to false is you manage home directories separately.


Usage
-----

Adding users:

```yaml
users:
  'Users gecos':
    username: user
    groups: [ 'admins' ]
    uid: 5001
    ssh_keys:
      - 'ssh-rsa AAAAA user@somewhere'
  'Another user':
    username: user_two
    groups: []
    uid: 5002
    ssh_keys: []
```

Deleting users:

```yaml
users_deleted:
  'user_afk':
  'user_gone':
```

Adding groups:

```yaml
groups:
  admins:
    gid: 10000
  lusers:
    gid: 10001
```

Removing groups:

```yaml
groups_deleted:
  robots:
  talkingcows:
```
