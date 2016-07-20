#!/usr/bin/python
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
DOCUMENTATION = '''
---
module: iam_policy
short_description: Manage IAM policies for users, groups, and roles
description:
     - Allows uploading or removing IAM policies for IAM users, groups or roles.
version_added: "2.0"
options:
  iam_type:
    description:
      - Type of IAM resource
    required: true
    default: null
    choices: [ "user", "group", "role"]
  iam_name:
    description:
      - Name of IAM resource you wish to target for policy actions. In other words, the user name, group name or role name.
    required: true
  policy_name:
    description:
      - The name label for the policy to create or remove.
    required: true
  policy_document:
    description:
      - The path to the properly json formatted policy file (mutually exclusive with C(policy_json))
    required: false
  policy_json:
    description:
      - A properly json formatted policy as string (mutually exclusive with C(policy_document), see https://github.com/ansible/ansible/issues/7005#issuecomment-42894813 on how to use it properly)
    required: false
  state:
    description:
      - Whether to create or delete the IAM policy.
    required: true
    default: null
    choices: [ "present", "absent"]
  skip_duplicates:
    description:
      - By default the module looks for any policies that match the document you pass in, if there is a match it will not make a new policy object with the same rules. You can override this by specifying false which would allow for two policy objects with different names but same rules.
    required: false
    default: "/"

notes:
  - 'Currently boto does not support the removal of Managed Policies, the module will not work removing/adding managed policies.'
author: "Jonathan I. Davila (@defionscode)"
extends_documentation_fragment:
    - aws
    - ec2
'''

EXAMPLES = '''
# Create a policy with the name of 'Admin' to the group 'administrators'
tasks:
- name: Assign a policy called Admin to the administrators group
  iam_policy:
    iam_type: group
    iam_name: administrators
    policy_name: Admin
    state: present
    policy_document: admin_policy.json

# Advanced example, create two new groups and add a READ-ONLY policy to both
# groups.
task:
- name: Create Two Groups, Mario and Luigi
  iam:
    iam_type: group
    name: "{{ item }}"
    state: present
  with_items:
     - Mario
     - Luigi
  register: new_groups

- name: Apply READ-ONLY policy to new groups that have been recently created
  iam_policy:
    iam_type: group
    iam_name: "{{ item.created_group.group_name }}"
    policy_name: "READ-ONLY"
    policy_document: readonlypolicy.json
    state: present
  with_items: new_groups.results

# Create a new S3 policy with prefix per user
tasks:
- name: Create S3 policy from template
  iam_policy:
    iam_type: user
    iam_name: "{{ item.user }}"
    policy_name: "s3_limited_access_{{ item.prefix }}"
    state: present
    policy_json: " {{ lookup( 'template', 's3_policy.json.j2') }} "
    with_items:
      - user: s3_user
        prefix: s3_user_prefix

'''

try:
    import botocore
    import boto3
    import boto
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False

from json import dumps, loads
import re
import datetime
from random import randint
from time import sleep

EXAMPLE_POLICY_DICT = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "*",
            "Resource": "*",
            "Effect": "Allow",
            "Sid": "Stmt1417926406000"
        }
    ]
}

EXAMPLE_POLICY_LIST = [
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": "*",
                "Resource": "*",
                "Effect": "Allow",
                "Sid": "Stmt1417926406000"
            }
        ]
    }
]

EXAMPLE_POLICY_STR = '{"Version": "2012-10-17", "Statement": [{"Action": "*", "Resource": "*", "Effect": "Allow", "Sid": "Stmt1417926406000"}]}'

EXAMPLE_POLICY_CREATE_RESULT_LOWER_CASE = {
    "policy": {
        "update_date": "2016-04-02T09:00:22.911962",
        "create_date": "2016-04-02T09:00:22.911953",
        "description": "string",
        "is_attachable": True,
        "policy_name": "test",
        "default_version_id": "v1",
        "attachment_count": 0,
        "path": "/",
        "arn": "arn:aws:iam::123456789:policy/test",
        "policy_id": "ANPAJDTHNXIKWXFW6P5EE"
    }
}

EXAMPLE_POLICY_CREATE_RESULT = {
    'Policy': {
        'PolicyName': 'test',
        'PolicyId': 'ANPAJDTHNXIKWXFW6P5EE',
        'Arn': 'arn:aws:iam::123456789:policy/test',
        'Path': '/',
        'DefaultVersionId': 'v1',
        'AttachmentCount': 0,
        'IsAttachable': True,
        'Description': 'string',
        'CreateDate': datetime.datetime.now(),
        'UpdateDate': datetime.datetime.now()
    }
}

EXAMPLE_POLICY_RESULTS_1 = {
    'Marker': 'ACUflMymIal39z7PCsx4pW3iKOWeUPqcDzRzFOnS/W26w3iNdSlU7TmWtMUG1XE9WCjeL1cSrTJ+gSLelldJp/WdoA5d6tpYVybCJQkEDTvW1A==',
    'AttachedPolicies': [
        {
            'PolicyName': 'test1',
            'PolicyArn': 'arn:aws:iam::123456789:policy/test1'
        }
    ],
    'IsTruncated': True,
    'ResponseMetadata': {
        'HTTPStatusCode': 200,
        'RequestId': '1275fbf3-f8fb-11e5-8825-61c7f7fe1359'
    }
}

EXAMPLE_POLICY_VERSION = {
    'PolicyVersion': {
        'Document': EXAMPLE_POLICY_STR,
        'VersionId': '2012-10-17',
        'IsDefaultVersion': True,
        'CreateDate': datetime.datetime.now(),
    },
    'ResponseMetadata': {
        'HTTPStatusCode': 200,
        'RequestId': '1275fbf3-f8fb-11e5-8825-61c7f7fe1359'
    }
}

EXAMPLE_POLICY_RESULTS_2 = {
    'AttachedPolicies': [
        {
            'PolicyName': 'test2',
            'PolicyArn': 'arn:aws:iam::123456789:policy/test2'
        }
    ],
    'IsTruncated': False,
    'ResponseMetadata': {
        'HTTPStatusCode': 200,
        'RequestId': '1275fbf3-f8fb-11e5-8825-61c7f7fe1359'
    }
}

EXAMPLE_LIST_ENTITIES_FOR_POLICY_1 = {
    'PolicyGroups': [
        {
            'GroupName': 'test1',
            'GroupId': 'arn:aws:iam::123456789:group/test1'
        },
    ],
    'PolicyUsers': [
        {
            'UserName': 'test1',
            'UserId': 'arn:aws:iam::123456789:user/test1'
        },
    ],
    'PolicyRoles': [
        {
            'RoleName': 'test1',
            'RoleId': 'arn:aws:iam::123456789:role/test1'
        },
    ],
    'IsTruncated': True,
    'Marker': 'ACUflMymIal39z7PCsx4pW3iKOWeUPqcDzRzFOnS/W26w3iNdSlU7TmWtMUG1XE9WCjeL1cSrTJ+gSLelldJp/WdoA5d6tpYVybCJQkEDTvW1A==',
}

EXAMPLE_LIST_ENTITIES_FOR_POLICY_2 = {
    'PolicyGroups': [
        {
            'GroupName': 'test2',
            'GroupId': 'arn:aws:iam::123456789:group/test2'
        },
    ],
    'PolicyUsers': [
        {
            'UserName': 'test2',
            'UserId': 'arn:aws:iam::123456789:user/test2'
        },
    ],
    'PolicyRoles': [
        {
            'RoleName': 'test2',
            'RoleId': 'arn:aws:iam::123456789:role/test2'
        },
    ],
    'IsTruncated': False,
}

EXAMPLE_LIST_POLICIES = {
    'Policies': [
        {
            'PolicyName': 'test',
            'PolicyId': 'ANPAJDTHNXIKWXFW6P5EE',
            'Arn': 'arn:aws:iam::123456789:policy/test',
            'Path': '/',
            'DefaultVersionId': 'v1',
            'AttachmentCount': 0,
            'IsAttachable': True,
            'Description': 'string',
            'CreateDate': datetime.datetime.now(),
            'UpdateDate': datetime.datetime.now()
        }
    ],
    'IsTruncated': False,
}

EXAMPLE_LIST_POLICY_VERSIONS = {
    'Versions': [
        {
            'Document': 'string',
            'VersionId': 'v1',
            'IsDefaultVersion': False,
            'CreateDate': datetime.datetime.now()
        },
    ],
    'IsTruncated': False
}


def convert_to_lower(data):
    """Convert all uppercase keys in dict with lowercase_
    Args:
        data (dict): Dictionary with keys that have upper cases in them
            Example.. FooBar == foo_bar
            if a val is of type datetime.datetime, it will be converted to
            the ISO 8601

    Basic Usage:
        >>> test = {'FooBar': []}
        >>> test = convert_to_lower(test)
        {
            'foo_bar': []
        }

    Returns:
        Dictionary
    """
    results = dict()
    if isinstance(data, dict):
        for key, val in data.items():
            key = re.sub(r'(([A-Z]{1,3}){1})', r'_\1', key).lower()
            if key[0] == '_':
                key = key[1:]
            if isinstance(val, datetime.datetime):
                results[key] = val.isoformat()
            elif isinstance(val, dict):
                results[key] = convert_to_lower(val)
            elif isinstance(val, list):
                converted = list()
                for item in val:
                    converted.append(convert_to_lower(item))
                results[key] = converted
            else:
                results[key] = val
    return results

def validate_json(policy_json, is_file=False):
    """Validate and convert to json if needed.

    Args:
        policy_json (str|dict): String representing the file path to the json
            document or a string representing the json or a dict to be converted
            into json.

    Kwargs:
        is_file (bool): If this is set to true, this function will try to
            open policy_json and validate or convert to json.

    Basic Usage:
        >>> policy_json = '{"Version": "2012-10-17", "Statement": [{"Action": "*", "Resource": "*", "Effect": "Allow", "Sid": "Stmt1417926406000"}]}'
        >>> policy, err_msg = validate_json(policy_json)
    """
    err_msg = ''
    policy = None

    if is_file:
        try:
            policy = dumps(loads(open(policy_json, 'r').read()))
        except Exception as e:
            err_msg = (
                'Failed to convert the policy into valid JSON: {0}'
                .format(str(e))
            )
    else:
        if isinstance(policy_json, dict):
            try:
                policy = dumps(policy_json)
            except Exception as e:
                err_msg = (
                    'Failed to convert the policy into valid JSON: {0}'
                    .format(str(e))
                )
        elif isinstance(policy_json, basestring):
            try:
                policy = dumps(loads(policy_json))
            except Exception as e:
                err_msg = (
                    'Failed to convert the policy into valid JSON: {0}'
                    .format(str(e))
                )
        else:
            err_msg = (
                'Policy is not a valid dict or string: {0}'
                .format(type(policy_json))
            )
    return policy, err_msg

def get_policy(client, policy_arn, check_mode=False):
    """Retrieve an IAM Managed Policy.

    Args:
        client (botocore.client.EC2): Boto3 client.
        policy_arn (str): The Amazon resource identifier.

    Kwargs:
        check_mode (bool): This will pass DryRun as one of the parameters to the aws api.
            default=False

    Basic Usage:
        >>> client = boto3.client('iam')
        >>> policy_arn = 'arn:aws:iam::123456789:policy/test'
        >>> get_policy(client, policy_arn)

    Returns:
        Tuple (bool, str, dict)
    """
    success = False
    err_msg = ''
    params = {
        'PolicyArn': policy_arn,
    }
    policy = dict()
    try:
        if not check_mode:
            policy = client.get_policy(**params)['Policy']
            success = True
        else:
            if policy_arn == 'arn:aws:iam::123456789:policy/test':
                policy = EXAMPLE_POLICY_CREATE_RESULT
                success = True
            else:
                success = False
                err_msg = (
                    'An error occurred (NoSuchEntity) when calling the ListPolicies operation: {0} does not exist.'
                    .format(policy_name)
                )
                return success, err_msg, policy

    except botocore.exceptions.ClientError, e:
        err_msg = str(e)

    return success, err_msg, policy

def get_policy_version(client, policy_arn, version_id, check_mode=False):
    """Retrieve an IAM Managed Policy.

    Args:
        client (botocore.client.EC2): Boto3 client.
        policy_arn (str): The Amazon resource identifier.
        version_id (str): The version of the policy.

    Kwargs:
        check_mode (bool): This will pass DryRun as one of the parameters to the aws api.
            default=False

    Basic Usage:
        >>> client = boto3.client('iam')
        >>> policy_arn = 'arn:aws:iam::123456789:policy/test'
        >>> version_id = 'v1'
        >>> get_policy_version(client, policy_arn, version_id)

    Returns:
        Tuple (bool, str, dict)
    """
    success = False
    err_msg = ''
    params = {
        'PolicyArn': policy_arn,
        'VersionId': version_id
    }
    policy = dict()
    try:
        if not check_mode:
            policy = client.get_policy_version(**params)['PolicyVersion']
            success = True
        else:
            if policy_arn == 'arn:aws:iam::123456789:policy/test':
                policy = EXAMPLE_POLICY_CREATE_RESULT
                success = True
            else:
                success = False
                err_msg = (
                    'An error occurred (NoSuchEntity) when calling the ListPolicies operation: {0} does not exist.'
                    .format(policy_name)
                )
                return success, err_msg, policy


    except botocore.exceptions.ClientError, e:
        err_msg = str(e)

    return success, err_msg, policy

def find_policy(client, policy_name, check_mode=False):
    """Retrieve an IAM Managed Policy.

    Args:
        client (botocore.client.EC2): Boto3 client.
        policy_name (str): Name of the managed policy you are retrieving.

    Kwargs:
        check_mode (bool): This will pass DryRun as one of the parameters to the aws api.
            default=False

    Basic Usage:
        >>> client = boto3.client('iam')
        >>> policy_name = 'test'
        >>> find_policy(client, policy_name)

    Returns:
        Tuple (bool, str, dict)
    """
    success = False
    err_msg = ''
    params = {
        'Scope': 'Local'
    }
    result = dict()
    try:
        is_truncated = True
        i = 0
        marker = None
        policies = dict()
        while is_truncated:
            if i > 0:
                params['Marker'] = marker
            if not check_mode:
                policies = client.list_policies(**params)
                for policy in policies['Policies']:
                    if policy['PolicyName'] == policy_name:
                        result = policy
                        success = True
                        err_msg = '{0} policy found.'.format(policy_name)
                        return success, err_msg, result

            else:
                if policy_name == 'test':
                    policies = EXAMPLE_LIST_POLICIES
                    success = True
                else:
                    success = False
                    err_msg = (
                        'An error occurred (NoSuchEntity) when calling the ListPolicies operation: {0} does not exist.'
                        .format(policy_name)
                    )
                    return success, err_msg, result

            is_truncated = policies['IsTruncated']
            if is_truncated:
                i += 1
                marker = policies.get('Marker', None)
                sleep(randint(1,2))

        success = True
    except botocore.exceptions.ClientError, e:
        err_msg = str(e)

    return success, err_msg, result

def list_attached_policies(client, resource_name, resource_type,
						   check_mode=False):
    """List all attached policies to a resource (group, user, role).

    Args:
        client (botocore.client.EC2): Boto3 client.
        resource_name (str): Name of the resource you are listing policies for.
        resource_type (str): group, user, or role.

    Kwargs:
        check_mode (bool): This will pass DryRun as one of the parameters to the aws api.
            default=False

    Basic Usage:
        >>> client = boto3.client('iam')
        >>> resource_name = 'admin'
        >>> resource_type = 'role'
        >>> list_attached_policies(client, resource_name, resource_type)

    Returns:
        Tuple (bool, str, dict)
    """
    err_msg = ''
    success = False
    results = list()

    actions = {
        'user': client.list_attached_user_policies,
        'group': client.list_attached_group_policies,
        'role': client.list_attached_role_policies,
    }
    params = {
        '{0}Name'.format(resource_type.capitalize()): resource_name
    }
    if resource_type != 'user' and resource_type != 'group' and resource_type != 'role':
        err_msg = 'Invalid resource type {0}'.format(resource_type)
        return success, err_msg, results
    try:
        is_truncated = True
        i = 0
        marker = None
        policies = dict()
        while is_truncated:
            if i > 0:
                params['Marker'] = marker
            if not check_mode:
                policies = actions[resource_type](**params)
            else:
                if resource_name == 'test':
                    if i == 0:
                        policies = EXAMPLE_POLICY_RESULTS_1
                    else:
                        policies = EXAMPLE_POLICY_RESULTS_2
                    success = True
                else:
                    success = False
                    err_msg = (
                        'An error occurred (NoSuchEntity) when calling the ListAttachedRolePolicies operation: {0} {1} does not exist.'
                        .format(resource_type.capitalize(), resource_name)
                    )
                    return success, err_msg, results

            is_truncated = policies['IsTruncated']
            results.extend(policies['AttachedPolicies'])
            if is_truncated:
                i += 1
                marker = policies.get('Marker', None)
                sleep(randint(1,2))

        success = True
    except botocore.exceptions.ClientError, e:
        err_msg = str(e)

    return success, err_msg, results

def list_policy_versions(client, policy_arn, check_mode=False):
    """List all versions for an IAM Policy.

    Args:
        client (botocore.client.EC2): Boto3 client.
        policy_arn (str): The Amazon resource identifier.

    Kwargs:
        check_mode (bool): This will pass DryRun as one of the parameters to the aws api.
            default=False

    Basic Usage:
        >>> client = boto3.client('iam')
        >>> policy_arn = 'arn:aws:iam::123456789:policy/test'
        >>> list_policy_versions(client, policy_arn)

    Returns:
        Tuple (bool, str, dict)
    """
    err_msg = ''
    success = False
    params = {
        'PolicyArn': policy_arn,
    }
    policy_versions = list()
    try:
        is_truncated = True
        i = 0
        marker = None
        versions = dict()
        while is_truncated:
            if i > 0:
                params['Marker'] = marker
            if not check_mode:
                versions = client.list_policy_versions(**params)
            else:
                if policy_arn[-4:] == 'test':
                    versions = EXAMPLE_LIST_POLICY_VERSIONS
                    success = True
                else:
                    success = False
                    err_msg = (
                        'An error occurred (NoSuchEntity) when calling the ListPolicyVersions operation: ARN {0} is not valid.'
                        .format(policy_arn)
                    )
                    return success, err_msg, policy_versions

            is_truncated = versions['IsTruncated']
            policy_versions.extend(versions['Versions'])
            if is_truncated:
                i += 1
                marker = versions.get('Marker', None)
                sleep(randint(1,2))

        success = True
    except botocore.exceptions.ClientError, e:
        err_msg = str(e)

    return success, err_msg, policy_versions

def list_entities_for_policy(client, policy_arn, check_mode=False):
    """List all entities for an IAM Policy. This will list every role, user,
        and group that has this policy attached.

    Args:
        client (botocore.client.EC2): Boto3 client.
        policy_arn (str): The Amazon resource identifier.

    Kwargs:
        check_mode (bool): This will pass DryRun as one of the parameters to the aws api.
            default=False

    Basic Usage:
        >>> client = boto3.client('iam')
        >>> policy_arn = 'arn:aws:iam::123456789:policy/test'
        >>> list_entities_for_policy(client, policy_arn)

    Returns:
        Tuple (bool, str, dict)
    """
    err_msg = ''
    success = False
    groups = list()
    users = list()
    roles = list()
    params = {
        'PolicyArn': policy_arn,
    }
    try:
        is_truncated = True
        i = 0
        marker = None
        entities = dict()
        while is_truncated:
            if i > 0:
                params['Marker'] = marker
            if not check_mode:
                entities = client.list_entities_for_policy(**params)
            else:
                if policy_arn[-4:] == 'test':
                    if i == 0:
                        entities = EXAMPLE_LIST_ENTITIES_FOR_POLICY_1
                    else:
                        entities = EXAMPLE_LIST_ENTITIES_FOR_POLICY_2
                    success = True
                else:
                    success = False
                    err_msg = (
                        'An error occurred (NoSuchEntity) when calling the ListEntitiesForPolicy operation: ARN {0} is not valid.'
                        .format(policy_arn)
                    )
                    return success, err_msg, users, groups, roles

            is_truncated = entities['IsTruncated']
            groups.extend(entities['PolicyGroups'])
            users.extend(entities['PolicyUsers'])
            roles.extend(entities['PolicyRoles'])
            if is_truncated:
                i += 1
                marker = entities.get('Marker', None)
                sleep(randint(1,2))

        success = True
    except botocore.exceptions.ClientError, e:
        err_msg = str(e)

    return success, err_msg, users, groups, roles

def policy_action(client, policy_name=None, policy_arn=None, policy_json=None,
                  policy_path='/', description='', version=None,
                  action='create', check_mode=False):
    """Create or Delete an IAM Managed Policy
    Args:
        client (botocore.client.EC2): Boto3 client.

    Kwargs:
        policy_name (str): The name of the IAM Managed POlicy.
        policy_arn (str): The Amazon resource identifier. This is needed when
            you are going to delete a policy.
        policy_json (str): A valid json string that contains the IAM policy.
        description (str): Description of this policy
        version (str): The version of the policy.
        action (str): The action to perform.
            valid actions == create and delete and create_version and delete_version
            default=create
        check_mode (bool): This will pass DryRun as one of the parameters to the aws api.
            default=False

    Basic Usage:
        >>> client = boto3.client('iam')
        >>> policy_name = 'test'
        >>> policy_json = '{"Version": "2012-10-17", "Statement": [{"Action": "*", "Resource": "*", "Effect": "Allow", "Sid": "Stmt1417926406000"}]}'
        >>> description = 'Test Policy'
        >>> policy_action(client, policy_name=policy_name, policy_json=policy_json,description=description, action='create')

    Returns:
        List (bool, str)
    """
    success = False
    err_msg = ''
    actions = {
        'create': {
            'params': {
                'PolicyName': policy_name,
                'Path': policy_path,
                'PolicyDocument': policy_json,
                'Description': description
            },
            'run': client.create_policy
        },
        'create_version': {
            'params': {
                'PolicyArn': policy_arn,
                'PolicyDocument': policy_json,
                'SetAsDefault': True
            },
            'run': client.create_policy_version
        },
        'delete': {
            'params': {
                'PolicyArn': policy_arn,
            },
            'run': client.delete_policy
        },
        'delete_version': {
            'params': {
                'PolicyArn': policy_arn,
                'VersionId': version
            },
            'run': client.delete_policy_version
        },
    }
    if action == 'create':
        if not policy_name or not policy_json:
            err_msg = 'Missing parameters for action create: policy_name and policy_json must be set'
            return success, err_msg
    elif action == 'create_version':
        if not policy_arn or not policy_json:
            err_msg = 'Missing parameters for action create_version: policy_arn and policy_json must be set'
            return success, err_msg
    elif action == 'delete':
        if not policy_arn:
            err_msg = 'Missing parameters for action delete: policy_arn must be set'
            return success, err_msg
    elif action == 'delete_version':
        if not policy_arn or not version:
            err_msg = 'Missing parameters for action delete: policy_arn and version must be set'
            return success, err_msg

    else:
        err_msg = 'Invalid action {0}'.format(action)
        return success, err_msg, dict()

    try:
        if not check_mode:
            actions[action]['run'](**actions[action]['params'])
            success = True
        else:
            success = True
        err_msg = '{0} succeded'.format('action')

    except botocore.exceptions.ClientError, e:
        err_msg = str(e)

    return success, err_msg

def resource_action(client, resource_name, resource_type, policy_arn,
                  action='attach', check_mode=False):
    """Create or Delete an IAM Managed Policy

    Args:
        client (botocore.client.EC2): Boto3 client.
        resource_name (str): The name of the resource that is being attached to the policy.
        resource_type (str): group, user, or role.
        policy_arn (str): The Amazon resource identifier. This is needed when
            you are going to delete a policy.

    Kwargs:
        action (str): The action to perform.
            valid actions == attach and detach
            default=attach
        check_mode (bool): This will pass DryRun as one of the parameters to the aws api.
            default=False

    Basic Usage:
        >>> client = boto3.client('iam')
        >>> resource_name = 'admin'
        >>> resource_type = 'role'
        >>> policy_arn = 'arn:aws:iam::123456789:policy/test'
        >>> resource_action(client, resource_name, resource_type, policy_arn)

    Returns:
        List (bool, str)
    """
    success = False
    err_msg = ''
    resources = {
        'user': {
            'attach': client.attach_user_policy,
            'detach': client.detach_user_policy,
        },
        'group': {
            'attach': client.attach_group_policy,
            'detach': client.detach_group_policy,
        },
        'role': {
            'attach': client.attach_role_policy,
            'detach': client.detach_role_policy,
        }
    }
    params = {
        'PolicyArn': policy_arn,
        '{0}Name'.format(resource_type.capitalize()): resource_name
    }
    if action != 'attach' and action != 'detach':
        err_msg = 'Invalid action {0}'.format(action)
        return success, err_msg

    if resource_type != 'user' and resource_type != 'group' and resource_type != 'role':
        err_msg = 'Invalid resource type {0}'.format(resource_type)
        return success, err_msg

    try:
        if not check_mode:
            resources[resource_type][action](**params)
            success = True
        else:
            success = True

    except botocore.exceptions.ClientError, e:
        err_msg = str(e)

    return success, err_msg

def attach(client, policy_arn, resource_name, resource_type, check_mode=False):
    """Attach an IAM Managed Policy to an IAM Resource (Role, User, Group).

    Args:
        client (botocore.client.EC2): Boto3 client.
        policy_arn (str): The Amazon resource identifier.
        resource_name (str): The name of the resource that is being attached to the policy.
        resource_type (str): group, user, or role.

    Kwargs:
        check_mode (bool): This will pass DryRun as one of the parameters to the aws api.
            default=False

    Basic Usage:
        >>> client = boto3.client('iam')
        >>> policy_arn = 'arn:aws:iam::123456789:policy/test'
        >>> resource_name = 'admin'
        >>> resource_type = 'role'
        >>> attach(client, resource_name, resource_type)

    Returns:
        List (bool, bool, str)
    """

    success = False
    changed = False
    err_msg = ''
    success, err_msg, policies = (
        list_attached_policies(
            client, resource_name, resource_type, check_mode=check_mode
        )
    )
    if success:
        policy_exist_in_resource = False
        if len(policies) > 0:
            for policy in policies:
                if policy['PolicyArn'] == policy_arn:
                    policy_exist_in_resource = True
                    success = True
                    break
        if not policy_exist_in_resource:
            success, err_msg = (
                resource_action(
                    client, resource_name, resource_type, policy_arn,
                    action='attach', check_mode=check_mode
                )
            )
            if success:
                changed = True

    return success, changed, err_msg

def delete_policy_versions(client, policy_arn, except_version=None,
                           check_mode=False):
    """Delete all versions of a policy, except the default one.

    Args:
        client (botocore.client.EC2): Boto3 client.
        policy_arn (str): The Amazon resource identifier.

    Kwargs:
        except_version (str): Version you want to keep.
        check_mode (bool): This will pass DryRun as one of the parameters to the aws api.
            default=False

    Basic Usage:
        >>> client = boto3.client('iam')
        >>> policy_arn = 'arn:aws:iam::123456789:policy/test'
        >>> delete_policy_versions(client, policy_arn)

    Returns:
        List (bool, bool, str)
    """

    success = False
    changed = False
    err_msg = ''
    success, err_msg, policy_versions = (
        list_policy_versions(client, policy_arn, check_mode)
    )
    versions_deleted = 0
    if not except_version:
        except_version = ''
    if success:
        if policy_versions:
            for version in policy_versions:
                if not version['IsDefaultVersion'] and version['VersionId'] != except_version:
                    success, err_msg = (
                        policy_action(
                            client, policy_arn=policy_arn,
                            action='delete_version',
                            version=version['VersionId'], check_mode=check_mode
                        )
                    )
                    if not success:
                        return success, changed, err_msg
                    versions_deleted += 1

    if versions_deleted > 0:
        changed = True
        err_msg = (
            '{0} versions of policy_arn {1} were deleted'
            .format(versions_deleted, policy_arn)
        )
    else:
        err_msg = (
            'No versions other than the default were found for policy_arn {0}'
            .format(policy_arn)
        )

    return success, changed, err_msg

def create_policy_version(client, policy_arn, policy_json, current_policy,
                          check_mode=False):
    """Create a new version of the current policy with an updated policy.

    Args:
        client (botocore.client.EC2): Boto3 client.
        policy_arn (str): The Amazon resource identifier.
        policy_json (str): The json policy you wish to attach.
        current_policy (dict): This is the output of find_policy.

    Kwargs:
        check_mode (bool): This will pass DryRun as one of the parameters to the aws api.
            default=False

    Basic Usage:
        >>> client = boto3.client('iam')
        >>> policy_arn = 'arn:aws:iam::123456789:policy/test'
        >>> policy_json = '{"Version": "2012-10-17", "Statement": [{"Action": "*", "Resource": "*", "Effect": "Allow", "Sid": "Stmt1417926406000"}]}'
        >>> current_policy = {
                'PolicyName': 'test',
                'PolicyId': 'ANPAJDTHNXIKWXFW6P5EE',
                'Arn': 'arn:aws:iam::123456789:policy/test',
                'Path': '/',
                'DefaultVersionId': 'v1',
                'AttachmentCount': 0,
                'IsAttachable': True,
                'Description': 'string',
                'CreateDate': datetime.datetime.now(),
                'UpdateDate': datetime.datetime.now()
            }
        >>> create_policy_version(client, policy_arn, policy_json, current_policy)

    Returns:
        List (bool, bool, str)
    """

    success = False
    changed = False
    err_msg = ''
    policy_arn = current_policy['Arn']
    current_policy_version = current_policy['DefaultVersionId']
    version_success, version_err, version_policy = (
        get_policy_version(
            client, policy_arn, current_policy_version, check_mode
        )
    )
    if version_success and version_policy:
        if version_policy['Document'] == loads(policy_json):
            success = True
            changed = False
            err_msg = (
                'Policy {0} has not changed'
                .format(current_policy['PolicyName'])
            )
        else:
            success, err_msg = (
                policy_action(
                    client, policy_arn=policy_arn, policy_json=policy_json,
                    action='create_version', check_mode=check_mode
                )
            )
            if success:
                get_success, get_err, default_policy = (
                    get_policy(
                        client, policy_arn, check_mode
                    )
                )
                err_msg = (
                    'Policy {0} updated with a new default version: {1}'
                    .format(
                        default_policy['PolicyName'],
                        default_policy['DefaultVersionId']
                    )
                )
                changed = True
    return success, changed, err_msg, version_policy

def create(client, policy_name, policy_json, resource_name=None,
           resource_type=None, delete_previous_versions_except_last=False,
           check_mode=False):
    """Create a new managed policy.

    Args:
        client (botocore.client.EC2): Boto3 client.
        policy_name (str): The name of the managed policy.
        policy_json (str): The json policy you wish to attach.

    Kwargs:
        resource_name (str): The name of the resource, you want to attach
            to the new policy.
        resource_type (str): Valid resource types = group, role, user
        delete_previous_versions_except_last (bool): Managed policies can only
            have up to 5 versions. If set to True, you will only ever have
            the current version and the previous.
        check_mode (bool): This will pass DryRun as one of the parameters to the aws api.
            default=False

    Basic Usage:
        >>> client = boto3.client('iam')
        >>> policy_name = 'test'
        >>> policy_json = '{"Version": "2012-10-17", "Statement": [{"Action": "*", "Resource": "*", "Effect": "Allow", "Sid": "Stmt1417926406000"}]}'
        >>> resource_name = 'admin'
        >>> resource_type = 'user'
        >>> current_policy = {
                'PolicyName': 'test',
                'PolicyId': 'ANPAJDTHNXIKWXFW6P5EE',
                'Arn': 'arn:aws:iam::123456789:policy/test',
                'Path': '/',
                'DefaultVersionId': 'v1',
                'AttachmentCount': 0,
                'IsAttachable': True,
                'Description': 'string',
                'CreateDate': datetime.datetime.now(),
                'UpdateDate': datetime.datetime.now()
            }
        >>> create(client, policy_name, policy_json, resource_name, resource_type)
		[
    		true,
    		false,
    		false,
    		false,
    		"Policy test has not changed: No changes were made, test03 is already attached to policy test",
    		{
        		"update_date": "2016-04-04T15:59:11+00:00",
        		"create_date": "2016-04-04T14:45:30+00:00",
        		"is_attachable": true,
        		"policy_name": "test",
        		"default_version_id": "v6",
        		"arn": "arn:aws:iam::123456789:policy/test",
        		"attachment_count": 1,
        		"path": "/",
        		"resources": {
            		"groups": [],
            		"users": [
                		{
                    		"user_id": "AIDAIXNTGXRK3WGLVAGDQ",
                    		"user_name": "test03"
                		}
            		],
            		"roles": []
        		},
        		"policy_id": "ANPAJ72KDAOXE4OMK27KO"
    		}
		]

    Returns:
        List (bool, bool, bool, bool, str, dict)
    """
    create_success = False
    success = False
    changed = False
    policy_modified = False
    resource_modified = False
    err_msg = ''
    result = dict()
    policy_exists, exists_err_msg, current_policy = (
        find_policy(client, policy_name, check_mode)
    )
    if policy_exists and current_policy:
        policy_arn = current_policy['Arn']
    else:
        policy_arn = None

    if policy_exists and current_policy and policy_json:
        create_success, create_changed, create_msg, create_policy = (
            create_policy_version(
                client, policy_arn, policy_json, current_policy,
                check_mode=check_mode
            )
        )
        if create_changed:
            if delete_previous_versions_except_last:
                delete_success, delete_changed, delete_err_msg = (
                    delete_policy_versions(
                       client, policy_arn,
                        except_version=current_policy['DefaultVersionId'],
                        check_mode=check_mode
                    )
                )
        success = create_success
        policy_modified = create_changed
        changed = create_changed
        err_msg = create_msg
    else:
        create_success, create_msg = (
            policy_action(
                client, policy_name=policy_name, policy_json=policy_json,
                action='create', check_mode=check_mode
            )
        )
        success = create_success
        if success:
            policy_exists, exists_err_msg, current_policy = (
                find_policy(client, policy_name, check_mode)
            )
            if policy_exists:
                policy_arn = current_policy['Arn']
                err_msg = (
                    'Policy {0} created. ARN = {1}'
                    .format(policy_name, policy_arn)
                )
            else:
                err_msg = (
                    'Policy {0} could not be found. Error: {1}'
                    .format(policy_name, exists_err_msg)
                )
        else:
            err_msg = create_msg

        policy_modified = create_success
        changed = create_success

    if create_success or not policy_json:
        if resource_name and resource_type:
            resource_success, resource_changed, resource_msg = (
                attach(
                    client, policy_arn, resource_name, resource_type,
                    check_mode=check_mode
                )
            )
            resource_modified = resource_changed
            success = resource_success
            if resource_changed:
                err_msg += (
                    ': Resource {0} successfully attached to {1}'
                    .format(resource_name, policy_name)
                )
            else:
                err_msg += (
                    ': No changes were made, {0} is already attached to policy {1}'
                    .format(resource_name, policy_name)
                )
        else:
            success = create_success

        _, _, current_policy = (
            find_policy(client, policy_name, check_mode)
        )
        _, _, users, groups, roles = (
            list_entities_for_policy(client, policy_arn, check_mode)
        )
        current_policy['resources'] = {
            'users': users,
            'groups': groups,
            'roles': roles
        }
        result = convert_to_lower(current_policy)

    return success, changed, policy_modified, resource_modified, err_msg, result

def delete(client, policy_name, check_mode=False):
    """Delete a managed policy.

    Args:
        client (botocore.client.EC2): Boto3 client.
        policy_name (str): The name of the managed policy.

    Kwargs:
        check_mode (bool): This will pass DryRun as one of the parameters to the aws api.
            default=False

    Basic Usage:
        >>> client = boto3.client('iam')
        >>> policy_name = 'test'
        >>> delete(client, policy_name)
		[
    		true,
    		false,
    		false,
    		false,
    		"Policy test deleted successfully".
    		{}
		]

    Returns:
        List (bool, bool, bool, bool, str, dict)
    """

    success = False
    changed = False
    policy_modified = False
    resource_modified = False
    resources_deleted = 0
    err_msg = ''
    result = dict()
    policy_exists, exists_err_msg, current_policy = (
        find_policy(client, policy_name, check_mode)
    )
    policy_arn = None
    if policy_exists and current_policy:
        policy_arn = current_policy['Arn']
        success, err_msg, users, groups, roles = (
            list_entities_for_policy(client, policy_arn, check_mode=check_mode)
        )
        resources = users + groups + roles
        if resources:
            for resource in resources:
                if resource.get('UserName', None):
                    rtype = 'user'
                    rname = resource.get('UserName')
                elif resource.get('GroupName', None):
                    rtype = 'group'
                    rname = resource.get('GroupName')
                else:
                    rtype = 'role'
                    rname = resource.get('RoleName')

                success, err_msg = (
                    resource_action(
                        client, rname, rtype, policy_arn,
                        action='detach', check_mode=check_mode
                    )
                )
                if not success:
                    return success, changed, policy_modified, resource_modified, err_msg, result
            resource_modified = True
            resources_deleted += 1

        success, changed, err_msg = (
            delete_policy_versions(client, policy_arn, check_mode)
        )
        if success:
            success, err_msg = (
                policy_action(
                    client, policy_arn=policy_arn, action='delete',
                    check_mode=check_mode
                )
            )
            if success:
                changed = True
                policy_modified = True
                err_msg = 'Policy {0} deleted successfully'.format(policy_name)
    else:
        err_msg = 'Policy {0} does not exist'.format(policy_name)
        success = True
        changed = False

    return success, changed, policy_modified, resource_modified, err_msg, result


def main():
    argument_spec = ec2_argument_spec()
    argument_spec.update(
        dict(
            iam_name=dict(type='str', default=None, required=False),
            iam_type=dict(
                default=None, required=False, choices=['user', 'group', 'role']
            ),
            state=dict(
                default=None, required=True, choices=[
                    'present', 'absent'
                ]
            ),
            policy_name=dict(type='str', default=None, required=True),
            policy_document=dict(type='str', default=None, required=False),
            policy_json=dict(default=None, required=False),
            skip_duplicates=dict(type='bool', default=True, required=False)
        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    if not HAS_BOTO3:
        module.fail_json(msg='boto3 is required')

    state = module.params.get('state').lower()
    iam_type = module.params.get('iam_type')
    if iam_type:
        iam_type = iam_type.lower()
    iam_name = module.params.get('iam_name')
    policy_name = module.params.get('policy_name')
    policy_document = module.params.get('policy_document')
    policy_json = module.params.get('policy_json')
    check_mode = module.check_mode

    if policy_document and policy_json:
        module.fail_json(
            msg='Only one of "policy_document" or "policy_json" may be set'
        )

    if policy_document:
        policy, err_msg = validate_json(policy_document, is_file=True)
        if err_msg:
            module.fail_json(
                msg='Failed to convert the policy into valid JSON: %s' % str(e)
            )

    elif policy_json:
        policy, err_msg = validate_json(policy_json)
        if err_msg:
            module.fail_json(msg=err_msg)
    else:
        policy=None

    try:
        region, ec2_url, aws_connect_kwargs = (
            get_aws_connection_info(module, boto3=True)
        )
        client = (
            boto3_conn(
                module, conn_type='client', resource='iam',
                region=region, endpoint=ec2_url, **aws_connect_kwargs
            )
        )
    except botocore.exceptions.ClientError, e:
        err_msg = 'Boto3 Client Error - {0}'.format(str(e.msg))
        module.fail_json(msg=err_msg)

    if state == 'present':
        success, changed, policy_modified, resource_modified, err_msg, result = (
            create(
                client, policy_name, policy, iam_name, iam_type, check_mode
            )
        )

    else:
        success, changed, policy_modified, resource_modified, err_msg, result = (
            delete(client, policy_name, check_mode)
        )

    if success:
        module.exit_json(
            success=success, changed=changed, policy_modified=policy_modified,
            resource_modified=resource_modified, msg=err_msg, **result
        )
    else:
        module.fail_json(msg=err_msg)

# import module snippets
from ansible.module_utils.basic import *
from ansible.module_utils.ec2 import *

if __name__ == '__main__':
    main()
