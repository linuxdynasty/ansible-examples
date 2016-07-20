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
module: ec2_vpc_peer
short_description: create, delete, accept, and reject VPC peering connections between two VPCs.
description:
  - Read the AWS documentation for VPC Peering Connections
    U(http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/vpc-peering.html)
version_added: "2.1"
author: Allen Sanabria(@linuxdynasty)
extends_documentation_fragment: aws
requirements: [boto3, botocore]
options:
  accept_peer:
    description:
      - If set to yes, the newly created peering connection will be accepted.
    required: false
  accept_with_profile:
    description:
      - The boto3 profile to use when you are auto accepting a cross account peer.
    required: false
  accepter_routes:
    description:
      - List of route table ids. These route tables will be updated with the
      - CIDR block of the vpc_id using the vpc_peering_id that is generated when the peer is created.
    required: false
  requester_routes:
    description:
      - List of route table ids. These route tables will be updated with the
      - CIDR block of the vpc_peer_id using the vpc_peering_id that is generated when the peer is created.
    required: false
  resource_tags:
    description:
      - Dictionary of Tags to apply to the newly created peer.
    required: false
  vpc_id:
    description:
      - VPC id of the requesting VPC.
    required: false
  peer_vpc_id:
    description:
      - VPC id of the accepting VPC.
    required: false
  peer_owner_id:
    description:
      - The AWS account number for cross account peering.
    required: false
  state:
    description:
      - Create, delete, accept, reject a peering connection.
    required: false
    default: present
    choices: ['present', 'absent', 'accept', 'reject']
'''
EXAMPLES = '''
# Complete example to create and accept a local peering connection and auto accept.
- name: Create local account VPC peering Connection and auto accept
  ec2_vpc_peer:
    region: us-west-2
    vpc_id: vpc-12345678
    peer_vpc_id: vpc-87654321
    state: present
    accept_peer: yes
    resource_tags:
      - Name: new_peer
      - Env: development
  register: vpc_peer

# Complete example to create and accept a local peering connection and auto
# accept as well as add routes to the requester CIDR (The CIDR block of the vpc_id)
# using the newly created peering connection id.
- name: Create local account VPC peering Connection and auto accept and add routes
  ec2_vpc_peer:
    region: us-west-2
    vpc_id: vpc-12345678
    peer_vpc_id: vpc-87654321
    state: present
    accept_peer: yes
    requester_routes:
      - rtb-12345678
      - rtb-98765432
    resource_tags:
      - Name: new_peer
      - Env: development
  register: vpc_peer

# Complete example to create and accept a local peering connection and auto
# accept as well as add routes to the accepter CIDR (The CIDR block of the vpc_peer_id)
# using the newly created peering connection id.
- name: Create local account VPC peering Connection and auto accept and add routes
  ec2_vpc_peer:
    region: us-west-2
    vpc_id: vpc-12345678
    peer_vpc_id: vpc-87654321
    state: present
    accept_peer: yes
    accepter_routes:
      - rtb-12345678
      - rtb-98765432
    resource_tags:
      - Name: new_peer
      - Env: development
  register: vpc_peer

# Complete example to create and accept a cross account peering connection and auto accept.
# Boto3 profile for the other account must exist in ~/.aws/credentials
- name: Create cross account VPC peering Connection and auto accept
  ec2_vpc_peer:
    region: us-west-2
    vpc_id: vpc-12345678
    peer_vpc_id: vpc-87654321
    state: present
    accept_with_profile: boto3_profile_goes_here
    peer_owner_id: 12345678910
    resource_tags:
      - Name: new_peer
      - Env: development
  register: vpc_peer

# Complete example to delete a local account peering connection.
# Boto3 profile for the other account must exist in ~/.aws/credentials
- name: Create cross account VPC peering Connection and auto accept
  ec2_vpc_peer:
    region: us-west-2
    vpc_id: vpc-12345678
    peer_vpc_id: vpc-87654321
    state: present
    resource_tags:
      - Name: new_peer
      - Env: development
  register: vpc_peer

- name: delete a VPC peering Connection
  ec2_vpc_peer:
    region: us-west-2
    peering_id: "{{ vpc_peer.vpc_peering_connection_id }}"
    state: absent
  register: vpc_peer

# Complete example to delete a cross account peering connection.
# Boto3 profile for the other account must exist in ~/.aws/credentials
- name: Create cross account VPC peering Connection and auto accept
  ec2_vpc_peer:
    region: us-west-2
    vpc_id: vpc-12345678
    peer_vpc_id: vpc-87654321
    state: present
    accept_with_profile: boto3_profile_goes_here
    peer_owner_id: 12345678910
    resource_tags:
      - Name: new_peer
      - Env: development
  register: vpc_peer

- name: delete a cross account VPC peering Connection
  ec2_vpc_peer:
    region: us-west-2
    peering_id: "{{ vpc_peer.vpc_peering_connection_id }}"
    state: absent
    profile: boto3_profile_goes_here
  register: vpc_peer

# Complete example to reject a local account peering connection.
# Boto3 profile for the other account must exist in ~/.aws/credentials
- name: Create VPC peering Connection.
  ec2_vpc_peer:
    region: us-west-2
    vpc_id: vpc-12345678
    peer_vpc_id: vpc-87654321
    state: present
    resource_tags:
      - Name: new_peer
      - Env: development
  register: vpc_peer

- name: Reject a VPC peering Connection
  ec2_vpc_peer:
    region: us-west-2
    peering_id: "{{ vpc_peer.vpc_peering_connection_id }}"
    state: reject
  register: vpc_peer

# Complete example to reject a cross account peering connection.
# Boto3 profile for the other account must exist in ~/.aws/credentials
- name: Create cross account VPC peering Connection.
  ec2_vpc_peer:
    region: us-west-2
    vpc_id: vpc-12345678
    peer_vpc_id: vpc-87654321
    state: present
    peer_owner_id: 12345678910
    resource_tags:
      - Name: new_peer
      - Env: development
  register: vpc_peer

- name: Reject a cross account VPC peering Connection
  ec2_vpc_peer:
    region: us-west-2
    peering_id: "{{ vpc_peer.vpc_peering_connection_id }}"
    state: reject
    profile: boto3_profile_goes_here
  register: vpc_peer
'''
RETURN = '''
success:
  description: Returns true if all succeeded and false if it failed.
  returned: In all cases.
  type: bool
  sample: true
changed:
  description: Returns true if action made a changed  and false if it didn't.
  returned: In all cases.
  type: bool
  sample: true
status:
  description: Dictionary containing the message and code.
  returned: Success.
  type: dictionary
  sample:
    {
        "message": "Active",
        "code": "active"
    }
tags:
  description: List of dictionaries containing the key, val of each tag.
  returned: Success.
  type: list
  sample:
    [
        {
            "value": "web",
            "key": "service"
        }
    ]
accepter_vpc_info:
  description: Dictionary containing the owner_id, vpc_id, and cidr_block.
  returned: Success.
  type: dictionary
  sample:
    {
        "owner_id": "12345678910",
        "vpc_id": "vpc-12345678",
        "cidr_block": "172.31.0.0/16"
    }
vpc_peering_connection_id:
  description: The peering connection id.
  returned: Success.
  type: string
  sample: pcx-12345678
requester_vpc_info:
  description: Dictionary containing the owner_id, vpc_id, and cidr_block.
  returned: Success.
  type: dictionary
  sample:
    {
        "owner_id": "12345678910",
        "vpc_id": "vpc-12345678",
        "cidr_block": "10.100.0.0/16"
    }
'''

try:
    import botocore
    import boto3
    import boto3.session
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False

import datetime
import re

def create_client_with_profile(profile_name, region, resource_name='ec2'):
    """ Create a new boto3 client with a boto3 profile  in ~/.aws/credentials
    Args:
        profile_name (str): The name of the profile that you have set in your
            ~/.aws/credentials profile.
        region (str): The aws region you want to connect to.
        resource_name (str): Valid aws resource.
            default=ec2

    Basic Usage:
        >>> client, err_msg = create_client_with_profile('lab01', 'us-west-2')

    Returns:
        Tuple (botocore.client.EC2, str)
    """
    client = None
    err_msg = ''
    try:
        session = (
            boto3.session.Session(
                profile_name=profile_name, region_name=region
            )
        )
        client = session.client(resource_name)
    except Exception as e:
        err_msg = str(e)

    return client, err_msg

def convert_to_lower(data):
    """Convert all uppercase keys in dict with lowercase_
    Args:
        data (dict): Dictionary with keys that have upper cases in them
            Example.. NatGatewayAddresses == nat_gateway_addresses
            if a val is of type datetime.datetime, it will be converted to
            the ISO 8601

    Basic Usage:
        >>> test = {'NatGatewaysAddresses': []}
        >>> test = convert_to_lower(test)
        {
            'nat_gateways_addresses': []
        }

    Returns:
        Dictionary
    """
    results = dict()
    if isinstance(data, dict):
        for key, val in data.items():
            key = re.sub('([A-Z]{1})', r'_\1', key).lower()
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

def find_tags(client, resource_id, check_mode=False):
    """Retrieve all tags for an Amazon resource id
    Args:
        client (botocore.client.EC2): Boto3 client
        resource_id (str): The Amazon resource id.

    Kwargs:
        check_mode (bool): This will pass DryRun as one of the parameters to the aws api.
            default=False

    Basic Usage:
        >>> client = boto3.client('ec2')
        >>> resource_id = 'rtb-123456'
        >>> success, msg, tags = find_tags(client, resource_id)
        (
            True,
            '',
            [
                {
                    u'Value': 'Test-Private-Zone-A',
                    u'Key': 'Name'
                }
            ]
        )

    Returns:
        Tuple (bool, str, list)
    """
    success = False
    err_msg = ''
    current_tags = list()
    search_params = {
        'Filters': [
            {
                'Name': 'resource-id',
                'Values': [resource_id]
            }
        ],
        'DryRun': check_mode
    }
    try:
        current_tags = client.describe_tags(**search_params)['Tags']
        success = True
        if current_tags:
            for i in range(len(current_tags)):
                current_tags[i].pop('ResourceType')
                current_tags[i].pop('ResourceId')

    except botocore.exceptions.ClientError, e:
        if e.response['Error']['Code'] == 'DryRunOperation':
            success = True
            err_msg = e.message
        else:
            err_msg = str(e)

    return success, err_msg, current_tags

def describe_peering_connections(client, vpc_id=None, vpc_peer_id=None,
                                 vpc_peering_id=None, status_codes=None,
                                 check_mode=False):
    """Retrieve peering connection info by peering_id or by searching by requestor and accepter.
    Args:
        client (botocore.client.EC2): Boto3 client

    Kwargs:
        vpc_id (str): The requestor vpc_id.
        vpc_peer_id (str): The accepter vpc_id.
        vpc_peering_id (str): The vpc peering connection id.
        status_codes (list): The codes to filter on.
            valid status codes = [
                pending-acceptance, failed, expired, provisioning,
                active, deleted, rejected
            ]
        check_mode (bool): This will pass DryRun as one of the parameters to the aws api.
            default=False

    Basic Usage:
        >>> client = boto3.client('ec2')
        >>> vpc_id='vpc-d18571b5'
        >>> vpc_peer_id='vpc-68da9d0d'
        >>> describe_peering_connections(client, vpc_id, vpc_peer_id)
        [
            True,
            "",
            [
                {
                    "Status": {
                    "Message": "Active",
                    "Code": "active"
                },
                "Tags": [
                    {
                        "Value": "env",
                        "Key": "Management"
                    },
                    {
                        "Value": "Management to Production",
                        "Key": "Name"
                    }
                ],
                "AccepterVpcInfo": {
                    "OwnerId": "12345678910",
                    "VpcId": "vpc-123456789",
                    "CidrBlock": "172.31.0.0/16"
                },
                "VpcPeeringConnectionId": "pcx-12345678",
                "RequesterVpcInfo": {
                    "OwnerId": "12345678910",
                    "VpcId": "vpc-12345678",
                    "CidrBlock": "172.32.0.0/16"
                }
            }
        ]
    ]
    Returns:
        Tuple (bool, str, list)
    """
    success = False
    err_msg = ''
    params = {
        'DryRun': check_mode
    }
    result = list()
    if vpc_id and vpc_peer_id:
        params['Filters'] = [
            {
                'Name': 'requester-vpc-info.vpc-id',
                'Values': [vpc_id],
            },
            {
                'Name': 'accepter-vpc-info.vpc-id',
                'Values': [vpc_peer_id],
            }
        ]
        if status_codes:
            params['Filters'].append(
                {
                    'Name': 'status-code',
                    'Values': status_codes
                }
            )

    elif vpc_peering_id:
        params['VpcPeeringConnectionIds'] = [vpc_peering_id]
        if status_codes:
            params['Filters'] = [
                {
                    'Name': 'status-code',
                    'Values': status_codes
                }
            ]

    try:
        result = (
            client.describe_vpc_peering_connections(**params)
            ['VpcPeeringConnections']
        )
        success = True

    except botocore.exceptions.ClientError, e:
        if e.response['Error']['Code'] == 'DryRunOperation':
            success = True
            err_msg = e.message
        else:
            err_msg = str(e)

    return success, err_msg, result

def is_active(peering_conn):
    return peering_conn['status']['code'] == 'active'

def is_deleted(peering_conn):
    return peering_conn['status']['code'] == 'deleted'

def is_expired(peering_conn):
    return peering_conn['status']['code'] == 'expired'

def is_failed(peering_conn):
    return peering_conn['status']['code'] == 'failed'

def is_initiating_request(peering_conn):
    return peering_conn['status']['code'] == 'initiating-request'

def is_pending(peering_conn):
    return peering_conn['status']['code'] == 'pending-acceptance'

def is_provisioning(peering_conn):
    return peering_conn['status']['code'] == 'provisioning'

def is_rejected(peering_conn):
    return peering_conn['status']['code'] == 'rejected'

def make_tags_in_proper_format(tags):
    """Take a list of aws tags and convert them into a list of dictionaries.
       Where the key is the actual key and not Key.
    Args:
        tags (list): The tags you want applied.

    Basic Usage:
        >>> tags = [{u'Key': 'env', u'Value': 'development'}]
        >>> make_tags_in_proper_format(tags)
        [
            {
               "env": "development",
            }
        ]

    Returns:
        List
    """
    formatted_tags = list()
    for tag in tags:
        formatted_tags.append(
            {
                tag.get('Key'): tag.get('Value')
            }
        )

    return formatted_tags

def convert_list_of_tags(tags):
    """Convert a list of AWS Tag dictionaries into a dictionary.
    Args:
        tags (list): The tags you want applied.

    Basic Usage:
        >>> tags = [{u'Key': 'env', u'Value': 'development'}]
        >>> convert_list_of_tags(tags)
        {
            "env": "development",
        }

    Returns:
        Dict
    """
    converted_tags = dict()
    for tag in tags:
        tag = convert_to_lower(tag)
        converted_tags[tag.get('key')] = tag.get('value')

    return converted_tags

def make_tags_in_aws_format(tags):
    """Take a dictionary of tags and convert them into the AWS Tags format.
    Args:
        tags (dict): The tags you want applied.

    Basic Usage:
        >>> tags = {'env': 'development', 'service': 'web'}
        >>> make_tags_in_aws_format(tags)
        [
            {
                "Value": "web",
                "Key": "service"
             },
            {
               "Value": "development",
               "key": "env"
            }
        ]

    Returns:
        List
    """
    formatted_tags = list()
    for key, val in tags.items():
        formatted_tags.append({
            'Key': key,
            'Value': val
        })

    return formatted_tags

def tags_action(client, resource_id, tags, action='create', check_mode=False):
    """Create or Delete tags for an Amazon resource id.
    Args:
        client (botocore.client.EC2): Boto3 client.
        resource_id (str): The Amazon resource id.
        tags (list): List of dictionaries.
            examples.. [{Name: "", Values: [""]}]

    Kwargs:
        action (str): The action to perform.
            valid actions == create and delete
            default=create
        check_mode (bool): This will pass DryRun as one of the parameters to the aws api.
            default=False

    Basic Usage:
        >>> client = boto3.client('ec2')
        >>> resource_id = 'pcx-123345678'
        >>> tags = [{'Name': 'env', 'Values': ['Development']}]
        >>> update_tags(client, resource_id, tags)
        [True, '']

    Returns:
        List (bool, str)
    """
    success = False
    err_msg = ""
    params = {
        'Resources': [resource_id],
        'Tags': tags,
        'DryRun': check_mode
    }
    try:
        if action == 'create':
            client.create_tags(**params)
            success = True
        elif action == 'delete':
            client.delete_tags(**params)
            success = True
        else:
            err_msg = 'Invalid action {0}'.format(action)

    except botocore.exceptions.ClientError, e:
        if e.response['Error']['Code'] == 'DryRunOperation':
            success = True
            err_msg = e.message
        else:
            err_msg = str(e)

    return success, err_msg

def recreate_tags_from_list(list_of_tags):
    """Recreate tags from a list of tuples into the Amazon Tag format.
    Args:
        list_of_tags (list): List of tuples.

    Basic Usage:
        >>> list_of_tags = [('Env', 'Development')]
        >>> recreate_tags_from_list(list_of_tags)
        [
            {
                "Value": "Development",
                "Key": "Env"
            }
        ]

    Returns:
        List
    """
    tags = list()
    i = 0
    list_of_tags = list_of_tags
    for i in range(len(list_of_tags)):
        key_name = list_of_tags[i][0]
        key_val = list_of_tags[i][1]
        tags.append(
            {
                'Key': key_name,
                'Value': key_val
            }
        )
    return tags

def update_routes(client, vpc_peering_id, cidr, route_table_ids,
                  check_mode=False):
    """Update routes in multiple route tables.
    Args:
        client (botocore.client.EC2): Boto3 client.
        vpc_peering_id (str): The vpc peering connection id.
        cidr (str): The dest cidr block.
            example.. 0.0.0.0/0
        route_table_ids (list): List of route table ids.

    Kwargs:
        check_mode (bool): This will pass DryRun as one of the parameters to the aws api.
            default=False

    Basic Usage:
        >>> client = boto3.client('ec2')
        >>> vpc_peering_id = 'vpx-1234567'
        >>> cidr = '0.0.0.0/0'
        >>> route_table_ids = ['rtb-1234567', 'rtb-7654321']
        [
            True,
            True,
            ''
        ]

    Returns:
        Tuple (bool, bool, str)
    """
    success = False
    changed = False
    err_msg = ''
    for route_table_id in route_table_ids:
        params = {
            'RouteTableId': route_table_id,
            'DestinationCidrBlock': cidr,
            'VpcPeeringConnectionId': vpc_peering_id,
            'DryRun': check_mode,
        }
        try:
            completed = client.create_route(**params)
            if completed.get('Return') == True:
                success, changed = True, True

        except botocore.exceptions.ClientError, e:
            err_msg = str(e)
            if e.response['Error']['Code'] == 'DryRunOperation':
                success = True
                err_msg = e.message
            elif re.search('RouteAlreadyExists', err_msg):
                success = True
    return success, changed, err_msg

def pre_update_routes(client, peer_info, accepter_routes=None,
                      requester_routes=None, check_mode=False):
    """Does the pre work before updating a route.
    Args:
        client (botocore.client.EC2): Boto3 client.
        peer_info (dict): This contains the output of describe_peering_connections

    Kwargs:
        accepter_routes (list): list of route table ids that you want
            to add routes to the cidr that belongs to the peer of the newly
            created peering_connection
            default=None
        requester_routes (list): list of route table ids that you want
            to add routes to the cidr that belongs to the vpc that is
            initiating the creation of the newly created peering_connection
            default=None
        check_mode (bool): This will pass DryRun as one of the parameters to the aws api.
            default=False

    Basic Usage:
        >>> client = boto3.client('ec2')
        >>> _, _, vpc_peer_info = describe_peering_connections(
                client, vpc_peering_id='vpx-1234567'
        )
        >>> accepter_routes = ['rtb-1234567', 'rtb-7654321']
        >>> pre_update_routes(client, vpc_peer_info[0], accepter_routes)
        [
            True,
            True,
            ''
        ]

    Returns:
        Tuple (bool, bool, str)
    """
    success = False
    changed = False
    err_msg = 'Need to pass either accepter_routes or requester_routes.'
    vpc_peering_id = peer_info['vpc_peering_connection_id']
    if accepter_routes and peer_info['accepter_vpc_info'].get('cidr_block', None):
        routes = accepter_routes
        cidr = peer_info['accepter_vpc_info']['cidr_block']
        success, changed, err_msg = (
            update_routes(client, vpc_peering_id, cidr, routes)
        )
    if requester_routes and peer_info['requester_vpc_info'].get('cidr_block', None):
        routes = requester_routes
        cidr = peer_info['requester_vpc_info']['cidr_block']
        success, changed, err_msg = (
            update_routes(client, vpc_peering_id, cidr, routes)
        )

    return success, changed, err_msg

def update_tags(client, resource_id, tags, check_mode=False):
    """Update tags for an amazon resource. This will delete any tag that is
        not part of the tags parameter and update|create.
    Args:
        resource_id (str): The Amazon resource id.
        tags (list): List of dictionaries.
            examples.. [{Name: "", Values: [""]}]

    Kwargs:
        check_mode (bool): This will pass DryRun as one of the parameters to the aws api.
            default=False

    Basic Usage:
        >>> client = boto3.client('ec2')
        >>> resource_id = 'pcx-123345678'
        >>> tags = [{'Name': 'env', 'Values': ['Development']}]
        >>> update_tags(client, resource_id, tags)
        [True, '']

    Return:
        Tuple (bool, str)
    """
    success = False
    err_msg = ''
    find_success, find_err, current_tags = (
        find_tags(client, resource_id, check_mode=check_mode)
    )
    if find_success:
        if current_tags:
            current_tags_set = (
                set(
                    reduce(
                        lambda x, y: x + y,
                        [x.items() for x in make_tags_in_proper_format(current_tags)]
                    )
                )
            )

            new_tags_set = (
                set(
                    reduce(
                        lambda x, y: x + y,
                        [x.items() for x in make_tags_in_proper_format(tags)]
                    )
                )
            )
            tags_to_delete = list(current_tags_set.difference(new_tags_set))
            tags_to_update = list(new_tags_set.difference(current_tags_set))
            if tags_to_delete:
                tags_to_delete = recreate_tags_from_list(tags_to_delete)
                delete_success, delete_msg = (
                    tags_action(
                        client, resource_id, tags_to_delete, action='delete',
                        check_mode=False
                    )
                )
                if not delete_success:
                    return delete_success, delete_msg
            if tags_to_update:
                tags = recreate_tags_from_list(tags_to_update)
                if not tags:
                    return delete_success, delete_msg

    if tags:
        create_success, create_msg = (
            tags_action(
                client, resource_id, tags, action='create',
                check_mode=False
            )
        )
        return create_success, create_msg

    return success, err_msg

def runner(client, state, params):
    """Generic function that will handle the calls to create, delete, reject and accept.
       This function should not be called directly, except by the run function.

    Args:
        client (botocore.client.EC2): Boto3 client.
        state (str): valid states. [accept, reject, absent, present].
        params (dict): Params contains the parameters to perform the aws request.

    Kwargs:
        boto3_profile (str): The name of the boto3 profile to use when
            making a cross account request.
            default=None

    Basic Usage:
        >>> client = boto3.client('ec2')
        >>> state = 'accept'
        >>> vpc_peering_id = 'pcx-12345'
        >>> params = {'VpcPeeringConnectionId': vpc_peering_id}
        >>> runner(client, state, params)
        [
            True,
            False,
            "",
            {
                "status": {
                    "message": "Active",
                    "code": "active"
                },
                "tags": [
                    {
                        "value": "web",
                        "key": "service"
                    },
                    {
                        "value": "Shaolin Allen",
                        "key": "Name"
                    },
                    {
                        "value": "development",
                        "key": "env"
                    }
                ],
                "accepter_vpc_info": {
                    "owner_id": "12345678910",
                    "vpc_id": "vpc-12345678",
                    "cidr_block": "172.31.0.0/16"
                },
                "vpc_peering_connection_id": "pcx-12345678",
                "requester_vpc_info": {
                    "owner_id": "12345678910",
                    "vpc_id": "vpc-12345678",
                    "cidr_block": "10.100.0.0/16"
                }
            }
        ]

    Return:
        Tuple (bool, bool, str, dict)
    """
    success = False
    changed = False
    err_msg = ''
    result = dict()
    invocations = {
        'accept': client.accept_vpc_peering_connection,
        'reject': client.reject_vpc_peering_connection,
        'absent': client.delete_vpc_peering_connection,
        'present': client.create_vpc_peering_connection,
    }
    if state not in ['accept', 'reject', 'absent', 'present']:
        return success, changed, err_msg, result

    try:
        result = invocations[state](**params)
        response = result.pop('ResponseMetadata')
        if result.get('VpcPeeringConnection', {}):
            result = result.pop('VpcPeeringConnection')
        if response['HTTPStatusCode'] == 200:
            changed = True
            success = True
        else:
            err_msg = "Failure occured, please check aws console"
        result = convert_to_lower(result)

    except botocore.exceptions.ClientError, e:
        if e.response['Error']['Code'] == 'DryRunOperation':
            success = True
            err_msg = e.message
        else:
            err_msg = str(e)

    return success, changed, err_msg, result

def run(client, vpc_peering_id, state, check_mode=False):
    """Generic function for ensuring the various states for a peering connection.
       This function is called by create, accept, reject, and delete.

    Args:
        client (botocore.client.EC2): Boto3 client.
        vpc_peering_id (str): The vpc peering connection id.
        state (str): valid states. [accept, reject, absent, present].

    Kwargs:
        check_mode (bool): This will pass DryRun as one of the parameters to the aws api.
            default=False

    Basic Usage:
        >>> client = boto3.client('ec2')
        >>> state = 'accept'
        >>> vpc_peering_id = 'pcx-12345'
        >>> run(client, state, params)
        [
            True,
            False,
            "",
            {
                "status": {
                    "message": "Active",
                    "code": "active"
                },
                "tags": [
                    {
                        "value": "web",
                        "key": "service"
                    },
                    {
                        "value": "Shaolin Allen",
                        "key": "Name"
                    },
                    {
                        "value": "development",
                        "key": "env"
                    }
                ],
                "accepter_vpc_info": {
                    "owner_id": "12345678910",
                    "vpc_id": "vpc-12345678",
                    "cidr_block": "172.31.0.0/16"
                },
                "vpc_peering_connection_id": "pcx-12345678",
                "requester_vpc_info": {
                    "owner_id": "12345678910",
                    "vpc_id": "vpc-12345678",
                    "cidr_block": "10.100.0.0/16"
                }
            }
        ]

    Return:
        Tuple (bool, bool, str, dict)
    """
    changed = False
    success, err_msg, results = (
        describe_peering_connections(
            client, vpc_peering_id=vpc_peering_id,
            status_codes=['pending-acceptance', 'active'],
            check_mode=check_mode
        )
    )
    params = {
        'VpcPeeringConnectionId': vpc_peering_id,
        'DryRun': check_mode,
    }
    if success and results:
        results = convert_to_lower(results[0])
        err_msg = (
            'Can not {0} on a {1} state: peer: {2}'
            .format(state, results['status']['code'], vpc_peering_id)
        )
        if is_pending(results):
            if state == 'accept' or state == 'absent' or state == 'reject':
                success, changed, err_msg, results = (
                    runner(client, state, params)
                )
        elif is_active(results):
            if state == 'absent':
                success, changed, err_msg, results = (
                    runner(client, state, params)
                )
    elif len(results) == 0:
        success = False
        err_msg = (
            'Can not {0} a peer does not exist: {1}-{2}'
            .format(state, err_msg, vpc_peering_id)
        )

    return success, changed, err_msg, convert_to_lower(results)

def accept(client, vpc_peering_id, check_mode=False):
    """Wrapper function that calls run with the proper state and returns
       the exact signature of the run function.

    Args:
        client (botocore.client.EC2): Boto3 client.
        vpc_peering_id (str): The vpc peering connection id.

    Kwargs:
        check_mode (bool): This will pass DryRun as one of the parameters to the aws api.
            default=False
    """
    success, changed, err_msg, _ = (
        run(client, vpc_peering_id, 'accept', check_mode=check_mode)
    )
    return success, changed, err_msg, {}

def reject(client, vpc_peering_id, check_mode=False):
    """Wrapper function that calls run with the proper state and returns
       the exact signature of the run function.

    Args:
        client (botocore.client.EC2): Boto3 client.
        vpc_peering_id (str): The vpc peering connection id.

    Kwargs:
        check_mode (bool): This will pass DryRun as one of the parameters to the aws api.
    """
    success, changed, err_msg, _ = (
        run(client, vpc_peering_id, 'reject', check_mode=check_mode)
    )
    return success, changed, err_msg, {}

def delete(client, vpc_peering_id, check_mode=False):
    """Wrapper function that calls run with the proper state and returns
       the exact signature of the run function.

    Args:
        client (botocore.client.EC2): Boto3 client.
        vpc_peering_id (str): The vpc peering connection id.

    Kwargs:
        check_mode (bool): This will pass DryRun as one of the parameters to the aws api.
            default=False
    """
    success, changed, err_msg, _ = (
        run(client, vpc_peering_id, 'absent', check_mode=check_mode)
    )
    return success, changed, err_msg, {}

def update(client, vpc_peering_id, tags, accept_peer=False,
           accept_with_profile=None, region=None,
           accepter_routes=None, requester_routes=None, check_mode=False):
    """Add Tags to a VPC Peering Connection and or Accept the peer.

    Args:
        client (botocore.client.EC2): Boto3 client.
        vpc_peering_id (str): The vpc peering connection id.
        tags (list): List of dictionaries.
            examples.. [{Name: "", Values: [""]}]

    Kwargs:
        accept_peer (bool): if set to True, the peer will be accepted.
        accept_with_profile (str): Boto3 Profile to use with accept.
        region (str): if accept_with_profile is passed, than this region
            also needs to be passed.
            default=None
        accepter_routes (list): list of route table ids that you want
            to add routes to the cidr that belongs to the peer of the newly
            created peering_connection
            default=None
        requester_routes (list): list of route table ids that you want
            to add routes to the cidr that belongs to the vpc that is
            initiating the creation of the newly created peering_connection
            default=None
        check_mode (bool): This will pass DryRun as one of the parameters to the aws api.
            default=False

    Basic Usage:
        >>> client = boto3.client('ec2')
        >>> vpc_peering_id = 'pcx-12345'
        >>> tags = [{'Name': 'Service', 'Values': ['Development']}]
        >>> accept_peer = True
        >>> update(client, vpc_peering_id, tags, accept_peer)
        [
            True,
            True,
            "",
            {
                "status": {
                    "message": "Active",
                    "code": "active"
                },
                "tags": [
                    {
                        "value": "web",
                        "key": "service"
                    },
                    {
                        "value": "Shaolin Allen",
                        "key": "Name"
                    },
                    {
                        "value": "development",
                        "key": "env"
                    }
                ],
                "accepter_vpc_info": {
                    "owner_id": "12345678910",
                    "vpc_id": "vpc-12345678",
                    "cidr_block": "172.31.0.0/16"
                },
                "vpc_peering_connection_id": "pcx-12345678",
                "requester_vpc_info": {
                    "owner_id": "12345678910",
                    "vpc_id": "vpc-12345678",
                    "cidr_block": "10.100.0.0/16"
                }
            }
        ]

    Return:
        Tuple (bool, bool, str, dict)
    """
    success = False
    changed = False
    err_msg = ""
    result = dict()
    success, err_msg, results = (
        describe_peering_connections(
            client, vpc_peering_id=vpc_peering_id,
            status_codes=['active', 'pending-acceptance', 'initiating-request'],
            check_mode=check_mode
        )
    )
    if results:
        peer_info = convert_to_lower(results[0])
        tag_update_success, tag_err_msg = (
            update_tags(
                client, vpc_peering_id, tags, check_mode=check_mode
            )
        )
        if tag_update_success:
            if (is_active(peer_info) or is_pending(peer_info)
                    or is_initiating_request(peer_info)):
                vpc_peering_id = peer_info['vpc_peering_connection_id']
                changed = True
                status_codes = ['pending-acceptance']
                original_client = client
                if accept_peer:
                    if accept_with_profile:
                        ###Switch client to use boto3 profile
                        accept_client, err_msg = (
                            create_client_with_profile(
                                accept_with_profile, region
                            )
                        )
                        if err_msg:
                            success = False
                        else:
                            client = accept_client
                    if success:
                        success, changed, err_msg, results = (
                            accept(
                                client, vpc_peering_id, check_mode=check_mode
                            )
                        )
                        status_codes.append('active')
                        if success:
                            ###Update tags for peered connection, using the boto3 profile
                            success, err_msg = (
                                update_tags(
                                    client, vpc_peering_id, tags,
                                    check_mode=check_mode
                                )
                            )

                _, _, result = (
                    describe_peering_connections(
                        client, vpc_peering_id=vpc_peering_id,
                        status_codes=status_codes, check_mode=check_mode
                    )
                )
                if result and success:
                    result = convert_to_lower(result[0])
                    if (accepter_routes and not accept_with_profile or
                            requester_routes):
                        client = original_client
                    if accepter_routes or requester_routes:
                        success, changed, _ = (
                            pre_update_routes(
                                client, result, accepter_routes,
                                requester_routes, check_mode
                            )
                        )

    return success, changed, err_msg, result

def create(client, vpc_id, vpc_peer_id, tags, peer_owner_id=None,
           accept_peer=False, accept_with_profile=None, region=None,
           accepter_routes=None, requester_routes=None, check_mode=False):
    """Create a local and cross account vpc peering connection

    Args:
        client (botocore.client.EC2): Boto3 client.
        vpc_id (str): The requestor vpc_id.
        vpc_peer_id (str): The accepter vpc_id.
        tags (list): List of dictionaries containing the tags you would like to
            add or update in this peer.

    Kwargs:
        peer_owner_id (str): The AWS Account you want to peer against.
            default=None
        accept_peer (bool): if set to True, the peer will be accepted.
            default=False (Peer will only be accepted if it is in the same AWS account)
        accept_with_profile (str): The name of the profile that you have set in your
            ~/.aws/credentials profile.
        region (str): The aws region you want to connect to.
        accepter_routes (list): list of route table ids that you want
            to add routes to the cidr that belongs to the peer of the newly
            created peering_connection
            default=None
        requester_routes (list): list of route table ids that you want
            to add routes to the cidr that belongs to the vpc that is
            initiating the creation of the newly created peering_connection
            default=None
        check_mode (bool): This will pass DryRun as one of the parameters to the aws api.
            default=False

    Basic Usage:
        >>> client = boto3.client('ec2')
        >>> vpc_id = 'vpc-1234567'
        >>> vpc_peer_id = 'vpc-7654321'
        >>> tags = [{'Name': 'Service', 'Values': ['Development']}]
        >>> create(client, vpc_id, vpc_peer_id, tags, accept_peer=True)
        [
            True,
            True,
            "",
            {
                "status": {
                    "message": "Active",
                    "code": "active"
                },
                "tags": [
                    {
                        "value": "web",
                        "key": "service"
                    },
                    {
                        "value": "Shaolin Allen",
                        "key": "Name"
                    },
                    {
                        "value": "development",
                        "key": "env"
                    }
                ],
                "accepter_vpc_info": {
                    "owner_id": "12345678910",
                    "vpc_id": "vpc-12345678",
                    "cidr_block": "172.31.0.0/16"
                },
                "vpc_peering_connection_id": "pcx-12345678",
                "requester_vpc_info": {
                    "owner_id": "12345678910",
                    "vpc_id": "vpc-12345678",
                    "cidr_block": "10.100.0.0/16"
                }
            }
        ]

    Return:
        Tuple (bool, bool, str, dict)
    """
    runit = False
    updateit = False
    changed = False
    success = False
    err_msg = ''
    results = dict()
    params = {
        'VpcId': vpc_id,
        'PeerVpcId': vpc_peer_id,
        'DryRun': check_mode
    }
    if peer_owner_id:
        params['PeerOwnerId'] = peer_owner_id

    success, err_msg, results = (
        describe_peering_connections(
            client, params['VpcId'], params['PeerVpcId'],
            status_codes=['active']
        )
    )
    if results:
        updateit = True
    else:
        runit = True

    if runit:
        success, changed, err_msg, results = (
            runner(client, 'present', params)
        )
        if success and changed:
            updateit = True

    if updateit:
        if isinstance(results, list):
            results = convert_to_lower(results[0])
        vpc_peering_id = results['vpc_peering_connection_id']
        success, changed, err_msg, results = (
            update(
                client, vpc_peering_id, tags, accept_peer,
                accept_with_profile, region, accepter_routes,
                requester_routes, check_mode
            )
        )
        if success:
            err_msg = ''

    results = convert_to_lower(results)
    if results.get('tags', None):
        results['tags'] = convert_list_of_tags(results['tags'])

    return success, changed, err_msg, results

def main():
    argument_spec = ec2_argument_spec()
    argument_spec.update(
        dict(
            accepter_routes=dict(type='list'),
            requester_routes=dict(type='list'),
            vpc_id=dict(),
            vpc_peer_id=dict(),
            vpc_peering_id=dict(),
            peer_owner_id=dict(),
            accept_peer=dict(type='bool', default=False),
            profile=dict(),
            accept_with_profile=dict(),
            resource_tags=dict(type='dict'),
            state=dict(
                default='present', choices=[
                    'present', 'absent', 'accept', 'reject'
                ]
            )
        )
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    if not HAS_BOTO3:
        module.fail_json(msg='boto3 is required.')

    check_mode = module.check_mode
    accept_with_profile = module.params.get('accept_with_profile')
    accepter_routes = module.params.get('accepter_routes')
    requester_routes = module.params.get('requester_routes')
    boto_profile = module.params.get('profile')
    vpc_id = module.params.get('vpc_id')
    vpc_peer_id = module.params.get('vpc_peer_id')
    vpc_peering_id = module.params.get('vpc_peering_id')
    peer_owner_id = module.params.get('peer_owner_id')
    accept_peer = module.params.get('accept_peer')
    tags = module.params.get('resource_tags')
    state = module.params.get('state').lower()

    if tags:
        tags = make_tags_in_aws_format(tags)

    if state == 'present' and not tags:
        err_msg = "parameters state=present and tags are required together"
        module.fail_json(
            success=False, changed=False, result={}, msg=err_msg
        )

    if accept_with_profile and state == 'present' and not accept_peer:
        err_msg = "accept_with_profile can only be used with accept_peer"
        module.fail_json(
            success=False, changed=False, result={}, msg=err_msg
        )

    try:
        region, ec2_url, aws_connect_kwargs = (
            get_aws_connection_info(module, boto3=True)
        )
        client = (
            boto3_conn(
                module, conn_type='client', resource='ec2',
                region=region, endpoint=ec2_url, **aws_connect_kwargs
            )
        )
    except botocore.exceptions.ClientError, e:
        err_msg = 'Boto3 Client Error - {0}'.format(str(e.msg))
        module.fail_json(
            success=False, changed=False, result={}, msg=err_msg
        )

    if boto_profile:
        client, err_msg = create_client_with_profile(boto_profile, region)
        if err_msg:
            module.fail_json(
                success=False, changed=False, result={}, msg=err_msg
            )

    if state == 'accept':
        success, changed, err_msg, results = (
            accept(client, vpc_peering_id, check_mode=check_mode)
        )
        if success and changed:
            err_msg = (
                'Peering connection {0} accepted.'
                .format(vpc_peering_id)
            )

    elif state == 'present':
        success, changed, err_msg, results = (
            create(
                client, vpc_id, vpc_peer_id, peer_owner_id=peer_owner_id,
                tags=tags, accept_peer=accept_peer,
                accept_with_profile=accept_with_profile,
                accepter_routes=accepter_routes,
                requester_routes=requester_routes, check_mode=check_mode,
                region=region
            )
        )
        if success and changed:
            vpc_peering_id = results['vpc_peering_connection_id']
            status_code = results['status']['code']
            err_msg = (
                'peering connection {0} created. Current status is {1}.'
                .format(vpc_peering_id, status_code)
            )

    elif state == 'reject':
        success, changed, err_msg, results = (
            reject(client, vpc_peering_id, check_mode=check_mode)
        )
        if success and changed:
            err_msg = 'Peering connection {0} rejected.'.format(vpc_peering_id)

    elif state == 'absent':
        success, changed, err_msg, results = (
            delete(client, vpc_peering_id, check_mode=check_mode)
        )
        if success and changed:
            err_msg = 'Peering connection {0} deleted.'.format(vpc_peering_id)

    if success:
        module.exit_json(
            success=success, changed=changed, msg=err_msg, **results
        )
    else:
        module.fail_json(
            success=success, changed=changed, msg=err_msg, result=results
        )


# import module snippets
from ansible.module_utils.basic import *
from ansible.module_utils.ec2 import *

if __name__ == '__main__':
    main()

