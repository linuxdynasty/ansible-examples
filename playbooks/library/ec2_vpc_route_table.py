#!/usr/bin/python
#
# This is a free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This Ansible library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this library.  If not, see <http://www.gnu.org/licenses/>.

DOCUMENTATION = '''
---
module: ec2_vpc_route_table
short_description: Manage route tables for AWS virtual private clouds
description:
    - Manage route tables for AWS virtual private clouds
version_added: "2.2"
author: Robert Estelle (@erydo), Rob White (@wimnat), Allen Sanabria (@linuxdynasty)
options:
  lookup:
    description:
      - "This option is deprecated. Tags are manadatory when creating a route
      table. If a route table id is specified, then that will be use. Otherwise, this module will perform an exact match for all the tags applied. If a match is not found, it will than search by tag Name."
      - "Look up route table by either tags or by route table ID. Non-unique
      tag lookup will fail. If no tags are specifed then no lookup for an existing route table is performed and a new route table will be created. To change tags of a route table, you must look up by id."
    required: false
    default: tag
    choices: [ 'tag', 'id' ]
  propagating_vgw_ids:
    description:
      - "Enable route propagation from virtual gateways specified by ID. Only 1 virtual gateway can only be applied to a vpc at a time."
    default: None
    required: false
  route_table_id:
    description:
      - "The ID of the route table to update or delete."
    required: false
    default: null
  routes:
    description:
      - "List of routes in the route table. Routes are specified as dicts
      containing the keys 'dest' and one of 'gateway_id', 'instance_id', 'nat_gateway_id', interface_id', or 'vpc_peering_connection_id'. If 'gateway_id' is specified, you can refer to the VPC's IGW by using the value 'igw'."
    required: true
  state:
    description:
      - "Create or destroy the VPC route table"
    required: false
    default: present
    choices: [ 'present', 'absent' ]
  subnets:
    description:
      - "An array of subnets to add to this route table. Subnets may be specified by either subnet ID, Name tag, or by a CIDR such as '10.0.0.0/24'."
    required: true
  tags:
    description:
      - "A dictionary of resource tags of the form: { tag1: value1, tag2: value2 }. Tags are used to uniquely identify route tables within a VPC when the route_table_id is not supplied."
    required: false
    default: null
    aliases: [ "resource_tags" ]
  vpc_id:
    description:
      - "VPC ID of the VPC in which to create the route table."
    required: true
extends_documentation_fragment:
    - aws
    - ec2
'''

EXAMPLES = '''
# Note: These examples do not set authentication details, see the AWS Guide for details.

# Basic creation example:
- name: Set up public subnet route table
  ec2_vpc_route_table:
    vpc_id: vpc-1245678
    region: us-west-1
    tags:
      Name: Public
    subnets:
      - "{{ jumpbox_subnet.subnet.id }}"
      - "{{ frontend_subnet.subnet.id }}"
      - "{{ vpn_subnet.subnet_id }}"
    routes:
      - dest: 0.0.0.0/0
        gateway_id: "{{ igw.gateway_id }}"
  register: public_route_table

- name: Set up NAT-protected route table
  ec2_vpc_route_table:
    vpc_id: vpc-1245678
    region: us-west-1
    tags:
      Name: Internal
    subnets:
      - "{{ application_subnet.subnet.id }}"
      - 'Database Subnet'
      - '10.0.0.0/8'
    routes:
      - dest: 0.0.0.0/0
        instance_id: "{{ nat.instance_id }}"
  register: nat_route_table

'''

try:
    import botocore
    import boto3
    from boto.exception import EC2ResponseError
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False

import re
import datetime
from functools import reduce
from time import sleep

DRY_RUN_MATCH = re.compile(r'DryRun flag is set')

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

GATEWAY_MAP = {
    'gateway_id': 'GatewayId',
    'instance_id': 'InstanceId',
    'network_interface_id': 'NetworkInterfaceId',
    'vpc_peering_connection_id': 'VpcPeeringConnectionId',
    'nat_gateway_id': 'NatGatewayId',
}

def valid_gateway_types():
    """List of currently supported gateway types in Boto3

    Basic Usage
        >>> valid_gateway_types()

    Returns:
        List
    """
    return  [
        'gateway_id',
        'instance_id',
        'network_interface_id',
        'vpc_peering_connection_id',
        'nat_gateway_id'
    ]

def valid_route_type(route):
    """Validate if dictionary contains a valid gateway key.

    Args:
        route (dict): Dictionary containing the route information.

    Basic Usage:
        >>> route = {'dest': '0.0.0.0/0', 'nat_gateway_id': 'ngw-123456789'}
        >>> success, key = valid_route_type(route)

    Returns:
        Tuple (bool, str)
    """
    success = False
    for key, val in route.items():
        if key != 'dest' and key in valid_gateway_types():
            success = True
            return success, key
        elif key != 'dest' and key not in valid_gateway_types():
            return success, key

def validate_routes(routes):
    """Validate if all of the routes contain valid gateway keys.
    Args:
        routes (list): List of routes.

    Basic Usage:
        >>> routes = [{'dest': '0.0.0.0/0', 'nat_gateway_id': 'ngw-123456789'}]
        >>> success, err_msg = validate_routes(routes)

    Returns:
        Tuple (bool, str)
    """
    success = True
    err_msg = ''
    for route in routes:
        success, route_type = valid_route_type(route)
        if not success:
            err_msg = '{0} is not a valid gateway type'.format(route_type)
    return success, err_msg

def route_keys(client, vpc_id, routes, check_mode=False):
    """Return a new list containing updated keys.
    Args:
        client (botocore.client.EC2): Boto3 client.
        vpc_id (str): The vpc_id of the vpc.
        routes (list): List of routes.

    Basic Usage:
        >>> client = boto3.client('ec2')
        >>> vpc_id = 'vpc-1234567'
        >>> routes = [{'dest': '0.0.0.0/0', 'nat_gateway_id': 'ngw-123456789'}]
        >>> new_routes = route_keys(client, vpc_id, routes)
        [
            {
                'dest': '0.0.0.0/0',
                'id': 'ngw-123456789',
                'gateway_type': 'nat_gateway_id'
            }
        ]

    Returns:
        List
    """
    new_routes = list()
    for route in routes:
        info = dict()
        for key, val in route.items():
            if key != 'dest' and key in valid_gateway_types():
                if key == 'gateway_id' and val == 'igw':
                    igw_success, igw_msg, igw_id = (
                        find_igw(client, vpc_id, check_mode=check_mode)
                    )
                    if igw_success and igw_id:
                        val = igw_id
                info['id'] = val
                info['gateway_type'] = key
            elif key == 'dest':
                info['dest'] = val
        new_routes.append(info)
    return new_routes

def make_tags_in_proper_format(tags):
    """Take a dictionary of tags and convert them into the AWS Tags format.
    Args:
        tags (list): The tags you want applied.

    Basic Usage:
        >>> tags = [{u'Key': 'env', u'Value': 'development'}]
        >>> make_tags_in_proper_format(tags)
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
    for tag in tags:
        formatted_tags.append(
            {
                tag.get('Key'): tag.get('Value')
            }
        )

    return formatted_tags

def make_tags_in_aws_format(tags):
    """Take a dictionary of tags and convert them into the AWS Tags format.
    Args:
        tags (dict): The tags you want applied.

    Basic Usage:
        >>> tags = {'env': 'development', 'service': 'web'}
        >>> make_tags_in_proper_format(tags)
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

def find_igw(client, vpc_id, check_mode=False):
    """Find an Internet Gateway for a VPC.
    Args:
        client (botocore.client.EC2): Boto3 client.
        vpc_id (str): The vpc_id of the vpc.

    Kwargs:
        check_mode (bool): This will pass DryRun as one of the parameters to the aws api.
            default=False

    Basic Usage:
        >>> client = boto3.client('ec2')
        >>> vpc_id = 'vpc-1234567'
        >>> find_igw(client, vpc_id)

    Returns:
        Tuple (bool, str, str)
    """
    err_msg = ''
    success = False
    igw_id = None
    params = {
        'DryRun': check_mode,
        'Filters': [
            {
                'Name': 'attachment.vpc-id',
                'Values': [vpc_id],
            }
        ]
    }
    try:
        results = (
            client.describe_internet_gateways(**params)['InternetGateways']
        )
        if len(results) == 1:
            success = True
            igw_id = results[0]['InternetGatewayId']
    except botocore.exceptions.ClientError, e:
        if e.response['Error']['Code'] == 'DryRunOperation':
            success = True
            err_msg = e.message
        else:
            err_msg = str(e)

    return success, err_msg, igw_id

def find_subnet_associations(client, vpc_id, subnet_ids, check_mode=False):
    """Find all route tables that contain the subnet_ids within vpc_id.
    Args:
        client (botocore.client.EC2): Boto3 client.
        vpc_id (str): The vpc_id of the vpc.
        subnet_ids (list): List of subnet_ids.

    Kwargs:
        check_mode (bool): This will pass DryRun as one of the parameters to the aws api.
            default=False

    Basic Usage:
        >>> client = boto3.client('ec2')
        >>> vpc_id = 'vpc-1234567'
        >>> subnet_ids = ['subnet-1234567', 'subnet-7654321']
        >>> find_subnet_associations(client, vpc_id, subnet_ids)

    Returns:
        Tuple (bool, str, list)
    """
    err_msg = ''
    success = False
    results = list()
    params = {
        'DryRun': check_mode,
        'Filters': [
            {
                'Name': 'vpc-id',
                'Values': [vpc_id],
            },
            {
                'Name': 'association.subnet-id',
                'Values': subnet_ids
            }
        ]
    }
    try:
        results = client.describe_route_tables(**params)['RouteTables']
        success = True
    except botocore.exceptions.ClientError, e:
        if e.response['Error']['Code'] == 'DryRunOperation':
            success = True
            err_msg = e.message
        else:
            err_msg = str(e)

    return success, err_msg, results

def find_route_table(client, vpc_id, tags=None, route_table_id=None,
                     check_mode=False):
    """Find a route table in a vpc by either the route_table_id or by matching
        the exact list of tags that were passed.
    Args:
        client (botocore.client.EC2): Boto3 client.
        vpc_id (str): The vpc_id of the vpc.

    Kwargs:
        tags (dict): Dictionary containing the tags you want to search by.
        route_table_id (str): The route table id.
        check_mode (bool): This will pass DryRun as one of the parameters to the aws api.
            default=False

    Basic Usage:
        >>> client = boto3.client('ec2')
        >>> vpc_id = 'vpc-1234567'
        >>> tags = {'Name': 'Public-Route-Table-A'}
        >>> find_route_table(client, vpc_id, tags=tags)

    Returns:
        Tuple (bool, str, list)
    """

    err_msg = ''
    success = False
    results = dict()
    params = {
        'DryRun': check_mode,
        'Filters': [
            {
                'Name': 'vpc-id',
                'Values': [vpc_id],
            }
        ]
    }
    if tags and not route_table_id:
        for key, val in tags.items():
            params['Filters'].append(
                {
                    'Name': 'tag:{0}'.format(key),
                    'Values': [ val ]
                }
            )
    elif route_table_id and not tags:
        params['RouteTableIds'] = [route_table_id]

    elif route_table_id and tags:
        #If route table id is passed with tags, use route_table_id
        params['RouteTableIds'] = [route_table_id]
    else:
        err_msg = 'Must lookup by tag or by id'

    try:
        results = client.describe_route_tables(**params)['RouteTables']
        if len(results) == 1:
            results = results[0]
            success = True
        elif len(results) > 1:
            err_msg = 'More than 1 route found'
        else:
            err_msg = 'No routes found'
            success = True
    except botocore.exceptions.ClientError, e:
        if e.response['Error']['Code'] == 'DryRunOperation':
            success = True
            err_msg = e.message
        else:
            err_msg = str(e)

    return success, err_msg, results

def tags_action(client, resource_id, tags, action='create', check_mode=False):
    """Create or delete multiple tags from an Amazon resource id
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
    sleep(2)
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

def update_tags(client, resource_id, current_tags, tags, check_mode=False):
    """Update tags for an amazon resource.
    Args:
        resource_id (str): The Amazon resource id.
        current_tags (list): List of dictionaries.
            examples.. [{Name: "", Values: [""]}]
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
                    check_mode=check_mode
                )
            )
            if not delete_success:
                return delete_success, delete_msg
        if tags_to_update:
            tags = recreate_tags_from_list(tags_to_update)
        else:
            return True, 'Tags do not need to be updated'

    if tags:
        create_success, create_msg = (
            tags_action(
                client, resource_id, tags, action='create',
                check_mode=check_mode
            )
        )
        return create_success, create_msg

    return success, err_msg

def vgw_action(client, route_table_id, vgw_id, action='create'):
    """Enable or disable multiple a virtual gateway from an Amazon route table.
    Args:
        client (botocore.client.EC2): Boto3 client.
        route_table_id (str): The Amazon resource id.
        vgw_id (str): The virtual gateway id.

    Kwargs:
        action (str): The action to perform.
            valid actions == create and delete
            default=create

    Basic Usage:
        >>> client = boto3.client('ec2')
        >>> route_table_id = 'rtb-123345678'
        >>> vgw_id = 'vgw-1234567'
        >>> vgw_action(client, route_table_id, vgw_id, 'create')
        [True, '']

    Returns:
        List (bool, str)
    """
    success = False
    err_msg = ''
    params = {
        'GatewayId': vgw_id,
        'RouteTableId': route_table_id,
    }
    try:
        if action == 'create':
            client.enable_vgw_route_propagation(**params)
            success = True
        elif action == 'delete':
            client.disable_vgw_route_propagation(**params)
            success = True
        else:
            err_msg = 'Invalid action {0}'.format(action)

    except botocore.exceptions.ClientError, e:
        err_msg = str(e)

    return success, err_msg

def update_vgw(client, route_table_id, current_vgws, vgw_id=None):
    """Update the virtual gateway status on an Amazon route table.
    Args:
        client (botocore.client.EC2): Boto3 client.
        route_table_id (str): The Amazon resource id.
        current_vgws (list): List, containing enabled virtual gateways.
        vgw_id (str): The virtual gateway id you want to keep enabled.

    Basic Usage:
        >>> client = boto3.client('ec2')
        >>> route_table_id = 'rtb-123345678'
        >>> current_vgws = [{u'GatewayId': 'vgw-1234567'}]
        >>> vgw_id = 'vgw-1234567'
        >>> update_vgw(client, route_table_id, current_vgws, vgw_id)
        [True, '']

    Returns:
        List (bool, str)
    """
    success = True
    err_msg = ''
    if current_vgws:
        for vgws in current_vgws:
            for vgw in vgws.values():
                if vgw != vgw_id or not vgw_id:
                    if not vgw_id:
                       vgw_to_delete_id = vgw
                    else:
                        vgw_to_delete_id = vgw_id
                    disable_success, disable_msg = (
                        vgw_action(
                            client, route_table_id, vgw_to_delete_id, 'delete'
                        )
                    )
                    if vgw_id and disable_success:
                        enable_success, enable_msg = (
                            vgw_action(client, route_table_id, vgw_id)
                        )
                        return enable_success, enable_msg
                    else:
                        return disable_success, disable_msg
    elif not current_vgws and vgw_id:
        enable_success, enable_msg = (
            vgw_action(client, route_table_id, vgw_id)
        )
        return enable_success, enable_msg
    return success, err_msg

def subnet_action(client, route_table_id, subnet_id=None, association_id=None,
                  action='create', check_mode=False):
    """Associate or Disasscoiate subnet_id from an Amazon route table.
    Args:
        client (botocore.client.EC2): Boto3 client.
        route_table_id (str): The Amazon resource id for a route table.

    Kwargs:
        subnet_id (str): The Amazon resource id for a subnet.
        association_id (str): The Amazon resource id for an association.
        action (str): The action to perform.
            valid actions == create and delete
            default=create

    Basic Usage:
        >>> client = boto3.client('ec2')
        >>> route_table_id = 'rtb-123345678'
        >>> subnet_id = 'subnet-1234567'
        >>> subnet_action(client, route_table_id, subnet_id, 'create')
        [True, '']

    Returns:
        List (bool, str)
    """
    success = False
    err_msg = ''
    params = {
        'DryRun': check_mode
    }
    try:
        if action == 'create':
            params['SubnetId'] = subnet_id
            params['RouteTableId'] = route_table_id
            client.associate_route_table(**params)
            success = True
        elif action == 'delete':
            params['AssociationId'] = association_id
            client.disassociate_route_table(**params)
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

def update_subnets(client, vpc_id, route_table_id, current_subnets,
                  new_subnet_ids, check_mode=False):
    """Update the associated subnets on an Amazon route table.
    Args:
        client (botocore.client.EC2): Boto3 client.
        vpc_id (str): The Amazon resource id of the vpc.
        route_table_id (str): The Amazon resource id of the route table.
        current_subnets (list): List, containing the current subnets.
        new_subnet_ids (str): List, containing the new subnet ids you want
            associated with this route table.

    Kwargs:
        check_mode (bool): This will pass DryRun as one of the parameters to the aws api.
            default=False

    Basic Usage:
        >>> client = boto3.client('ec2')
        >>> vpc_id = 'vpc-1234567'
        >>> route_table_id = 'rtb-123345678'
        >>> current_subnets = [
            {
                u'SubnetId': 'subnet-1234567',
                u'RouteTableAssociationId': 'rtbassoc-1234567',
                u'Main': False,
                u'RouteTableId': 'rtb-1234567'
            }
        ]
        >>> subnet_ids = ['subnet-7654321', 'subnet-243567']
        >>> update_subnets(client, vpc_id, route_table_id, current_subnets, subnet_ids)
        [True, '']

    Returns:
        List (bool, str)
    """
    current_subnet_ids = (
        map(
            lambda subnet: subnet['SubnetId'], current_subnets
        )
    )
    subnet_ids_to_add = (
        list(set(new_subnet_ids).difference(current_subnet_ids))
    )
    subnet_ids_to_remove = (
        list(set(current_subnet_ids).difference(new_subnet_ids))
    )
    association_ids_to_remove = list()
    for subnet_id in subnet_ids_to_remove:
        for subnet in current_subnets:
            subnet = convert_to_lower(subnet)
            if subnet_id == subnet['subnet_id']:
                association_ids_to_remove.append(
                    subnet['route_table_association_id']
                )

    success, err_msg, routes = (
        find_subnet_associations(
            client, vpc_id, subnet_ids_to_add, check_mode=check_mode
        )
    )
    association_ids_to_remove_before_adding = list()
    if success:
        for route in routes:
            for association in route['Associations']:
                association_ids_to_remove_before_adding.append(
                    association['RouteTableAssociationId']
                )
        for association_id in association_ids_to_remove_before_adding:
            delete_success, delete_msg = (
                subnet_action(
                    client, route_table_id, association_id=association_id,
                    action='delete', check_mode=check_mode
                )
            )
            if not delete_success:
                return delete_success, delete_msg

    for subnet_id in subnet_ids_to_add:
        create_success, create_msg = (
            subnet_action(
                client, route_table_id, subnet_id, action='create',
                check_mode=check_mode
            )
        )
        if not create_success:
            return create_success, create_msg

    for association_id in association_ids_to_remove:
        delete_success, delete_msg = (
            subnet_action(
                client, route_table_id, association_id=association_id,
                action='delete', check_mode=False
            )
        )
        if not delete_success:
            return delete_success, delete_msg

    return True, ''

def route_table_action(client, vpc_id=None, route_table_id=None,
                       action='create', check_mode=False):
    """Create or Delete an Amazon route table.
    Args:
        client (botocore.client.EC2): Boto3 client.

    Kwargs:
        vpc_id (str): The Amazon resource id for a vpc.
        route_table_id (str): The Amazon resource id for a route table.
        action (str): The action to perform.
            valid actions == create and delete
            default=create
        check_mode (bool): This will pass DryRun as one of the parameters to the aws api.
            default=False

    Basic Usage:
        >>> client = boto3.client('ec2')
        >>> vpc_id = 'vpc-123345678'
        >>> route_table_action(client, vpc_id, 'create')
        [True, '']

    Returns:
        List (bool, str)
    """
    success = False
    err_msg = ''
    route_table = dict()
    params = {
        'DryRun': check_mode
    }
    try:
        if action == 'create' and vpc_id:
            params['VpcId'] = vpc_id
            route_table = client.create_route_table(**params)['RouteTable']
            success = True
        elif action == 'delete' and route_table_id:
            params['RouteTableId'] = route_table_id
            client.delete_route_table(**params)
            success = True
        elif action == 'create' and not vpc_id:
            err_msg = 'Action create needs parameter vpc_id'
        elif action == 'delete' and not route_table_id:
            err_msg = 'Action delete needs parameter route_table_id'
        else:
            err_msg = 'Invalid action {0}'.format(action)

    except botocore.exceptions.ClientError, e:
        if e.response['Error']['Code'] == 'DryRunOperation':
            success = True
            err_msg = e.message
        else:
            err_msg = str(e)

    return success, err_msg, route_table

def route_action(client, route, route_table_id, action='create',
                 check_mode=False):
    """Create or Delete a route on an Amazon route table.
    Args:
        client (botocore.client.EC2): Boto3 client.
        route (dict): Dictionary, containing the necessary data for a route.
        route_table_id (str): The Amazon resource id for a route table.

    Kwargs:
        action (str): The action to perform.
            valid actions == create and delete
            default=create
        check_mode (bool): This will pass DryRun as one of the parameters to the aws api.
            default=False

    Basic Usage:
        >>> client = boto3.client('ec2')
        >>> route = {
            'dest': '0.0.0.0/0',
            'gateway_type': 'nat_gateway_id',
            'id': 'ngw-12345678'
        }
        >>> route_table_id = 'rtb-123345678'
        >>> route_action(client, route, route_table_id, 'create')
        [True, '']

    Returns:
        List (bool, str)
    """
    success = False
    err_msg = ''
    params = {
        'DestinationCidrBlock': route['dest'],
        'RouteTableId': route_table_id,
        'DryRun': check_mode
    }
    if action == 'create':
        params[GATEWAY_MAP[route['gateway_type']]] =  route['id']

    try:
        if action == 'create':
            success = client.create_route(**params)['Return']
        elif action == 'delete':
            client.delete_route(**params)
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

def update_route(client, route_table_id, current_routes, route_to_update,
                 check_mode=False):
    """Update the routes on an Amazon route table.
    Args:
        client (botocore.client.EC2): Boto3 client.
        route_table_id (str): The Amazon resource id of the route table.
        current_routes (list): List, containing the current routes.
        route_to_update (str): List, containing the new subnet ids you want
            associated with this route table.

    Kwargs:
        check_mode (bool): This will pass DryRun as one of the parameters to the aws api.
            default=False

    Basic Usage:
        >>> client = boto3.client('ec2')
        >>> vpc_id = 'vpc-1234567'
        >>> route_table_id = 'rtb-123345678'
        >>> current_routes = [
            {
                u'GatewayId': 'local',
                u'DestinationCidrBlock': '10.100.0.0/16',
                u'State': 'active',
                u'Origin': 'CreateRouteTable'
            },
            {
                u'Origin': 'CreateRoute',
                u'DestinationCidrBlock': '0.0.0.0/0',
                u'GatewayId': 'igw-1234567',
                u'State': 'active'
            }
        ]
        >>> routes_to_update = [
            {
                'dest': '0.0.0.0/0',
                'gateway_type': 'nat_gateway_id',
                'id': 'nat-987654321'
            }
        ]
        >>> update_route(client, route_table_id, current_routes, routes_to_update)
        [True, '']

    Returns:
        List (bool, str)
    """
    for route in current_routes:
        route = convert_to_lower(route)
        if route['origin'] != 'create_route_table' and len(current_routes) > 1:
            if route['destination_cidr_block'] == route_to_update['dest']:
                gateway_key = route_to_update['gateway_type']
                if route.has_key(gateway_key):
                    return True, 'route already exists'
                else:
                    delete_success, delete_msg = (
                        route_action(
                            client, route_to_update, route_table_id,
                            'delete', check_mode=check_mode
                        )
                    )
                    if delete_success:
                        create_success, create_msg = (
                            route_action(
                                client, route_to_update, route_table_id,
                                'create', check_mode=check_mode
                            )
                        )
                        return create_success, create_msg
                    else:
                        return delete_success, delete_msg
        elif len(current_routes) == 1:
            create_success, create_msg = (
                route_action(
                    client, route_to_update, route_table_id,
                    'create', check_mode
                )
            )
            return create_success, create_msg

def update(client, vpc_id, route_table_id, current_route_table, routes=None,
           subnets=None, tags=None, vgw_id=None, check_mode=False):
    """Update the attributes of a route table.
    Args:
        client (botocore.client.EC2): Boto3 client.
        vpc_id (str): The Amazon resource id for a vpc.
        route_table_id (str): The Amazon resource id of the route table.
        current_routes (list): List, containing the current routes.

    Kwargs:
        routes (list): List, containing the necessary data for a route.
        subnets (str): List, containing the new subnet ids you want
            associated with this route table.
        tags (dict): Dictionary containing the tags you want to search by.
        vgw_id (str): The Virtual Gateway you want to enable.
        check_mode (bool): This will pass DryRun as one of the parameters to the aws api.
            default=False

    Basic Usage:
        >>> client = boto3.client('ec2')
        >>> vpc_id = 'vpc-1234567'
        >>> current_routes = [
            {
                u'GatewayId': 'local',
                u'DestinationCidrBlock': '10.100.0.0/16',
                u'State': 'active',
                u'Origin': 'CreateRouteTable'
            }
        ]
        >>> routes = [
            {
                'dest': '0.0.0.0/0',
                'nat_gateway_id': 'nat-12345678'
            }
        ]
        >>> subnets = ['subnet-1234567', 'subnet-7654321']
        >>> tags = {'env': 'development', 'Name': 'dev_route_table'}

    Returns:
        Tuple (bool, str)
    """
    success = True
    err_msg = ''
    if tags:
        tags = make_tags_in_aws_format(tags)
        tag_success, tag_msg = (
            update_tags(
                client, route_table_id, current_route_table['Tags'], tags,
                check_mode=check_mode
            )
        )
        if not tag_success:
            success = False
            return tag_success, tag_msg

    if subnets:
        subnet_success, subnet_msg = (
            update_subnets(
                client, vpc_id, route_table_id,
                current_route_table['Associations'], subnets,
                check_mode=check_mode
            )
        )
        if not subnet_success:
            success = False
            return subnet_success, subnet_msg

    if routes:
        routes = route_keys(client, vpc_id, routes, check_mode)
        for route in routes:
            routes_success, routes_msg = (
                update_route(
                    client, route_table_id, current_route_table['Routes'],
                    route, check_mode
                )
            )
            if not routes_success:
                success = False
                return routes_success, routes_msg

    vgw_success, vgw_msg = (
        update_vgw(
            client, route_table_id, current_route_table['PropagatingVgws'],
            vgw_id
        )
    )
    if not vgw_success:
        success = False
        return vgw_success, vgw_msg

    return success, err_msg

def pre_create_route_table(client, vpc_id, routes, subnets, tags, vgw_id=None,
                           route_table_id=None, check_mode=False):
    """Find route and if it exists update it. If not return back to
        create_route_table. This should not be called directly, except by
        create_route_table.
    Args:
        client (botocore.client.EC2): Boto3 client.
        vpc_id (str): The Amazon resource id for a vpc.
        routes (list): List, containing the necessary data for a route.
        subnets (str): List, containing the new subnet ids you want
            associated with this route table.
        tags (dict): Dictionary containing the tags you want to search by.

    Kwargs:
        vgw_id (str): The Virtual Gateway you want to enable.
        route_table_id (str): The Amazon resource id of the route table.
        check_mode (bool): This will pass DryRun as one of the parameters to the aws api.
            default=False

    Basic Usage:
        >>> client = boto3.client('ec2')
        >>> vpc_id = 'vpc-1234567'
        >>> routes = [
            {
                'dest': '0.0.0.0/0',
                'nat_gateway_id': 'nat-12345678'
            }
        ]
        >>> subnets = ['subnet-1234567', 'subnet-7654321']
        >>> tags = {'env': 'development', 'Name': 'dev_route_table'}

    Returns:
        Tuple (bool, bool, str, dict)
    """

    route_table_exist = False
    route_table = None
    success, err_msg, route_table = (
        find_route_table(client, vpc_id, tags, route_table_id, check_mode)
    )
    if route_table and success:
        route_table_exist = True

    if not route_table and not route_table_id:
        if tags.get('Name', None):
            tag_wth_name_only = {'Name': tags.get('Name')}
            success, err_msg, route_table = (
                find_route_table(
                    client, vpc_id, tag_wth_name_only, check_mode=check_mode
                )
            )
            if route_table and success:
                route_table_exist = True

    if route_table_exist:
        if not route_table_id:
            route_table_id = route_table['RouteTableId']
        success, err_msg = (
            update(
                client, vpc_id, route_table_id, route_table, routes, subnets,
                tags, vgw_id, check_mode=check_mode
            )
        )

        if success:
            changed = True
            success, err_msg, route_table = (
                find_route_table(
                    client, vpc_id, tags, route_table_id, check_mode
                )
            )
        else:
            changed = False

        return success, changed, err_msg, route_table

    else:
        return False, False, 'Route table does not exist', dict()

def create_route_table(client, vpc_id, routes, subnets, tags, vgw_id=None,
                       route_table_id=None, check_mode=False):
    """Create a new route table. If route table is found by id if not
        by tag, it will then update the existing one.
    Args:
        client (botocore.client.EC2): Boto3 client.
        vpc_id (str): The Amazon resource id for a vpc.
        routes (dict): Dictionary, containing the necessary data for a route.
        subnets (str): List, containing the new subnet ids you want
            associated with this route table.
        tags (dict): Dictionary containing the tags you want to search by.

    Kwargs:
        vgw_id (str): The Virtual Gateway you want to enable.
        route_table_id (str): The Amazon resource id of the route table.
        check_mode (bool): This will pass DryRun as one of the parameters to the aws api.
            default=False

    Basic Usage:
        >>> client = boto3.client('ec2')
        >>> vpc_id = 'vpc-1234567'
        >>> routes = [
            {
                'dest': '0.0.0.0/0',
                'nat_gateway_id': 'nat-12345678'
            }
        ]
        >>> subnets = ['subnet-1234567', 'subnet-7654321']
        >>> tags = {'env': 'development', 'Name': 'dev_route_table'}
        [                                                                                                                                                                                                    [4/967]
            true,
            true,
            "Route table rtb-1234567 updated.",
            {
                "associations": [
                    {
                        "subnet_id": "subnet-12345667",
                        "route_table_id": "rtb-1234567",
                        "main": false,
                        "route_table_association_id": "rtbassoc-1234567"
                    },
                    {
                        "subnet_id": "subnet-78654321",
                        "route_table_id": "rtb-78654321",
                        "main": false,
                        "route_table_association_id": "rtbassoc-78654321"
                    }
                ],
                "tags": [
                    {
                        "key": "Name",
                        "value": "dev_route_table"
                    },
                    {
                        "key": "env",
                        "value": "development"
                    }
                ],
                "routes": [
                    {
                        "gateway_id": "local",
                        "origin": "CreateRouteTable",
                        "state": "active",
                        "destination_cidr_block": "10.100.0.0/16"
                    },
                    {
                        "origin": "CreateRoute",
                        "state": "active",
                        "nat_gateway_id": "nat-12345678",
                        "destination_cidr_block": "0.0.0.0/0"
                    }
                ],
                "route_table_id": "rtb-1234567",
                "vpc_id": "vpc-1234567",
                "propagating_vgws": []
            }
        ]

    Returns:
        Tuple (bool, bool, str, dict)
    """
    success, changed, err_msg, results = (
        pre_create_route_table(
            client, vpc_id, routes, subnets, tags, vgw_id,
            route_table_id, check_mode=check_mode
        )
    )
    if not success and not changed and err_msg == 'Route table does not exist':
        route_table_success, route_table_msg, route_table = (
            route_table_action(
                client, vpc_id=vpc_id, action='create', check_mode=check_mode
            )
        )
        if route_table_success:
            route_table_id = route_table['RouteTableId']
            success, err_msg = (
                update(
                    client, vpc_id, route_table_id, route_table, routes,
                    subnets, tags, vgw_id, check_mode
                )
            )
            changed = True
            if success:
                err_msg = 'Route table {0} created.'.format(route_table_id)
            return success, changed, err_msg, convert_to_lower(results)

    else:
        if success and changed:
            route_table_id = results['RouteTableId']
            err_msg = 'Route table {0} updated.'.format(route_table_id)
        return success, changed, err_msg, convert_to_lower(results)

def delete_route_table(client, route_table_id, check_mode=False):
    """Create a new route table. If route table is found by id if not
        by tag, it will then update the existing one.
    Args:
        client (botocore.client.EC2): Boto3 client.
        route_table_id (str): The Amazon resource id of the route table.

    Kwargs:
        check_mode (bool): This will pass DryRun as one of the parameters to the aws api.
            default=False

    Basic Usage:
        >>> client = boto3.client('ec2')
        >>> route_table_id = 'rtb-1234567'
        >>> delete_route_table(client, route_table_id)

    Returns:
        Tuple (bool, bool, str, dict)
    """
    success = False
    changed = False
    success, err_msg, results = (
        route_table_action(
            client, route_table_id=route_table_id, action='delete'
        )
    )
    if success:
        changed = True
        err_msg = 'Route table id {0} deleted'.format(route_table_id)

    return success, changed, err_msg, results

def main():
    argument_spec = ec2_argument_spec()
    argument_spec.update(
        dict(
            lookup = dict(default='tag', required=False, choices=['tag', 'id']),
            propagating_vgw_ids = dict(default=None, required=False, type='list'),
            route_table_id = dict(default=None, required=False),
            routes = dict(default=None, required=False, type='list'),
            state = dict(default='present', choices=['present', 'absent']),
            subnets = dict(default=None, required=False, type='list'),
            tags = dict(default=None, required=False, type='dict', aliases=['resource_tags']),
            vpc_id = dict(default=None, required=True)
        )
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    propagating_vgw_ids = module.params.get('propagating_vgw_ids')
    route_table_id = module.params.get('route_table_id')
    routes = module.params.get('routes')
    state = module.params.get('state')
    subnets = module.params.get('subnets')
    tags = module.params.get('tags')
    vpc_id = module.params.get('vpc_id')

    #In order to maintain backward compatability with the original version
    #I am leaving propagating_vgw_ids parameter as a list. Though you can
    #only have 1 virtual gateway enabled on a route table.
    if isinstance(propagating_vgw_ids, list):
        if len(propagating_vgw_ids) == 1:
            propagating_vgw_ids = propagating_vgw_ids[0]
        elif len(propagating_vgw_ids) == 0:
            propagating_vgw_ids = None
        else:
            module.fail_json(
                success=False, changed=False,
                msg='propagating_vgw_ids can only take in 1 parameter.'
            )

    if not HAS_BOTO3:
        module.fail_json(msg='boto3 is required.')

    check_mode = module.check_mode
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

    if routes:
        routes_validated, err_msg = validate_routes(routes)
        if not routes_validated:
            module.fail_json(
                success=False, changed=False, result={}, msg=err_msg
            )

    if state == 'present':
        success, changed, err_msg, results = (
            create_route_table(
                client, vpc_id, routes, subnets, tags,
                propagating_vgw_ids, route_table_id, check_mode
            )
        )
    elif state == 'absent':
        if route_table_id:
            success, changed, err_msg, results = (
                delete_route_table(client, route_table_id)
            )
        else:
            success = False
            changed = False
            err_msg = 'When state == absent, you must pass a route_table_id'
            results = dict()

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
