import re
import requests
from ansible import errors


def iterate_over_sg_rules(data, proto, ports, cidr=False, sg_id=False):
    sg_data = list()
    for source in data:
        if cidr:
            source_type = 'cidr_ip'
        elif sg_id:
            source_type = 'group_id'

        for port in ports:
            sg_data.append(
                {
                    "proto": proto,
                    "from_port": port,
                    "to_port": port,
                    source_type: source
                }
            )
    return sg_data

def validate_sg_rules(list_of_data, data_type="ports"):
    """
    Args:
        list_of_data: (list): List of cidr blocks or ports.

    Kwargs:
        data_type: (str): The type of data you want to validate.
            ports or cidrs. default=ports

    Basic Usage:
        >>> cidrs = ["10.0.0.100/32", "10.100.0.0/24"]
        >>> validate_sg_rules(cidrs, data_type="ports")
    """
    if not isinstance(list_of_data, list):
        raise errors.AnsibleFilterError(
            "{0} has to be a valid list of {0}".format(data_type)
        )
    elif isinstance(list_of_data, list) and len(list_of_data) == 0:
        raise errors.AnsibleFilterError(
            "{0} can not be an empty list of {0}".format(data_type)
        )
    elif isinstance(list_of_data, list) and len(list_of_data) > 0:
        for data in list_of_data:
            if data_type == "ports":
                if not isinstance(data, int):
                    raise errors.AnsibleFilterError(
                        "Please pass a valid port as an integer: {0}"
                        .format(data)
                    )
            elif data_type == "cidrs":
                if not isinstance(data, basestring):
                    raise errors.AnsibleFilterError(
                        "Please pass a valid cidr as an string: {0}"
                        .format(data)
                    )
                elif len(re.split("\.|\/", data)) != 5:
                    raise errors.AnsibleFilterError(
                        "Please pass a valid cidr block: {0}"
                        .format(data)
                    )

def make_sg_rules(cidrs=None, group_ids=None, ports=None, proto="tcp"):
    """
    Args:
        cidrs: (list): List of cidr blocks to add to the security group
            rules.
        group_ids: (list): List of group_uds to add to the security group
            rules.
        port_ranges: (list): List of ports to add to the rule sets.

    Kwargs:
        proto: (str): The protocol to use for the rules

    Basic Usage:
        >>> cidrs = ["10.0.0.100/32", "10.100.0.0/24"]
        >>> ports = [22, 80]
        >>> proto = "tcp"
        >>> rules = make_sg_rules(cidrs, ports, proto)

    Returns:
        List of security group rules
    [
        {
            "to_port": 22,
            "from_port": 22,
            "cidr_ip": "10.0.0.100/32",
            "proto": "tcp"
        },
        {
            "to_port": 80,
            "from_port": 80,
            "cidr_ip": "10.0.0.100/32",
            "proto": "tcp"
        },
        {
            "to_port": 22,
            "from_port": 22,
            "cidr_ip": "10.100.0.0/24",
            "proto": "tcp"
        },
        {
            "to_port": 80,
            "from_port": 80,
            "cidr_ip": "10.100.0.0/24",
            "proto": "tcp"
        }
    ]

    """
    validate_sg_rules(ports, data_type="ports")
    if cidrs:
        validate_sg_rules(cidrs, data_type="cidrs")
    sg_data = list()
    if cidrs:
        cidr_data = iterate_over_sg_rules(cidrs, proto, ports, cidr=True)
        sg_data.extend(cidr_data)
    if group_ids:
        sg_id_data = iterate_over_sg_rules(group_ids, proto, ports, sg_id=True)
        sg_data.extend(sg_id_data)
    return sg_data

def my_ip(url):
    cidr = "{0}/32".format(str(requests.get(url).text))
    return cidr

def build_subnet_data(region, name, env, cidrs):
    subnets = []
    for i in sorted(cidrs):
        subnet_output = {
            "cidr": cidrs[i],
            "az": "%s%s" % (region, i),
            "resource_tags": {
                "Name": "%s-%s" %(name, i.capitalize()),
                "Environment": env,
            }
        }
        subnets.append(subnet_output)
    return subnets

def parse_nat_results(zones, results=None, nat_gateway_id=None):
    """
    Args:
        results (list): List of dictionaries of the instances that were created.
        zones (list): List of zone names.

    Kwargs:
        nat_gateway_id (str): The Amazon resource id of the gateway.

    Basic Usage:
        >>> results = []
        >>> instance_ids = parse_results(results)

    Returns:
        List of ec2 instance ids
    """
    # return an attribute for all subnets that match
    nat_ids = []

    if isinstance(results, list) and isinstance(zones, list):
        if len(results) == len(zones):
            i = 0
            for item in results:
                nat_ids.append(
                    {
                        'nat_gateway_id': item.get('nat_gateway_id'),
                        'zone': zones[i][-1],
                    }
                )
                i += 1
    elif nat_gateway_id and isinstance(zones, list):
        for i in range(len(zones)):
            nat_ids.append(
                {
                    'nat_gateway_id': nat_gateway_id,
                    'zone': zones[i][-1],
                }
            )


    if len(nat_ids) > 0:
        return nat_ids
    else:
        raise errors.AnsibleFilterError("Did not find any ec2 instances")

def parse_ec2_results(results, key="id", tagged=True, az=None):
    """
    Args:
        results (list): List of dictionaries of the instances that were created.

    Kwargs:
        tagged (bool): Iterate over tagged_instances instead of instances.
            default=True
        az (str): The availability zone of the instance you want.

    Basic Usage:
        >>> results = []
        >>> instance_ids = parse_results(results)

    Returns:
        List of ec2 instance ids
    """
    # return an attribute for all subnets that match
    instances = []
    def get_instance_id(item):
        list_to_iterate = None
        if tagged:
            list_to_iterate = item.get('tagged_instances', list())
        else:
            list_to_iterate = item.get('instances', list())

        for data in list_to_iterate:
            instance_id = data.get(key, None)
            instance_az = data.get("placement", None)
            if az:
                if instance_id and instance_az == az:
                    instances.append(instance_id)
            elif instance_id:
                instances.append(instance_id)

    if isinstance(results, list):
        for item in results:
            get_instance_id(item)

    elif isinstance(results, dict):
        get_instance_id(results)

    if len(instances) > 0:
        instances = list(set(instances))
        return instances
    else:
        raise errors.AnsibleFilterError("Did not find any ec2 instances")

def parse_subnets_by_tag(subnets, tag_key, tag_value, return_key='id'):
    """
    Args:
        subnets (list): List of dictionaries of the subnets that were created.
        tag_key (str): The tag key you are searching by.
        tag_value (str): The value of the tag you want to search by.

    Kwargs:
        return_key (str): The key you want returned.

    Basic Usage:
        >>> subnets = [
            {
                "az": "eu-west-1a",
                "cidr": "10.1.0.0/24",
                "id": "subnet-f6275193",
                "resource_tags": {
                    "Environment": "dev",
                    "Name": "dev_public",
                    "Tier": "public"
                }
            },
            {
                "az": "eu-west-1a",
                "cidr": "10.1.100.0/24",
                "id": "subnet-f1275194",
                "resource_tags": {
                    "Environment": "dev",
                    "Name": "dev_private",
                    "Tier": "private"
                }
            }
        ]
        >>> tag_key = "Name"
        >>> tag_value = "Development Private"
        >>> subnet_ids = parse_subnets_by_tag(subnets, tag_key, tag_value)

    Returns:
        List of vpc subnet ids
    """
    # return an attribute for all subnets that match
    subnet_values = []
    for item in subnets:
        for key, value in item['resource_tags'].iteritems():
            if key == tag_key and value == tag_value:
                subnet_values.append(item[return_key])
    subnet_values.sort()
    return subnet_values


class FilterModule(object):
    ''' Ansible core jinja2 filters '''

    def filters(self):
        return {
            'build_subnet_data': build_subnet_data,
            'parse_subnets_by_tag': parse_subnets_by_tag,
            'parse_ec2_results': parse_ec2_results,
            'parse_nat_results': parse_nat_results,
            'my_ip': my_ip,
            'make_sg_rules': make_sg_rules,
        }
