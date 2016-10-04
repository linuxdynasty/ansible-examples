vpc_deploy
---------------------------
To build/update a VPC and all of it's dependencies.

## Role Actions.
1. Create a VPC
2. Create an IGW.
3. Create Subnets.
4. Create Security Groups.
5. Create AWS NAT instances.
6. Create/Update Route tables.
7. Create a Peering Connection (*If this is ran on the Management Environment*.)

## Variables this role is dependent on.
**You must pass 2 variables when calling ansible-playbook -e service {{ service_name }} -e env {{ env_name }}**

This role is dependant on one yaml file `vars/environments/{{ env }}/network.yml`.

Here is an example of an environment Foo
```yaml
domain: foo.com
subdomain: d2.foo.com
aws_vpc_name: Foo
env_short_name: foo
aws_cidr: 10.111.0.0/16

#PRIVATE
aws_private_subnet_name: "{{ aws_vpc_name }}-Private"
aws_private_cidrs:
  a: 10.111.10.0/24
  b: 10.111.11.0/24
  c: 10.111.12.0/24
aws_private_subnets_info: "{{ aws_region | build_subnet_data(aws_private_subnet_name, env, aws_private_cidrs) }}"

#PUBLIC
aws_public_subnet_name: "{{ aws_vpc_name }}-Public"
aws_public_elb_sg: "{{ aws_vpc_name }}ELB"
aws_public_cidrs:
  a: 10.111.0.0/24
  b: 10.111.1.0/24
  c: 10.111.2.0/24
aws_public_subnets_info: "{{ aws_region | build_subnet_data(aws_public_subnet_name, env, aws_public_cidrs) }}"

#PERSISTENT
aws_persistent_subnet_name: "{{ aws_vpc_name }}-Persistent"
aws_persistent_cidrs:
  a: 10.111.20.0/24
  b: 10.111.21.0/24
  c: 10.111.22.0/24
aws_persistent_subnets_info: "{{ aws_region | build_subnet_data(aws_persistent_subnet_name, env, aws_persistent_cidrs) }}"

aws_vpc_subnets: "{{ aws_private_cidrs.values() + aws_public_cidrs.values() + aws_persistent_cidrs.values() }}"
aws_subnets_info: "{{ aws_private_subnets_info + aws_public_subnets_info + aws_persistent_subnets_info }}"
internal_cidrs:
  a:
    - "{{ aws_private_cidrs.a }}"
    - "{{ aws_persistent_cidrs.a }}"  
  b: 
    - "{{ aws_private_cidrs.b }}"
    - "{{ aws_persistent_cidrs.b }}"
  c: 
    - "{{ aws_private_cidrs.c }}"
    - "{{ aws_persistent_cidrs.c }}"
```
