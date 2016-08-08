# Ansible Filters for AWS in aws.py
* get_vpc_id_by_name
* get_ami_image_id
* get_instance_id_by_name
* get_subnet_ids
* get_sg
* get_sg_cidrs
* get_older_images
* get_instance
* get_all_vpcs_info_except
* get_route_table_ids
* get_all_route_table_ids
* get_all_route_table_ids_except
* get_subnet_ids_in_zone
* latest_ami_id
* get_rds_endpoint
* zones
* get_sqs
* get_instance_profile
* get_server_certificate
* vpc_exists
* get_dynamodb_base_arn
* get_kinesis_stream_arn
* get_account_id
* get_instance_by_tags
* get_instances_by_tags
* get_acm_arn
* get_redshift_ip
* get_redshift_endpoint
* get_elasticache_endpoint
* get_vpc_ids_from_names
* get_route53_id

## AWS Examples.
Example placement of the filters below *roles/vpc_deploy/vars/main.yml*
```yaml
---
aws_region: us-west-2
zone_2c: us-west-2c
vpc_name: test
vpc_id: "{{ vpc_name | get_vpc_id_by_name(aws_region) }}"
subnet_ids_in_west_2c: "{{ vpc_id | get_subnet_ids_in_zone(zone, aws_region)}}"
```
