#!/usr/bin/env python
#
# Creates/Deletes a RDS Cluster with CloudFormation
#
import argparse
import time

import boto.cloudformation
import boto.ec2
import boto.vpc
import boto.vpc.subnet
from colorama import init


class Rds:
    """
    Creates or Destroys a RDS cluster.
    """

    def __init__(self, dbengine, dbengine_version, dbinstance_type, db_name,
                 master_user_name, master_password, region, environment,
                 security_group_names, dns_name, profile):
        """
        :param dbengine: str, dbengine
        :param dbengine_version: str, dbengine_version
        :param dbinstance_type: str, dbinstance_type
        :param db_name: str, db_name
        :param master_user_name: str, master_user_name
        :param master_password: str, master_password
        :param region: str, region
        :param environment: str, environment
        :param security_group_names: list, security_group_names
        :param dns_name: str, dns_name
        :param profile: str, profile
        """

        self.dbengine = dbengine
        self.dbengine_version = dbengine_version
        self.dbinstance_type = dbinstance_type
        self.db_name = db_name
        self.master_user_name = master_user_name
        self.master_password = master_password
        self.region = region
        self.environment = environment
        self.security_group_names = security_group_names
        self.dns_name = dns_name
        self.profile = profile

    def setup(self):
        """
        Creates and Deploys a RDS Cluster
        :return:
        """
        ec2_region = boto.ec2.get_region(region_name=self.region)
        if self.profile is None:
            conn_cloudform = boto.cloudformation.connect_to_region(region_name=self.region)
        else:
            conn_cloudform = boto.cloudformation.connect_to_region(region_name=self.region, profile_name=self.profile)

        vpc_id = get_main_vpc_id(environment=self.environment, region=ec2_region, profile=self.profile)
        vpc_subnets = get_vpc_subnets(region=ec2_region, vpc_id=vpc_id, profile=self.profile)
        zones = get_vpc_availability_zones(region=ec2_region, vpc_id=vpc_id, profile=self.profile)

        # Validate Security Groups and get a list of IDs.
        # If any of the Security Groups fail to validate,
        # the process will terminate.
        vpc_sg_ids = []
        for sg_name in self.security_group_names:
            sg = get_security_group(self.region, vpc_id, sg_name, profile=self.profile)
            if sg is None:
                log_error("Security group '{name}' does not exist in VPC '{vpc}'", name=sg_name, vpc=vpc_id)
                sys.exit(1)
            else:
                vpc_sg_ids.append(sg.id)

        if self.environment == "test":
            hosted_zone_name = self.environment + "data.sema.technology"
        else:
            hosted_zone_name = "data.sema.technology"
        hosted_zone = get_hosted_zone_id(zone_name=hosted_zone_name, profile=self.profile)

        if self.dns_name is None:
            dns_name = stack_name
        else:
            dns_name = self.dns_name

        params = [("ClusterName", stack_name),
                  ("CloudEnvironment", self.environment),
                  ("EC2Region", self.region),
                  ("HostedZoneName", hosted_zone_name),
                  ("HostedZoneId", hosted_zone),
                  ("DBName", self.db_name),
                  ("Engine", self.dbengine),
                  ("EngineVersion", self.dbengine_version),
                  ("MasterUserName", self.master_user_name),
                  ("MasterUserPassword", self.master_password),
                  ("DBInstanceClass", self.dbinstance_type),
                  ("SubnetIds", ",".join(vpc_subnets)),
                  ("VpcSecurityGroupIds", ",".join(vpc_sg_ids)),
                  ("AvailabilityZones", ",".join(zones)),
                  ("DNSName", dns_name)]

        with open("./template/rds.json") as file:
            template = file.read()

        log_success("Deploying '{name}' RDS cluster", name=self.db_name)
        conn_cloudform.create_stack(stack_name=stack_name,
                                    template_body=template,
                                    parameters=params,
                                    capabilities=["CAPABILITY_IAM"])

        while True:
            time.sleep(10)
            stacks = conn_cloudform.describe_stacks(stack_name)
            if len(stacks) == 1:
                stack = stacks[0]
            else:
                log_error("Invalid, more than one '{name}' stack", name=stack_name)
                return

            if stack.stack_status == "ROLLBACK_COMPLETE":
                log_error("'{name}' stack creation failed.", name=stack_name)
                return

            if stack.stack_status == "CREATE_COMPLETE":
                log_success("RDS cluster '{name}' deployed.", name=self.db_name)
                break

    def teardown(self):
        """
        Tears Down a RDS Cluster
        :return:
        """
        if self.profile is None:
            conn_cloudform = boto.cloudformation.connect_to_region(self.region)
        else:
            conn_cloudform = boto.cloudformation.connect_to_region(self.region, profile_name=self.profile)

        log_success("Deleting '{name}' stack...", name=stack_name)
        conn_cloudform.delete_stack(stack_name)

        while True:
            time.sleep(30)
            try:
                exists = conn_cloudform.describe_stacks(stack_name)
                if exists:
                    log_success("Stack '{name}' still exists...", name=stack_name)
            except:
                log_success("Deleted stack '{name}'!", name=stack_name)
                break

if __name__ == "__main__":
    if __package__ is None:
        import sys
        from os import path

        sys.path.append(path.dirname(path.dirname(path.dirname(path.abspath(__file__)))))
        from utils.logging_util import log_success, log_error
        from utils.account_util import get_main_vpc_id, get_vpc_subnets, get_hosted_zone_id, \
            get_security_group, get_vpc_availability_zones

        init()
    else:
        from utils.logging_util import log_success, log_error
        from utils.account_util import get_main_vpc_id, get_vpc_subnets, get_hosted_zone_id, \
            get_security_group, get_vpc_availability_zones

    parser = argparse.ArgumentParser(description="Creates RDS Cluster in a AWS VPC.")
    parser.add_argument("--stack-name", required=True, action="store", dest="stack_name",
                        help="Name of the CloudFormation stack")
    parser.add_argument("--db-engine", required=True, action="store", dest="dbengine",
                        help="The database engine for the instances",
                        choices=["aurora"])
    parser.add_argument("--db-engine-version", required=True, action="store", dest="dbengine_version",
                        help="Database engine version")
    parser.add_argument("--db-instance-type", required=False, action="store", dest="dbinstance_type", default="db.t2.medium",
                        help="AWS instance type",
                        choices=["db.t2.medium",
                                 "db.t2.large",
                                 "db.r3.large",
                                 "db.r3.xlarge"])
    parser.add_argument("--db-name", required=True, action="store", dest="db_name")
    parser.add_argument("--master-username", required=True, action="store", dest="master_username",
                        help="Master login ID for database cluster")
    parser.add_argument("--master-password", required=True, action="store", dest="master_password",
                        help="Password for the master user")
    parser.add_argument("--region", required=False, action="store", dest="region", default="us-west-2",
                        help="AWS region to deploy in")
    parser.add_argument("--environment", required=True, action="store", dest="environment",
                        help="The platform environment the stack is being created",
                        choices=["test",
                                 "prod"])
    parser.add_argument("--security-groups", required=True, nargs="+", action="store", dest="sg_names",
                        help="Space separated list of VPC security groups for the RDS cluster")
    parser.add_argument("--dns-simple-name", required=False, action="store", dest="dns_name",
                        help="First group name for DNS name of the cluster address")
    parser.add_argument("--profile", required=False, action="store", dest="profile",
                        help="AWS credentials profile name")

    command_group = parser.add_mutually_exclusive_group()
    command_group.add_argument("-s", "--setup", help="Creates RDS Cluster using CloudFormation.",
                               action="store_true")
    command_group.add_argument("-t", "--teardown",
                               help="Removes the cluster, security groups and cache subnet group from the account.",
                               action="store_true")
    args = parser.parse_args()

    stack_name = args.stack_name
    rdsCluster = Rds(args.dbengine, args.dbengine_version, args.dbinstance_type, args.db_name, args.master_username,
                     args.master_password, args.region, args.environment, args.sg_names, args.dns_name, args.profile)

    if args.setup:
        rdsCluster.setup()
    elif args.teardown:
        rdsCluster.teardown()
    else:
        parser.error("No action requested, add --setup, or --teardown")
