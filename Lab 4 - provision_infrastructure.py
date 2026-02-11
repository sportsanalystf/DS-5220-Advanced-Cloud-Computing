#!/usr/bin/env python3
"""
provision_infrastructure.py

Creates a minimal AWS environment for a demo instance:
- S3 bucket
- IAM role + inline policy for S3 access
- Security group allowing SSH/HTTP/Jupyter from caller IP
- Key pair (if missing)
- EC2 instance (Ubuntu) with user-data that writes a simple index.html and attempts an S3 upload
- Elastic IP associated to the instance

Includes:
- Robust error handling and logging
- Idempotent-ish behavior (checks for existing resources by name)
- cleanup() to tear down created resources
- CLI with --cleanup flag

Key decisions (brief):
- Use boto3 with explicit clients/resources to keep control over API calls.
- Use inline role policy to keep the example self-contained (no external managed policies).
- Use simple user-data that demonstrates instance metadata and S3 upload attempt.
- Keep resource names deterministic so cleanup can find them.
"""

import argparse
import json
import logging
import os
import sys
import time
from typing import Dict, Optional

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, WaiterError

# -----------------------
# Configuration / Defaults
# -----------------------
REGION = os.environ.get("AWS_REGION", "us-east-1")
AMI_ID = os.environ.get("AMI_ID", "ami-0030e4319cbf4dbf2")  # example Ubuntu AMI; replace if needed
INSTANCE_TYPE = os.environ.get("INSTANCE_TYPE", "t3.micro")
KEY_NAME = os.environ.get("KEY_NAME", "provision-demo-key")
SECURITY_GROUP_NAME = "provision-demo-sg"
ROLE_NAME = "EC2-S3-Limited-Access"
INLINE_POLICY_NAME = "AllowS3PutObjectForProvisioning"
BUCKET_NAME = "iac-python-bucket-79daea90"
INSTANCE_NAME_TAG = "provision-demo-instance"
# Ports we want open from caller IP
PORTS = {"ssh": 22, "http": 80, "jupyter": 8888}

# -----------------------
# Logging configuration
# -----------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("provision_infra")

# -----------------------
# AWS clients
# -----------------------
try:
    session = boto3.Session(region_name=REGION)
    ec2 = session.client("ec2")
    iam = session.client("iam")
    s3 = session.client("s3")
    sts = session.client("sts")
except NoCredentialsError:
    logger.exception("AWS credentials not found in environment.")
    raise

# -----------------------
# Helper functions
# -----------------------


def get_caller_identity() -> Dict:
    """Return the AWS caller identity for debugging and verification."""
    try:
        identity = sts.get_caller_identity()
        logger.debug("Caller identity: %s", identity)
        return identity
    except ClientError:
        logger.exception("Failed to get caller identity")
        raise


def ensure_s3_bucket(bucket_name: str) -> None:
    """
    Create S3 bucket if it doesn't exist.
    Note: For simplicity this uses the same region as the session.
    """
    try:
        s3.head_bucket(Bucket=bucket_name)
        logger.info("S3 bucket '%s' already exists", bucket_name)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in ("404", "NoSuchBucket", "NotFound"):
            logger.info("Creating S3 bucket '%s' in %s", bucket_name, REGION)
            create_kwargs = {"Bucket": bucket_name}
            if REGION != "us-east-1":
                create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": REGION}
            try:
                s3.create_bucket(**create_kwargs)
                logger.info("Created bucket %s", bucket_name)
            except ClientError:
                logger.exception("Failed to create bucket %s", bucket_name)
                raise
        else:
            logger.exception("Error checking bucket %s: %s", bucket_name, e)
            raise


def ensure_iam_role(role_name: str, bucket_name: str) -> str:
    """
    Ensure an IAM role exists with an inline policy that allows S3 PutObject/ListBucket/GetObject
    for the specified bucket. Returns the role name.
    """
    assume_role_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }

    try:
        iam.get_role(RoleName=role_name)
        logger.info("IAM role '%s' already exists", role_name)
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            logger.info("Creating IAM role '%s'", role_name)
            try:
                iam.create_role(
                    RoleName=role_name,
                    AssumeRolePolicyDocument=json.dumps(assume_role_policy),
                    Description="Role for EC2 to access a specific S3 bucket for provisioning demo",
                )
                logger.info("Created role %s", role_name)
            except ClientError:
                logger.exception("Failed to create role %s", role_name)
                raise
        else:
            logger.exception("Error checking role %s: %s", role_name, e)
            raise

    # Put inline policy
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject", "s3:GetObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
            }
        ],
    }
    try:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=INLINE_POLICY_NAME,
            PolicyDocument=json.dumps(policy_doc),
        )
        logger.info("Attached inline policy %s to role %s", INLINE_POLICY_NAME, role_name)
    except ClientError:
        logger.exception("Failed to attach inline policy to role %s", role_name)
        raise

    # Create instance profile if missing and attach role
    try:
        iam.get_instance_profile(InstanceProfileName=role_name)
        logger.info("Instance profile '%s' already exists", role_name)
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            logger.info("Creating instance profile '%s'", role_name)
            try:
                iam.create_instance_profile(InstanceProfileName=role_name)
            except ClientError:
                logger.exception("Failed to create instance profile %s", role_name)
                raise
        else:
            logger.exception("Error checking instance profile %s: %s", role_name, e)
            raise

    # Add role to instance profile (idempotent)
    try:
        # list roles in instance profile to check
        resp = iam.get_instance_profile(InstanceProfileName=role_name)
        roles = [r["RoleName"] for r in resp["InstanceProfile"].get("Roles", [])]
        if role_name not in roles:
            iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
            logger.info("Added role %s to instance profile %s", role_name, role_name)
        else:
            logger.debug("Role %s already in instance profile %s", role_name, role_name)
    except ClientError:
        logger.exception("Failed to add role to instance profile %s", role_name)
        raise

    return role_name


def ensure_key_pair(key_name: str) -> Optional[str]:
    """
    Ensure a key pair exists. If it doesn't, create it and write the private key to ./<key_name>.pem.
    Returns the path to the private key file (or None if it already existed locally).
    """
    local_key_path = f"./{key_name}.pem"
    try:
        ec2.describe_key_pairs(KeyNames=[key_name])
        logger.info("Key pair '%s' already exists in AWS", key_name)
    except ClientError as e:
        if e.response["Error"]["Code"] == "InvalidKeyPair.NotFound":
            logger.info("Creating key pair '%s'", key_name)
            try:
                resp = ec2.create_key_pair(KeyName=key_name)
                private_key = resp["KeyMaterial"]
                with open(local_key_path, "w", encoding="utf-8") as f:
                    f.write(private_key)
                os.chmod(local_key_path, 0o600)
                logger.info("Wrote private key to %s", local_key_path)
                return local_key_path
            except ClientError:
                logger.exception("Failed to create key pair %s", key_name)
                raise
        else:
            logger.exception("Error checking key pair %s: %s", key_name, e)
            raise
    # If key exists in AWS but not locally, warn but continue
    if not os.path.exists(local_key_path):
        logger.warning(
            "Key pair %s exists in AWS but private key not found locally at %s. "
            "You will need the private key to SSH into instances.",
            key_name,
            local_key_path,
        )
        return None
    return local_key_path


def ensure_security_group(group_name: str, description: str = "Provision demo SG") -> str:
    """
    Create or return a security group id with the given name.
    """
    try:
        resp = ec2.describe_security_groups(Filters=[{"Name": "group-name", "Values": [group_name]}])
        groups = resp.get("SecurityGroups", [])
        if groups:
            sg_id = groups[0]["GroupId"]
            logger.info("Found existing security group %s (%s)", group_name, sg_id)
            return sg_id
    except ClientError:
        logger.exception("Failed to describe security groups")
        raise

    try:
        vpcs = ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])
        vpc_id = vpcs["Vpcs"][0]["VpcId"] if vpcs.get("Vpcs") else None
        create_args = {"GroupName": group_name, "Description": description}
        if vpc_id:
            create_args["VpcId"] = vpc_id
        resp = ec2.create_security_group(**create_args)
        sg_id = resp["GroupId"]
        logger.info("Created security group %s (%s)", group_name, sg_id)
        return sg_id
    except ClientError:
        logger.exception("Failed to create security group %s", group_name)
        raise


def authorize_ingress_from_my_ip(sg_id: str, ports: Dict[str, int]) -> None:
    """
    Authorize ingress for the given ports from the caller's public IP only.
    This reduces exposure compared to opening to 0.0.0.0/0.
    """
    try:
        # Get caller public IP
        import requests  # local import to avoid hard dependency if not used elsewhere

        my_ip = requests.get("https://ifconfig.me", timeout=5).text.strip()
        cidr = f"{my_ip}/32"
        logger.info("Authorizing ingress from %s for ports %s", cidr, list(ports.values()))
    except Exception:
        logger.exception("Failed to determine public IP; falling back to 0.0.0.0/0 (less secure)")
        cidr = "0.0.0.0/0"

    # Build IpPermissions
    ip_permissions = []
    for name, port in ports.items():
        ip_permissions.append({"IpProtocol": "tcp", "FromPort": port, "ToPort": port, "IpRanges": [{"CidrIp": cidr}]})

    try:
        ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=ip_permissions)
        logger.info("Authorized ingress on SG %s", sg_id)
    except ClientError as e:
        # If rules already exist, ignore the error
        if e.response["Error"]["Code"] in ("InvalidPermission.Duplicate", "InvalidPermission"):
            logger.debug("Ingress rules already present or duplicate: %s", e)
        else:
            logger.exception("Failed to authorize ingress on %s", sg_id)
            raise


def create_instance(
    ami: str,
    instance_type: str,
    key_name: str,
    sg_id: str,
    iam_role_name: str,
    bucket_name: str,
    instance_tag: str,
) -> str:
    """
    Launch an EC2 instance with user-data that writes a simple index.html and attempts to upload to S3.
    Returns the instance id.
    """
    # user-data script: minimal, demonstrates metadata and S3 upload attempt
    user_data = f"""#!/bin/bash
set -e
apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get install -y apache2 curl awscli
systemctl enable --now apache2
INSTANCE_ID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
LOCAL_IPV4=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)
PUBLIC_IPV4=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 || echo "N/A")
AZ=$(curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone)
cat > /var/www/html/index.html <<'HTML'
<html><body>
<h1>Instance Metadata</h1>
<ul>
<li>Instance ID: ${INSTANCE_ID}</li>
<li>Local IPv4: ${LOCAL_IPV4}</li>
<li>Public IPv4: ${PUBLIC_IPV4}</li>
<li>AZ: ${AZ}</li>
</ul>
</body></html>
HTML
chown www-data:www-data /var/www/html/index.html
# Try to upload a small file to S3 to validate role permissions
echo "s3 test from $(date)" > /tmp/s3_test.txt
aws s3 cp /tmp/s3_test.txt s3://{bucket_name}/ || echo "S3 upload failed"
"""

    # Find instance profile ARN
    try:
        resp = iam.get_instance_profile(InstanceProfileName=iam_role_name)
        instance_profile_arn = resp["InstanceProfile"]["Arn"]
        logger.debug("Using instance profile ARN: %s", instance_profile_arn)
    except ClientError:
        logger.exception("Instance profile %s not found", iam_role_name)
        raise

    try:
        logger.info("Launching EC2 instance (AMI=%s, type=%s)", ami, instance_type)
        resp = ec2.run_instances(
            ImageId=ami,
            InstanceType=instance_type,
            KeyName=key_name,
            MaxCount=1,
            MinCount=1,
            SecurityGroupIds=[sg_id],
            IamInstanceProfile={"Name": iam_role_name},
            UserData=user_data,
            TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": instance_tag}]}],
        )
        instance_id = resp["Instances"][0]["InstanceId"]
        logger.info("Launched instance %s", instance_id)
        return instance_id
    except ClientError:
        logger.exception("Failed to launch instance")
        raise


def allocate_and_associate_eip(instance_id: str) -> str:
    """
    Allocate an Elastic IP and associate it with the instance.
    Returns the allocation id.
    """
    try:
        resp = ec2.allocate_address(Domain="vpc")
        allocation_id = resp["AllocationId"]
        public_ip = resp["PublicIp"]
        logger.info("Allocated EIP %s (allocation %s)", public_ip, allocation_id)
        ec2.associate_address(InstanceId=instance_id, AllocationId=allocation_id)
        logger.info("Associated EIP %s with instance %s", public_ip, instance_id)
        return allocation_id
    except ClientError:
        logger.exception("Failed to allocate or associate EIP")
        raise


def wait_for_instance_running(instance_id: str, timeout: int = 300) -> None:
    """Wait until the instance is in running state."""
    try:
        waiter = ec2.get_waiter("instance_running")
        waiter.wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 5, "MaxAttempts": int(timeout / 5)})
        logger.info("Instance %s is running", instance_id)
    except WaiterError:
        logger.exception("Timed out waiting for instance %s to run", instance_id)
        raise


# -----------------------
# Cleanup
# -----------------------


def cleanup(resources: Dict[str, str]) -> None:
    """
    Tear down resources created by this script. The resources dict should contain keys:
    - instance_id
    - allocation_id (EIP)
    - security_group_id
    - key_name
    - role_name
    - bucket_name
    """
    logger.info("Starting cleanup of resources: %s", resources)
    # Terminate instance
    instance_id = resources.get("instance_id")
    if instance_id:
        try:
            ec2.terminate_instances(InstanceIds=[instance_id])
            logger.info("Terminated instance %s", instance_id)
        except ClientError:
            logger.exception("Failed to terminate instance %s", instance_id)

    # Wait for termination
    if instance_id:
        try:
            waiter = ec2.get_waiter("instance_terminated")
            waiter.wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 5, "MaxAttempts": 60})
            logger.info("Instance %s terminated", instance_id)
        except Exception:
            logger.debug("Instance %s may still be terminating", instance_id)

    # Release EIP
    allocation_id = resources.get("allocation_id")
    if allocation_id:
        try:
            # Need to disassociate first (best-effort)
            try:
                assoc_resp = ec2.describe_addresses(AllocationIds=[allocation_id])
                for addr in assoc_resp.get("Addresses", []):
                    if "AssociationId" in addr:
                        ec2.disassociate_address(AssociationId=addr["AssociationId"])
                        logger.info("Disassociated EIP association %s", addr["AssociationId"])
            except Exception:
                logger.debug("Could not disassociate EIP (it may already be gone)")

            ec2.release_address(AllocationId=allocation_id)
            logger.info("Released EIP allocation %s", allocation_id)
        except ClientError:
            logger.exception("Failed to release EIP %s", allocation_id)

    # Delete security group
    sg_id = resources.get("security_group_id")
    if sg_id:
        try:
            ec2.delete_security_group(GroupId=sg_id)
            logger.info("Deleted security group %s", sg_id)
        except ClientError:
            logger.exception("Failed to delete security group %s", sg_id)

    # Delete key pair (AWS side) and local file
    key_name = resources.get("key_name")
    if key_name:
        try:
            ec2.delete_key_pair(KeyName=key_name)
            logger.info("Deleted key pair %s from AWS", key_name)
        except ClientError:
            logger.exception("Failed to delete key pair %s from AWS", key_name)
        local_key = f"./{key_name}.pem"
        if os.path.exists(local_key):
            try:
                os.remove(local_key)
                logger.info("Removed local key file %s", local_key)
            except Exception:
                logger.exception("Failed to remove local key file %s", local_key)

    # Remove inline policy and role/instance-profile
    role_name = resources.get("role_name")
    if role_name:
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=INLINE_POLICY_NAME)
            logger.info("Deleted inline policy %s from role %s", INLINE_POLICY_NAME, role_name)
        except ClientError:
            logger.debug("Could not delete inline policy (may not exist)")

        try:
            # Remove role from instance profile
            try:
                resp = iam.get_instance_profile(InstanceProfileName=role_name)
                roles = resp["InstanceProfile"].get("Roles", [])
                for r in roles:
                    if r["RoleName"] == role_name:
                        iam.remove_role_from_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
                        logger.info("Removed role %s from instance profile %s", role_name, role_name)
            except ClientError:
                logger.debug("Instance profile may not exist or role not attached")

            iam.delete_instance_profile(InstanceProfileName=role_name)
            logger.info("Deleted instance profile %s", role_name)
        except ClientError:
            logger.debug("Could not delete instance profile %s", role_name)

        try:
            iam.delete_role(RoleName=role_name)
            logger.info("Deleted role %s", role_name)
        except ClientError:
            logger.exception("Failed to delete role %s", role_name)

    # Delete S3 bucket (must be empty)
    bucket_name = resources.get("bucket_name")
    if bucket_name:
        try:
            # Empty bucket
            try:
                paginator = s3.get_paginator("list_objects_v2")
                for page in paginator.paginate(Bucket=bucket_name):
                    for obj in page.get("Contents", []):
                        s3.delete_object(Bucket=bucket_name, Key=obj["Key"])
                        logger.debug("Deleted object %s from bucket %s", obj["Key"], bucket_name)
            except ClientError:
                logger.debug("Could not list/delete objects in bucket (may be empty or inaccessible)")

            s3.delete_bucket(Bucket=bucket_name)
            logger.info("Deleted S3 bucket %s", bucket_name)
        except ClientError:
            logger.exception("Failed to delete S3 bucket %s", bucket_name)

    logger.info("Cleanup complete.")


# -----------------------
# Main orchestration
# -----------------------


def provision() -> Dict[str, str]:
    """
    Provision all resources and return a dict of created resource identifiers.
    """
    resources = {}
    logger.info("Starting provisioning in region %s", REGION)
    get_caller_identity()

    # 1) Ensure S3 bucket
    ensure_s3_bucket(BUCKET_NAME)
    resources["bucket_name"] = BUCKET_NAME

    # 2) Ensure IAM role and instance profile
    ensure_iam_role(ROLE_NAME, BUCKET_NAME)
    resources["role_name"] = ROLE_NAME

    # 3) Ensure key pair (may write local file)
    key_path = ensure_key_pair(KEY_NAME)
    resources["key_name"] = KEY_NAME
    if key_path:
        logger.info("Private key available at %s", key_path)
    else:
        logger.info("Private key not created locally; ensure you have the key to SSH")

    # 4) Ensure security group
    sg_id = ensure_security_group(SECURITY_GROUP_NAME)
    resources["security_group_id"] = sg_id

    # 5) Authorize ingress from caller IP
    authorize_ingress_from_my_ip(sg_id, PORTS)

    # 6) Launch instance
    instance_id = create_instance(AMI_ID, INSTANCE_TYPE, KEY_NAME, sg_id, ROLE_NAME, BUCKET_NAME, INSTANCE_NAME_TAG)
    resources["instance_id"] = instance_id

    # 7) Wait for instance running
    wait_for_instance_running(instance_id)

    # 8) Allocate and associate EIP
    allocation_id = allocate_and_associate_eip(instance_id)
    resources["allocation_id"] = allocation_id

    logger.info("Provisioning complete. Resources: %s", resources)
    return resources


def parse_args():
    p = argparse.ArgumentParser(description="Provision demo infrastructure on AWS")
    p.add_argument("--cleanup", action="store_true", help="Tear down resources created by this script")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    try:
        if args.cleanup:
            # Attempt to discover resources by name to clean up
            logger.info("Running cleanup mode: attempting to discover resources by name")
            discovered = {}
            # Find instance by tag
            try:
                resp = ec2.describe_instances(
                    Filters=[{"Name": "tag:Name", "Values": [INSTANCE_NAME_TAG]}, {"Name": "instance-state-name", "Values": ["running", "pending", "stopping", "stopped"]}]
                )
                instances = [i for r in resp.get("Reservations", []) for i in r.get("Instances", [])]
                if instances:
                    discovered["instance_id"] = instances[0]["InstanceId"]
                    logger.info("Discovered instance %s for cleanup", discovered["instance_id"])
            except ClientError:
                logger.debug("Could not discover instance by tag")

            # Find security group
            try:
                resp = ec2.describe_security_groups(Filters=[{"Name": "group-name", "Values": [SECURITY_GROUP_NAME]}])
                if resp.get("SecurityGroups"):
                    discovered["security_group_id"] = resp["SecurityGroups"][0]["GroupId"]
            except ClientError:
                logger.debug("Could not discover security group")

            # Find EIP allocation associated with instance
            if "instance_id" in discovered:
                try:
                    addrs = ec2.describe_addresses(Filters=[{"Name": "instance-id", "Values": [discovered["instance_id"]]}])
                    if addrs.get("Addresses"):
                        discovered["allocation_id"] = addrs["Addresses"][0].get("AllocationId")
                except ClientError:
                    logger.debug("Could not discover EIP")

            # Role and bucket names are known constants
            discovered["role_name"] = ROLE_NAME
            discovered["key_name"] = KEY_NAME
            discovered["bucket_name"] = BUCKET_NAME

            cleanup(discovered)
        else:
            resources = provision()
            logger.info("Provisioning finished. Resources created: %s", resources)
            logger.info("If you want to tear down these resources later, re-run with --cleanup")
    except Exception:
        logger.exception("An error occurred during provisioning/cleanup")
        sys.exit(1)
