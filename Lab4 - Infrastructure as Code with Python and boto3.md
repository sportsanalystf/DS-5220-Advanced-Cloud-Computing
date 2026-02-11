# Lab: Infrastructure as Code with Python and `boto3`

## Overview

In this lab, you will use Python and the AWS SDK (boto3) to programmatically provision and configure EC2 infrastructure. This represents a shift from manual console work or shell scripts to true Infrastructure as Code (IaC) using a general-purpose programming language.

**Learning Objectives:**
- Use `boto3` to interact with AWS services programmatically
- Provision EC2 instances with user data for bootstrapping
- Manage Elastic IP addresses and associate them with instances
- Create and attach IAM roles with S3 permissions
- Implement proper error handling and logging in infrastructure code
- Write maintainable, functional Python code for cloud automation

**Prerequisites:**
- AWS account with appropriate permissions
- AWS CLI configured locally with credentials
- Python 3.10+ installed locally
- Basic understanding of EC2, S3, and IAM concepts

**Reference:**
- [`boto3` Documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)
- [AWS CLI Installation Reference](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html)
- [Python Virtual Environments](https://realpython.com/python-virtual-environments-a-primer/)


---

## Part 1: Environment Setup

### Project Structure

Create a directory for this lab and set up your initial Python file:

```bash
mkdir boto3-ec2-lab
cd boto3-ec2-lab
touch provision_infrastructure.py
```

### Create a Python Environment

- Create a virtual environment `pipenv`, `pyenv`, `uv`, `conda`, or `virtualenv`
- Activate it in your terminal

### Install Required Libraries

Use the recommended method for your virtual environment
```bash
pip install boto3 pyyaml
pipenv install boto3 pyyaml
. . .
```

### Understanding `boto3` Clients

boto3 provides two main interfaces: **clients** (low-level) and **resources** (high-level). For this lab, we'll use clients for precise control.

```python
import boto3

# Create clients for different services
ec2 = boto3.client('ec2', region_name='us-east-1')
s3 = boto3.client('s3', region_name='us-east-1')
iam = boto3.client('iam')  # IAM is global
```

**Question:** Why might IAM not require a region parameter?

---

## Part 2: Setting Up Logging and Configuration

Good infrastructure code needs visibility.
Set up Python's logging module:

```python
import logging

# Configure logging (console + local file)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("provision.log", mode="a", encoding="utf-8")
    ]
)
logger = logging.getLogger(__name__)
```

Use the provided YAML template at `labs/lab04/config.yaml` to store **launch settings**.
Update all appropriate values before you run your script. Use an existing Security Group that allows SSH access, and add an ingress rule to allow port 8888 from all addresses.

```yaml
# labs/lab04/config.yaml
region: us-east-1
bucket_name: your-bucket-name-12345
instance:
  ami_id: ami-0b6c6ebed2801a5cb # ubuntu 24.04lts
  instance_type: m7i.large
  key_name: your-key-name
  security_group_id: sg-12345abcde
  role_name: EC2-S3-Instance-Role
  instance_profile_name: EC2-S3-Instance-Profile
```

Load the YAML file once and store it in `CONFIG`:

```python
import yaml

def load_config(path="config.yaml"):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

CONFIG = load_config("config.yaml")
```

You will use nested keys like `CONFIG['instance']['instance_type']` and
`CONFIG['instance']['ami_id']` when launching the instance.

Deserialize these nested keys to fetch usable values for resources such as `instance_type`, `key_name`, etc.

---

## Part 3: Create an S3 Bucket

**Task:** Write another function called `create_s3_bucket()` that creates an S3 bucket for your EC2 instance to access.

**Requirements:**
- The function should accept `bucket_name` and `region` as parameters
- Use try/except to handle errors (e.g., if the bucket already exists)
- Log success or failure appropriately
- Return the bucket name on success, None on failure

**Hints:**
- Look up `s3_client.create_bucket()` in the boto3 documentation
- Be aware: `us-east-1` has special rules for bucket creation (no LocationConstraint needed)
- The `BucketAlreadyOwnedByYou` exception can be handled gracefully

**Starter code:**

```python
def create_s3_bucket(bucket_name, region):
    """
    Create an S3 bucket in the specified region.
    
    Args:
        bucket_name (str): Name of the bucket to create
        region (str): AWS region
        
    Returns:
        str: Bucket name if successful, None otherwise
    """
    s3 = boto3.client('s3', region_name=region)
    
    try:
        # YOUR CODE HERE: Create the bucket
        # Remember: us-east-1 is a special case
        
        logger.info(f"Successfully created bucket: {bucket_name}")
        return bucket_name
    except Exception as e:
        # YOUR CODE HERE: Handle exceptions appropriately
        # Consider: What exceptions might occur? How should you handle them?
        pass
```

---

## Part 4: Creating IAM Role and Instance Profile

Your EC2 instance needs permissions to access the S3 bucket. This requires:
1. An IAM role with a trust policy (allowing EC2 to assume it)
2. A policy granting S3 access
3. An instance profile to attach the role to EC2

### Function 1: Create IAM Role

**Task:** Write `create_iam_role()` to create a role that EC2 can assume.

**Key concepts:**
- Trust policy: JSON document specifying who can assume the role
- The trust policy for EC2 should allow the `ec2.amazonaws.com` service

**Starter code:**

```python
import json

def create_iam_role(role_name):
    """
    Create an IAM role for EC2 with a trust policy.
    
    Args:
        role_name (str): Name of the IAM role
        
    Returns:
        str: Role ARN if successful, None otherwise
    """
    iam = boto3.client('iam')
    
    # Trust policy allowing EC2 to assume this role
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole"
            }
        ]
    }
    
    try:
        response = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description='Role for EC2 to access S3'
        )
        logger.info(f"Created IAM role: {role_name}")
        return response['Role']['Arn']
    except iam.exceptions.EntityAlreadyExistsException:
        logger.warning(f"Role {role_name} already exists")
        # YOUR CODE HERE: Get and return the existing role's ARN
        # Hint: Use iam.get_role()
        pass
    except Exception as e:
        logger.error(f"Error creating IAM role: {e}")
        return None
```

### Function 2: Attach S3 Policy

**Task:** Write `attach_s3_policy()` to grant the role access to your S3 bucket.

**Requirements:**
- Create an inline policy allowing `s3:GetObject`, `s3:PutObject`, `s3:ListBucket`, and `s3:ListAllMyBuckets`
- Handle cases where the policy already exists

**Starter code:**

```python
def attach_s3_policy(role_name, bucket_name):
    """
    Attach an inline policy to the role granting S3 access.
    
    Args:
        role_name (str): Name of the IAM role
        bucket_name (str): Name of the S3 bucket to grant access to
        
    Returns:
        bool: True if successful, False otherwise
    """
    iam = boto3.client('iam')
    
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    # YOUR CODE HERE: Add appropriate S3 actions
                ],
                "Resource": [
                    # YOUR CODE HERE: Add ARNs for the bucket and its objects
                    # Format: arn:aws:s3:::bucket-name and arn:aws:s3:::bucket-name/*
                ]
            }
        ]
    }
    
    try:
        # YOUR CODE HERE: Use put_role_policy to attach the inline policy
        # Policy name suggestion: 'S3AccessPolicy'
        
        logger.info(f"Attached S3 policy to role {role_name}")
        return True
    except Exception as e:
        logger.error(f"Error attaching policy: {e}")
        return False
```

### Function 3: Create Instance Profile

**Task:** Write `create_instance_profile()` to create an instance profile and add the role to it.

**Note:** Instance profiles are the mechanism that attaches IAM roles to EC2 instances.

```python
def create_instance_profile(profile_name, role_name):
    """
    Create an instance profile and add the IAM role to it.
    
    Args:
        profile_name (str): Name of the instance profile
        role_name (str): Name of the IAM role to add
        
    Returns:
        str: Instance profile ARN if successful, None otherwise
    """
    iam = boto3.client('iam')
    
    try:
        # YOUR CODE HERE: 
        # 1. Create the instance profile using create_instance_profile()
        # 2. Add the role to it using add_role_to_instance_profile()
        # 3. Return the ARN
        
        pass
    except iam.exceptions.EntityAlreadyExistsException:
        # YOUR CODE HERE: Handle existing profile
        # If it exists, ensure the role is added and return the ARN
        pass
    except Exception as e:
        logger.error(f"Error creating instance profile: {e}")
        return None
```

---

## Part 5: Allocating and Associating an Elastic IP

**Task:** Write two functions to manage Elastic IPs.

### Function 1: Allocate Elastic IP

```python
def allocate_elastic_ip():
    """
    Allocate an Elastic IP address.
    
    Returns:
        dict: Dictionary with 'AllocationId' and 'PublicIp', or None
    """
    ec2 = boto3.client('ec2', region_name=CONFIG['region'])
    
    try:
        # YOUR CODE HERE: Allocate an EIP for VPC
        # Hint: Use allocate_address with Domain='vpc'
        
        pass
    except Exception as e:
        logger.error(f"Error allocating Elastic IP: {e}")
        return None
```

### Function 2: Associate Elastic IP with Instance

```python
def associate_elastic_ip(instance_id, allocation_id):
    """
    Associate an Elastic IP with an EC2 instance.
    
    Args:
        instance_id (str): ID of the EC2 instance
        allocation_id (str): Allocation ID of the Elastic IP
        
    Returns:
        str: Association ID if successful, None otherwise
    """
    ec2 = boto3.client('ec2', region_name=CONFIG['region'])
    
    try:
        # YOUR CODE HERE: Associate the EIP with the instance
        
        pass
    except Exception as e:
        logger.error(f"Error associating Elastic IP: {e}")
        return None
```

---

## Part 6: Launching an EC2 Instance

Now for the main event! Write a function to launch an EC2 instance with user data for bootstrapping.

**Task:** Complete the `launch_ec2_instance()` function.

**Requirements:**
- Accept parameters for instance type, AMI ID, key name, and instance profile
- Include user data that installs Apache and creates a simple web page showing the instance metadata
- Wait for the instance to be running before returning
- Use proper error handling

```python
def launch_ec2_instance(instance_type, ami_id, key_name, security_group, instance_profile_name, bucket_name):
    """
    Launch an EC2 instance with user data and instance profile.
    
    Args:
        instance_type (str): EC2 instance type
        ami_id (str): AMI ID to use
        key_name (str): SSH key pair name
        security_group (str): Security Group ID
        instance_profile_name (str): Instance profile name
        bucket_name (str): S3 bucket name
        
    Returns:
        str: Instance ID if successful, None otherwise
    """
    ec2 = boto3.client('ec2', region_name=CONFIG['region'])
    
    # User data script - bootstraps the instance
    user_data_script = f"""#!/bin/bash
    apt update
    apt upgrade -y

    snap install docker
    sleep 10
    docker run -d --restart=always -p 8888:8888 quay.io/jupyter/base-notebook start-notebook.py --NotebookApp.token='my-token'
    
    # Test S3 access by copying a file
    aws s3 cp /var/log/apt/history.log s3://{bucket_name}/
    """
    
    try:
        response = ec2.run_instances(
            ImageId=ami_id,
            InstanceType=instance_type,
            KeyName=key_name,
            MinCount=1,
            MaxCount=1,
            UserData=user_data_script,
            SecurityGroupIds=[security_group],
            IamInstanceProfile={'Name': instance_profile_name},
            TagSpecifications=[
                {
                    'ResourceType': 'instance',
                    'Tags': [
                        {'Key': 'Name', 'Value': 'boto3-lab-instance'},
                        {'Key': 'Lab', 'Value': 'IaC-Python'}
                    ]
                }
            ]
        )
        
        instance_id = response['Instances'][0]['InstanceId']
        logger.info(f"Launched instance: {instance_id}")
        
        # YOUR CODE HERE: Wait for instance to be running
        # Hint: Use waiter = ec2.get_waiter('instance_running')
        #       then waiter.wait(InstanceIds=[instance_id])
        
        return instance_id
        
    except Exception as e:
        logger.error(f"Error launching instance: {e}")
        return None
```

---

## Part 7: Main Orchestration Function

**Task:** Write the `main()` function that orchestrates all the pieces.

```python
def main():
    """
    Main function to provision complete infrastructure.
    """
    logger.info("Starting infrastructure provisioning...")
    
    # Step 1: Create S3 bucket
    # YOUR CODE HERE
    
    # Step 2: Create IAM role
    # YOUR CODE HERE
    
    # Step 3: Attach S3 policy to role
    # YOUR CODE HERE
    
    # Step 4: Create instance profile
    # YOUR CODE HERE
    
    # Note: IAM resources need time to propagate
    logger.info("Waiting 10 seconds for IAM resources to propagate...")
    import time
    time.sleep(10)
    
    # Step 5: Launch EC2 instance
    # YOUR CODE HERE
    
    # Step 6: Allocate Elastic IP
    # YOUR CODE HERE
    
    # Step 7: Associate Elastic IP with instance
    # YOUR CODE HERE
    
    logger.info("Infrastructure provisioning complete!")
    logger.info(f"Your instance is accessible at: {elastic_ip_info['PublicIp']}")
    logger.info(f"S3 bucket created: {CONFIG['bucket_name']}")
    
    return {
        'instance_id': instance_id,
        'public_ip': elastic_ip_info['PublicIp'],
        'bucket_name': CONFIG['bucket_name']
    }


if __name__ == "__main__":
    main()
```

---

## Part 8: Testing and Validation

### Test Your Code

1. **Run your script:**
   ```bash
   python provision_infrastructure.py
   ```
   Resource instantiation may take 1-3 minutes to complete.

2. **Verify in AWS Console:**
   - Check EC2 for your instance
   - Verify Elastic IP association
   - Check S3 for your bucket and the uploaded file
   - Review IAM for role and instance profile

3. **Test the Jupyter console:**
   ```bash
   # be sure your security group allows port 8888
   # add that rule by hand if necessary
   curl http://<your-elastic-ip>:8888/lab?token=my-token
   ```

4. **Verify S3 access from Jupyter:**
   - Create a new Jupyter Notebook
   - Install the `boto3` package from a code cell:
     ```
     %pip install boto3
     ```
   - Jupyter should inherit AWS Role access through the instance. Try to  list all buckets in another code cell:
     ```
     import boto3
     
     s3 = boto3.client('s3')
     response = s3.list_buckets()
     for b in response['Buckets']:
       print(b['Name'])
     ```

### Challenge Extensions

1. **Add a security group:** Modify your code to create a new security group allowing HTTP (port 8888) and SSH (port 22).

2. **Cleanup function:** Write a `cleanup()` function that tears down all resources in reverse order.

3. **Config validation:** Add checks to ensure required keys exist in `config.yaml`, or constrains choices such as instance types.

4. **Better error recovery:** Implement retry logic with exponential backoff for transient failures.

---

## Submission Requirements

Create a GitHub Gist containing a single Python file (`provision_infrastructure.py`) that:
- Includes all required functions with proper error handling
- Uses logging throughout
- Follows the functional structure with `if __name__ == "__main__":`
- Includes comments explaining key decisions
- Successfully provisions all resources when executed

**Bonus:** Include a `cleanup()` function and a `--cleanup` command-line argument to tear down resources.

**Submit the URL to your Gist in Canvas for grading.**

---

## Reflection Questions

Consider these questions and be sure you understand the inner workings of this script:

1. What are the advantages of using boto3 for infrastructure provisioning compared to the AWS Console or CLI?
2. How does IAM role propagation affect automation workflows? How might you handle this in production?
3. What security considerations should you keep in mind when writing infrastructure code?
4. How would you extend this code to be reusable across multiple environments (dev, staging, prod)?
5. Why must Elastic IP association happen so late in the logical flow?
