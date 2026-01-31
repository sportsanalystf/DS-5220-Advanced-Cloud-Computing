# Lab: Creating and Managing EC2 Instances

## Learning Objectives

By the end of this lab, you will be able to:
- Launch an EC2 instance using the AWS Console
- Connect to an EC2 instance via SSH
- Understand key EC2 concepts: AMIs, instance types, and EBS storage
- Create, attach, format, and mount additional EBS volumes
- Automate EC2 instance creation using the AWS CLI
- Programmatically create EC2 instances using boto3

## Prerequisites

- An AWS account with appropriate permissions
- AWS CLI installed and configured on your local machine with your security credentials. [Watch this video](https://youtu.be/uUSZSyxbv80) for how to set this up if you have not already.
- Python 3.10+ with `boto3` installed (`pip install boto3`)
- An SSH client (built into macOS/Linux, use PuTTY or WSL on Windows)

## Setup: Configure Your AWS Region

**Important**: This lab assumes you're working in the **us-east-1** (N. Virginia) region.

### Verify Your Region

**In the AWS Console:**
1. Look at the top-right corner of the AWS Console
2. Click the region dropdown
3. Select **US East (N. Virginia) us-east-1** if not already selected

**In the AWS CLI:**
```bash
# Check your current default region
aws configure get region

# If it's not us-east-1, set it
aws configure set region us-east-1

# Verify
aws configure get region
```

**In Python using `boto3`:**

Your Python scripts will automatically use `us-east-1` if configured above, but you can also specify it explicitly in code (we'll show this later).

## Part 1: Creating an EC2 Instance via the AWS Console (25 minutes)

### What is EC2?

Amazon Elastic Compute Cloud (EC2) provides scalable virtual servers in the cloud. Think of an EC2 instance as a computer running in AWS's data center that you can access remotely.

### Step 1: Generate an SSH Key Pair (if necessary)

Before launching an instance, you need a way to securely connect to it. AWS uses SSH key pairs for authentication. You may already have one from class. However, this keypair **must** be in the `us-east-1` region.

1. Navigate to the EC2 Dashboard in the AWS Console (make sure you're in **us-east-1**)
2. In the left sidebar, under "Network & Security", click **Key Pairs**
3. Click **Create key pair**
4. Configure:
   - **Name**: `ds5220-keypair` (or some other name you can identify easily)
   - **Key pair type**: RSA
   - **Private key file format**: `.pem` (for macOS/Linux) or `.ppk` (for PuTTY on Windows)
5. Click **Create key pair**

The private key file will automatically download. **This is your only chance to download it!**

**Important**: Move this file to a secure location and set proper permissions:

```bash
# macOS/Linux
mv ~/Downloads/ds5220-keypair.pem ~/.ssh/
chmod 400 ~/.ssh/ds5220-keypair.pem
```

### Step 2: Launch Your First Instance

1. From the EC2 Dashboard, click **Launch Instance**
2. Configure the following settings:

**Name and tags**
- Name: `my-first-instance`

**Application and OS Images (Amazon Machine Image)**
- Quick Start: **Amazon Linux**
- Amazon Machine Image (AMI): **Amazon Linux 2023 AMI** (should be selected by default)
- Architecture: **64-bit (x86)**

> **What's an AMI?** An Amazon Machine Image is a template that contains the operating system, application server, and applications. Think of it as a snapshot that defines what software is installed when your instance starts. AWS provides many pre-configured AMIs, and you can create custom ones.

**Instance type**
- Instance type: **t2.micro** (should be in the free tier)

> **What's an instance type?** Instance types define the hardware characteristics: CPU, memory, storage, and network capacity. The naming convention is: **family.size**
> - `t2` = family (T-series are burstable performance instances, good for variable workloads)
> - `micro` = size (1 vCPU, 1 GB RAM)

**Key pair**
- Select the key pair you created: `ds5220-keypair`

**Network settings** (leave defaults for now)
- We'll explore security groups in detail in a future lab
- For now, ensure "Allow SSH traffic from" is checked with "Anywhere" (0.0.0.0/0)

**Configure storage**
- The default should be **8 GB gp3** (General Purpose SSD)
- Leave this as is for now - we'll add more storage in the next step

> **What's EBS?** Elastic Block Store provides persistent block storage volumes. Even if you stop your instance, this data persists. The `gp3` volume type is a balanced, general-purpose SSD.

3. Click **Launch instance**
4. Wait for the instance state to show **Running** (this may take 1-2 minutes)

### Step 3: Create and Attach an Additional EBS Volume

Now let's add a second storage volume to your instance.

1. In the left sidebar, under "Elastic Block Store", click **Volumes**
2. Click **Create volume**
3. Configure:
   - **Volume Type**: General Purpose SSD (gp3)
   - **Size**: 10 GiB
   - **Availability Zone**: **Must match your instance's AZ** (e.g., us-east-1a)
     - To find your instance's AZ: Go to Instances → select your instance → look at "Availability Zone" in the details
   - **Add tag**: Key = `Name`, Value = `my-data-volume`
4. Click **Create volume**

**Important**: The volume must be in the same Availability Zone as your instance!

5. Once the volume state is **available**, select it
6. Click **Actions** → **Attach volume**
7. Configure:
   - **Instance**: Select `my-first-instance`
   - **Device name**: Leave as default (probably `/dev/sdf` or `/dev/xvdf`)
8. Click **Attach volume**

The volume state should change to **in-use**.

### Step 4: Connect to Your Instance

1. Go back to **Instances** in the left sidebar
2. Select your instance
3. Note the **Public IPv4 address** (something like `54.123.45.67`)
4. Open your terminal and connect via SSH:

```bash
ssh -i ~/.ssh/ds5220-keypair.pem ec2-user@<YOUR-PUBLIC-IP>
```

Replace `<YOUR-PUBLIC-IP>` with your instance's public IP address.

**Note**: The default username for Amazon Linux is `ec2-user`

5. Type `yes` when prompted about the host authenticity
6. You should now be connected!

### Step 5: Format and Mount the New Volume

The volume is attached but not yet usable. We need to format it and mount it.

```bash
# List all block devices
lsblk
```

You should see something like:
```
NAME          MAJ:MIN RM SIZE RO TYPE MOUNTPOINTS
xvda          202:0    0   8G  0 disk 
├─xvda1       202:1    0   8G  0 part /
└─xvda128     202:128  0   1M  0 part 
xvdf          202:80   0  10G  0 disk
```

Notice `xvdf` (or similar) is present but has no mountpoint.

```bash
# Check if the volume has a filesystem (it shouldn't)
sudo file -s /dev/xvdf
```

If it says "data", the volume is empty and needs formatting.

```bash
# Create an ext4 filesystem on the volume
sudo mkfs -t ext4 /dev/xvdf
```

This will take a few seconds and show output about creating the filesystem.

```bash
# Create a mount point (directory where we'll access the volume)
sudo mkdir /data

# Mount the volume
sudo mount /dev/xvdf /data

# Verify it's mounted
df -h
```

You should see `/dev/xvdf` mounted at `/data` with ~10GB available.

```bash
# Change ownership so ec2-user can write to it
sudo chown ec2-user:ec2-user /data

# Test it out
echo "Hello from my data volume!" > /data/test.txt
cat /data/test.txt

# Check disk usage
df -h /data
```

**Important note**: This mount is temporary. If you reboot the instance, you'll need to mount it again. To make it permanent, you would add an entry to `/etc/fstab`, but we'll skip that for this lab.

### Step 6: Explore Your Instance

Try a few more commands to understand your environment:

```bash
# Check the OS
cat /etc/os-release

# List all block devices with more detail
lsblk -f

# Check memory
free -h

# Check CPU info
lscpu

# See both volumes
ls -lh /
ls -lh /data
```

Type `exit` to disconnect when you're done exploring.

### Checkpoint Questions

Before moving on, make sure you understand:
- What AMI did you use, and what does it contain?
- What are the CPU and memory specifications of a t2.micro?
- How much storage is attached to your instance, and on how many volumes?
- What's the difference between the root volume and the data volume you created?
- Why do you need the private key file to connect?
- What happens to your data volume if you terminate the instance?

## Part 2: Creating an EC2 Instance via the AWS CLI (15 minutes)

Now let's automate the same process using the command line.

### Step 1: Explore Available Resources

First, let's see what's available in your region:

```bash
# List available Amazon Linux 2023 AMIs (this returns a lot of data!)
aws ec2 describe-images \
  --owners amazon \
  --filters "Name=name,Values=al2023-ami-2023*" \
  --query 'Images[0].[ImageId,Name,Description]' \
  --output table \
  --region us-east-1

# Get just the AMI ID we need
AMI_ID=$(aws ec2 describe-images \
  --owners amazon \
  --filters "Name=name,Values=al2023-ami-2023*" "Name=architecture,Values=x86_64" \
  --query 'Images[0].ImageId' \
  --output text \
  --region us-east-1)

echo "Using AMI: $AMI_ID"
export AMI_ID
```

### Step 2: Create a Reusable SSH Security Group

Create a security group once and reuse it for instances you launch in this lab.

```bash
# Get the default VPC ID
VPC_ID=$(aws ec2 describe-vpcs \
  --filters "Name=isDefault,Values=true" \
  --query 'Vpcs[0].VpcId' \
  --output text \
  --region us-east-1)

# Create a security group for SSH access
SSH_SG_ID=$(aws ec2 create-security-group \
  --group-name ds5220-ssh \
  --description "DS5220 SSH access" \
  --vpc-id $VPC_ID \
  --query 'GroupId' \
  --output text \
  --region us-east-1)

# Allow inbound SSH from anywhere (0.0.0.0/0)
aws ec2 authorize-security-group-ingress \
  --group-id $SSH_SG_ID \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0 \
  --region us-east-1

echo "SSH security group ID: $SSH_SG_ID"
```

### Step 3: Create a New Instance with an Additional Volume

Be sure to update the `--key-name` to match your key.

```bash
# Launch the instance with block device mapping for additional storage
aws ec2 run-instances \
  --image-id $AMI_ID \
  --instance-type t2.micro \
  --key-name ds5220-keypair \
  --security-group-ids $SSH_SG_ID \
  --block-device-mappings '[
    {
      "DeviceName": "/dev/xvda",
      "Ebs": {
        "VolumeSize": 8,
        "VolumeType": "gp3",
        "DeleteOnTermination": true
      }
    },
    {
      "DeviceName": "/dev/sdf",
      "Ebs": {
        "VolumeSize": 10,
        "VolumeType": "gp3",
        "DeleteOnTermination": false
      }
    }
  ]' \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=cli-created-instance}]' 'ResourceType=volume,Tags=[{Key=Name,Value=cli-created-volumes}]' \
  --region us-east-1 \
  --output table
```

Notice the `--block-device-mappings` parameter creates both the root volume (8 GB) and an additional data volume (10 GB) in a single command!

### Step 4: Monitor and Connect

```bash
# Get your instance ID
INSTANCE_ID=$(aws ec2 describe-instances \
  --filters "Name=tag:Name,Values=cli-created-instance" "Name=instance-state-name,Values=running" \
  --query 'Reservations[0].Instances[0].InstanceId' \
  --output text \
  --region us-east-1)

echo "Instance ID: $INSTANCE_ID"

# Wait for it to be running
aws ec2 wait instance-running --instance-ids $INSTANCE_ID --region us-east-1

# Get the public IP
PUBLIC_IP=$(aws ec2 describe-instances \
  --instance-ids $INSTANCE_ID \
  --query 'Reservations[0].Instances[0].PublicIpAddress' \
  --output text \
  --region us-east-1)

echo "Public IP: $PUBLIC_IP"

# See information about attached volumes
aws ec2 describe-volumes \
  --filters "Name=attachment.instance-id,Values=$INSTANCE_ID" \
  --query 'Volumes[*].[VolumeId,Size,VolumeType,State,Attachments[0].Device]' \
  --output table \
  --region us-east-1

# Connect via SSH
ssh -i ~/.ssh/ds5220-keypair.pem ec2-user@$PUBLIC_IP
```

You can verify both volumes are attached with `lsblk`, but we won't format/mount them in this section.

### Step 5: Clean Up

When you're done exploring, terminate this instance:

```bash
aws ec2 terminate-instances --instance-ids $INSTANCE_ID --region us-east-1
```

Note: The additional volume (with `DeleteOnTermination: false`) will still exist. You can delete it manually:

```bash
# List volumes not attached to any instance
aws ec2 describe-volumes \
  --filters "Name=status,Values=available" \
  --query 'Volumes[*].[VolumeId,Size,Tags[?Key==`Name`].Value|[0]]' \
  --output table \
  --region us-east-1

# Delete a specific volume
# aws ec2 delete-volume --volume-id vol-xxxxxxxxxxxxx --region us-east-1
```

## Part 3: Creating an EC2 Instance with `boto3` (20 minutes)

Now let's do the same thing programmatically with Python.

### Step 1: Set Up Your Python Environment

Create a new virtual environment in Python and install the `boto3` package. 

Then create a new file called `create_ec2.py`:

```python
import boto3
import time
from pprint import pprint

# Create EC2 client and resource for us-east-1
ec2_client = boto3.client('ec2', region_name='us-east-1')
ec2_resource = boto3.resource('ec2', region_name='us-east-1')

AWS_AMI_ID = "ami-07ff62358b87c7116"
SSH_SG_ID = "sg-xxxxxxxxxxxxxxxxx"  # Reuse the SG you created in Step 2

def create_instance(ami_id, instance_name="boto3-created-instance"):
    """Create an EC2 instance with additional EBS volume"""
    print(f"\nCreating instance: {instance_name}")
    
    # Define block device mappings
    # This creates both the root volume and an additional data volume
    block_device_mappings = [
        {
            'DeviceName': '/dev/xvda',  # Root volume
            'Ebs': {
                'VolumeSize': 8,
                'VolumeType': 'gp3',
                'DeleteOnTermination': True
            }
        },
        {
            'DeviceName': '/dev/sdf',  # Additional data volume
            'Ebs': {
                'VolumeSize': 10,
                'VolumeType': 'gp3',
                'DeleteOnTermination': False  # Keep volume after termination
            }
        }
    ]
    
    # Launch the instance
    instances = ec2_resource.create_instances(
        ImageId=ami_id,
        InstanceType='t2.micro',
        KeyName='ds5220-keypair',
        MinCount=1,
        MaxCount=1,
        # update the line below with your security group id
        SecurityGroupIds=[SSH_SG_ID],
        BlockDeviceMappings=block_device_mappings,
        TagSpecifications=[
            {
                'ResourceType': 'instance',
                'Tags': [
                    {'Key': 'Name', 'Value': instance_name},
                    {'Key': 'CreatedBy', 'Value': 'boto3-script'}
                ]
            },
            {
                'ResourceType': 'volume',
                'Tags': [
                    {'Key': 'Name', 'Value': f'{instance_name}-volume'},
                    {'Key': 'CreatedBy', 'Value': 'boto3-script'}
                ]
            }
        ]
    )
    
    instance = instances[0]
    instance_id = instance.id
    
    print(f"Instance created: {instance_id}")
    print("Waiting for instance to be running...")
    
    # Wait for the instance to be running
    instance.wait_until_running()
    
    # Reload instance attributes
    instance.reload()
    
    return instance

def display_instance_info(instance):
    """Display information about an instance"""
    print(f"\n{'='*50}")
    print(f"Instance Details")
    print(f"{'='*50}")
    print(f"Instance ID:     {instance.id}")
    print(f"Instance Type:   {instance.instance_type}")
    print(f"AMI ID:          {instance.image_id}")
    print(f"State:           {instance.state['Name']}")
    print(f"Public IP:       {instance.public_ip_address}")
    print(f"Private IP:      {instance.private_ip_address}")
    print(f"Key Name:        {instance.key_name}")
    print(f"Availability Zone: {instance.placement['AvailabilityZone']}")
    
    # Display storage information
    print(f"\nAttached Storage:")
    for idx, bdm in enumerate(instance.block_device_mappings, 1):
        print(f"\n  Volume {idx}:")
        print(f"    Device:        {bdm['DeviceName']}")
        print(f"    Volume ID:     {bdm['Ebs']['VolumeId']}")
        
        # Get volume details
        volume = ec2_resource.Volume(bdm['Ebs']['VolumeId'])
        print(f"    Size:          {volume.size} GB")
        print(f"    Volume Type:   {volume.volume_type}")
        print(f"    Delete on Term: {bdm['Ebs']['DeleteOnTermination']}")
    
    print(f"\n{'='*50}\n")

def main():
    print("Creating EC2 instance in us-east-1...")
    
    # Get the latest AMI
    ami_id = AWS_AMI_ID
    
    # Create the instance
    instance = create_instance(ami_id)
    
    # Display instance information
    display_instance_info(instance)
    
    # Show SSH command
    print(f"Connect using:")
    print(f"ssh -i ~/.ssh/ds5220-keypair.pem ec2-user@{instance.public_ip_address}")
    print()
    print("Note: The instance has two volumes attached:")
    print("  - /dev/xvda (8 GB root volume)")
    print("  - /dev/sdf (10 GB data volume - needs formatting/mounting)")
    print()
    
    # Ask if user wants to terminate
    response = input("Do you want to terminate this instance? (yes/no): ")
    if response.lower() == 'yes':
        print(f"\nTerminating instance {instance.id}...")
        instance.terminate()
        print("Instance terminated.")
        print("\nNote: The data volume (/dev/sdf) was configured to persist.")
        print("You may want to delete it manually to avoid charges:")
        print("  1. Go to EC2 → Volumes in the console")
        print("  2. Find volumes with 'available' status")
        print("  3. Select and delete unused volumes")
    else:
        print(f"\nInstance {instance.id} is still running.")
        print("Don't forget to terminate it later to avoid charges!")

if __name__ == "__main__":
    main()
```

### Step 2: Run Your Script

```bash
python create_ec2.py
```

### Step 3: Understand the Code

The script demonstrates several key boto3 patterns:

1. **Regional specification**: We explicitly set `region_name='us-east-1'` when creating clients

2. **Client vs Resource**: 
   - `boto3.client('ec2')` - Low-level service access
   - `boto3.resource('ec2')` - Higher-level object-oriented interface

3. **Block device mappings**: The `BlockDeviceMappings` parameter allows us to:
   - Configure the root volume size and type
   - Add additional volumes at launch time
   - Control `DeleteOnTermination` behavior

4. **Creating instances**: The `create_instances()` method with parameters matching what we configured in the console

5. **Waiting for state changes**: Using `wait_until_running()` to block until the instance is ready

6. **Accessing instance attributes**: After reloading, we can access properties like `public_ip_address`

### Exploration Exercise

Modify the script to:

1. Accept instance type as a command-line argument
2. Create multiple instances at once (change `MaxCount`)
3. Add a third EBS volume (20 GB)
4. Add additional tags (like `Environment: development`)
5. List the Availability Zone and use it when describing volumes

## Part 4: Understanding What You Created

### AMI Deep Dive

An AMI includes:
- **Root volume template**: The OS and pre-installed software
- **Launch permissions**: Who can use it
- **Block device mapping**: Defines attached volumes at launch

You can create your own AMIs by configuring an instance and then creating an image from it. This is useful for creating standardized environments.

### Instance Types Explained

The naming pattern is `family.size`:

**Common Families:**
- `t2/t3` - Burstable performance (baseline with ability to burst)
- `m5/m6` - General purpose (balanced compute, memory, networking)
- `c5/c6` - Compute optimized (high CPU)
- `r5/r6` - Memory optimized (high RAM)

**Sizes**: nano, micro, small, medium, large, xlarge, 2xlarge, etc.

Your t2.micro has 1 vCPU and 1 GB RAM - fine for learning, but too small for most production workloads.

### Storage Architecture

When you launch an instance, you can have:
- **Root volume**: Contains the OS (8 GB in our lab)
- **Additional EBS volumes**: Persistent block storage that can survive termination (10 GB in our lab)
- **Instance store** (if available): Temporary storage that's lost on stop/termination

Key concepts:
- **DeleteOnTermination**: Controls whether volumes are automatically deleted when the instance terminates
  - Root volumes: Usually `true` (deleted with instance)
  - Data volumes: Often `false` (persist after instance termination)
- **Availability Zones**: Volumes must be in the same AZ as the instance they're attached to
- **Formatting**: New volumes need a filesystem before they can store data
- **Mounting**: Volumes must be mounted to a directory to be accessible

### Volume Lifecycle

1. **Create** → Volume exists but isn't attached (state: available)
2. **Attach** → Volume is connected to an instance (state: in-use)
3. **Format** → Create a filesystem (one-time operation)
4. **Mount** → Make it accessible at a mount point (required after each boot)
5. **Detach** → Disconnect from instance (state: available again)
6. **Delete** → Permanently destroy the volume


## Submit

Submit a short log snapshot that shows you launched, connected, and attached storage. Include:

- The output of `aws ec2 describe-instances --instance-ids <INSTANCE_ID> --query 'Reservations[0].Instances[0].[InstanceId,PublicIpAddress,SecurityGroups]' --output table`
- The output of `lsblk` after you mounted the data volume
- The output of `df -h /data`


## Clean Up

Before you finish, make sure to clean up all resources:

### Terminate Instances

**Via Console:**
1. Go to EC2 → Instances
2. Select each instance you created
3. Instance State → Terminate instance

**Via CLI:**
```bash
# List all your running instances
aws ec2 describe-instances \
  --filters "Name=instance-state-name,Values=running" \
  --query 'Reservations[*].Instances[*].[InstanceId,Tags[?Key==`Name`].Value|[0],State.Name]' \
  --output table \
  --region us-east-1

# Terminate specific instances
aws ec2 terminate-instances --instance-ids i-1234567890abcdef0 --region us-east-1
```

### Delete Unattached Volumes

Remember, volumes with `DeleteOnTermination: false` will persist after instance termination.

**Via Console:**
1. Go to EC2 → Volumes
2. Filter by State: available
3. Select volumes you created
4. Actions → Delete volume

**Via CLI:**
```bash
# List available (unattached) volumes
aws ec2 describe-volumes \
  --filters "Name=status,Values=available" \
  --query 'Volumes[*].[VolumeId,Size,Tags[?Key==`Name`].Value|[0]]' \
  --output table \
  --region us-east-1

# Delete specific volume
aws ec2 delete-volume --volume-id vol-xxxxxxxxxxxxx --region us-east-1
```

## Summary

You've learned to create EC2 instances three ways:
- **AWS Console**: Point-and-click, great for learning and one-off tasks
- **AWS CLI**: Command-line automation, good for scripting
- **Boto3**: Programmatic control from Python, best for complex workflows

You now understand:
- **AMIs**: Templates defining your instance's software
- **Instance types**: Hardware specifications (CPU, RAM, network)
- **EBS storage**: Persistent block storage attached to instances
- **Volume management**: Creating, attaching, formatting, and mounting volumes
- **SSH key pairs**: How to securely access your instances
- **Regional operations**: Working consistently in `us-east-1`
  

## Next Steps

In future labs, we'll explore:
- Security groups and network access control
- IAM roles for granting instances permissions to AWS services
- User data scripts for automated configuration at launch
- Auto Scaling groups for managing fleets of instances
- Making volumes persistent across reboots using `/etc/fstab`
