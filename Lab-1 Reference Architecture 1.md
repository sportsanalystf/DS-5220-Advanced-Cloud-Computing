# Lab 1: Reference Architecture 1 - Custom EC2 instance with S3 bucket and IAM policy

![Topology Diagram](https://s3.amazonaws.com/uvasds-systems/images/refarch1-diagram.png)

## Overview
In this lab, you'll deploy a CloudFormation template that creates multiple AWS resources, then explore what was created and how these resources interact. This hands-on exercise will (A) help you understand how infrastructure is provisioned and connected in AWS; and (B) have a concrete example as we discuss cloud primitives such as compute resources, storage, networking, security, etc.

## Learning Objectives
By the end of this lab, you will be able to:
- Deploy a CloudFormation stack from a template file
- Navigate the AWS Console to locate created resources
- Begin to understand the relationships between EC2, IAM, S3, and Security Groups
- Verify resource functionality through testing

## Prerequisites
- Access to an AWS account (AWS Academy or personal account)
- An existing EC2 key pair in your AWS region (`us-east-1`)
- Your UVA computing ID
- Basic familiarity with the AWS Console
- A default VPC. From within the AWS Console, be sure to select the N. Virginia region in the upper-right corner, go to the VPC service, and verify that you have at least one (1) VPC already created.

## Part 1: Deploy the CloudFormation Stack

### Step 0: Download the Reference Architecture

[**Download**](https://s3.amazonaws.com/uvasds-systems/ds5220/refarch-1-custom-ec2-with-s3-bucket.docx) the Word document and use it to enter your resource details.

### Step 1: Open the Template in CloudFormation
1. Browse the [YAML template](ec2-with-bucket-policy.yaml) manually
2. Open the AWS Console and be sure you are signed in.
3. Open the instructor's [**Launch Template**](https://us-east-1.console.aws.amazon.com/cloudformation/home/?region=us-east-1#/stacks/quickcreate?templateURL=https://s3.amazonaws.com/uvasds-systems/cloudformation/ec2-with-bucket-policy.yaml&stackName=refarch1).

### Step 2: Quick create stack
1. **Stack name**: Leave the default value for this, `refarch1`.
2. Fill in the parameters:
   - **InstanceType**: Leave as `t3.micro` (default)
   - **KeyName**: Select an existing key pair from the dropdown
   - **UvaId**: Enter your computing ID (e.g., `abc3def`)
   - **SSHLocation**: Leave as `0.0.0.0/0` (or restrict to your IP for security)
   - **SubnetId**: Select any **public** subnet from the dropdown
   - **VPC**: Select the VPC that contains your chosen subnet
3. Scroll to the bottom and check the box: **"I acknowledge that AWS CloudFormation might create IAM resources"**
4. Click **Submit**

### Step 3: Monitor Stack Creation
1. You'll be taken to the stack details page
2. Watch the **Events** tab to see resources being created in real-time
3. Wait until the stack status shows **CREATE_COMPLETE** (this takes 3-5 minutes)
4. If any errors occur, check the Events tab for details

## Part 2: Identify and Explore Created Resources

Now that your stack is deployed, let's find and examine each resource it created.

### Resource 1: EC2 Instance

1. Navigate to **EC2** → **Instances**
2. Find the instance with the Name tag matching your stack name (e.g., `lab-infrastructure-ec2-instance`)
3. Record the following information:
   - **Instance ID**: `i-xxxxxxxxxxxxxxxxx`
   - **Public IP address**: `x.x.x.x`
   - **Private IP address**: `x.x.x.x`
   - **Instance type**: Should be `t3.micro`

**Test the instance:**
- Copy the public IP address
- Open a browser and navigate to `http://[PUBLIC-IP]`
- You should see a welcome page with your UVA ID and bucket name

### Resource 2: Security Group

1. From the EC2 console, go to **Security Groups** (left sidebar under "Network & Security")
2. Find the security group with your stack name (e.g., `lab-infrastructure-ec2-sg`)
3. Click on the security group and examine the **Inbound rules** tab
4. Within the inbound rules, what ports are allowed?

**Questions to consider:**
- What traffic is allowed into the EC2 instance?
- Why are these specific ports open?

### Resource 3: S3 Bucket

1. Navigate to **S3** service
2. Find your bucket (should be named `[your-uva-id]-[stack-name]`)
3. Click on the bucket name to explore it.
4. Check the following tabs:
   - **Properties**: Is versioning enabled?
   - **Permissions**: What public access settings are configured?

**Test S3 access from EC2:**
```bash
# SSH into your instance (replace with your key and IP)
# Before you use your key, move it to your home directory
# within the `.ssh` directory and then limit its permissions:
# chmod 600 ~/.ssh/your-key.pem
ssh -i your-key.pem ec2-user@[PUBLIC-IP]

# List bucket contents from within the instance
aws s3 ls s3://[your-bucket-name]/

# Create a test file
echo "Hello from EC2" > test.txt

# Upload to S3
aws s3 cp test.txt s3://[your-bucket-name]/

# Verify upload
aws s3 ls s3://[your-bucket-name]/

# Download the file
aws s3 cp s3://[your-bucket-name]/test.txt downloaded.txt

# View contents
cat downloaded.txt

# Delete the file in S3
aws s3 rm s3://[your-bucket-name]/test.txt
```

### Resource 4: IAM Role

1. Navigate to **IAM** → **Roles**
2. Search for your stack name to find the role (e.g., `lab-infrastructure-ec2-role`)
3. Click on the role name
4. Examine the **Permissions** tab:
   - How many policies are attached?
   - What are their names?
5. Click on the `S3BucketAccessPolicy` to view it
6. Record what S3 actions are allowed:
   - _______________
   - _______________
   - _______________
   - _______________

### Resource 5: IAM Instance Profile

1. Still in IAM, go to **Roles** and view your EC2 role
2. Look for the "Instance profiles" section
3. Note: This is what actually attaches the IAM role to the EC2 instance

**Verify the connection:**
1. Go back to **EC2** → **Instances**
2. Select your instance
3. Go to the **Security** tab
4. Confirm the IAM role name matches what you found earlier

## Part 4: Examine CloudFormation Outputs

1. Return to **CloudFormation** → **Stacks**
2. Click on your stack name
3. Go to the **Outputs** tab
4. Record the output values and identify any remaining resources on the worksheet.

**Question:** Why might these outputs be useful if you were building a larger infrastructure?

## Part 5: Review Stack Resources Tab

1. In CloudFormation, click the **Resources** tab
2. Count how many resources were created: _____
3. List each resource type and its logical name from the template.
4. Take a screenshot of the Resources tab for submission and insert it into the reference architecture document.

This tab shows the complete inventory of what CloudFormation created for you.

## Part 6: Cleanup

**Important:** To avoid charges, delete your stack when finished.

1. Go to **CloudFormation** → **Stacks**
2. Select your stack
3. Click **Delete**
4. Confirm the deletion
5. Monitor the **Events** tab as resources are deleted
6. Verify in S3 that your bucket was deleted (it should be empty first)

**Note:** If deletion fails, check the Events tab for errors. S3 buckets must be empty to delete.

## Deliverables

1. Insert the screenshot of the Resources tab output from your CloudFormation stack into the reference architecture.
2. Answer the following questions within the reference architecture. Note that how you answer each question is likely to change in the coming weeks.
3. Submit a PDF version of your reference architecture in Canvas to complete the lab.

## Discussion Questions

1. What advantages does CloudFormation provide compared to manually creating these resources through the console?
2. Can you identify the created resources that have to do with computational resources? network security? various types of storage?
3. How does the IAM role enable the EC2 instance to access S3 without storing credentials?
4. What would happen if you deleted the S3 bucket manually before deleting the CloudFormation stack?
5. Why is the security group configured to allow only ports 22 and 80? What are those ports used for?