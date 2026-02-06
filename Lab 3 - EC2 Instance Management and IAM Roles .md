# Lab: EC2 Instance Management and IAM Roles

> **Report any bugs!** If you identify a resolvable error or bug in these instructions, please notify the instructor OR fork this repository, fix the bug(s), and submit a Pull Request. Communities make software better.

## Learning Objectives
By the end of this lab, you will be able to:
- Launch and configure EC2 instances with appropriate security groups
- Connect to EC2 instances via SSH
- Install and test web servers on EC2 instances
- Create and attach IAM roles to EC2 instances
- Test and modify IAM permissions
- Properly terminate AWS resources

## Prerequisites
- Personal AWS account
- SSH client (Terminal on macOS/Linux, PuTTY or PowerShell on Windows)
- Your existing SSH key pair from previous labs
- Basic familiarity with the Linux command line

## Part 1: Web Server Instance

### Step 1: Launch an Ubuntu EC2 Instance

1. Navigate to the EC2 Dashboard in the AWS Console
2. Click **Launch Instance**
3. Configure your instance:
   - **Name**: `webserver-lab`
   - **AMI**: Ubuntu Server 24.04 LTS
   - **Instance type**: `t3.micro` (Free tier eligible)
   - **Key pair**: Select your existing key pair from previous labs

### Step 2: Configure Security Group

1. In the **Network settings** section, click **Edit**
2. Create a new security group:
   - **Security group name**: `webserver-sg`
   - **Description**: `Allow SSH from my IP and HTTP from anywhere`
3. Configure inbound rules:
   - **Rule 1 (SSH)**:
     - Type: SSH
     - Protocol: TCP
     - Port: 22
     - Source: My IP (this will auto-populate your current IP)
   - **Rule 2 (HTTP)**:
     - Click **Add security group rule**
     - Type: HTTP
     - Protocol: TCP
     - Port: 80
     - Source: Anywhere-IPv4 (0.0.0.0/0)

4. Leave all other settings as default
5. Click **Launch Instance**

### Step 3: Connect to Your Instance

1. Wait for the instance state to show **Running** (refresh the console if needed)
2. Select your instance and note the **Public IPv4 address**
3. Connect via SSH (replace `<YOUR_KEY_NAME>` with your actual key filename and `<YOUR_PUBLIC_IP>` with your instance IP):
   ```bash
   ssh -i ~/.ssh/<YOUR_KEY_NAME>.pem ubuntu@<YOUR_PUBLIC_IP>
   ```
   
4. Type `yes` when prompted about the host authenticity

### Step 4: Install and Configure nginx

1. Update the package index:
   ```bash
   sudo apt update
   ```

2. Install nginx:
   ```bash
   sudo apt install -y nginx
   ```

3. Verify nginx is running:
   ```bash
   sudo systemctl status nginx
   ```
   
   You should see `active (running)` in green text. Press `q` to exit.

### Step 5: Test Your Web Server

1. Open a web browser and navigate to:
   ```
   http://<YOUR_PUBLIC_IP>
   ```

2. You should see the default nginx welcome page that says "Welcome to nginx!"

3. **Checkpoint Question**: What happens if you try to access `https://<YOUR_PUBLIC_IP>` (with an 's')? Why?

### Step 6: Clean Up Part 1

1. Exit your SSH session:
   ```bash
   exit
   ```

2. In the EC2 console, select your `webserver-lab` instance
3. Click **Instance state** → **Terminate instance**
4. Confirm the termination

**Do not delete your security group yet** - we'll verify it's removed later.

---

## Part 2: EC2 with IAM Role and S3 Access

### Step 1: Create an S3 Bucket

1. Navigate to the S3 service in the AWS Console
2. Click **Create bucket**
3. Configure your bucket:
   - **Bucket name**: `lab-bucket-<your-computing-id>` (e.g., `lab-bucket-abc3de`)
   - **Region**: Use the same region as your EC2 instance (e.g., us-east-1)
   - Leave all other settings as default (Block all public access should be ON)
4. Click **Create bucket**

### Step 2: Create an IAM Role

1. Navigate to the **IAM** service
2. In the left sidebar, click **Roles**
3. Click **Create role**
4. Configure the role:
   - **Trusted entity type**: AWS service
   - **Use case**: EC2
   - Click **Next**
5. **Do not attach any policies yet** - click **Next**
6. Name your role:
   - **Role name**: `EC2-S3-Limited-Access`
   - **Description**: `Allows EC2 instances to access specific S3 bucket`
7. Click **Create role**

### Step 3: Create a Custom IAM Policy

1. Still in the IAM console, click **Policies** in the left sidebar
2. Click **Create policy**
3. Click the **JSON** tab
4. Replace the entire contents with:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket"
            ],
            "Resource": "arn:aws:s3:::lab-bucket-<your-computing-id>"
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:GetObject"
            ],
            "Resource": "arn:aws:s3:::lab-bucket-<your-computing-id>/*"
        }
    ]
}
```

**Important**: Replace `<your-computing-id>` with your actual computing ID in BOTH places.

5. Click **Next**
6. Name your policy:
   - **Policy name**: `S3-Limited-Bucket-Access`
   - **Description**: `Allows listing bucket and getting/putting objects`
7. Click **Create policy**

### Step 4: Attach Policy to Role

1. Go back to **Roles** in the IAM console
2. Search for and click on `EC2-S3-Limited-Access`
3. Click the **Permissions** tab
4. Click **Add permissions** → **Attach policies**
5. Search for `S3-Limited-Bucket-Access`
6. Check the box next to your policy
7. Click **Add permissions**

### Step 5: Launch EC2 Instance with IAM Role

1. Return to the EC2 Dashboard
2. Click **Launch Instance**
3. Configure your instance:
   - **Name**: `s3-access-lab`
   - **AMI**: Ubuntu Server 24.04 LTS
   - **Instance type**: `t3.micro` (Free tier eligible)
   - **Key pair**: Select your existing key pair from previous labs
   - **Network settings**: Use your existing `webserver-sg` security group
   - **Advanced details** (expand this section):
     - **IAM instance profile**: Select `EC2-S3-Limited-Access`
4. Click **Launch Instance**

### Step 6: Connect and Test S3 Access

1. Wait for the instance to be **Running**
2. Connect via SSH (replace with your key name and new public IP):
   ```bash
   ssh -i ~/.ssh/<YOUR_KEY_NAME>.pem ubuntu@<NEW_PUBLIC_IP>
   ```

3. Install the AWS CLI on the instance:
   ```bash
   sudo snap install aws-cli --classic
   ```

4. Verify AWS CLI is installed correctly and the IAM role is working:
   ```bash
   aws sts get-caller-identity
   ```
   
   You should see output showing your assumed role ARN.

### Step 7: Test Initial Permissions

1. Create a test file:
   ```bash
   echo "Hello from EC2!" > test.txt
   ```

2. **Upload (PUT) the file to S3**:
   ```bash
   aws s3 cp test.txt s3://lab-bucket-<your-computing-id>/
   ```
   
   This should succeed.

3. **List objects in the bucket**:
   ```bash
   aws s3 ls s3://lab-bucket-<your-computing-id>/
   ```
   
   This should succeed and show your `test.txt` file.

4. **Download (GET) the file**:
   ```bash
   aws s3 cp s3://lab-bucket-<your-computing-id>/test.txt downloaded.txt
   cat downloaded.txt
   ```
   
   This should succeed.

5. **Try to list ALL buckets** (this should fail):
   ```bash
   aws s3 ls
   ```
   
   **Checkpoint Question**: What error message do you get? Why does this fail?

6. **Try to delete an object** (this should also fail):
   ```bash
   aws s3 rm s3://lab-bucket-<your-computing-id>/test.txt
   ```
   
   **Checkpoint Question**: What error message do you get? What permission is missing?

### Step 8: Update IAM Policy to Add Permissions

1. Leave your SSH session open
2. Return to the IAM console in your browser
3. Click **Policies** in the left sidebar
4. Search for and click on `S3-Limited-Bucket-Access`
5. Click **Edit** (next to Policy versions)
6. Replace the JSON with:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket"
            ],
            "Resource": "arn:aws:s3:::lab-bucket-<your-computing-id>"
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:GetObject",
                "s3:DeleteObject"
            ],
            "Resource": "arn:aws:s3:::lab-bucket-<your-computing-id>/*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListAllMyBuckets"
            ],
            "Resource": "*"
        }
    ]
}
```

**Important**: Replace `<your-computing-id>` with your actual computing ID.

7. Click **Next**
8. Click **Save changes**

**Note**: IAM policy changes can take up to 60 seconds to propagate.

### Step 9: Retest with Updated Permissions

1. Return to your SSH session
2. Wait about 60 seconds for the policy to propagate
3. If you haven't installed the AWS CLI on this instance yet:
   ```bash
   sudo apt install awscli
   ```

4. **Try to list ALL buckets again**:
   ```bash
   aws s3 ls
   ```
   
   This should now succeed and show all your S3 buckets!

5. **Upload the test file again** (in case you were able to delete it):
   ```bash
   aws s3 cp test.txt s3://lab-bucket-<your-computing-id>/
   ```

6. **Try to delete the object**:
   ```bash
   aws s3 rm s3://lab-bucket-<your-computing-id>/test.txt
   ```
   
   This should now succeed!

7. **Verify deletion**:
   ```bash
   aws s3 ls s3://lab-bucket-<your-computing-id>/
   ```
   
   The file should be gone.

### Step 10: Clean Up Part 2

1. Exit your SSH session:
   ```bash
   exit
   ```

2. **Terminate EC2 instance**:
   - Select your `s3-access-lab` instance
   - Click **Instance state** → **Terminate instance**

3. **Delete S3 bucket**:
   - Go to S3 console
   - Select `lab-bucket-<your-computing-id>`
   - Click **Delete**
   - Confirm by typing the bucket name

4. **Delete IAM Policy**:
   - Go to IAM → Policies
   - Select `S3-Limited-Bucket-Access`
   - Click **Actions** → **Delete**
   - Confirm deletion

5. **Delete IAM Role**:
   - Go to IAM → Roles
   - Select `EC2-S3-Limited-Access`
   - Click **Delete**
   - Confirm deletion

6. **Delete Security Group**:
   - Return to EC2 → Security Groups
   - Select `webserver-sg`
   - Click **Actions** → **Delete security groups**
   - Confirm deletion

---

## Reflection Questions

1. Why is it important to restrict SSH access to your IP address rather than allowing it from anywhere (0.0.0.0/0)?

2. Explain the difference between the two Resource ARNs in the IAM policy:
   - `arn:aws:s3:::lab-bucket-<id>`
   - `arn:aws:s3:::lab-bucket-<id>/*`

3. Why does the `ListAllMyBuckets` permission require `"Resource": "*"` instead of a specific bucket ARN?

4. What is the principle of least privilege, and how does this lab demonstrate it?

5. If you needed to give an EC2 instance read-only access to all S3 buckets in your account, how would you modify the IAM policy?

---

## Submission

Submit a document containing:
1. Screenshots showing:
   - The nginx welcome page from Part 1
   - The error message when trying to list all buckets (before updating the policy)
   - The successful output after updating the policy
2. Answers to all checkpoint questions and reflection questions
3. A brief paragraph (3-4 sentences) explaining a real-world scenario where you might use an EC2 instance with limited S3 access via an IAM role
