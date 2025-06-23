# Temporal Proxy with AWS KMS Encryption POC

This poc project implements a proxy for Temporal workflows with end-to-end encryption using AWS KMS.

## Prerequisites

- Go 1.16 or later
- AWS account with permissions to create and use KMS keys
- A Temporal Cloud account

## Setup Instructions

### 1. Create an AWS KMS Key

1. Sign in to the AWS Management Console and open the KMS console at https://console.aws.amazon.com/kms
2. Choose **Create key**
3. Select **Symmetric** for Key type
4. For Key usage, select **Encrypt and decrypt**
5. Add a name and description for your key
6. Configure key administrative permissions and key usage permissions
7. Review and finish creating the key
8. Note the ARN of your new key, which will look like: `arn:aws:kms:region:account-id:key/key-id`

### 2. Configure AWS Credentials

Ensure your AWS credentials are properly configured:

```bash
aws configure
```

Or set environment variables:

```bash
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_REGION=your_region
```

## Build

```sh
make
```

## Run

Update `config.yaml` with namespace details.

```sh
./tclp --config config.yaml
```
