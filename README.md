## Automatic scanning and remediation for S3 public GetObject Access

This Python script uses boto3 to check all S3 buckets on your AWS account for public GetObject access.

If a bucket has public GetObject access allowed, it will automatically change the policy to Deny.

Error handling is included for buckets that do not have a policy attached.

This script was designed to be secure and re-usable.   It does not include hard-coded ARNs or resource names.

This is basic, and mostly useless, but written as a PoC and practice for using the boto3 SDK.