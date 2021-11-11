import boto3
import json

# Retrieve a bucket's policy
s3 = boto3.client('s3')
result = s3.get_bucket_policy(Bucket='obfuscated-for-github')

# some funky stuff you have to do to format the returned object properly
parsed = json.loads(result['Policy'])
print(json.dumps(parsed, indent=4, sort_keys=True))
shorthand = parsed['Statement'][0]

# if the bucket allows public access
# let user know it is vulnerable
# then automatically remediate by blocking public access
 
if shorthand['Effect'] == "Allow" and shorthand['Principal'] == "*" and shorthand['Action'] == "s3:GetObject":
    print(f"Resource {shorthand['Resource']} is vulnerable")
    print(f"Because {shorthand['Action']}")
    print(f"and {shorthand['Effect']}\nand {shorthand['Principal']}")
    print("are enabled")

    fixed_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "PublicReadGetObject",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::obfuscated-for-github/*"
        }
    ]
    }
    # format the policy for sending to AWS api
    fixed_policy = json.dumps(fixed_policy)
    
    s3.put_bucket_policy(Bucket="wutkanitest",Policy=fixed_policy)
