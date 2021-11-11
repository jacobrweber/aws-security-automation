import botocore
import boto3
import json

# Retrieve a bucket's policy
s3 = boto3.client('s3')
response = s3.list_buckets()

# use this to understand how respone is formatted
# print(response['Buckets'])

# make a list of all s3 buckets in account
all_buckets = list(buckets['Name'] for buckets in response['Buckets'])


for each_bucket in all_buckets:
    try:
        result = s3.get_bucket_policy(Bucket=each_bucket)
    except botocore.exceptions.ClientError as error:
         print(f"No policy is attached to {each_bucket}")
         pass


    # some funky stuff you have to do to format the returned object properly
    parsed = json.loads(result['Policy'])
    # print(json.dumps(parsed, indent=4, sort_keys=True))
    shorthand = parsed['Statement'][0]

    # if the bucket allows public access
    # let user know it is vulnerable
    # then automatically remediate by blocking public access
 
    if (shorthand['Effect'] == "Allow"
        and shorthand['Principal'] == "*" 
        and shorthand['Action'] == "s3:GetObject"):
            print(f"\nResource {shorthand['Resource']} is vulnerable")
            print(f"Because {shorthand['Action']}")
            print(f"is {shorthand['Effect']}ed for Principal: {shorthand['Principal']}")
            print("are enabled")

            fixed_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "PublicReadGetObject",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::" + each_bucket + "/*"
                }
            ]
            }
            # format the policy for sending to AWS api
            fixed_policy = json.dumps(fixed_policy)
            
            s3.put_bucket_policy(Bucket=each_bucket,Policy=fixed_policy)

            print(f"\nPublic GET access has been removed for {each_bucket}")
    else:
        print(f"\n{each_bucket} does not allow public access")
