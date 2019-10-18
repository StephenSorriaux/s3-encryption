[![Build Status](https://travis-ci.org/boldfield/s3-encryption.svg?branch=master)](https://travis-ci.org/boldfield/s3-encryption)
[![PyPI version](https://badge.fury.io/py/s3-encryption.svg)](https://badge.fury.io/py/s3-encryption)


s3-encryption is a thin wrapper around the `boto3` S3 client.  It facilitates client-side encryption
which is compatible to that provided by the Ruby aws-sdk-core-resources.

Functionality is currently limited to that demonstrated below.

## Using KMS to store your master key

See [this AWS documentation](https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingClientSideEncryption.html#client-side-encryption-kms-managed-master-key-intro) for more details.

Since KMS will generate a new key from your master key for each file you upload, you **need** to store it next to your object (this is the `encode_key` in following examples).

Upload encrypted content in python using KMS to store your master key:
```python

import boto3
from s3_encryption.client.sync_client import S3EncryptionSyncClient

REGION = 'us-west-2'
BUCKET = 'testing.stuff.bucket'
s3_key = 'testing.txt'

s3e = S3EncryptionSyncClient(encryption_key=plaintext_key, region_name=REGION)
s3e.put_object(Body='this is a test', Bucket=BUCKET, Key='testing.txt')
s3e.client.put_object(Body=encoded_key, Bucket=BUCKET, Key=s3_key + '.key')
```

Download encrypted content in python using KMs to store your master key:
```python

REGION = 'us-west-2'
BUCKET = 'testing.stuff.bucket'
s3_key = 'testing.txt'

s3 = boto3.client('s3', region_name=REGION)
encoded_key = s3.get_object(Bucket=BUCKET, Key=s3_key + '.key')

plaintext_key = decode_encryption_key(encoded_key)

s3e = S3EncryptionSyncClient(encryption_key=plaintext_key, region_name=REGION)
print s3e.get_object(Bucket=BUCKET, Key=s3_key)
>> 'this is a test'
```


Download encrypted content in ruby using KMS to store your master key:
```ruby

REGION = 'us-west-2'
BUCKET = 'testing.stuff.bucket'
s3_key = 'testing.txt'

s3c = Aws::S3::Client.new
res = s3c.get_object(:bucket => BUCKET, :key => s3_key + '.key')
enc_key = res[:body].read

plaintext_key = decode_encryption_key(enc_key)

s3ec = Aws::S3::Encryption::Client.new(:encryption_key => plaintext_key)
res = s3ec.get_object(:bucket => bucket, :key => s3_key)
body = res[:body].read
puts body
>> 'this is a test'
```

## Providing a symetric master key to your app
### Sync client
See [this AWS documentation](https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingClientSideEncryption.html#client-side-encryption-client-side-master-key-intro) for more details.

Your symetric key will be used to encrypt the data.

Upload encrypted content in python using your master key:
```python

import boto3
from s3_encryption.client.sync_client import S3EncryptionSyncClient

REGION = 'us-west-2'
BUCKET = 'testing.stuff.bucket'
s3_key = 'testing.txt'
plaintext_key = b'my-32-bytes-key'

s3e = S3EncryptionSyncClient(encryption_key=plaintext_key, region_name=REGION)
s3e.put_object(Body='this is a test', Bucket=BUCKET, Key='testing.txt')
```

Download encrypted content in python using your master key:
```python

REGION = 'us-west-2'
BUCKET = 'testing.stuff.bucket'
s3_key = 'testing.txt'

plaintext_key = b'my-32-bytes-key'

s3e = S3EncryptionSyncClient(encryption_key=plaintext_key, region_name=REGION)
print s3e.get_object(Bucket=BUCKET, Key=s3_key)
>> 'this is a test'
```
