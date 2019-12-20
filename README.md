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

# Streaming multipart uploads (symetric key only)
## Study
Cant use AES/CBC since it requires each block to be 128-bits long. If used with multipart uploads, each part will have the padding thus the final object will have padding in the middle of it.
AES/CTR can be used but it is not available "out of the box" in official S3 clients (only for GET ranges with AES/GCM). There might be need to develop specific behavior for other clients, but most seems to allow to specify the algorithm to use.
AES/GCM requires to store the generated tag somewhere, for each part (?). Moreover, there is no use for an authenticated encryption since the encrypted data will be transmitted over HTTPS.

## Authenticating uploads
Ensure contents has not be altered on the network.
See X-Amz-Content-SHA256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD

## How it works
### v1
Used with EncryptionOnly mode and no KMS, and previous SDK
`x-amz-key`
`x-amz-iv`
`x-amz-matdesc`

Object content encrypted with: AES/CBC/PKCS5Padding. CEK encrypted with AES/ECB/NoPadding.

### v2
Used with Authenticated and StrictAuthenticated modes, or EncryptionOnly mode and KMS
`x-amz-key-v2`
`x-amz-iv`
`x-amz-matdesc`
`x-amz-cek-alg`
`x-amz-tag-len` bits LOL
`x-amz-wrap-alg`

Object content encrypted with: AES/GCM/NoPadding. Decrypted with AES/CTR/NoPadding if using range GETs (only a part of the object data is read so no auth possible).

- Provide either a symetric or an asymetric master key
- For each objects, a data key is generated and used to encrypt the object data using the choosen cipher (`AES/CBC/PKCS5Padding` by default, can be `AES/CTR/NoPadding` or `name = 'AES/ECB/PKCS5Padding`)
- The master key is used to encrypt the data key using:
    - AES/CBC if symetric and encryption only or v1 (`x-amz-wrap-alg` set to `AESWrap` and `x-amz-cek-alg` set to `AES/CBC`, or both unset for if API v1),
    - AES/GCM if symetric and encryption + authentification (`x-amz-wrap-alg` set to `AESWrap`, `x-amz-cek-alg` set to `AES/GCM/NoPadding`)
    - RSA/ECB/OAEPWithSHA-256AndMGF1Padding if asymetric (`x-amz-wrap-alg` set to `RSA/ECB/OAEPWithSHA-256AndMGF1Padding`)
    All of this are stored in the materials (header `x-amz-matdesc` which must be a valid JSON)
- Be careful, most of the time IV and nonce are assimilated to the same thing in other AWS clients


### Common

When using multipart upload and encrypting each part individually: each parts (except the last one) must be a multiple of the cipher block size (see below). This is done to avoid padding.

Note from the Java AWS SDK (src/main/java/com/amazonaws/services/s3/internal/crypto/S3CryptoModuleBase.java:272): 
```
     * <b>NOTE:</b> Because the encryption process requires context from
     * previous blocks, parts uploaded with the AmazonS3EncryptionClient (as
     * opposed to the normal AmazonS3Client) must be uploaded serially, and in
     * order. Otherwise, the previous encryption context isn't available to use
     * when encrypting the current part.
```

Also:
```
            // The last part of the multipart upload will contain an extra
            // 16-byte mac
```

For AES CBC (EncryptionOnly and v1):
- key(data key) of 256 bits
- Block size: 16 bits
- IV: 16 bits

- Saved as metadata : Iv, Datakey

For AES GCM:
- key: 256 bits (32 bytes)
- Block size: 16 bytes
- IV (nonce): 12 bytes
- Tag: 128 bits (16 bytes)

- Saved as metadata: Iv, Datakey, 

Multipart upload is created with a generated IV. First part uses this IV to get encrypted. Second part use the last block as the IV and so on. For the last part, padding is added (if needed).

### Data key (CEK - content encryption key)
A data key is generated and encrypted with the provided master key (KEK - key encription key).
Before it was using the unsafe AES ECB mode, now it is using [AES Wrap](https://tools.ietf.org/html/rfc3394)

Logic: use value from `x-amz-wrap-alg` or fallback to AES/ECB.

