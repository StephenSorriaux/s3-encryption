import io

import boto3

from s3_encryption.client.base import S3EncryptionAbstractClient
from s3_encryption import crypto
from s3_encryption.handler import EncryptionHandler, DecryptionHandler


class S3EncryptionSyncClient(S3EncryptionAbstractClient):

    def __init__(self, encryption_key=None, encryption_mode=None, **kwargs):

        self.client = kwargs.get('client', None)
        if self.client is None:
            self.client = boto3.client(
                's3',
                region_name=kwargs.get('region_name', None)
            )
        self.resource = kwargs.get('resource', None)
        if self.resource is None:
            self.resource = boto3.resource(
                's3',
                region_name=kwargs.get('region_name', None)
            )
        super().__init__(encryption_key=encryption_key,
                         encryption_mode=encryption_mode, **kwargs)

    def put_object(self, Bucket=None, Key=None, Body=None, ACL=None, **kwargs):
        context = {
            'raw_body': Body,
            'cipher': crypto.aes_cipher(mode='CBC')
        }
        handler = EncryptionHandler(self.key_provider)
        context = handler.build_request_context(context)
        kwargs.update({
           'Bucket': Bucket,
           'Key': Key,
           'Body': context['body'],
           'Metadata': context['envelope']
        })
        if ACL is not None:
            kwargs['ACL'] = ACL
        self.client.put_object(**kwargs)

    def get_handler(self):
        pass

    def multipart_upload(self, Bucket=None, Key=None, Body=None, ACL=None,
                         part_size=None, **kwargs):
        context = {
            'raw_body': Body,
            'cipher': crypto.aes_cipher(mode='CBC')
        }
        handler = EncryptionHandler(self.key_provider)
        context = handler.build_request_context(context)
        if ACL is not None:
            kwargs['ACL'] = ACL
        bucket = self.resource.Object(Bucket, Key)
        kwargs.update({
           'Metadata': context['envelope']
        })
        multipart_upload = bucket.initiate_multipart_upload(**kwargs)

        result = None

        try:
            f = io.BytesIO(context['body'])
            parts = []
            current_part = 0
            chunk = f.read(part_size)
            part = multipart_upload.Part(current_part)
            response = part.upload(Body=chunk)
            parts.append({
                'PartNumber': current_part,
                'ETag': response['ETag']
            })

            chunk = f.read(part_size)
            while chunk:
                current_part += 1
                part = multipart_upload.Part(current_part)
                response = part.upload(Body=chunk)
                parts.append({
                    'PartNumber': current_part,
                    'ETag': response['ETag']
                })
                chunk = f.read(part_size)

            result = multipart_upload.complete(
                MultipartUpload={'Parts': parts.copy()}
            )
        except Exception as e:
            response = multipart_upload.abort()
            raise e

        return result

    def get_object(self, Bucket=None, Key=None, handler=None):
        resp = self.client.get_object(Bucket=Bucket, Key=Key)
        data_enc =  resp['Body'].read()
        if handler is None:
            handler = DecryptionHandler(self.key_provider)
        data = handler.build_from_metadata_and_decrypt(resp['Metadata'], data_enc)
        return data
