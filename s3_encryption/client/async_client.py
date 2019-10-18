import io

import aiobotocore
import aioboto3
import boto3

from s3_encryption.client.base import S3EncryptionAbstractClient
from s3_encryption import crypto
from s3_encryption.handler import EncryptionHandler, DecryptionHandler


class S3EncryptionASyncClient(S3EncryptionAbstractClient):

    def __init__(self, encryption_key=None, **kwargs):
        self.client = kwargs.get('client', None)
        if self.client is None:
            self.client = aiobotocore.client(
                's3',
                region_name=kwargs.get('region_name', None)
            )
        self.resource = kwargs.get('resource', None)
        if self.resource is None:
            self.resource = aioboto3.resource(
                's3',
                region_name=kwargs.get('region_name', None)
            )

        super().__init__(encryption_key=encryption_key, **kwargs)

    async def put_object(self, Bucket=None, Key=None, Body=None, ACL=None,
                         **kwargs):
        raise NotImplementedError('Use multipart_upload() instead')

    async def multipart_upload(self, Bucket=None, Key=None, Body=None,
                               ACL=None, config=None, callback=None, **kwargs):

        if config is None:
            config = boto3.s3.transfer.TransferConfig()

        context = {
            'raw_body': Body,
            'cipher': crypto.aes_cipher(mode='CBC')
        }
        handler = EncryptionHandler(self.key_provider)
        context = handler.build_request_context(context)
        if ACL is not None:
            kwargs['ACL'] = ACL

        kwargs.update({
           'Metadata': context['envelope']
        })
        f = io.BytesIO(context['body'])

        await self.client.upload_fileobj(
            f,
            Bucket=Bucket,
            Key=Key,
            ExtraArgs=kwargs.copy(),
            Callback=callback,
            Config=config
        )

    async def close(self):
        if self.client:
            await self.client.close()
        if self.resource:
            await self.resource.close()

    async def get_object(self, Bucket=None, Key=None):
        resp = await self.client.get_object(Bucket=Bucket, Key=Key)
        context = {'body': await resp['Body'].read()}
        handler = DecryptionHandler(self.key_provider)
        context = handler.build_response_context(resp['Metadata'], context)
        return context['raw_body']
