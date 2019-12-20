import asyncio
import concurrent.futures
import functools
import io
import logging

import aiobotocore
import aioboto3
import boto3

from s3_encryption.client.base import S3EncryptionAbstractClient, S3Action
from s3_encryption import crypto
from s3_encryption.handler import EncryptionHandler, DecryptionHandler


logger = logging.getLogger(__name__)


class S3EncryptionASyncClient(S3EncryptionAbstractClient):
    '''
    An async client for S3.

    Requires to be initialized with:
    - an event `loop` 
    - an `encryption_key` in bytes
    - an `encryption_mode` (see `class: s3_encryption.client.base.EncryptionMode`)
    
    A S3 `client` might be added according to your configuration.
    '''

    def __init__(self, encryption_key, loop=None, encryption_mode=None,
                 client=None, **kwargs):
        self.client = client
        if self.client is None:
            self.client = aiobotocore.client(
                's3',
                region_name=kwargs.get('region_name', None)
            )
        self.loop = loop or asyncio.get_event_loop()

        super().__init__(encryption_key=encryption_key,
                         encryption_mode=encryption_mode, **kwargs)

    async def put_object(self, Bucket=None, Key=None, Body=None, ACL=None,
                         **kwargs):
        raise NotImplementedError('Use multipart_upload() instead')

    async def multipart_upload(self, Bucket=None, Key=None, Body=None,
                               ACL=None, config=None, callback=None, **kwargs):

        if config is None:
            config = boto3.s3.transfer.TransferConfig()

        context = {'raw_body': Body}
        handler = EncryptionHandler(self.key_provider, self.encryption_mode)
        # with concurrent.futures.ThreadPoolExecutor() as pool:
        #     context = await self.loop.run_in_executor(
        #         pool, handler.build_request_context, context)

        if S3Action.MULTIPART_UPLOAD not in handler.actions_for_cipher():
            raise ValueError(
                'Current cipher can not be used for full multipart upload'
            )

        context = handler.build_request_context(context)
        if ACL is not None:
            kwargs['ACL'] = ACL

        kwargs.update({
           'Metadata': context['envelope']
        })
        f = io.BytesIO(context['body'].full_data)

        await self.client.upload_fileobj(
            f,
            Bucket=Bucket,
            Key=Key,
            ExtraArgs=kwargs.copy(),
            Callback=callback,
            Config=config
        )

    async def close(self):
        logger.info('Closing client')
        if self.client:
            await self.client.close()


    async def create_multipart_upload(self, bucket, key, metadata=None):
        '''
        Starts a multipart upload and return its upload_id
        '''
        if metadata is None:
            metadata = {}

        resp = await self.client.create_multipart_upload(
            Bucket=bucket,
            Key=key,
            Metadata=metadata
        )
        logger.info('Created new multipart upload "%s"', resp['UploadId'])
        return resp['UploadId']

    def get_handler(self):
        '''
        Generates an EncryptionHandler for the current key_provider
        and client encryption mode

        Be careful since a new data key will be generated for each handler.
        '''
        return EncryptionHandler(self.key_provider, self.encryption_mode)
        

    async def upload_part(self, body, bucket, key, part_number, upload_id,
                          handler, is_last_part=False):
        '''
        Encrypt and upload an unencrypted part. If it is not the latest part
        and using a cipher that requies padding, be sure to be to have the
        data length a multiple of the block size.

        Returns resp for s3 client with `last_block` key to be used
        '''

        if S3Action.PART_UPLOAD not in handler.actions_for_cipher():
            raise ValueError(
                'Current cipher can not be used for single part upload'
            )

        enc_func = functools.partial(handler.encrypt, body, padding=is_last_part)

        enc = await self.loop.run_in_executor(None, enc_func)

        body_enc = enc.full_data if is_last_part else enc.data

        resp = await self.client.upload_part(
            Body=body_enc,
            Bucket=bucket,
            Key=key,
            PartNumber=part_number,
            UploadId=upload_id
        )

        # should be used as IV for the next part
        resp['last_blocks'] = body_enc[-16:]
        logger.info('Upload part for multipart upload "%s"', upload_id)
        return resp

    async def complete_multipart_upload(self, bucket, key, upload_id, parts):
        '''
        Finishes a multipart upload
        '''
        await self.client.complete_multipart_upload(
            Bucket=bucket,
            Key=key,
            UploadId=upload_id,
            MultipartUpload=parts
        )
        logger.info('Completed multipart upload "%s"', upload_id)
    
    async def abort_multipart_upload(self, bucket, key, upload_id):
        await self.client.abort_multipart_upload(
            Bucket=bucket, Key=key, UploadId=upload_id
        )
        logger.info('Aborted multipart upload')

    async def get_object(self, Bucket=None, Key=None):
        logger.info(
            'Getting object with key "%s" from bucket "%s"', Key, Bucket
        )
        resp = await self.client.get_object(Bucket=Bucket, Key=Key)
        data_enc = await resp['Body'].read()
        handler = DecryptionHandler(self.key_provider, self.encryption_mode)
        handler.build_from_metadata(resp['Metadata'])

        if S3Action.GET_OBJECT not in handler.actions_for_cipher():
            raise ValueError(
                'Current cipher can not be used to get a single object'
            )

        data = await self.loop.run_in_executor(None, handler.decrypt, data_enc)

        return data
