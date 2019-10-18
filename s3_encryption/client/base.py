import abc

from s3_encryption.exceptions import ArgumentError
from s3_encryption.key_provider import DefaultKeyProvider


class S3EncryptionAbstractClient(abc.ABC):

    def __init__(self, encryption_key=None, **kwargs):
        self.key_provider = self.extract_key_provider(
            encryption_key=encryption_key,
            **kwargs
        )
        self.envelope_location = self.extract_location(**kwargs)
        self.instruction_file_suffix = self.extract_suffix(**kwargs)

    @classmethod
    @abc.abstractmethod
    async def put_object(self, Bucket=None, Key=None, Body=None,
                         ACL=None, **kwargs):
        ...

    @classmethod
    @abc.abstractmethod
    async def multipart_upload(self, Bucket=None, Key=None, Body=None,
                               ACL=None, config=None, callback=None, **kwargs):
        ...

    @classmethod
    @abc.abstractmethod
    async def get_object(self, Bucket=None, Key=None):
        ...

    def extract_key_provider(self, **kwargs):
        if 'encryption_key' not in kwargs:
            msg = 's3_encryption currently only supports '\
                  'encryption with client provided keys.'
            raise ArgumentError(msg)
        return DefaultKeyProvider(kwargs['encryption_key'], **kwargs)

    def extract_location(self, **kwargs):
        location = kwargs.get('envelope_location', 'metadata')
        if location not in ['instruction_file', 'metadata']:
            raise ArgumentError('envelope_location must be one of: metadata, '
                                'instruction_file')
        return location

    def extract_suffix(self, **kwargs):
        return kwargs.get('instruction_file_suffix', '.instruction')
