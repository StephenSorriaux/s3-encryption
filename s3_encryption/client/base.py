import abc
from enum import Enum
import logging

from s3_encryption.exceptions import ArgumentError
from s3_encryption.key_provider import DefaultKeyProvider


logger = logging.getLogger(__name__)


class EncryptionMode(Enum):
    ENCRYPTION_ONLY = 1
    AUTHENTICATED_ENCRYPTION = 2


class S3Action(Enum):
    PUT_OBJECT = 1
    GET_OBJECT = 2
    MULTIPART_UPLOAD = 3
    PART_UPLOAD = 4
    RANGED_GET_OBJECT = 5


class S3EncryptionAbstractClient(abc.ABC):

    def __init__(self, encryption_key=None, encryption_mode=None, **kwargs):
        self.encryption_mode = \
            encryption_mode or EncryptionMode.AUTHENTICATED_ENCRYPTION
        self.key_provider = self.extract_key_provider(
            encryption_key=encryption_key,
            **kwargs
        )
        self.envelope_location = self.extract_location(**kwargs)
        self.instruction_file_suffix = self.extract_suffix(**kwargs)

    @abc.abstractmethod
    async def put_object(self, Bucket=None, Key=None, Body=None,
                         ACL=None, **kwargs):
        ...

    @abc.abstractmethod
    async def multipart_upload(self, Bucket=None, Key=None, Body=None,
                               ACL=None, config=None, callback=None, **kwargs):
        ...

    @abc.abstractmethod
    async def get_object(self, Bucket=None, Key=None):
        ...

    def extract_key_provider(self, encryption_key=None, **kwargs):
        if 'encryption_key' is None:
            raise ArgumentError(
                's3_encryption currently only supports '
                'encryption with client provided keys.'
            )
        if not isinstance(encryption_key, bytes):
            raise ValueError(
                'Provided encryption key is not of type bytes'
            )

        return DefaultKeyProvider(encryption_key, **kwargs)

    def extract_location(self, envelope_location='metadata', **kwargs):
        if envelope_location not in ['instruction_file', 'metadata']:
            raise ArgumentError('envelope_location must be one of: metadata, '
                                'instruction_file')
        return envelope_location

    def extract_suffix(self, **kwargs):
        return kwargs.get('instruction_file_suffix', '.instruction')
