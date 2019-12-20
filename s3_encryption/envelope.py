import json
import base64
import codecs

from s3_encryption.exceptions import IncompleteMetadataError


class EncryptionEnvelopeV1(dict):

    def __init__(self, materials=None):
        if materials is not None:
            self['x-amz-matdesc'] = json.dumps(materials.description)

    @property
    def key(self):
        _key = self.get('x-amz-key', None)
        if _key is not None:
            _key = self.decode64(_key)
        return _key

    @property
    def iv(self):
        _iv = self.get('x-amz-iv', None)
        if _iv is not None:
            _iv = self.decode64(_iv)
        return _iv

    @property
    def content_length(self):
        return self.get('x-amz-unencrypted-content-length', None)

    @content_length.setter
    def content_length(self, data):
        self['x-amz-unencrypted-content-length'] = str(len(data))

    @key.setter
    def key(self, key):
        self['x-amz-key'] = self.encode64(key)

    @iv.setter
    def iv(self, iv):
        self['x-amz-iv'] = self.encode64(iv)

    def json(self):
        return json.dumps(self)

    def from_metadata(self, metadata):
        self['x-amz-key'] = metadata.get('x-amz-key', metadata.get('x-amz-key'.title()))
        self['x-amz-iv'] = metadata.get('x-amz-iv', metadata.get('x-amz-iv'.title()))
        self['x-amz-matdesc'] = metadata.get('x-amz-matdesc', metadata.get('x-amz-matdesc'.title()))
        if not (self['x-amz-key'] is not None and self['x-amz-iv'] is not None and self['x-amz-matdesc'] is not None):
            raise IncompleteMetadataError('All metadata keys are required for decryption (x-amz-key, x-amz-iv, x-amz-matdesc).')

    def encode64(self, data):
        try:
            byte_data = bytes(data, 'utf-8')
        except TypeError:
            byte_data = bytes(data)
        return codecs.decode(base64.b64encode(byte_data), 'utf-8')

    def decode64(self, data):
        try:
            byte_data = bytes(data, 'utf-8')
        except TypeError:
            byte_data = bytes(data)
        return base64.b64decode(byte_data)


class EncryptionEnvelopeV2(dict):

    all_keys = [
        'x-amz-key-v2',
        'x-amz-matdesc',
        'x-amz-iv',
        'x-amz-cek-alg',
        'x-amz-wrap-alg',
        'x-amz-tag-len'
    ]

    def __init__(self, materials=None):
        if materials is not None:
            self['x-amz-matdesc'] = json.dumps(materials.description)

    @property
    def key(self):
        _key = self.get('x-amz-key-v2', None)
        if _key is not None:
            _key = self.decode64(_key)
        return _key

    @property
    def iv(self):
        _iv = self.get('x-amz-iv', None)
        if _iv is not None:
            _iv = self.decode64(_iv)
        return _iv

    # @property
    # def content_length(self):
    #     return self.get('x-amz-unencrypted-content-length', None)

    @property
    def cek_alg(self):
        return self.get('x-amz-cek-alg', None)


    @property
    def wrap_alg(self):
        return self.get('x-amz-wrap-alg', None)

    @property
    def tag_len(self):
        return self.get('x-amz-tag-len', None)

    @key.setter
    def key(self, key):
        self['x-amz-key-v2'] = self.encode64(key)

    @iv.setter
    def iv(self, iv):
        self['x-amz-iv'] = self.encode64(iv)

    # @content_length.setter
    # def content_length(self, data):
    #     self['x-amz-unencrypted-content-length'] = str(len(data))

    @cek_alg.setter
    def cek_alg(self, cek_alg):
        self['x-amz-cek-alg'] = str(cek_alg)

    @wrap_alg.setter
    def wrap_alg(self, wrap_alg):
        self['x-amz-wrap-alg'] = str(wrap_alg)

    @tag_len.setter
    def tag_len(self, tag_len):
        self['x-amz-tag-len'] = str(tag_len)

    def json(self):
        return json.dumps(self)

    def from_metadata(self, metadata):
        # .title() for Minio
        for key in self.all_keys:
            self[key] = metadata.get(key, metadata.get(key.title()))

        if not all([self[key] for key in self.all_keys]):
            raise IncompleteMetadataError(
                'Missing one or more metadata from object ({} instead of {})'.format(
                    ','.join([key for key in self.keys() if not key]),
                    ','.join(self.all_keys)
                )
            )

    def encode64(self, data):
        try:
            byte_data = bytes(data, 'utf-8')
        except TypeError:
            byte_data = bytes(data)
        return codecs.decode(base64.b64encode(byte_data), 'utf-8')

    def decode64(self, data):
        try:
            byte_data = bytes(data, 'utf-8')
        except TypeError:
            byte_data = bytes(data)
        return base64.b64decode(byte_data)
