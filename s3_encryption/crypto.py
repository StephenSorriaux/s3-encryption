import abc
import codecs
import os

from s3_encryption.client.base import EncryptionMode, S3Action

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, keywrap

class Encrypted(object):

    data = None
    tag = None

    def __init__(self, data, tag=None):
        self.data = data
        if tag is not None:
            self.tag = tag

    @property
    def full_data(self):
        return self.data if not self.tag else self.data + self.tag


class Decrypted(object):

    data = None
    tag = None

    def __init__(self, data, tag=None):
        self.data = data
        if tag is not None:
            self.tag = tag

def str_to_bytes(data):
    t = type(b''.decode('utf-8'))
    if isinstance(data, t):
        return codecs.encode(data, 'utf-8')
    return data


class AES(abc.ABC):

    tag_len = 0

    def __init__(self, key=None):
        self.key = key or self.generate_key()

    @abc.abstractmethod
    def encrypt(self, data, **kwargs):
        ...

    @abc.abstractmethod
    def decrypt(self, data, **kwargs):
        ...

    @property
    @abc.abstractmethod
    def metadata_iv(self):
        ...

    def generate_key(self, size=32):
        return os.urandom(size)


class AES_CBC(AES):

    # compatibility with JAVA client
    name = 'AES/CBC/PKCS5Padding'
    block_size = 128

    used_with = [
        S3Action.GET_OBJECT,
        S3Action.RANGED_GET_OBJECT,
        S3Action.MULTIPART_UPLOAD,
        S3Action.PART_UPLOAD,
        S3Action.PUT_OBJECT
    ]

    def __init__(self, key=None, iv=None):
        super().__init__(key=key)
        self._iv = iv or self.generate_iv()
        self.cipher = Cipher(
            algorithms.AES(self.key),
            mode=modes.CBC(self._iv),
            backend=default_backend()
        )

    @property
    def iv(self):
        return self._iv

    @iv.setter
    def iv(self, iv):
        self._iv = iv
        self.cipher = Cipher(
            algorithms.AES(self.key),
            mode=modes.CBC(self._iv),
            backend=default_backend()
        )

    def pad(self, data):
        padder = padding.PKCS7(self.block_size).padder()
        data = padder.update(data)
        data += padder.finalize()
        return data

    def unpad(self, data):
        unpadder = padding.PKCS7(self.block_size).unpadder()
        data = unpadder.update(data)
        data += unpadder.finalize()
        return data

    def encrypt(self, data, padding=True, **kwargs):
        encryptor = self.cipher.encryptor()
        data = str_to_bytes(data)
        if padding:
            data = self.pad(data)
        else:
            if not len(data) % self.block_size == 0:
                raise ValueError(
                    'data should be a multiple of block_size if no padding is used'
                )

        encrypted = Encrypted(encryptor.update(data) + encryptor.finalize())
        return encrypted

    def encrypt_no_padding(self, data):
        if not len(data) % self.block_size == 0:
            raise ValueError(
                'data should be a multiple of block_size if no padding is used'
            )

        return self.encrypt(data, padding=False)

    def decrypt(self, data):
        decryptor = self.cipher.decryptor()
        data = decryptor.update(data) + decryptor.finalize()

        return self.unpad(data)

    @property
    def metadata_iv(self):
        return self._iv

    def generate_iv(self, size=16):
        # generate a size-bytes long IV
        return os.urandom(size)


class AES_CTR(AES):
    name = 'AES/CTR/NoPadding'
    block_size = 128

    used_with = [
        S3Action.GET_OBJECT,
        S3Action.RANGED_GET_OBJECT,
        S3Action.MULTIPART_UPLOAD,
        S3Action.PART_UPLOAD,
        S3Action.PUT_OBJECT
    ]

    def __init__(self, key=None, iv=None):
        super().__init__(key=key)
        self._iv = iv or self.generate_iv()
        self.cipher = Cipher(
            algorithms.AES(self.key),
            mode=modes.CTR(self._iv),
            backend=default_backend()
        )

    @property
    def iv(self):
        return self._iv

    @iv.setter
    def iv(self, iv):
        self._iv = iv
        self.cipher = Cipher(
            algorithms.AES(self.key),
            mode=modes.CTR(self._iv),
            backend=default_backend()
        )

    def encrypt(self, data, **kwargs):
        encryptor = self.cipher.encryptor()
        data = str_to_bytes(data)
        encrypted = Encrypted(encryptor.update(data) + encryptor.finalize())
        return encrypted

    def decrypt(self, data):
        decryptor = self.cipher.decryptor()
        data = decryptor.update(data) + decryptor.finalize()
        return data

    @property
    def metadata_iv(self):
        return self._iv

    def generate_iv(self, size=16):
        # generate a size-bytes long IV
        return os.urandom(size)


class AES_GCM(AES):

    name = 'AES/GCM/NoPadding'
    block_size = 128
    tag_len = 16

    used_with = [
        S3Action.GET_OBJECT,
        S3Action.MULTIPART_UPLOAD,
        S3Action.PUT_OBJECT
    ]

    # TODO
    fall_back_cipher = {
        S3Action.PART_UPLOAD: AES_CTR,
        S3Action.RANGED_GET_OBJECT: AES_CTR
    }

    def __init__(self, key=None, iv=None):
        super().__init__(key=key)
        self._iv = iv or self.generate_nonce()
        self.cipher = Cipher(
            algorithms.AES(self.key),
            modes.GCM(self._iv),
            backend=default_backend()
        )

    @property
    def iv(self):
        return self._iv

    @iv.setter
    def iv(self, iv):
        self._iv = iv
        self.cipher = Cipher(
            algorithms.AES(self.key),
            mode=modes.GCM(self._iv),
            backend=default_backend()
        )

    def encrypt(self, data, **kwargs):
        '''
        TODO aad?
        return encrypted data with tag appended
        '''
        encryptor = self.cipher.encryptor()
        cipher_text = encryptor.update(data) + encryptor.finalize()
        encrypted = Encrypted(cipher_text, tag=encryptor.tag)
        return encrypted

    def decrypt(self, data):
        # TODO aad?
        decryptor = self.cipher.decryptor()
        tag = data[-self.tag_len:]
        data = data[:-self.tag_len]
        return decryptor.update(data) + decryptor.finalize_with_tag(tag)

    def generate_nonce(self, size=12):
        '''
        Never reuse a nonce with a key
        '''
        return os.urandom(size)

    @property
    def metadata_iv(self):
        '''
        No distinction is made between IV and nonce in the S3 API.
        '''
        return self.iv


class AES_ECB(AES):

    name = 'AES/ECB/PKCS5Padding'
    block_size = 128

    def __init__(self, key=None, iv=None):
        super().__init__(key=key)
        self.cipher = Cipher(
            algorithms.AES(self.key),
            mode=modes.ECB(),
            backend=default_backend()
        )

    def pad(self, data):
        padder = padding.PKCS7(self.block_size).padder()
        data = padder.update(data)
        data += padder.finalize()
        return data

    def unpad(self, data):
        unpadder = padding.PKCS7(self.block_size).unpadder()
        data = unpadder.update(data)
        data += unpadder.finalize()
        return data

    def encrypt(self, data, padding=True, **kwargs):
        encryptor = self.cipher.encryptor()
        data = str_to_bytes(data)
        if padding:
            data = self.pad(data)
        else:
            if not len(data) % self.block_size == 0:
                raise ValueError(
                    'data should be a multiple of block_size if no padding is used'
                )

        return encryptor.update(data) + encryptor.finalize()

    def decrypt(self, data):
        decryptor = self.cipher.decryptor()
        data = decryptor.update(data) + decryptor.finalize()
        return self.unpad(data)

    @property
    def metadata_iv(self):
        raise NotImplementedError('No IV for AES with ECB mode')


class AES_Wrap(AES):
    '''
    Initialized with the master key
    '''
    name = 'AESWrap'
    block_size = 128

    def encrypt(self, data):
        # Dont use padding to keep compatibility
        # with Java client
        return keywrap.aes_key_wrap(
            self.key,
            str_to_bytes(data),
            default_backend()
        )

    def decrypt(self, data):
        # Dont use padding to keep compatibility
        # with Java client
        return keywrap.aes_key_unwrap(
            self.key,
            str_to_bytes(data),
            default_backend()
        )

    @property
    def metadata_iv(self):
        return NotImplementedError('No IV for AESWrap')


# TODO kek for asymetric key
class RSAwhatever(AES):
    pass


data_ciphers = {
    EncryptionMode.ENCRYPTION_ONLY: AES_CBC,
    EncryptionMode.AUTHENTICATED_ENCRYPTION: AES_GCM
}

# TODO should be based on key type (symetric vs asymetric)
kek_ciphers = {
    EncryptionMode.ENCRYPTION_ONLY: AES_Wrap,
    EncryptionMode.AUTHENTICATED_ENCRYPTION: AES_Wrap
}

cek_alg_to_content_ciphers = {
    'AES/CBC/PKCS5Padding': AES_CBC,
    'AES/CBC/PKCS7Padding': AES_CBC,
    'AES/GCM/NoPadding': AES_GCM,
    'AES/CTR/NoPadding': AES_CTR
}

# TODO asymetric kek
wrap_alg_to_kek_ciphers = {
    'AESWrap': AES_Wrap
}


def content_from_encryption_mode(mode):
    if mode not in data_ciphers:
        raise ValueError(
            '{} should be one of {}'.format(
                mode, ','.join(data_ciphers.keys())
            )
        )

    return data_ciphers[mode]


def kek_from_encryption_mode(mode):
    if mode not in kek_ciphers:
        raise ValueError(
            '{} should be one of {}'.format(
                mode, ','.join(kek_ciphers.keys())
            )
        )

    return kek_ciphers[mode]

def content_from_metadata(metadata):
    if 'x-amz-cek-alg' not in metadata:
        # fallback to v1
        return AES_CBC
    
    if metadata['x-amz-cek-alg'] not in cek_alg_to_content_ciphers:
        raise ValueError('Unknown x-amz-cek-alg: ' + metadata['x-amz-cek-alg'])

    return cek_alg_to_content_ciphers[metadata['x-amz-cek-alg']]

def kek_from_metadata(metadata):
    if 'x-amz-wrap-alg' not in metadata:
        # fallback to v1
        return AES_ECB
    
    if metadata['x-amz-wrap-alg'] not in wrap_alg_to_kek_ciphers:
        raise ValueError('Unknown x-amz-wrap-alg: ' + metadata['x-amz-wrap-alg'])

    return wrap_alg_to_kek_ciphers[metadata['x-amz-wrap-alg']]

