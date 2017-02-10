#   Copyright 2017 Covata Limited or its affiliates
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

from __future__ import absolute_import

import base64
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from binascii import hexlify

from ..util import LogMixin
from .signer import CVTSigner


class CryptoService(LogMixin):
    def __init__(self,
                 key_store_path,
                 key_store_passphrase):
        # type: (str, str) -> self
        """
        Constructs a new Crypto service with the given configuration.

        :param str key_store_path: the path to the private key store
        :param str key_store_passphrase: the passphrase to decrypt the keys
        """
        self.key_store_path = os.path.expanduser(key_store_path)
        self.__key_store_passphrase = key_store_passphrase

    def save(self, private_key, file_name):
        """
        Saves a private key object (encrypted) to keystore

        Saving the Private Cryptographic Key:

        >>> crypto_service.save(private_key, identity_id + ".crypto.pem")

        Saving the Private Signing Key:

        >>> crypto_service.save(private_key, identity_id + ".signing.pem")

        :param private_key: the private key object
        :type private_key: :class:`RSAPrivateKey`
        :param str file_name: the name of the .pem file to be written
        """
        # type: (rsa.RSAPrivateKey, str) -> None
        pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(self.__key_store_passphrase))

        file_path = os.path.join(self.key_store_path, file_name)
        if not os.path.isdir(self.key_store_path):
            self.logger.debug("creating directory %s", self.key_store_path)
            os.makedirs(self.key_store_path)

        if os.path.isfile(file_path):
            msg = "Save failed: A key with name [{}] exists in keystore".format(
                file_name)
            self.logger.error(msg)
            raise IOError(msg)

        with open(file_path, 'w') as f:
            self.logger.debug("Saving %s", file_name)
            f.write(pem.decode(encoding='utf8'))

    def load(self, file_name):
        # type: (str) -> rsa.RSAPrivateKey
        """
        Loads a private key instance from an encrypted .pem file in the keystore

        Loading the Private Cryptographic Key:

        >>> private_key = crypto_service.load(identity_id + ".crypto.pem")

        Loading the Private Signing Key:

        >>> private_key = crypto_service.load(identity_id + ".signing.pem")

        :param str file_name: the name of the .pem file to be loaded
        :return: the private key object
        """
        file_path = os.path.join(self.key_store_path, file_name)
        with(open(file_path, 'r')) as f:
            self.logger.debug("Loading %s", file_name)
            return serialization \
                .load_pem_private_key(f.read().encode('utf-8'),
                                      password=self.__key_store_passphrase,
                                      backend=default_backend())

    @staticmethod
    def generate_key():
        # type: () -> rsa.RSAPrivateKey
        """
        Generates an RSA private key object. The public key object can be
        extracted by calling public_key() method on the generated key object.

        >>> private_key = CryptoService.generate_key() # generate a private key
        >>> public_key = private_key.public_key() # get associated public key

        :return: the generated private key object
        """
        return rsa.generate_private_key(public_exponent=65537,
                                        key_size=4096,
                                        backend=default_backend())

    @staticmethod
    def serialized(public_key):
        # type: (rsa.RSAPublicKey) -> unicode
        """
        Serialize the provided public key object as base-64-encoded DER format
        using X.509 SubjectPublicKeyInfo with PKCS1

        :param public_key: the public Key object
        :type public_key: :class:`RSAPublicKey`
        :return: the key as base64 encoded unicode string
        :rtype: str
        """
        der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        return base64.b64encode(der).decode(encoding='utf-8')

    @staticmethod
    def sha256hex(payload):
        """
        Calculate the SHA256 hex digest of the given payload

        :param str payload: the payload to be calculated
        :return: SHA256 hex digest
        :rtype: bytes
        """
        # type: (str) -> bytes
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(payload if payload is bytes else payload.encode('utf-8'))
        x = digest.finalize()  # type: bytes
        return hexlify(x)

    def signer(self, identity_id):
        # type: (str) -> CVTSigner
        """
        Instantiate a new :class:`~.CVTSigner` for the authorizing identity
        using this :class:`~.CryptoService`.

        >>> signer = crypto_service.signer(authorizing_identity)

        :param str identity_id: the authorizing identity id
        :return: the CVTSigner object
        :rtype: :class:`~covata.delta.crypto.CVTSigner`
        """
        return CVTSigner(self, identity_id)
