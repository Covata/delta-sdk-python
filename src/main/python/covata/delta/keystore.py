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

from abc import ABCMeta, abstractmethod

import six

import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from .utils import LogMixin


@six.add_metaclass(ABCMeta)
class DeltaKeyStore(object):

    @abstractmethod
    def store_keys(self,
                   identity_id,
                   private_signing_key,
                   private_encryption_key):
        """
        Stores the signing and encryption key pairs under a given identity id.

        :param str identity_id: the identity id of the key owner
        :param private_signing_key: the private signing key object
        :type private_signing_key: :class:`RSAPrivateKey`
        :param private_encryption_key: the private cryptographic key object
        :type private_encryption_key: :class:`RSAPrivateKey`
        """

    @abstractmethod
    def get_private_signing_key(self, identity_id):
        """
        Loads a private signing key instance for the given identity id.

        :param str identity_id: the identity id of the key owner
        :return: the signing private key object
        """

    @abstractmethod
    def get_private_encryption_key(self, identity_id):
        """
        Loads a private encryption key instance for the given identity id.

        :param str identity_id: the identity id of the key owner
        :return: the cryptographic private key object
        """


class FileSystemKeyStore(DeltaKeyStore, LogMixin):
    def __init__(self,
                 key_store_path,
                 key_store_passphrase):
        # type: (str, bytes) -> self
        """
        Constructs a new Filesystem-backed Keystore with the given
        configuration.

        :param str key_store_path: the path to the private key store
        :param bytes key_store_passphrase: the passphrase to decrypt the keys
        """
        self.key_store_path = os.path.expanduser(key_store_path)
        self.__key_store_passphrase = key_store_passphrase

    def store_keys(self,
                   identity_id,
                   private_signing_key,
                   private_encryption_key):
        # type: (RSAPrivateKey, RSAPrivateKey, str) -> None
        self.__save(private_signing_key, "{}.signing.pem".format(identity_id))
        self.__save(private_encryption_key, "{}.crypto.pem".format(identity_id))

    def get_private_signing_key(self, identity_id):
        return self.__load("{}.signing.pem".format(identity_id))

    def get_private_encryption_key(self, identity_id):
        return self.__load("{}.crypto.pem".format(identity_id))

    def __save(self, private_key, file_name):
        # type: (RSAPrivateKey, str) -> None
        if not isinstance(private_key, RSAPrivateKey):
            raise TypeError("private_key must be an instance of RSAPrivateKey, "
                            "actual: {}".format(type(private_key).__name__))

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

    def __load(self, file_name):
        # type: (str) -> RSAPrivateKey
        file_path = os.path.join(self.key_store_path, file_name)
        with(open(file_path, 'r')) as f:
            self.logger.debug("Loading %s", file_name)
            return serialization.load_pem_private_key(
                f.read().encode('utf-8'),
                password=self.__key_store_passphrase,
                backend=default_backend())
