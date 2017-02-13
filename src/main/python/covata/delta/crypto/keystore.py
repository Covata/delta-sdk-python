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

import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from covata.delta import DeltaKeyStore
from covata.delta import LogMixin


class FileSystemKeyStore(DeltaKeyStore, LogMixin):
    def __init__(self,
                 key_store_path,
                 key_store_passphrase):
        # type: (str, str) -> self
        """
        Constructs a new Filesystem-backed Keystore with the given
        configuration.

        :param str key_store_path: the path to the private key store
        :param str key_store_passphrase: the passphrase to decrypt the keys
        """
        self.key_store_path = os.path.expanduser(key_store_path)
        self.__key_store_passphrase = key_store_passphrase

    def save(self, signing_private_key, crypto_private_key, identity_id):
        # type: (RSAPrivateKey, RSAPrivateKey, str) -> None
        self.__save(signing_private_key, "{}.signing.pem".format(identity_id))
        self.__save(crypto_private_key, "{}.crypto.pem".format(identity_id))

    def load_signing_private_key(self, identity_id):
        return self.__load("{}.signing.pem".format(identity_id))

    def load_crypto_private_key(self, identity_id):
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
