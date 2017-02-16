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


@six.add_metaclass(ABCMeta)
class DeltaApiClient(object):

    DELTA_URL = 'https://delta.covata.io/v1'        # type: str
    RESOURCE_IDENTITIES = '/identities'             # type: str
    RESOURCE_SECRETS = '/secrets'                   # type: str

    def __init__(self, keystore):
        # type: (DeltaKeyStore) -> DeltaApiClient
        """
        Constructs a new Delta API client with the given configuration.

        :param keystore: the KeyStore object
        :type keystore: :class:`~.KeyStore`
        """
        self.__keystore = keystore

    @property
    def keystore(self):
        return self.__keystore

    @abstractmethod
    def register_identity(self, external_id=None, metadata=None):
        """
        Creates a new identity in Delta with the provided metadata
        and external id.

        :param external_id: the external id to associate with the identity
        :param metadata: the metadata to associate with the identity
        :return: the id of the newly created identity
        :type external_id: Optional[str]
        :type metadata: Optional[Dict[str, str]]
        :rtype: str
        """

    @abstractmethod
    def get_identity(self, requestor_id, identity_id):
        """
        Gets the identity matching the given identity id.

        :param str requestor_id: the authenticating identity id
        :param str identity_id: the identity id to retrieve
        :return: the retrieved identity
        :rtype: Dict[str, Any]
        """

    @abstractmethod
    def create_secret(self, requestor_id, content, encryption_details):
        """
        Creates a new secret in Delta. The key used for encryption should
        be encrypted with the key of the authenticating identity.

        :param str requestor_id: the authenticating identity id
        :param bytes content: the contents of the secret
        :param encryption_details: the encryption details
        :type encryption_details: Dict[str, bytes]
        :return: the created secret
        :rtype: Dict[str, str]
        """

    @abstractmethod
    def get_secret(self, requestor_id, secret_id):
        """
        Gets the given secret. This does not include the metadata and contents,
        they need to be made as separate requests,
        :func:`~.DeltaApiClient.get_secret_metadata`
        and :func:`~.DeltaApiClient.get_secret_content` respectively.

        :param str requestor_id: the authenticating identity id
        :param str secret_id: the secret id to be retrieved
        :return: the retrieved secret
        :rtype: Dict[str, Any]
        """

    @abstractmethod
    def get_secret_metadata(self, requestor_id, secret_id):
        """
        Gets the metadata key and value pairs for the given secret.

        :param str requestor_id: the authenticating identity id
        :param str secret_id: the secret id to be retrieved
        :return: the retrieved secret metadata dictionary and version tuple
        :rtype: Tuple[Dict[str, str], int]
        """

    @abstractmethod
    def get_secret_content(self, requestor_id, secret_id):
        """
        Gets the contents of the given secret.

        :param str requestor_id: the authenticating identity id
        :param str secret_id: the secret id to be retrieved
        :return: the retrieved secret
        :rtype: bytes
        """

    @abstractmethod
    def update_secret_metadata(self,
                               requestor_id,
                               secret_id,
                               metadata,
                               version):
        """
        Updates the metadata of the given secret given the version number.
        The version of a secret's metadata can be obtained by calling
        :func:`~.DeltaApiClient.get_secret_content`.
        A newly created base secret has a metadata version of 1.

        :param str requestor_id: the authenticating identity id
        :param str secret_id: the secret id to be retrieved
        :param metadata: metadata dictionary
        :type metadata: Dict[str, str]
        :param int version: metadata version, required for optimistic locking
        """


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
