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

import requests

from . import signer, utils


class ApiClient(utils.LogMixin):
    """
    The Delta API Client is an abstraction over the Delta API for execution of
    requests and responses.
    """

    DELTA_URL = 'https://delta.covata.io/v1'        # type: str
    RESOURCE_IDENTITIES = '/identities'             # type: str
    RESOURCE_SECRETS = '/secrets'                   # type: str

    def __init__(self, key_store):
        """
        Constructs a new Delta API client with the given configuration.

        :param key_store: the DeltaKeyStore object
        :type key_store: :class:`DeltaKeyStore`
        """
        self.__key_store = key_store

    @property
    def key_store(self):
        return self.__key_store

    def register_identity(self, public_encryption_key, public_signing_key,
                          external_id=None, metadata=None):
        """
        Creates a new identity in Delta with the provided metadata
        and external id.

        :param str public_encryption_key:
            the public encryption key to associate with the identity
        :param str public_signing_key:
            the public signing key to associate with the identity
        :param external_id: the external id to associate with the identity
        :type external_id: str | None
        :param metadata: the metadata to associate with the identity
        :type metadata: dict[str, str] | None
        :return: the id of the newly created identity
        :rtype: str
        """

        body = dict(
            signingPublicKey=public_signing_key,
            cryptoPublicKey=public_encryption_key,
            externalId=external_id,
            metadata=metadata)

        response = requests.post(
            url=self.DELTA_URL + self.RESOURCE_IDENTITIES,
            json=dict((k, v) for k, v in body.items() if v is not None))
        response.raise_for_status()
        identity_id = response.json()['identityId']

        return identity_id

    def get_identity(self, requestor_id, identity_id):
        """
        Gets the identity matching the given identity id.

        :param str requestor_id: the authenticating identity id
        :param str identity_id: the identity id to retrieve
        :return: the retrieved identity
        :rtype: dict[str, any]
        """
        response = requests.get(
            url="{base_url}{resource}/{identity_id}".format(
                base_url=self.DELTA_URL,
                resource=self.RESOURCE_IDENTITIES,
                identity_id=identity_id),
            auth=self.signer(requestor_id))
        response.raise_for_status()
        identity = response.json()
        return identity

    @utils.check_arguments(
        "page, page_size",
        lambda x: True if x is None else int(x) > 0,
        "must be a non-zero positive integer")
    def get_identities_by_metadata(self, requestor_id, metadata,
                                   page=None, page_size=None):
        """
        Gets a list of identities matching the given metadata key and value
        pairs, bound by the pagination parameters.

        :param str requestor_id: the authenticating identity id
        :param metadata: the metadata key and value pairs to filter
        :type metadata: dict[str, str]
        :param page: the page number
        :type page: int | None
        :param page_size: the page size
        :type page_size: int | None
        :return: a list of identities satisfying the request
        :rtype: list[dict[str, any]]
        """
        metadata_ = dict(("metadata." + k, v) for k, v in metadata.items())
        response = requests.get(
            url="{base_url}{resource}".format(
                base_url=self.DELTA_URL,
                resource=self.RESOURCE_IDENTITIES),
            params=dict(metadata_,
                        page=int(page) if page else None,
                        pageSize=int(page_size) if page_size else None),
            auth=self.signer(requestor_id))
        response.raise_for_status()
        return response.json()

    def create_secret(self, requestor_id, content, encryption_details):
        """
        Creates a new secret in Delta. The key used for encryption should
        be encrypted with the key of the authenticating identity.

        It is the responsibility of the caller to ensure that the contents
        and key material in the encryption details are properly represented
        in a suitable string encoding (such as base64).

        :param str requestor_id: the authenticating identity id
        :param str content: the contents of the secret
        :param encryption_details: the encryption details
        :type encryption_details: dict[str, str]
        :return: the created base secret
        :rtype: dict[str, str]
        """
        response = requests.post(
            url="{base_url}{resource}".format(
                base_url=self.DELTA_URL,
                resource=self.RESOURCE_SECRETS),
            json=dict(
                content=content,
                encryptionDetails=encryption_details
            ),
            auth=self.signer(requestor_id))

        response.raise_for_status()
        return response.json()

    def share_secret(self, requestor_id, content, encryption_details,
                     base_secret_id, rsa_key_owner_id):
        """
        Shares the base secret with the specified target RSA key owner. The
        contents must be encrypted with the public encryption key of the
        RSA key owner, and the encrypted key and initialisation vector must
        be provided. This call will result in a new derived secret being created
        and returned as a response.

        It is the responsibility of the caller to ensure that the contents
        and key material in the encryption details are properly represented
        in a suitable string encoding (such as base64).

        :param str requestor_id: the authenticating identity id
        :param bytes content: the contents of the secret
        :param encryption_details: the encryption details
        :type encryption_details: dict[str, bytes]
        :param str base_secret_id: the id of the base secret
        :param str rsa_key_owner_id: the id of the rsa key owner
        :return: the created derived secret
        :rtype: dict[str, str]
        """
        response = requests.post(
            url="{base_url}{resource}".format(
                base_url=self.DELTA_URL,
                resource=self.RESOURCE_SECRETS),
            json=dict(
                content=content,
                encryptionDetails=encryption_details,
                baseSecret=base_secret_id,
                rsaKeyOwner=rsa_key_owner_id
            ),
            auth=self.signer(requestor_id))

        response.raise_for_status()
        return response.json()

    def delete_secret(self, requestor_id, secret_id):
        """
        Deletes the secret with the given secret id.

        :param str requestor_id: the authenticating identity id
        :param str secret_id: the secret id to be deleted
        """
        response = requests.delete(
            url="{base_url}{resource}/{secret_id}".format(
                base_url=self.DELTA_URL,
                resource=self.RESOURCE_SECRETS,
                secret_id=secret_id),
            auth=self.signer(requestor_id))
        response.raise_for_status()

    def get_secret(self, requestor_id, secret_id):
        """
        Gets the given secret. This does not include the metadata and contents,
        they need to be made as separate requests,
        :func:`~.ApiClient.get_secret_metadata`
        and :func:`~.ApiClient.get_secret_content` respectively.

        :param str requestor_id: the authenticating identity id
        :param str secret_id: the secret id to be retrieved
        :return: the retrieved secret
        :rtype: dict[str, any]
        """
        response = requests.get(
            url="{base_url}{resource}/{secret_id}".format(
                base_url=self.DELTA_URL,
                resource=self.RESOURCE_SECRETS,
                secret_id=secret_id),
            auth=self.signer(requestor_id))
        response.raise_for_status()
        return response.json()

    def get_secret_metadata(self, requestor_id, secret_id):
        """
        Gets the metadata key and value pairs for the given secret.

        :param str requestor_id: the authenticating identity id
        :param str secret_id: the secret id to be retrieved
        :return: the retrieved secret metadata dictionary and version tuple
        :rtype: (dict[str, str], int)
        """
        response = requests.get(
            url="{base_url}{resource}/{secret_id}/metadata".format(
                base_url=self.DELTA_URL,
                resource=self.RESOURCE_SECRETS,
                secret_id=secret_id),
            auth=self.signer(requestor_id))

        response.raise_for_status()
        metadata = response.json()
        version = int(response.headers["ETag"])
        return metadata, version

    def get_secret_content(self, requestor_id, secret_id):
        """
        Gets the contents of the given secret.

        :param str requestor_id: the authenticating identity id
        :param str secret_id: the secret id to be retrieved
        :return: the retrieved secret
        :rtype: dict[str, str]
        """
        response = requests.get(
            url="{base_url}{resource}/{secret_id}/content".format(
                base_url=self.DELTA_URL,
                resource=self.RESOURCE_SECRETS,
                secret_id=secret_id),
            auth=self.signer(requestor_id))

        response.raise_for_status()
        return response.json()

    def update_secret_metadata(self,
                               requestor_id,
                               secret_id,
                               metadata,
                               version):
        """
        Updates the metadata of the given secret given the version number.
        The version of a secret's metadata can be obtained by calling
        :func:`~.ApiClient.get_secret`.
        A newly created base secret has a metadata version of 1.

        :param str requestor_id: the authenticating identity id
        :param str secret_id: the secret id to be updated
        :param metadata: metadata dictionary
        :type metadata: dict[str, str]
        :param int version: metadata version, required for optimistic locking
        """
        response = requests.put(
            url="{base_url}{resource}/{secret_id}/metadata".format(
                base_url=self.DELTA_URL,
                resource=self.RESOURCE_SECRETS,
                secret_id=secret_id),
            headers={
                "if-match": str(version)
            },
            json=metadata,
            auth=self.signer(requestor_id))

        response.raise_for_status()

    def update_identity_metadata(self,
                                 requestor_id,
                                 identity_id,
                                 metadata,
                                 version):
        """
        Updates the metadata of the given identity given the version number.
        The version of an identity's metadata can be obtained by calling
        :func:`~.ApiClient.get_identity`.
        An identity has an initial metadata version of 1.

        :param str requestor_id: the authenticating identity id
        :param str identity_id: the identity id to be updated
        :param metadata: metadata dictionary
        :type metadata: dict[str, str]
        :param int version: metadata version, required for optimistic locking
        """
        response = requests.put(
            url="{base_url}{resource}/{identity_id}".format(
                base_url=self.DELTA_URL,
                resource=self.RESOURCE_IDENTITIES,
                identity_id=identity_id),
            headers={
                "if-match": str(version)
            },
            json=dict(metadata=metadata),
            auth=self.signer(requestor_id))
        response.raise_for_status()

    def signer(self, identity_id):
        """
        Generates a request signer function for the
        the authorizing identity.

        >>> signer = api_client.signer(authorizing_identity)

        :param str identity_id: the authorizing identity id
        :return: the request signer function
        :rtype: (:class:`PreparedRequest`) -> :class:`PreparedRequest`
        """
        def sign_request(r):
            # type: (requests.PreparedRequest) -> requests.PreparedRequest
            signing_key = self.key_store.get_private_signing_key(identity_id)
            r.headers = signer.get_updated_headers(
                identity_id=identity_id,
                method=r.method,
                url=r.url,
                headers=r.headers,
                payload=r.body,
                private_signing_key=signing_key)
            return r
        return sign_request
