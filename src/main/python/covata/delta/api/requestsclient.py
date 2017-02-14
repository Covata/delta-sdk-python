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

from covata.delta import DeltaApiClient, LogMixin, crypto
from covata.delta.api.signer import CVTSigner

from requests.auth import AuthBase


class RequestsApiClient(DeltaApiClient, LogMixin):
    def register_identity(self, external_id=None, metadata=None):
        private_signing_key = crypto.generate_private_key()
        private_encryption_key = crypto.generate_private_key()

        public_signing_key = private_signing_key.public_key()
        public_encryption_key = private_encryption_key.public_key()

        body = dict(
            signingPublicKey=crypto.serialize_public_key(public_signing_key),
            cryptoPublicKey=crypto.serialize_public_key(public_encryption_key),
            externalId=external_id,
            metadata=metadata)

        response = requests.post(
            url=self.DELTA_URL + self.RESOURCE_IDENTITIES,
            json=dict((k, v) for k, v in body.items() if v is not None))

        identity_id = response.json()['identityId']

        self.keystore.store_keys(
            identity_id=identity_id,
            private_signing_key=private_signing_key,
            private_encryption_key=private_encryption_key)
        return identity_id

    def get_identity(self, requestor_id, identity_id):
        return requests.get(
            url="{base_url}{resource}/{identity_id}".format(
                base_url=self.DELTA_URL,
                resource=self.RESOURCE_IDENTITIES,
                identity_id=identity_id),
            auth=self.signer(requestor_id)).json()

    def signer(self, identity_id):
        # type: (str) -> RequestsCVTSigner
        """
        Instantiates a new :class:`~covata.delta.api.RequestsCVTSigner` for
        the authorizing identity using this :class:`~.RequestsApiClient`.

        >>> signer = api_client.signer(authorizing_identity)

        :param str identity_id: the authorizing identity id
        :return: the RequestsCVTSigner object
        :rtype: :class:`~.RequestsCVTSigner`
        """
        return RequestsCVTSigner(self.keystore, identity_id)


class RequestsCVTSigner(AuthBase, CVTSigner, LogMixin):
    def __init__(self, keystore, identity_id):
        """
        Creates a Request Signer object to sign a :class:`~requests.Request`
        object using the CVT1 request signing scheme.

        The :class:`~.RequestsSigner` can be instantiated directly using its
        constructor:

        >>> signer = RequestsCVTSigner(keystore, authorizing_identity)

        It can also be instantiated indirectly via a
        :class:`~covata.delta.api.RequestsApiClient` object by calling
        :func:`~covata.delta.api.RequestsApiClient.signer`:

        >>> signer = api_client.signer(authorizing_identity)

        Example usage for retrieving an identity:

        >>> api_client = RequestsApiClient(keystore)
        >>> signer = api_client.signer(authorizing_identity)
        >>> response = requests.get(
        ...     url="{base_url}{resource}{identity_id}".format(
        ...         base_url="https://delta.covata.io/v1",
        ...         resource="/identities/",
        ...         identity_id="e5fa4059-24c0-42a8-af9a-fe7280b43256"),
        ...     auth=signer)
        >>> print(response.json())

        It is also possible to invoke the :func:`~.RequestsSigner.__call__`
        manually to attach the appropriate headers to a
        :class:`~requests.PreparedRequest` object:

        >>> prepared_request = request.prepare()
        >>> signer(prepared_request)

        :param keystore: The KeyStore object
        :type keystore: :class:`~covata.delta.KeyStore`

        :param str identity_id: the authorizing identity id
        """
        super(RequestsCVTSigner, self).__init__(keystore)
        self.__identity_id = identity_id

    def __call__(self, r):
        r.headers = self.get_signed_headers(identity_id=self.__identity_id,
                                            method=r.method,
                                            url=r.url,
                                            headers=r.headers,
                                            payload=r.body)
        return r
