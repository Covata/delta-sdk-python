#   Copyright 2016 Covata Limited or its affiliates
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

from interface import ApiClient
import requests
import json


class RequestsApiClient(ApiClient):
    def register_identity(self, external_id=None, metadata=None):
        signing_private_key = self.crypto_service.generate_key()
        crypto_private_key = self.crypto_service.generate_key()

        signing_public_key = signing_private_key.public_key()
        crypto_public_key = crypto_private_key.public_key()

        body = dict(
            signingPublicKey=self.crypto_service.serialized(signing_public_key),
            cryptoPublicKey=self.crypto_service.serialized(crypto_public_key),
            externalId=external_id,
            metadata=metadata)

        response = requests.post(
            url=self.DELTA_URL + self.RESOURCE_IDENTITIES,
            json=dict((k, v) for k, v in body.iteritems() if v is not None))

        identity_id = json.loads(response.content)['identityId']

        self.crypto_service.write_to_file(
            signing_private_key, identity_id + ".signing.pem")
        self.crypto_service.write_to_file(
            crypto_private_key, identity_id + ".crypto.pem")

        return identity_id
