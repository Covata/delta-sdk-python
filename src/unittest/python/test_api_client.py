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

import uuid

import responses

from covata.delta.api import ApiClient, RequestsApiClient


@responses.activate
def test_register_identity(mocker, crypto_service, private_key, key2bytes):
    expected_id = str(uuid.uuid4())
    responses.add(responses.POST,
                  ApiClient.DELTA_URL + ApiClient.RESOURCE_IDENTITIES,
                  status=201,
                  json=dict(identityId=expected_id))

    mocker.patch.object(crypto_service, 'generate_key', return_value=private_key)

    api_client = RequestsApiClient(crypto_service)
    identity_id = api_client.register_identity("1", {})
    crypto_key = crypto_service.load("%s.crypto.pem" % identity_id)
    signing_key = crypto_service.load("%s.signing.pem" % identity_id)
    assert identity_id == expected_id
    assert key2bytes(crypto_key) == key2bytes(private_key)
    assert key2bytes(signing_key) == key2bytes(private_key)
