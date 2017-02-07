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

import json
import uuid

import responses

from covata.delta.api import ApiClient, RequestsApiClient


@responses.activate
def test_register_identity(mocker, crypto_service, private_key):
    expected_id = str(uuid.uuid4())
    responses.add(responses.POST,
                  ApiClient.DELTA_URL + ApiClient.RESOURCE_IDENTITIES,
                  status=201,
                  body=json.dumps(dict(identityId=expected_id)),
                  content_type='application/json')

    mocker.patch.object(crypto_service, 'generate_key', return_value=private_key)

    api_client = RequestsApiClient(crypto_service)
    identity_id = api_client.register_identity("1", {})
    assert identity_id == expected_id
