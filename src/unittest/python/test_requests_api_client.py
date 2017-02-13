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

import pytest
import requests
import responses

from covata.delta import ApiClient
from covata.delta.api import RequestsApiClient


@pytest.fixture(scope="function")
def mock_signer(mocker, api_client):
    return mocker.patch.object(api_client, "signer",
                               return_value=mocker.Mock())


@pytest.fixture(scope="function")
def api_client(keystore):
    return RequestsApiClient(keystore)


@responses.activate
def test_register_identity(mocker, api_client, keystore, private_key,
                           key2bytes):
    expected_id = str(uuid.uuid4())
    responses.add(responses.POST,
                  ApiClient.DELTA_URL + ApiClient.RESOURCE_IDENTITIES,
                  status=201,
                  json=dict(identityId=expected_id))

    mocker.patch('covata.delta.crypto.generate_key', return_value=private_key)

    identity_id = api_client.register_identity("1", {})
    crypto_key = keystore.load("%s.crypto.pem" % identity_id)
    signing_key = keystore.load("%s.signing.pem" % identity_id)
    assert identity_id == expected_id
    assert key2bytes(crypto_key) == key2bytes(private_key)
    assert key2bytes(signing_key) == key2bytes(private_key)


@responses.activate
def test_get_identity(api_client, mock_signer):
    expected_id = str(uuid.uuid4())
    expected_json = dict(version=1,
                         id=expected_id,
                         cryptoPublicKey="crypto_public_key",
                         metadata=dict(name="Bob"))

    responses.add(responses.GET,
                  "{base_path}{resource}/{identity_id}".format(
                      base_path=ApiClient.DELTA_URL,
                      resource=ApiClient.RESOURCE_IDENTITIES,
                      identity_id=expected_id),
                  status=200,
                  json=expected_json)

    response = api_client.get_identity(requestor_id="requestor_id",
                                       identity_id=expected_id)

    mock_signer.assert_called_once_with("requestor_id")

    assert response == expected_json


def test_construct_signer(mocker, api_client, keystore, private_key):
    load = mocker.patch.object(keystore, 'load', return_value=private_key)
    signer = api_client.signer("mock")

    r = requests.Request(url='https://test.com/stage/resource',
                         method='POST',
                         headers=dict(someKey="some value"),
                         json=dict(content="abcd"))
    signer(r.prepare())
    load.assert_called_once_with("mock.signing.pem")
