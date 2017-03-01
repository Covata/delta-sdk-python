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

import pytest
from covata.delta import signer
import json
import re
from datetime import datetime
from freezegun import freeze_time

SIGNING_ALGORITHM = "CVT1-RSA4096-SHA256"
CVT_DATE_FORMAT = "%Y%m%dT%H%M%SZ"


@pytest.mark.parametrize('payload, expected_hash', [
    (b'{"name": "user"}',
     '5077ee49430b0c34347573ca6d189b29fc98cf15b63b74f82460cf46ac1bb0a5'),
    (b'{}', '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a'),
])
def test_get_hashed_payload(payload, expected_hash):
    assert signer.__get_hashed_payload(payload) == expected_hash


def test_malformed_payload():
    with pytest.raises(ValueError) as excepinfo:
        signer.__get_hashed_payload(b'{""}')
        assert excepinfo.type is json.JSONDecodeError


def test_none_payload():
    assert signer.__get_hashed_payload(b'{}') == \
           signer.__get_hashed_payload(None)


def test_unordered_payload():
    assert signer.__get_hashed_payload(b'{"name": "rattan", "a": "value"}') == \
           signer.__get_hashed_payload(b'{"a": "value", "name": "rattan"}')


def test_nested_payload():
    input_json = \
        b"""
        {
            "name": "rattan",
            "a": "value",
            "c": {
                "za": "value",
                "a": "hello"
            }
        }
        """

    sorted_json = \
        b"""
        {
            "a": "value",
            "c": {
                "a": "hello",
                "za": "value"
            },
            "name": "rattan"
        }
        """

    assert signer.__get_hashed_payload(input_json) == \
           signer.__get_hashed_payload(sorted_json)


@pytest.mark.parametrize('url, expected_encoded_url', [
    ('/identity blah/', '/identity%20blah/'),
    ('/identity-blah/', '/identity-blah/'),
    ('/', '/'),
    ('/identityABC/', '/identityABC/'),
])
def test_uri_endoing(url, expected_encoded_url):
    assert signer.__encode_uri(url) == expected_encoded_url


@freeze_time()
def test_signature_material():
    expected_cvt_date_value = datetime.utcnow().strftime(CVT_DATE_FORMAT)
    method = "POST"
    url = "https://delta.covata.io/v1/secrets?hello=w+orld"
    headers = {
        "Content-Type": "application/json",
    }
    payload = \
        b"""
        {
            "name": "rattan",
            "a": "value",
            "c": {
                "za": "value",
                "a": "hello"
            }
        }
        """

    uri = "/secrets/"
    query = "hello=w%20orld"
    expected_content_type = 'application/json'
    canonical_headers = "content-type:{}\n cvt-date:{}".format(
        expected_content_type, expected_cvt_date_value)
    signed_headers = 'content-type;cvt-date'
    hashed_payload = \
        '758ffa295b9a475f04aef51abd60563dabb8df1988cf6d62b9298b1d5ba6b8bf'
    expected_canonical_request = "\n".join(
        [method, uri, query, canonical_headers, signed_headers, hashed_payload])
    expected_headers = {"Content-Type": expected_content_type,
        "Cvt-Date": expected_cvt_date_value
    }
    materials = \
        signer.__get_signature_materials(method, url, headers, payload)

    assert materials.method == method
    assert materials.uri == uri
    assert materials.headers_ == expected_headers
    assert materials.query_params == query
    assert materials.canonical_headers == canonical_headers
    assert materials.canonical_request == expected_canonical_request
    assert materials.signed_headers == signed_headers
    assert materials.hashed_payload == hashed_payload
    assert materials.headers_['Content-Type'] == \
           expected_content_type
    assert materials.headers_[
               'Cvt-Date'] == expected_cvt_date_value


def test_updated_headers(private_key):
    method = "POST"
    url = "https://delta.covata.io/v1/secrets?hello=world"
    headers = {
        "Content-Type": "application/json"
    }
    payload = \
        b"""
        {
            "name": "rattan",
            "a": "value",
            "c": {
                "za": "value",
                "a": "hello"
            }
        }
        """
    identity_id_ = 'Delta-Id'
    signature_materials = \
        signer.__get_signature_materials(method, url, headers, payload)

    auth_pattern = "{algorithm} Identity={identity_id}, " \
                   "SignedHeaders={signed_headers}, Signature=.*$" \
        .format(algorithm=SIGNING_ALGORITHM,
                identity_id=identity_id_,
                signed_headers=signature_materials.signed_headers)

    updated_headers = signer.get_updated_headers(
        identity_id_, method, url, headers, payload, private_key)

    assert "Authorization" in updated_headers
    assert re.match(auth_pattern, updated_headers["Authorization"]) is not None
