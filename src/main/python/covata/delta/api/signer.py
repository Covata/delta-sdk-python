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

import json
import re
from base64 import b64encode
from collections import OrderedDict
from collections import namedtuple
from datetime import datetime

import six.moves.urllib as urllib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from ..crypto import sha256hex
from ..utils import LogMixin


class SignatureMaterial(namedtuple('SignatureMaterial', [
    'method',
    'uri',
    'query_params',
    'canonical_headers',
    'signed_headers',
    'hashed_payload'
])):
    def __init__(self, *args, **kwargs):
        super(SignatureMaterial, self).__init__()
        self.__canonical_request = "\n".join([
            self.method,
            self.uri,
            self.query_params,
            self.canonical_headers,
            self.signed_headers,
            self.hashed_payload])

    @property
    def canonical_request(self):
        return self.__canonical_request


class CVTSigner(LogMixin):
    UNDESIRED_HEADERS = ["Connection", "Content-Length"]
    SIGNING_ALGORITHM = "CVT1-RSA4096-SHA256"
    CVT_DATE_FORMAT = "%Y%m%dT%H%M%SZ"

    def __init__(self, keystore):
        """
        Creates a Request Signer object to sign a request
        using the CVT1 request signing scheme.

        :param keystore: The KeyStore object
        :type keystore: :class:`~covata.delta.KeyStore`
        """
        self.__keystore = keystore

    def get_signed_headers(self, identity_id, method, url, headers, payload):
        """
        Gets the signed headers

        :param str identity_id: the authorizing identity id
        :param str method: the HTTP request method
        :param str url: the delta url
        :param dict headers: the request headers
        :param payload: the request payload
        :return: the original headers with a signed Authorization header.
        :rtype: dict
        """
        _url = urllib.parse.urlparse(url)
        cvt_date = datetime.utcnow().strftime(self.CVT_DATE_FORMAT)
        _headers = dict(headers)
        _headers["Cvt-Date"] = cvt_date
        _headers['Host'] = _url.hostname
        signature_materials = self.__get_materials(
            method, _url.path, _url.query, _headers, payload)
        canonical_request = signature_materials.canonical_request
        self.logger.debug(canonical_request)
        string_to_sign = "\n".join([
            self.SIGNING_ALGORITHM,
            cvt_date,
            sha256hex(canonical_request).decode('utf-8')])

        self.logger.debug(string_to_sign)
        signature = \
            b64encode(self.__sign(string_to_sign, identity_id)).decode('utf-8')

        _headers["Authorization"] = \
            "{algorithm} Identity={identity_id}, " \
            "SignedHeaders={signed_headers}, Signature={signature}" \
            .format(algorithm=self.SIGNING_ALGORITHM,
                    identity_id=identity_id,
                    signed_headers=signature_materials.signed_headers,
                    signature=signature)
        return _headers

    def __sign(self, string_to_sign, identity_id):
        private_key = self.__keystore.load(identity_id + ".signing.pem")
        return private_key.sign(string_to_sign.encode("utf-8"),
                                padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                            salt_length=32),
                                hashes.SHA256())

    def __get_materials(self, method, path, query, headers, payload):
        # type: (str, str, dict, dict, bytes or None) -> SignatureMaterial
        # /master/identities/a123?key=an+arbitrary+value&key2=x
        uri = self.__encode_uri("/".join(path.split("/")[2:]))
        query = query.replace("+", "%20")

        sorted_header = OrderedDict(sorted(
            (k.lower(), re.sub("\s+", ' ', v).strip())
            for k, v in headers.items()
            if k not in self.UNDESIRED_HEADERS))

        canonical_headers = "\n ".join(
            "{}:{}".format(k, v) for (k, v) in sorted_header.items())

        signed_headers = ";".join(sorted_header.keys())
        hashed_payload = self.__get_hashed_payload(payload)

        return SignatureMaterial(method=method,
                                 uri=uri,
                                 query_params=query,
                                 canonical_headers=canonical_headers,
                                 signed_headers=signed_headers,
                                 hashed_payload=hashed_payload)

    @staticmethod
    def __get_hashed_payload(payload):
        # type: (bytes) -> unicode
        sorted_payload = "{}" if payload is None else json.dumps(
            json.loads(payload.decode('utf-8')),
            separators=(',', ':'),
            sort_keys=True)
        return sha256hex(sorted_payload).decode('utf-8')

    @staticmethod
    def __encode_uri(resource_path):
        # type: (str) -> str
        if resource_path is not "/":
            uri_parsed = re.sub("^/+|/+$", "", resource_path)
            quoted_uri = urllib.parse.quote(uri_parsed).replace("%7E", "~")
            return "/{}/".format(quoted_uri)
        else:
            return resource_path
