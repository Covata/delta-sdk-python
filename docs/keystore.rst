.. Copyright 2017 Covata Limited or its affiliates

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.


Key Store
=========

The management and storage of private keys is the responsibility of the
client. The ``DeltaKeyStore`` provides the interface for a key-storage
implementation. The ``FileSystemKeyStore`` is an implementation to store keys
in PEM formats on the file system.

Retrieval and usage of these keys is required in the following use cases:

- Request Signing - all endpoints requiring authentication will require the
  private signing key of the requesting identity as part of the CVT1 request
  signing process.

- Retrieving Secret Content - to retrieve secret content, a client will need
  access to the secret encryption key, which can only be decrypted with their
  private decryption key.

The Delta framework does not dictate or impose restrictions on how a client
should manage and store private keys. It is therefore up to the
implementation on whether to develop a custom solution or use
pre-existing solutions, as long as the keys are accessible in the above use
cases.

.. currentmodule:: covata.delta.keystore

.. autoclass:: DeltaKeyStore
    :members:

File-System Key Store
---------------------

Implementation of the ``DeltaKeyStore`` abstract base class using the file
system. Private keys are saved in the file system as encrypted PEM formats
and are only decrypted in memory on read.

.. currentmodule:: covata.delta.keystore

.. autoclass:: FileSystemKeyStore
    :show-inheritance:
    :members: