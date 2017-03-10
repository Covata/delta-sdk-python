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

Identity
========

An Identity is an entity (such as user, device, or another service) registered
with Delta and is comprised of a number of attributes, of which two rely on
cryptographic primitives. These are the long-lived key pairs:

- Encryption key pair - An asymmetric key pair, associated with an identity
  for the purposes of encrypting and decrypting secret encryption keys:
   - Public encryption key - The public key that functions as a key encryption
     key, to encrypt a secret encryption key. The public encryption key is
     stored in Delta as part of the identity creation process.
   - Private decryption key - The private key used to decrypt a secret
    encryption key. The private decryption key must be managed outside of Delta.

- Signing key pair - An asymmetric key pair, associated with an identity for
  the purpose of request signing and authentication:
   - Public signing verification key - The public key used to verify request
     authenticity and ownership. The public signing verification key is stored
     in Delta as part of the identity creation process and is not publicly
     visible (unlike the public encryption key).
   - Private signing key - The private key used to sign requests as required by
     Delta so that the requests can be verified. The private signing key must be
     managed outside of Delta.

.. currentmodule:: covata.delta

.. autoclass:: Identity
   :members:
