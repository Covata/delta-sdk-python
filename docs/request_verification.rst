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

CVT1 Request Verification
=========================

The Delta service will process all requests to establish authenticity and set
the identity for the actions requested. The following elements are extracted
from the Authorization header:

- identityId
- signedHeaders
- signature

Using these elements, the following actions are performed on the request to
ensure the signature is valid:

#. Create a canonical request, consisting of:

   - The HTTP request method
   - The canonical path
   - The canonical query string
   - The canonical headers, as determined by the list of signedHeaders
   - The signedHeaders list
   - The hashed payload

#. Create a string to sign, using the canonical request from step 1.
#. Calculate a SHA256 digest of the string to sign from step 2. The output must
   be hex-encoded and be lowercase, as defined by Section 8 of RFC 4648.
#. Retrieve the public signing (verification) key of the identity matching the
   identifierId.
#. Decrypt the signature with the public signing (verification) key using
   RSASSA-PSS with the following parameters:

   - SHA256 as the digest function
   - MGF1 with SHA256 as the mask generator function
   - 32 bytes as the salt value for MGF1

#. Check the decrypted signature (from step 5) matches the digested string to
   sign (from step 3)- if match, then the request is allowed to continue,
   otherwise a HTTP status 403 is returned
