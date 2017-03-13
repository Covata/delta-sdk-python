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

====================
CVT1 Request Signing
====================

All requests to the Delta service (with the exception of the Create Identity
request) must be signed using the CVT1 request signing scheme, which is similar
to other request signing schemes such as those implemented by Amazon AWS.

At a high level, signing a request using the CVT1 request signing scheme
involves the following 4 steps (noting that each step uses output from the
previous stage):

- Create a canonical request (a digital fingerprint unique to the request),
  consisting of:
  - The HTTP request method
  - The canonical path
  - The canonical query string
  - The canonical headers
  - The signed headers
  - The hashed payload
- Create a string to sign, using the canonical request
- Calculate the signature, using the string to sign
- Add the authorization header to the request, using the signature

Each of these steps are described below.

Creating a canonical request
============================

The canonical request is a representation of the request in a standardised
(canonical) format that can be procedurally constructed (and reconstructed on
the server) to be used as part of the signature calculation and verification
process. The canonical request is constructed with the following request
elements:

- The HTTP request method
- The canonical path
- The HTTP query string, in a canonical format (the canonical query string)
- The HTTP header names and values, in a canonical format (the canonical
  headers)
- The HTTP header names, in the order they are appear in the canonical headers
  (the signed headers)
- The payload, ordered and hashed using SHA-256 (the hashed payload)

These elements are joined together as a single string, delimited by newline
('\n') character. The following example shows the pseudocode to create a
canonical request::

 CanonicalRequest = HTTPRequestMethod + '\n'
  + CanonicalURI + '\n'
  + CanonicalQueryString + '\n'
  + CanonicalHeaders + '\n'
  + SignedHeaders + '\n'
  + HashedPayload

To construct each of these elements, follow the steps below.

Constructing the HTTP request method
------------------------------------
This is the HTTP request method (GET, PUT, POST, etc.) in uppercase.

Example for a POST request::

 POST

Constructing the canonical path
-------------------------------

The canonical path is the absolute path component of the entire URI - that is,
everything in the URI from the end of the HTTP host component through to the
question mark character ("?") that begins the query string parameters.
Each such path-segment should be URI-encoded and normalised according to
RFC 3986. The absolute path component should be enclosed by an opening and
trailing "/".

A request to the identities endpoint ``https://delta.covata.io/v1/identities``
has the following canonical path::

 /identities/

If the absolute path is empty, simply represent this as a forward slash (/)::

 /

If the canonical path requires encoding, this should be present in the string
too::

 /my%20secrets/

Constructing the canonical query string
---------------------------------------
The canonical query string consists of the query string, sorted, URI-encoded
and normalised according to RFC 3986. If the request does not include a query
string, use an empty string so that the delimited canonical header will include
a blank line between the canonical request and the canonical headers::

 POST
 /identities/

 content-type:application/json; charset=utf-8
 ...

To create the canonical query string:

#. Sort the parameter names by character code in ascending order (ASCII
   order). For example, a parameter name that begins with the uppercase letter
   F (ASCII code 70) precedes a parameter name that begins with a lowercase
   letter b (ASCII code 98).
#. URI-encode each parameter name and value according to the following rules:

   - Do not URI-encode any of the unreserved characters that RFC 3986 defines:
     A-Z, a-z, 0-9, hyphen ( - ), underscore ( _ ), period ( . ), and tilde (
     ~ ).
   - Percent-encode all other characters with %XY, where X and Y are
     hexadecimal characters (0-9 and uppercase A-F). For example, the space
     character must be encoded as %20. Do not include plus symbols ('+'), as
     some encoding schemes do.
   - Extended UTF-8 characters must be in the form %XY%ZA%BC.
#. Build the canonical query string by starting with the first parameter name
   in the sorted list.
#. For each parameter, append the URI-encoded parameter name, followed by the
   character '=' (ASCII code 61), followed by the URI-encoded parameter value.
   Use an empty string for parameters that have no value.
#. Append the character '&' (ASCII code 38) after each parameter value, except
   for the last value in the list.

Example of a canonical query string containing a single parameter::

 sampleQueryParamName=sampleQueryParamValue

Example of a canonical query string containing 2 parameters where the first
parameter has no value:

exampleQueryParamName=&sampleQueryParamName=sampleQueryParamValue

Constructing the canonical headers
----------------------------------

The canonical headers consist of a list of all the HTTP headers that are
included with the signed request in a form that Delta can interpret. At a
minimum, the date header ``Cvt-Date`` must be included. Standard headers like
Content-Type are optional. Be aware that different Delta API endpoints may
require other headers.

To create the list of canonical headers:

#. Convert all header names to lowercase and remove leading and trailing spaces.
#. Convert sequential/consecutive spaces in the header value to a single space
   (and remove leading and trailing spaces from these segments).
#. Append the lowercase header name with a colon, followed immediately by the
   value itself. This concatenated string is the canonical header entry.
#. Lexicographically, sort all the canonical header entries.
#. Join all the canonical header entries, where each entry is delimited by a
   newline character (' \n') followed by a space.

The following pseudocode describes how to construct the list of canonical
headers::

 CanonicalHeaderEntry = Lowercase(HeaderName)
  + ':'
  + Trimall(HeaderValue)
  + (FinalHeader ? '' : ' \n')

 CanonicalHeaders = CanonicalHeaderEntry0
  + CanonicalHeaderEntry1
  + ...
  + CanonicalHeaderEntryN

Note:

- Lowercase() represents a function that converts all characters in its
  argument to lowercase.
- Trimall() represents a function that converts all sets of consecutive spaces
  in its argument's value (including any quoted content) to single spaces.

The following example shows the original, complex set of headers::

 Host: delta.covata.io
 Content-Type:application/json; charset=utf-8
 My-header1:    a   b   c
 Cvt-Date:20150830T123600Z
 My-Header2:    "a   b   c"

And the list of headers in their canonical form::

 content-type:application/json; charset=utf-8
  cvt-date:20150830T123600Z
  host:delta.covata.io
  my-header1:a b c
  my-header2:"a b c"

Constructing the signed headers
-------------------------------

The signed headers is the list of headers which are included in the list
canonical headers (above).
The purpose of the signed headers list is to instruct Delta about which headers
in the request have been included in the signing process and which headers can
be ignored. Such additional headers may be those which are added after the
client application has completed the signing process (for instance by a proxy)
and therefore, these additional headers would be unknown to the client
application making the request.

Hence, the signed headers list must represent every header included in the list
of canonical headers (above).

To create the list of signed headers:

- Convert all header names to lowercase.
- Sort the lowercase header names lexicographically.
- Join all the sorted, lowercase headers delimited by a semicolon.

The following pseudocode describes how to construct the list of signed headers::

 SignedHeaders = Lowercase(HeaderName0) + ';'
  + Lowercase(HeaderName1) + ";"
  + ...
  + Lowercase(HeaderNameN)

The following example shows a signed header string::

 content-type;cvt-date;host;my-header1;my-header2

Constructing the hashed payload
-------------------------------

Use a hash (digest) function like SHA256 to create a hashed value from the body
of the request (i.e. the payload). The hashed payload must be represented as a
lowercase hexadecimal string.

All such payloads are contained in a JSON object, whose contents should be
sorted and compacted.

- Sorting is performed by member name and must be conducted at all levels of
  the entire JSON object (i.e. if any member has a value which itself is
  another JSON object, the contents of this nested JSON object need to be
  sorted too).
- The compacting process involves removing all spaces outside of everything
  contained outside quoted strings in the JSON object.

In summary, to construct the hashed payload:

#. Sort all members of every level in the JSON object payload by member name.
#. Compact the entire JSON object payload.
#. Run a SHA256 function on the compacted payload.
#. Encode the results of this function as hexadecimal.
#. Ensure that all alphabetical characters in the hexadecimal-encoded result
   are lowercase.

For requests with empty payloads (i.e. all GET requests), use the empty JSON
object ("{}") as the payload. This should always result in a hashed value of
``44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a``.

The following example shows a request's JSON object payload, which is unsorted
and uncompacted::

 {
     "signingPublicKey": "E021472BCF554198752798A956DCB5065126D578CCCF632A6BB2BA1EEF7EE685",
     "cryptoPublicKey": "220418D56A32B5B747EF301E57FA1466C229F03B1B11CC5B7900A996ACF360E8"
 }
This is what the JSON object payload looks like after sorting and compacting::

 {"cryptoPublicKey":"220418D56A32B5B747EF301E57FA1466C229F03B1B11CC5B7900A996ACF360E8","signingPublicKey":"E021472BCF554198752798A956DCB5065126D578CCCF632A6BB2BA1EEF7EE685"}

And this is what the payload looks like after hashing with SHA256 and encoding
as a lowercase hexadecimal string::

 daadd72c2e2f5b63ad67e2131a598e4a6edcd75d6bc70c36e7e3f3ec5de95417

Example canonical request
-------------------------

To construct the completed canonical request, combine all the components from
each step as a single string. As noted (above), each component ends with a
newline character.

An example canonical request string is shown below::

 POST
 /identities/
 sampleQueryParamName=sampleQueryParamValue
 content-type:application/json; charset=utf-8
  cvt-date:20150830T123600Z
  host:delta.covata.io
  my-header1:a b c
  my-header2:"a b c"
 content-type;cvt-date;host;my-header1;my-header2
 daadd72c2e2f5b63ad67e2131a598e4a6edcd75d6bc70c36e7e3f3ec5de95417

Creating a string to sign
=========================

The string to sign is a set of strings representing meta information about the
entire request.

The following pseudocode describes how to create the string to sign, which is
a concatenation of the algorithm (representing this CVT1 request signing
scheme), the date of the request (which must match the date in the header) and
the digest of the canonical request (using SHA256), delimited with the newline
('\n') character, as shown::

 StringToSign = Algorithm
	+ '\n' + RequestDate
	+ '\n' + HashedCanonicalRequest

Algorithm
---------

The designation for the CVT1 request signing scheme algorithm is::

 CVT1-RSA4096-SHA256

Request Date
------------

The request date is the value of the cvt-date header (which is in ISO8601
format YYYYMMDD'T'HHMMSS'Z'). The date/time must be in UTC and does not include
milliseconds. This value must match the value you used in relevant previous
stages.

.. code::
   20150830T123600Z

Hashed Canonical Request
------------------------

The canonical request (see Example canonical request and Stage 1 description
above) whose content has been hashed using the SHA256 algorithm.

.. code::
   cc113fcef267dbbdce8416b1a9a8bcb09a32460142449c3289bc093598a9eef0

The hashed canonical request must be hex-encoded and be lowercase, as defined
by Section 8 of RFC 4648.

Example string to sign
----------------------

The following is a completed string to sign, with a date of 31st January, 2017
at 12:34.56pm::

 CVT1-RSA4096-SHA256
 20170131T123456Z
 cc113fcef267dbbdce8416b1a9a8bcb09a32460142449c3289bc093598a9eef0

Calculating the signature
=========================

The final signature is calculated according to the following steps:

#. Calculate a SHA256 digest of the string to sign from the previous stage
   (above). The output must be hex-encoded and be lowercase, as defined by
   Section 8 of RFC 4648.
#. Obtain the private signing key of the identity that is making the request.
   This should be in base64-encoded DER format.
#. Create an RSA signature of the string to sign using RSASSA-PSS and the
   private signing key, with the following parameters:
   - SHA256 as the digest function
   - MGF1 with SHA256 as the mask generator function
   - 32 bytes as the salt value for MGF1
   - base64 encoding
Note that RSASSA-PSS will generate a different result each time due to the salt.

The following shows an example SHA256 digest output of the string to sign::

 725890633d7210c079a408d521c6545ffefc6c8e1fa8843052a047a1568a5912

Next, using the private signing key, create an RSA signature of the String to
Sign. An example of a private signing key in base64-encoded DER format is
shown below::

 MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCk2gVVEjuQEUFKvysoJS8i3hjc0cJ9OJtAZHqz0QsUbjQz0jvurUpbh5jJhAIlOFLRjNhTEwoEj/YUr3IGd1LFFDfezXbChUGh+TcptCGr97BQuMEAiP1kPT+YtS8QYtfwTq13DvP4WZ9ql129m8dfrBPXO/eBd0dSV3NLUiG1YIEnPWREJRAmV+FDWtxQYSBCa+JeUGRz3iRagL6oqDPpc2mcdU4o7gvjfoYNgTtcJw5Qnn6vRsu1oFgs7GgAt3yHNzlv8Mg+HXqI7J7XlEv7n36iGUHdiRhmxWZSt7/yz/jvuB76jbgRZnctehxzQVVk/9Xb3GOFcOj4jpkEZX9VAgMBAAECggEAB9FfF125/WcUFZtjTJAW4CxwOWipNI8OrcsWFpj/UYS4bQy3UuZc9GJF2KiuAV3eb5miWK46d2TsYqa/XZcjEb2XuLU9wJPZPPk4qH2mayVf8zQP0xqsCajt7ywIg1psqzTP/Sl0YH6/lKqBA5Dzr5HVjwuE/VrOwxTqntPSTWumhd2tXc434QdfEWXsVW7H6xKLPTZTK1jWYzQxYZmvf/td5NKKXmhfY3TMamRHb2x5XDnnCE6ktOs83CffBISzhucSe/w5/1DChRy3Xuri442nIxKtQI1Ad21aI7C/yoiUqPYpt0TkDJ53KFKgsPGvyY7c6fxL3ERfD/mpLO01gQKBgQDsxOWTf+p2C+det5p2j6iZ5N/dyWL5tUm9WPnmX3r83h3VkOdEdeGPa8QNhVrHv8us9VYOUVDh/0YDNzTJQog+QeV205NGQ272C2oRwkfo6ltHk/0DEjyPFSw0viyPSoBN0gytRqULmA0ULXZ7LcL36zDrQlD0DUU3HJvG58NGyQKBgQCyPcFPU5Vlx3ll0YSezfj9e1N82/bws7Tgk+3r6A8kdNvZN/9xZ7QKJ6a2ihHfs8HIGCGfTLCj5nXcbERfc784Cx4/jvaMj2BICuqf5K4Xatab0FmAF9waOwtkO61/dd8OKPf9nE04C8HZDQvIg5FqDtdHcOt9QsbudBrr7VKeLQKBgCuq2MiOY/ink2GFrUhGkIrpilxGQynYxKPWYCib3Xv7nzb/RZf7wcEI2BzCRo7mkbLxgJCdcLRtt0TqjqK70ZLh5mc2+EeSMknQqxxhX4/WgUU/Rv+lAmRFPGTx2hgHXoh7v/jJObFctrTM+bgYJYhB6UDKd1G7jNNwRE63+ez5AoGAVhbp1YzDbgNoqTsHWUSW7KeybW442Y2S4Z3Rns3Y8nzW6xXW9Ulndjgsl6Ice/XwtNqi8rQx5Rgc+Tf51jirtT/5fi1o+/8MO/+5zzy+sWTS/zMk52+eybSXDfSdGiEueUJkdUQXL+jN2i4o8NJLW/SLGmB5/WhReT7u+eEItIkCgYEAronO5VDCjZXEhJGebUKbKACHamp5DVxqhWsDxUHEldqA7V0OISYOpfOuVMeE7mIAae6yAGXLIhpSALr2fIcKoAKj2iCuzUdHmS8U7xBD7F2XBDHTVltAnhxq+FPd32Sdl6G8uVi1MoBiLAsjvdXMfU36FnZNlJZI4mcx18XoeXU=


Initialising the cipher using the specified parameters will result in a signed
string. This should be encoded in base64. RSASSA-PSS will generate a different
signature every time, so running this example generate a different example each
time.

.. code::
 ZwccJzSaGuNO0GRleZFpMqZ3VBs59VAxB7J6COubsCJTnVccmgyxuxtpRpi9qP20Ytk83SLY0ZyeXRphlZTyW7OqLB1I5U3as9AKqD4WpQK1iNPn7z6K1X3nODq3jWk2TqbcW2pMoFZXGvaCyN5j1ma7Qr/iEYGVDtGzzMdrGKKMfN6GUWVM9nwozXn82eqgjtvxw7X2eA/ecGs44fy10KygdXHiaB+lkzTDfNh1k26FfHF5YEeiBCwCQahYHo89aac0/LeWjjXqlqUiQntYnwUM7hYphbX8ArES75+4VtqIEGf1NCON52ctbifVLjXzhb8j20CfJgXhsl0fwoQpQ==

Adding the authorization header
===============================

Add to the request an HTTP header named Authorization, whose value includes:
- The algorithm of the CVT1 signing scheme.
- The ID of the identity making the request.
- The signed headers.
- The signature calculated in Stage 3 (above).

The contents of the header are created after you calculate the signature as
described in stage 3, so the Authorization header is not included in the list
of signed headers. Although the header is named Authorization, the signing
information is actually used for authentication.

The following pseudocode shows the construction of the Authorization header::

 Authorization: algorithm Identity=identityId, SignedHeaders=signedHeaders, Signature=signature

The following example shows a finished Authorization header (the algorithm is
the CVT1 request signing scheme as designated by the string
``CVT1-RSA4096-SHA256``)::

 Authorization: CVT1-RSA4096-SHA256 Identity=b15e50ea-ce07-4a3d-a4fc-0cd6b4d9ab13, SignedHeaders=content-type;host;x-cvt-date, Signature=ZwccJzSaGuNO0GRleZFpMqZ3VBs59VAxB7J6COubsCJTnVccmgyx/uxtpRpi9qP20Ytk83SLY0ZyeXRphlZTyW7OqLB1I5U3as9AKqD4WpQK1iNPn7z6K1X3nODq3jWk2TqbcW2pMoFZXGvaCyN5j1ma7Qr/iEYGVDtGzzMdrGKKMfN6GUWVM9nwozXn82eqgjtvxw7X2eA/ecGs44fy10KygdXHiaB+lkzTDfNh1k26FfHF5YEeiBCwCQahYHo89aac0/LeWjjXqlqUiQntYnwUM7hYphbX8ArES75+4VtqIEGf1NCON52ctbifVLjXzhb8j20CfJgXhsl0fwoQpQ==

Note the following:

- There is no comma between the algorithm and Identity. However, the
  SignedHeaders and Signature are separated from the preceding values with a
  comma.
- The value is the identifier generated by Delta during identity registration.
