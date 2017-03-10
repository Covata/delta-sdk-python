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

from covata.delta import Client, FileSystemKeyStore

key_store = FileSystemKeyStore("~/keystore/", "passPhrase")
client = Client(key_store)

# option 1: via identity object
identity = client.get_identity("8e91cb8c-1ea5-4b69-bedf-9a14940cce44")
secret = identity.get_secret("a9724dd3-8fa1-4ecd-bbda-331748410cf8")

# option 2: via client object
secret = client.get_secret("8e91cb8c-1ea5-4b69-bedf-9a14940cce44",
                           "a9724dd3-8fa1-4ecd-bbda-331748410cf8")

# it's all the same secret
content = secret.get_content()
