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

identity = client.get_identity("8e91cb8c-1ea5-4b69-bedf-9a14940cce44",
                               "1cb9375f-329c-405a-9b0c-b1659d9c66a4")
