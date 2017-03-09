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


def main():
    """
    This example demonstrates the basics of creating identities, storing and
    sharing secrets.

    You will need to have a folder called "keystore" in your home directory or
    will be created as a result of running this example.
    """
    key_store = FileSystemKeyStore("~/keystore/", "passPhrase")
    client = Client(key_store)

    identity_a = client.create_identity()
    print("Identity A created; identity id = {}".format(identity_a.id))

    secret = identity_a.create_secret("Hello World!".encode("utf-8"))
    print("Identity A: Created a base secret; secret id = {}; content = {}"
          .format(secret.id, secret.get_content().decode('utf-8')))

    identity_b = client.create_identity()
    print("Identity B created; identity id = {}".format(identity_b.id))

    derived_secret_id = secret.share_with(identity_b.id).id
    print("Identity A: Shared a derived secret with Identity B; "
          "derived secret id = {}".format(derived_secret_id))

    derived_secret = identity_b.retrieve_secret(derived_secret_id)
    print("Identity B: Retrieved a derived secret; secret id = {}; content = {}"
          .format(derived_secret.id,
                  derived_secret.get_content().decode('utf-8')))

if __name__ == "__main__":
    main()
