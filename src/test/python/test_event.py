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
from covata.delta import Event, EventDetails
from datetime import datetime


@pytest.fixture(scope="function")
def event_a():
    return Event(
        event_details=EventDetails(
            base_secret_id="base-secret-id-a",
            requestor_id="identity-id-a",
            rsa_key_owner_id="identity-id-b",
            secret_id="secret-id-a",
            secret_owner_id="secret-owner-id"
        ),
        host="delta.covata.io",
        source_ip="202.54.112.42",
        id="event-id-a",
        timestamp=datetime.utcnow(),
        event_type="access_success_event"
    )


def test_repr(event_a):
    assert str(event_a) == "Event(id={})".format(event_a.id)
