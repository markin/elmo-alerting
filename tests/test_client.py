import pytest
from requests.exceptions import HTTPError

import responses
from elmo.api.client import ElmoClient
from elmo.api.exceptions import LockNotAcquired, PermissionDenied


def test_client_constructor():
    """Should build the client using the base URL and the vendor suffix."""
    client = ElmoClient("https://example.com", "vendor")
    assert client._router._base_url == "https://example.com"
    assert client._router._vendor == "vendor"
    assert client._session_id is None


def test_client_constructor_with_session_id():
    """Should build the client with a provided `session_id`."""
    client = ElmoClient("https://example.com", "vendor", session_id="test")
    assert client._session_id == "test"


def test_client_auth_success(server, client):
    """Should authenticate with valid credentials."""
    html = """<script type="text/javascript">
        var apiURL = 'https://example.com';
        var sessionId = '00000000-0000-0000-0000-000000000000';
        var canElevate = '1';
    """
    server.add(responses.POST, "https://example.com/vendor", body=html, status=200)

    assert client.auth("test", "test") == "00000000-0000-0000-0000-000000000000"
    assert client._session_id == "00000000-0000-0000-0000-000000000000"
    assert len(server.calls) == 1


def test_client_auth_forbidden(server, client):
    """Should raise an exception if credentials are not valid. Elmo
    endpoint returns a 200 with a wrong authentication error.
    """
    server.add(
        responses.POST,
        "https://example.com/vendor",
        body="Wrong authentication",
        status=200,
    )

    with pytest.raises(PermissionDenied) as excinfo:
        client.auth("test", "test")
    assert client._session_id is None
    assert len(server.calls) == 1
    assert str(excinfo.value) == "Incorrect authentication credentials"


def test_client_auth_unknown_error(server, client):
    """Should raise an exception if there is an unknown error."""
    server.add(
        responses.POST, "https://example.com/vendor", body="Server Error", status=500
    )

    with pytest.raises(HTTPError):
        client.auth("test", "test")
    assert client._session_id is None
    assert len(server.calls) == 1


def test_client_lock(server, client, mocker):
    """Should acquire a lock if credentials are properly provided."""
    html = """[
        {
            "Poller": {"Poller": 1, "Panel": 1},
            "CommandId": 5,
            "Successful": True,
        }
    ]"""
    server.add(
        responses.POST, "https://example.com/api/panel/syncLogin", body=html, status=200
    )
    mocker.patch.object(client, "unlock")
    client._session_id = "test"

    with client.lock("test"):
        assert not client._lock.acquire(False)
    assert len(server.calls) == 1


def test_client_lock_forbidden(server, client, mocker):
    """Should raise an Exception if credentials are not correct."""
    html = """[
        {
            "Poller": {"Poller": 1, "Panel": 1},
            "CommandId": 5,
            "Successful": False,
        }
    ]"""
    server.add(
        responses.POST, "https://example.com/api/panel/syncLogin", body=html, status=403
    )
    mocker.patch.object(client, "unlock")
    client._session_id = "test"

    with pytest.raises(HTTPError):
        with client.lock("test"):
            pass
    assert len(server.calls) == 1


def test_client_lock_unknown_error(server, client, mocker):
    """Should raise an Exception for unknown status code."""
    server.add(
        responses.POST,
        "https://example.com/api/panel/syncLogin",
        body="Server Error",
        status=500,
    )

    mocker.patch.object(client, "unlock")
    client._session_id = "test"

    with pytest.raises(HTTPError):
        with client.lock(None):
            pass
    assert len(server.calls) == 1


def test_client_lock_calls_unlock(server, client, mocker):
    """Should call unlock() when exiting from the context."""
    server.add(responses.POST, "https://example.com/api/panel/syncLogin")
    mocker.patch.object(client, "unlock")
    client._session_id = "test"

    with client.lock("test"):
        pass
    assert client.unlock.called is True
    assert len(server.calls) == 1


def test_client_unlock(server, client):
    """Should call the API and release the system lock."""
    html = """[
        {
            "Poller": {"Poller": 1, "Panel": 1},
            "CommandId": 5,
            "Successful": True,
        }
    ]"""
    server.add(
        responses.POST,
        "https://example.com/api/panel/syncLogout",
        body=html,
        status=200,
    )
    client._session_id = "test"
    client._lock.acquire()

    assert client.unlock() is True
    assert client._lock.acquire(False)
    assert len(server.calls) == 1


def test_client_unlock_fails_missing_lock(server, client):
    """unlock() should fail without calling the endpoint if Lock() has not been acquired."""
    client._session_id = "test"

    with pytest.raises(LockNotAcquired):
        client.unlock()
    assert client._lock.acquire(False)
    assert len(server.calls) == 0


def test_client_unlock_fails_forbidden(server, client):
    """Should fail if wrong credentials are used."""
    html = """[
        {
            "Poller": {"Poller": 1, "Panel": 1},
            "CommandId": 5,
            "Successful": False,
        }
    ]"""
    server.add(
        responses.POST,
        "https://example.com/api/panel/syncLogout",
        body=html,
        status=403,
    )

    client._session_id = "test"
    client._lock.acquire()

    with pytest.raises(HTTPError):
        client.unlock()
    assert not client._lock.acquire(False)
    assert len(server.calls) == 1


def test_client_unlock_fails_unexpected_error(server, client):
    """Should raise an error and keep the lock if the server has problems."""
    html = """[
        {
            "Poller": {"Poller": 1, "Panel": 1},
            "CommandId": 5,
            "Successful": False,
        }
    ]"""
    server.add(
        responses.POST,
        "https://example.com/api/panel/syncLogout",
        body=html,
        status=500,
    )
    client._session_id = "test"
    client._lock.acquire()

    with pytest.raises(HTTPError):
        client.unlock()
    assert not client._lock.acquire(False)
    assert len(server.calls) == 1


def test_client_arm(server, client):
    """Should call the API and arm the system."""
    html = """[
        {
            "Poller": {"Poller": 1, "Panel": 1},
            "CommandId": 5,
            "Successful": True,
        }
    ]"""
    server.add(
        responses.POST,
        "https://example.com/api/panel/syncSendCommand",
        body=html,
        status=200,
    )
    client._session_id = "test"
    client._lock.acquire()

    assert client.arm() is True
    assert len(server.calls) == 1


def test_client_arm_fails_missing_lock(server, client):
    """arm() should fail without calling the endpoint if Lock() has not been acquired."""
    client._session_id = "test"

    with pytest.raises(LockNotAcquired):
        client.arm()
    assert client._lock.acquire(False)
    assert len(server.calls) == 0


def test_client_arm_fails_missing_session(server, client):
    """Should fail if a wrong access token is used."""
    html = """[
        {
            "Poller": {"Poller": 1, "Panel": 1},
            "CommandId": 5,
            "Successful": False,
        }
    ]"""
    server.add(
        responses.POST,
        "https://example.com/api/panel/syncSendCommand",
        body=html,
        status=403,
    )
    client._session_id = "test"
    client._lock.acquire()

    with pytest.raises(HTTPError):
        client.arm()
    assert len(server.calls) == 1


def test_client_arm_fails_unknown_error(server, client):
    """Should fail if an unknown error happens."""
    server.add(
        responses.POST,
        "https://example.com/api/panel/syncSendCommand",
        body="Server Error",
        status=500,
    )
    client._session_id = "test"
    client._lock.acquire()

    with pytest.raises(HTTPError):
        client.arm()
    assert len(server.calls) == 1


def test_client_disarm(server, client):
    """Should call the API and disarm the system."""
    html = """[
        {
            "Poller": {"Poller": 1, "Panel": 1},
            "CommandId": 5,
            "Successful": True,
        }
    ]"""
    server.add(
        responses.POST,
        "https://example.com/api/panel/syncSendCommand",
        body=html,
        status=200,
    )
    client._session_id = "test"
    client._lock.acquire()

    assert client.disarm() is True
    assert len(server.calls) == 1


def test_client_disarm_fails_missing_lock(server, client):
    """disarm() should fail without calling the endpoint if Lock() has not been acquired."""
    client._session_id = "test"

    with pytest.raises(LockNotAcquired):
        client.disarm()
    assert client._lock.acquire(False)
    assert len(server.calls) == 0


def test_client_disarm_fails_missing_session(server, client):
    """Should fail if a wrong access token is used."""
    html = """[
        {
            "Poller": {"Poller": 1, "Panel": 1},
            "CommandId": 5,
            "Successful": False,
        }
    ]"""
    server.add(
        responses.POST,
        "https://example.com/api/panel/syncSendCommand",
        body=html,
        status=403,
    )
    client._session_id = "test"
    client._lock.acquire()

    with pytest.raises(HTTPError):
        client.disarm()
    assert len(server.calls) == 1


def test_client_disarm_fails_unknown_error(server, client):
    """Should fail if an unknown error happens."""
    server.add(
        responses.POST,
        "https://example.com/api/panel/syncSendCommand",
        body="Server Error",
        status=500,
    )
    client._session_id = "unknown"
    client._lock.acquire()

    with pytest.raises(HTTPError):
        client.disarm()
    assert len(server.calls) == 1


def test_client_get_areas(server, client, areas_html):
    """Should make a call to retrieve items from Elmo dashboards."""
    server.add(
        responses.GET, "https://example.com/vendor/Areas", body=areas_html, status=200,
    )
    client._session_id = "test"
    areas_names = client._get_names(client._router.areas_list)
    assert areas_names == ["Entryway", "Corridor"]


def test_client_get_inputs(server, client, inputs_html):
    """Should make a call to retrieve items from Elmo dashboards."""
    server.add(
        responses.GET,
        "https://example.com/vendor/Inputs",
        body=inputs_html,
        status=200,
    )
    client._session_id = "test"
    inputs_names = client._get_names(client._router.inputs_list)
    assert inputs_names == ["Main door", "Window", "Shade"]


def test_client_get_items_unauthorized(server, client):
    """Should raise PermissionDenied if the request is unauthorized."""
    server.add(
        responses.GET,
        "https://example.com/vendor/Areas",
        body="User not authenticated",
        status=403,
    )
    client._session_id = "test"
    with pytest.raises(HTTPError):
        client._get_names(client._router.areas_list)


def test_client_get_items_error(server, client):
    """Should raise APIException if there is a client error."""
    server.add(
        responses.GET,
        "https://example.com/vendor/Areas",
        body="Bad Request",
        status=400,
    )
    client._session_id = "test"
    with pytest.raises(HTTPError):
        client._get_names(client._router.areas_list)


def test_client_check_success(
    server, client, areas_html, areas_data, inputs_data, inputs_html
):
    """Should make multiple calls to Elmo endpoints, to retrieve the status of the system."""
    server.add(
        responses.GET, "https://example.com/vendor/Areas", body=areas_html, status=200,
    )
    server.add(
        responses.GET,
        "https://example.com/vendor/Inputs",
        body=inputs_html,
        status=200,
    )
    server.add(
        responses.POST, "https://example.com/api/areas", body=areas_data, status=200,
    )
    server.add(
        responses.POST, "https://example.com/api/inputs", body=inputs_data, status=200,
    )
    client._session_id = "test"
    status = client.check()
    assert status == {
        "areas_armed": [{"id": 1, "name": "Entryway"}],
        "areas_disarmed": [{"id": 2, "name": "Corridor"}],
        "inputs_alerted": [],
        "inputs_wait": [{"id": 1, "name": "Main door"}, {"id": 2, "name": "Window"}],
    }


def test_client_check_fail_areas_html(
    server, client, areas_html, areas_data, inputs_data, inputs_html
):
    """Should raise an exception if the Areas dashboard page fails to load."""
    server.add(
        responses.GET, "https://example.com/vendor/Areas", body=areas_html, status=500,
    )
    server.add(
        responses.GET,
        "https://example.com/vendor/Inputs",
        body=inputs_html,
        status=200,
    )
    server.add(
        responses.POST, "https://example.com/api/areas", body=areas_data, status=200,
    )
    server.add(
        responses.POST, "https://example.com/api/inputs", body=inputs_data, status=200,
    )
    # Some endpoints will not be called
    server.assert_all_requests_are_fired = False
    client._session_id = "test"

    with pytest.raises(HTTPError):
        client.check()

    assert len(server.calls) == 2


def test_client_check_fail_inputs_html(
    server, client, areas_html, areas_data, inputs_data, inputs_html
):
    """Should raise an exception if the Inputs dashboard page fails to load."""
    server.add(
        responses.GET, "https://example.com/vendor/Areas", body=areas_html, status=200,
    )
    server.add(
        responses.GET,
        "https://example.com/vendor/Inputs",
        body=inputs_html,
        status=500,
    )
    server.add(
        responses.POST, "https://example.com/api/areas", body=areas_data, status=200,
    )
    server.add(
        responses.POST, "https://example.com/api/inputs", body=inputs_data, status=200,
    )
    # Some endpoints will not be called
    server.assert_all_requests_are_fired = False
    client._session_id = "test"

    with pytest.raises(HTTPError):
        client.check()

    assert len(server.calls) == 4


def test_client_check_fail_areas_api(
    server, client, areas_html, areas_data, inputs_data, inputs_html
):
    """Should raise an exception if the Areas API endpoint fails."""
    server.add(
        responses.GET, "https://example.com/vendor/Areas", body=areas_html, status=200,
    )
    server.add(
        responses.GET,
        "https://example.com/vendor/Inputs",
        body=inputs_html,
        status=200,
    )
    server.add(
        responses.POST, "https://example.com/api/areas", body=areas_data, status=500,
    )
    server.add(
        responses.POST, "https://example.com/api/inputs", body=inputs_data, status=200,
    )
    # Some endpoints will not be called
    server.assert_all_requests_are_fired = False
    client._session_id = "test"

    with pytest.raises(HTTPError):
        client.check()

    assert len(server.calls) == 1


def test_client_check_fail_inputs_api(
    server, client, areas_html, areas_data, inputs_data, inputs_html
):
    """Should raise an exception if the Inputs API endpoint fails."""
    server.add(
        responses.GET, "https://example.com/vendor/Areas", body=areas_html, status=200,
    )
    server.add(
        responses.GET,
        "https://example.com/vendor/Inputs",
        body=inputs_html,
        status=200,
    )
    server.add(
        responses.POST, "https://example.com/api/areas", body=areas_data, status=200,
    )
    server.add(
        responses.POST, "https://example.com/api/inputs", body=inputs_data, status=500,
    )
    # Some endpoints will not be called
    server.assert_all_requests_are_fired = False
    client._session_id = "test"

    with pytest.raises(HTTPError):
        client.check()

    assert len(server.calls) == 3
