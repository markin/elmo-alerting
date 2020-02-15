import re
from contextlib import contextmanager
from threading import Lock

from requests import Session

from .const import ARM_COMMAND, DISARM_COMMAND, INPUT_CLASS, SECTOR_CLASS
from .decorators import require_lock, require_session
from .elmo_item import ElmoItem
from .exceptions import PermissionDenied
from .router import Router
from .utils import re_case


class ElmoClient(object):
    """ElmoClient class provides all the functionalities to connect
    to an Elmo system. During the authentication a short-lived token is stored
    in the instance and is used to arm/disarm the system.

    Usage:
        # Authenticate to the system (read-only mode)
        c = ElmoClient("https://example.com", "vendor")
        c.auth("username", "password")

        # Obtain a lock to do actions on the system (write mode)
        with c.lock("alarm_code"):
            c.arm()     # Arms all alarms
            c.disarm()  # Disarm all alarms
    """

    def __init__(self, base_url, vendor, session_id=None):
        self._router = Router(base_url)
        self._session = Session()
        self._lock = Lock()

        self._session_id = session_id
        self._vendor = vendor

        self._strings = None
        self._areas = None
        self._inputs = None

    def add_name(self, element, class_):
        index = element["Index"]
        name = next(
            filter(
                lambda x: x["Class"] == class_ and x["Index"] == index, self._strings
            ),
            None,
        )["Description"]
        element["Name"] = name
        return element

    def auth(self, username, password):
        """Authenticate the client and retrieves the access token. This API uses
        the authentication API. 

        Args:
            username: the Username used for the authentication.
            password: the Password used for the authentication.
        Raises:
            HTTPError: if there is an error raised by the API (not 2xx response).
        Returns:
            The access token retrieved from the API. The token is also
            cached in the `ElmoClient` instance.
        """
        payload = {"username": username, "password": password, "domain": self._vendor}
        response = self._session.get(self._router.auth, params=payload)
        response.raise_for_status()

        data = response.json()
        self._session_id = data["SessionId"]

        if data["Redirect"]:
            self._router = Router(data["RedirectTo"])
            self._session_id = self.auth(username, password)
            return self._session_id

        return self._session_id

    @require_session
    def update_strings(self):
        payload = {"sessionId": self._session_id}

        response = self._session.post(self._router.strings, data=payload)
        response.raise_for_status()

        self._strings = response.json()

    @require_session
    def update_areas(self):
        payload = {"sessionId": self._session_id}

        response = self._session.post(self._router.areas, data=payload)
        response.raise_for_status()

        self._areas = list(filter(lambda area: area["InUse"], response.json()))
        self._areas = list(map(lambda x: self.add_name(x, SECTOR_CLASS), self._areas))
        self._areas = list(
            map(lambda x: {re_case(k): v for k, v in x.items()}, self._areas)
        )
        self._areas = list(map(lambda x: ElmoItem(**x), self._areas))

    @require_session
    def update_inputs(self):
        payload = {"sessionId": self._session_id}

        response = self._session.post(self._router.inputs, data=payload)
        response.raise_for_status()

        self._inputs = list(filter(lambda input_: input_["InUse"], response.json()))
        self._inputs = list(map(lambda x: self.add_name(x, INPUT_CLASS), self._inputs))
        self._inputs = list(
            map(lambda x: {re_case(k): v for k, v in x.items()}, self._inputs)
        )
        self._inputs = list(map(lambda x: ElmoItem(**x), self._inputs))

    @require_session
    def update(self):
        """
        Fetch data from API returning names of the items.
        """
        payload = {"sessionId": self._session_id}

        if not self._strings:
            self.update_strings()

        self.update_areas()
        self.update_inputs()

    def get_items(self):
        return {"areas": self._areas, "inputs": self._inputs}

    @contextmanager
    @require_session
    def lock(self, code):
        """Context manager to obtain a system lock. The alerting system allows
        only one user at a time and obtaining the lock is mandatory. When the
        context manager is closed, the lock is automatically released.

        Args:
            code: the alarm code used to obtain the lock.
        Raises:
            HTTPError: if there is an error raised by the API (not 2xx response).
        Returns:
            A client instance with an acquired lock.
        """
        payload = {"userId": 1, "password": code, "sessionId": self._session_id}
        response = self._session.post(self._router.lock, data=payload)
        response.raise_for_status()

        self._lock.acquire()
        yield self
        self.unlock()

    @require_session
    @require_lock
    def unlock(self):
        """Release the system lock so that other threads (or this instance) can
        acquire the lock again. This method requires a valid session ID and if called
        when a Lock() is not acquired it bails out.

        If there is a server error or if the call fails, the lock is not released
        so the current thread can do further work before letting another thread
        gain the lock.

        Raises:
            HTTPError: if there is an error raised by the API (not 2xx response).
        Returns:
            A boolean if the lock has been released correctly.
        """
        payload = {"sessionId": self._session_id}
        response = self._session.post(self._router.unlock, data=payload)
        response.raise_for_status()

        # Release the lock only in case of success, so that if it fails
        # the owner of the lock can properly unlock the system again
        # (maybe with a retry)
        self._lock.release()
        return True

    @require_session
    @require_lock
    def arm(self):
        """Arm all system alarms without any activation delay. This API works only
        if a system lock has been obtained, otherwise the action ends with a failure.
        Note: API subject to changes when more configurations are allowed, such as
        enabling only some alerts.

        Raises:
            HTTPError: if there is an error raised by the API (not 2xx response).
        Returns:
            A boolean if the system has been armed correctly.
        """
        payload = {
            "CommandType": ARM_COMMAND,
            "ElementsClass": 1,
            "ElementsIndexes": 1,
            "sessionId": self._session_id,
        }
        response = self._session.post(self._router.send_command, data=payload)
        response.raise_for_status()
        return True

    @require_session
    @require_lock
    def disarm(self):
        """Deactivate all system alarms. This API works only if a system lock has been
        obtained, otherwise the action ends with a failure.
        Note: API subject to changes when more configurations are allowed, such as
        enabling only some alerts.

        Raises:
            HTTPError: if there is an error raised by the API (not 2xx response).
        Returns:
            A boolean if the system has been disarmed correctly.
        """
        payload = {
            "CommandType": DISARM_COMMAND,
            "ElementsClass": 1,
            "ElementsIndexes": 1,
            "sessionId": self._session_id,
        }
        response = self._session.post(self._router.send_command, data=payload)
        response.raise_for_status()
        return True

    @require_session
    @require_lock
    def arm_sectors(self, sector_numbers):
        """Arm selected sector without any activation delay. This API works only
        if a system lock has been obtained, otherwise the action ends with a failure.
        Note: API subject to changes when more configurations are allowed, such as
        enabling only some alerts.

        Raises:
            HTTPError: if there is an error raised by the API (not 2xx response).
        Returns:
            A boolean if the sector has been armed correctly.
        """
        payload = {
            "CommandType": ARM_COMMAND,
            "ElementsClass": SECTOR_CLASS,
            "ElementsIndexes": sector_numbers,
            "sessionId": self._session_id,
        }
        response = self._session.post(self._router.send_command, data=payload)
        response.raise_for_status()
        return True

    @require_session
    @require_lock
    def disarm_sectors(self, sector_numbers):
        """Deactivate selected sector alarm. This API works only if a system lock has been
        obtained, otherwise the action ends with a failure.
        Note: API subject to changes when more configurations are allowed, such as
        enabling only some alerts.

        Raises:
            HTTPError: if there is an error raised by the API (not 2xx response).
        Returns:
            A boolean if the sector has been disarmed correctly.
        """
        payload = {
            "CommandType": DISARM_COMMAND,
            "ElementsClass": SECTOR_CLASS,
            "ElementsIndexes": sector_numbers,
            "sessionId": self._session_id,
        }
        response = self._session.post(self._router.send_command, data=payload)
        response.raise_for_status()
        return True
