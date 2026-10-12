"""Firebase Authentication and Cloud Firestore access over the REST APIs.

All Firestore requests are sent with the signed-in user's ID token, so the
security rules in ``firestore.rules`` decide what each user can read or write.
No service-account credentials are needed, which keeps the app on the free
Spark plan.

Data layout:
    users/{uid}                  profile (email, displayName, createdAt)
    users/{uid}/history/{id}     one detection result per document
"""
from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timezone

import requests

AUTH_URL = "https://identitytoolkit.googleapis.com/v1/accounts"
TOKEN_URL = "https://securetoken.googleapis.com/v1/token"
FIRESTORE_URL = "https://firestore.googleapis.com/v1"
TIMEOUT = 20
# Refresh the 1-hour ID token a little before it actually expires.
REFRESH_MARGIN_SECONDS = 300
HISTORY_PAGE_SIZE = 100
COMMIT_BATCH_SIZE = 500
MAX_EMAIL_TEXT = 20000
MAX_SOURCE = 200

INPUT_METHODS = ("paste", "screenshot", "text_file")
SUMMARY_FIELDS = (
    "createdAt", "inputMethod", "source", "modelName", "modelPrediction",
    "phishingProbability", "finalResult", "ruleScore", "reasons", "emailText", "hasImage",
)

AUTH_ERRORS = {
    "EMAIL_EXISTS": "An account with this email already exists.",
    "EMAIL_NOT_FOUND": "Incorrect email or password.",
    "INVALID_PASSWORD": "Incorrect email or password.",
    "INVALID_LOGIN_CREDENTIALS": "Incorrect email or password.",
    "INVALID_EMAIL": "Please enter a valid email address.",
    "MISSING_PASSWORD": "Please enter a password.",
    "MISSING_EMAIL": "Please enter an email address.",
    "WEAK_PASSWORD": "Password must be at least 6 characters.",
    "USER_DISABLED": "This account has been disabled.",
    "TOO_MANY_ATTEMPTS_TRY_LATER": "Too many attempts. Please try again later.",
    "TOKEN_EXPIRED": "Your session has expired. Please sign in again.",
    "INVALID_REFRESH_TOKEN": "Your session has expired. Please sign in again.",
    "INVALID_ID_TOKEN": "Your session has expired. Please sign in again.",
    "USER_NOT_FOUND": "Your session has expired. Please sign in again.",
    "OPERATION_NOT_ALLOWED": "Email/password sign-in is not enabled for this Firebase project.",
}


class FirebaseError(Exception):
    """Raised with a user-friendly message when a Firebase request fails."""

    def __init__(self, message, code=None, status=None):
        super().__init__(message)
        self.code = code
        self.status = status


class AuthError(FirebaseError):
    pass


@dataclass(frozen=True)
class FirebaseConfig:
    api_key: str
    project_id: str

    @classmethod
    def load(cls, secrets=None):
        """Read config from Streamlit secrets ([firebase] table) or environment variables."""
        section = {}
        if secrets is not None:
            try:
                section = dict(secrets.get("firebase", {}))
            except Exception:
                section = {}
        api_key = section.get("api_key") or os.environ.get("FIREBASE_API_KEY", "")
        project_id = section.get("project_id") or os.environ.get("FIREBASE_PROJECT_ID", "")
        if not api_key or not project_id:
            raise FirebaseError(
                "Firebase is not configured. Add api_key and project_id under [firebase] in "
                ".streamlit/secrets.toml, or set FIREBASE_API_KEY and FIREBASE_PROJECT_ID."
            )
        return cls(api_key=api_key, project_id=project_id)


@dataclass(frozen=True)
class UserSession:
    uid: str
    email: str
    display_name: str
    id_token: str
    refresh_token: str
    expires_at: float

    def needs_refresh(self, now=None):
        now = time.time() if now is None else now
        return now >= self.expires_at - REFRESH_MARGIN_SECONDS


# ---- Firestore value encoding ------------------------------------------------

def encode_value(value):
    if value is None:
        return {"nullValue": None}
    if isinstance(value, bool):
        return {"booleanValue": value}
    if isinstance(value, int):
        return {"integerValue": str(value)}
    if isinstance(value, float):
        return {"doubleValue": value}
    if isinstance(value, str):
        return {"stringValue": value}
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return {"timestampValue": value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")}
    if isinstance(value, (list, tuple)):
        return {"arrayValue": {"values": [encode_value(v) for v in value]}}
    if isinstance(value, dict):
        return {"mapValue": {"fields": encode_fields(value)}}
    raise TypeError(f"Unsupported Firestore value type: {type(value).__name__}")


def encode_fields(data):
    return {key: encode_value(val) for key, val in data.items()}


def decode_value(value):
    if "nullValue" in value:
        return None
    if "booleanValue" in value:
        return value["booleanValue"]
    if "integerValue" in value:
        return int(value["integerValue"])
    if "doubleValue" in value:
        return float(value["doubleValue"])
    if "stringValue" in value:
        return value["stringValue"]
    if "timestampValue" in value:
        return parse_timestamp(value["timestampValue"])
    if "arrayValue" in value:
        return [decode_value(v) for v in value["arrayValue"].get("values", [])]
    if "mapValue" in value:
        return decode_fields(value["mapValue"].get("fields", {}))
    raise ValueError(f"Unsupported Firestore value: {value}")


def decode_fields(fields):
    return {key: decode_value(val) for key, val in (fields or {}).items()}


def parse_timestamp(text):
    # Firestore returns up to nanosecond precision; Python handles microseconds.
    text = text.rstrip("Z")
    if "." in text:
        base, frac = text.split(".", 1)
        text = f"{base}.{frac[:6]}"
    return datetime.fromisoformat(text).replace(tzinfo=timezone.utc)


def _error_code(response):
    try:
        error = response.json().get("error", {})
    except ValueError:
        return "", response.text[:200]
    if isinstance(error, str):
        return error, error
    message = error.get("message", "") or ""
    return message.split(":")[0].strip().split(" ")[0], message


class FirebaseClient:
    """Thin wrapper around the Firebase Auth and Firestore REST endpoints."""

    def __init__(self, config, http=None):
        self.config = config
        self.http = http or requests.Session()
        self.db_path = f"projects/{config.project_id}/databases/(default)"
        self.documents_url = f"{FIRESTORE_URL}/{self.db_path}/documents"

    # ---- Authentication -------------------------------------------------------

    def _auth_post(self, action, payload):
        try:
            response = self.http.post(
                f"{AUTH_URL}:{action}", params={"key": self.config.api_key},
                json=payload, timeout=TIMEOUT,
            )
        except requests.RequestException as exc:
            raise AuthError("Could not reach Firebase. Check your internet connection.") from exc
        if not response.ok:
            code, message = _error_code(response)
            raise AuthError(AUTH_ERRORS.get(code, message or "Authentication failed."),
                            code=code, status=response.status_code)
        return response.json()

    @staticmethod
    def _session_from(data, display_name=None):
        return UserSession(
            uid=data["localId"],
            email=data.get("email", ""),
            display_name=display_name if display_name is not None else data.get("displayName", "") or "",
            id_token=data["idToken"],
            refresh_token=data["refreshToken"],
            expires_at=time.time() + int(data.get("expiresIn", 3600)),
        )

    def sign_up(self, email, password, display_name=""):
        data = self._auth_post("signUp", {
            "email": email.strip(), "password": password, "returnSecureToken": True,
        })
        session = self._session_from(data, display_name="")
        display_name = display_name.strip()[:60]
        if display_name:
            updated = self._auth_post("update", {
                "idToken": session.id_token, "displayName": display_name, "returnSecureToken": True,
            })
            session = replace(
                session, display_name=display_name,
                id_token=updated.get("idToken", session.id_token),
                refresh_token=updated.get("refreshToken", session.refresh_token),
            )
        self.ensure_profile(session)
        return session

    def sign_in(self, email, password):
        data = self._auth_post("signInWithPassword", {
            "email": email.strip(), "password": password, "returnSecureToken": True,
        })
        session = self._session_from(data)
        self.ensure_profile(session)
        return session

    def send_password_reset(self, email):
        self._auth_post("sendOobCode", {"requestType": "PASSWORD_RESET", "email": email.strip()})

    def delete_account(self, session):
        self._auth_post("delete", {"idToken": session.id_token})

    def refresh(self, session):
        try:
            response = self.http.post(
                TOKEN_URL, params={"key": self.config.api_key},
                data={"grant_type": "refresh_token", "refresh_token": session.refresh_token},
                timeout=TIMEOUT,
            )
        except requests.RequestException as exc:
            raise AuthError("Could not reach Firebase. Check your internet connection.") from exc
        if not response.ok:
            code, message = _error_code(response)
            raise AuthError(AUTH_ERRORS.get(code, "Your session has expired. Please sign in again."),
                            code=code, status=response.status_code)
        data = response.json()
        return replace(
            session,
            id_token=data["id_token"],
            refresh_token=data["refresh_token"],
            expires_at=time.time() + int(data.get("expires_in", 3600)),
        )

    def fresh(self, session):
        """Return a session whose ID token is valid for at least a few minutes."""
        return self.refresh(session) if session.needs_refresh() else session

    # ---- Firestore ------------------------------------------------------------

    def _fs(self, method, url, session, **kwargs):
        headers = {"Authorization": f"Bearer {session.id_token}"}
        try:
            response = self.http.request(method, url, headers=headers, timeout=TIMEOUT, **kwargs)
        except requests.RequestException as exc:
            raise FirebaseError("Could not reach the database. Check your internet connection.") from exc
        if response.status_code == 404 and method == "GET":
            return None
        if not response.ok:
            _, message = _error_code(response)
            try:
                code = response.json().get("error", {}).get("status")
            except (ValueError, AttributeError):
                code = None
            if response.status_code == 403:
                message = "Permission denied by the database security rules."
            elif response.status_code == 401:
                message = "Your session has expired. Please sign in again."
            raise FirebaseError(message or "Database request failed.", code=code,
                                status=response.status_code)
        return response.json() if response.content else {}

    def _commit(self, session, writes):
        return self._fs("POST", f"{self.documents_url}:commit", session, json={"writes": writes})

    def _user_doc(self, uid):
        return f"{self.db_path}/documents/users/{uid}"

    def ensure_profile(self, session):
        """Create users/{uid} the first time a user signs in."""
        name = self._user_doc(session.uid)
        if self._fs("GET", f"{FIRESTORE_URL}/{name}", session) is not None:
            return
        try:
            self._commit(session, [{
                "update": {"name": name, "fields": encode_fields({
                    "email": session.email, "displayName": session.display_name,
                })},
                "updateTransforms": [{"fieldPath": "createdAt", "setToServerValue": "REQUEST_TIME"}],
                "currentDocument": {"exists": False},
            }])
        except FirebaseError as exc:
            # Another tab may have created it in the meantime.
            if exc.status != 409 and exc.code not in ("FAILED_PRECONDITION", "ALREADY_EXISTS"):
                raise

    def add_history(self, session, entry):
        """Store a detection result. ``entry`` keys follow the Firestore data model."""
        entry = dict(entry)
        entry["emailText"] = (entry.get("emailText") or "")[:MAX_EMAIL_TEXT]
        entry["source"] = (entry.get("source") or "")[:MAX_SOURCE]
        entry["reasons"] = list(entry.get("reasons") or [])[:20]
        image = entry.pop("imageBase64", None)
        mime = entry.pop("imageMime", None)
        entry["hasImage"] = bool(image)
        if image:
            entry["imageBase64"] = image
            entry["imageMime"] = mime or "image/jpeg"
        entry.pop("createdAt", None)

        doc_id = uuid.uuid4().hex
        name = f"{self._user_doc(session.uid)}/history/{doc_id}"
        self._commit(session, [{
            "update": {"name": name, "fields": encode_fields(entry)},
            "updateTransforms": [{"fieldPath": "createdAt", "setToServerValue": "REQUEST_TIME"}],
            "currentDocument": {"exists": False},
        }])
        return doc_id

    def list_history(self, session, limit=HISTORY_PAGE_SIZE):
        """Newest-first history without the (large) screenshot data."""
        url = f"{self.documents_url}/users/{session.uid}/history"
        params = [("pageSize", str(limit)), ("orderBy", "createdAt desc")]
        params += [("mask.fieldPaths", f) for f in SUMMARY_FIELDS]
        data = self._fs("GET", url, session, params=params) or {}
        items = []
        for doc in data.get("documents", []):
            item = decode_fields(doc.get("fields"))
            item["id"] = doc["name"].rsplit("/", 1)[-1]
            items.append(item)
        return items

    def get_history_image(self, session, entry_id):
        """Return (base64 string, mime type) for an entry, or (None, None)."""
        url = f"{self.documents_url}/users/{session.uid}/history/{entry_id}"
        params = [("mask.fieldPaths", "imageBase64"), ("mask.fieldPaths", "imageMime")]
        doc = self._fs("GET", url, session, params=params)
        if not doc:
            return None, None
        fields = decode_fields(doc.get("fields"))
        return fields.get("imageBase64"), fields.get("imageMime")

    def delete_history(self, session, entry_id):
        self._fs("DELETE", f"{self.documents_url}/users/{session.uid}/history/{entry_id}", session)

    def clear_history(self, session):
        """Delete every history entry for the user. Returns the number deleted."""
        deleted = 0
        while True:
            url = f"{self.documents_url}/users/{session.uid}/history"
            params = [("pageSize", "300"), ("mask.fieldPaths", "hasImage")]
            data = self._fs("GET", url, session, params=params) or {}
            names = [doc["name"] for doc in data.get("documents", [])]
            if not names:
                return deleted
            for start in range(0, len(names), COMMIT_BATCH_SIZE):
                batch = names[start:start + COMMIT_BATCH_SIZE]
                self._commit(session, [{"delete": n} for n in batch])
                deleted += len(batch)
