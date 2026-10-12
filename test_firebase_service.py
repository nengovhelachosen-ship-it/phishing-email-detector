import base64
import io
import time
from datetime import datetime, timezone

import pytest
from PIL import Image

from firebase_service import (
    AuthError, FirebaseClient, FirebaseConfig, FirebaseError, UserSession,
    decode_fields, encode_fields, parse_timestamp,
)
from image_utils import MAX_BASE64_CHARS, base64_to_bytes, image_to_base64


class FakeResponse:
    def __init__(self, status=200, payload=None):
        self.status_code = status
        self._payload = payload if payload is not None else {}
        self.ok = 200 <= status < 300
        self.content = b"{}" if payload is not None else b""
        self.text = str(payload)

    def json(self):
        return self._payload


class FakeHttp:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def _next(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.responses.pop(0)

    def post(self, url, **kwargs):
        return self._next("POST", url, **kwargs)

    def request(self, method, url, **kwargs):
        return self._next(method, url, **kwargs)


CONFIG = FirebaseConfig(api_key="key", project_id="demo")
SESSION = UserSession("uid1", "a@b.com", "", "id-token", "refresh", time.time() + 3600)
AUTH_OK = {"localId": "uid1", "email": "a@b.com", "idToken": "tok", "refreshToken": "ref", "expiresIn": "3600"}


def test_encode_decode_round_trip():
    data = {"s": "x", "i": 3, "f": 0.5, "b": True, "n": None, "l": ["a", 1], "m": {"k": "v"}}
    assert decode_fields(encode_fields(data)) == data


def test_encode_rejects_bool_as_int():
    assert encode_fields({"b": False}) == {"b": {"booleanValue": False}}


def test_parse_timestamp_handles_nanoseconds():
    ts = parse_timestamp("2026-10-12T15:01:02.123456789Z")
    assert ts == datetime(2026, 10, 12, 15, 1, 2, 123456, tzinfo=timezone.utc)


def test_config_from_secrets_and_missing():
    assert FirebaseConfig.load({"firebase": {"api_key": "k", "project_id": "p"}}) == FirebaseConfig("k", "p")
    with pytest.raises(FirebaseError):
        FirebaseConfig.load({})


def test_sign_in_maps_errors_to_friendly_message():
    http = FakeHttp([FakeResponse(400, {"error": {"message": "INVALID_LOGIN_CREDENTIALS"}})])
    with pytest.raises(AuthError) as err:
        FirebaseClient(CONFIG, http).sign_in("a@b.com", "bad")
    assert err.value.code == "INVALID_LOGIN_CREDENTIALS"
    assert "Incorrect email or password" in str(err.value)


def test_weak_password_message():
    http = FakeHttp([FakeResponse(400, {"error": {"message": "WEAK_PASSWORD : Password should be at least 6 characters"}})])
    with pytest.raises(AuthError) as err:
        FirebaseClient(CONFIG, http).sign_up("a@b.com", "123")
    assert "at least 6" in str(err.value)


def test_sign_in_creates_missing_profile():
    http = FakeHttp([FakeResponse(200, AUTH_OK), FakeResponse(404, {}), FakeResponse(200, {})])
    session = FirebaseClient(CONFIG, http).sign_in("a@b.com", "secret")
    assert session.uid == "uid1" and session.id_token == "tok"
    method, url, kwargs = http.calls[2]
    write = kwargs["json"]["writes"][0]
    assert url.endswith("/documents:commit")
    assert write["update"]["name"].endswith("/documents/users/uid1")
    assert write["currentDocument"] == {"exists": False}
    assert kwargs["headers"]["Authorization"] == "Bearer tok"


def test_add_history_stores_image_and_server_timestamp():
    http = FakeHttp([FakeResponse(200, {})])
    FirebaseClient(CONFIG, http).add_history(SESSION, {
        "inputMethod": "screenshot", "source": "s.png", "modelName": "LightGBM",
        "modelPrediction": "SAFE", "phishingProbability": 0.2, "finalResult": "SAFE",
        "ruleScore": 0, "reasons": ["r"], "emailText": "hello",
        "imageBase64": "QUJD", "imageMime": "image/jpeg",
    })
    write = http.calls[0][2]["json"]["writes"][0]
    fields = decode_fields(write["update"]["fields"])
    assert "/documents/users/uid1/history/" in write["update"]["name"]
    assert fields["hasImage"] is True and fields["imageBase64"] == "QUJD"
    assert write["updateTransforms"] == [{"fieldPath": "createdAt", "setToServerValue": "REQUEST_TIME"}]


def test_add_history_without_image_sets_flag_false():
    http = FakeHttp([FakeResponse(200, {})])
    FirebaseClient(CONFIG, http).add_history(SESSION, {"emailText": "x" * 30000})
    fields = decode_fields(http.calls[0][2]["json"]["writes"][0]["update"]["fields"])
    assert fields["hasImage"] is False
    assert "imageBase64" not in fields
    assert len(fields["emailText"]) == 20000


def test_list_history_excludes_image_field():
    doc = {"name": "projects/demo/databases/(default)/documents/users/uid1/history/abc",
           "fields": encode_fields({"finalResult": "SAFE", "hasImage": True})}
    http = FakeHttp([FakeResponse(200, {"documents": [doc]})])
    items = FirebaseClient(CONFIG, http).list_history(SESSION)
    assert items == [{"finalResult": "SAFE", "hasImage": True, "id": "abc"}]
    params = http.calls[0][2]["params"]
    assert ("orderBy", "createdAt desc") in params
    assert ("mask.fieldPaths", "imageBase64") not in params


def test_permission_denied_raises_firebase_error():
    http = FakeHttp([FakeResponse(403, {"error": {"status": "PERMISSION_DENIED", "message": "denied"}})])
    with pytest.raises(FirebaseError) as err:
        FirebaseClient(CONFIG, http).delete_history(SESSION, "abc")
    assert err.value.status == 403


def test_expired_session_is_refreshed():
    old = UserSession("uid1", "a@b.com", "", "old", "ref", time.time() - 1)
    http = FakeHttp([FakeResponse(200, {"id_token": "new", "refresh_token": "ref2", "expires_in": "3600"})])
    new = FirebaseClient(CONFIG, http).fresh(old)
    assert new.id_token == "new" and new.refresh_token == "ref2"
    assert not new.needs_refresh()


def test_image_to_base64_fits_limit_and_decodes():
    noisy = Image.effect_noise((3000, 2000), 100).convert("RGBA")
    encoded, mime = image_to_base64(noisy)
    assert mime == "image/jpeg"
    assert len(encoded) <= MAX_BASE64_CHARS
    decoded = Image.open(io.BytesIO(base64_to_bytes(encoded)))
    assert decoded.format == "JPEG" and max(decoded.size) <= 1600


def test_image_to_base64_is_valid_base64():
    encoded, _ = image_to_base64(Image.new("RGB", (200, 100), "white"))
    assert base64.b64encode(base64.b64decode(encoded)).decode() == encoded
