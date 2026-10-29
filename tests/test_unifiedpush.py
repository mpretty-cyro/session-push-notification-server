"""
Unit tests for the UnifiedPush notifier (spns/notifiers/unifiedpush.py).

These need the notifier's Python dependencies (oxenc, oxenmq, nacl, systemd, coloredlogs, aiohttp,
cryptography, http_ece, py_vapid) but not the compiled hivemind module, which is stubbed if absent.
Run from the project root with:

    python3 -m unittest tests/test_unifiedpush.py
    python3 -m pytest tests/test_unifiedpush.py
"""

import asyncio
import base64
import enum
import json
import os
import sys
import tempfile
import time
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

try:
    import spns_hivemind  # noqa: F401
except ImportError:
    stub = types.ModuleType("spns_hivemind")

    class Config:
        hivemind_sock = ""
        omq_privkey = b""
        omq_pubkey = b""

    class SUBSCRIBE(enum.IntEnum):
        OK = 0
        BAD_INPUT = 1
        SERVICE_NOT_AVAILABLE = 2
        SERVICE_TIMEOUT = 3
        ERROR = 4
        INTERNAL_ERROR = 5

    stub.Config = Config
    stub.SUBSCRIBE = SUBSCRIBE
    stub.logger = types.SimpleNamespace(set_level=lambda *a: None)
    sys.modules["spns_hivemind"] = stub

import aiohttp
import http_ece
import oxenc
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt
from nacl.public import PrivateKey
from py_vapid import Vapid02

TMP = tempfile.mkdtemp(prefix="spns-up-test-")
VAPID_KEY = ec.generate_private_key(ec.SECP256R1())
with open(os.path.join(TMP, "vapid.pem"), "wb") as f:
    f.write(
        VAPID_KEY.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
with open(os.path.join(TMP, "key_x25519"), "w") as f:
    f.write(PrivateKey.generate().encode().hex())
with open(os.path.join(TMP, "spns.ini"), "w") as f:
    f.write(
        f"""
[hivemind]
listen = ipc://{TMP}/hivemind.sock

[keys]
hivemind = {TMP}/key_x25519

[notify-unifiedpush]
vapid_private_key = {TMP}/vapid.pem
vapid_contact = mailto:push@example.org
retries = 2
retry_interval = 1
"""
    )
os.environ["SPNS_CONFIG"] = os.path.join(TMP, "spns.ini")

from spns.notifiers import unifiedpush as up  # noqa: E402


def b64url(b: bytes, pad=False) -> str:
    s = base64.urlsafe_b64encode(b).decode()
    return s if pad else s.rstrip("=")


def device_keys():
    """A device-side Web Push keypair and auth secret, as a UnifiedPush connector generates."""
    key = ec.generate_private_key(ec.SECP256R1())
    pub = key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    return key, pub, os.urandom(16)


ENDPOINT = "https://ntfy.example.org/upAbCdEfGhIjKl?up=1"


def service_info(pub, auth, endpoint=ENDPOINT):
    return {"endpoint": endpoint, "p256dh": b64url(pub), "auth": b64url(auth)}


def push_dict(enc_key, body=None, msg_hash=None, svcid="", svcdata=b""):
    """A hivemind `notifier.push` dict with the largest realistic metadata values."""
    now_ms = int(time.time() * 1000)
    d = {
        b"": b"unifiedpush",
        b"&": svcid.encode(),
        b"!": svcdata,
        b"^": enc_key,
        b"#": (msg_hash or "A" * 43).encode(),  # storage server hashes are 43-char base64
        b"@": bytes.fromhex("05" + "ab" * 32),
        b"n": -32768,
        b"t": now_ms,
        b"z": now_ms + 14 * 86400 * 1000,
    }
    if body is not None:
        d[b"~"] = body
    return d


def open_body(device_key, auth, encrypted):
    """Device side: Web Push decrypt, then parse the FCM-style data map."""
    plain = http_ece.decrypt(
        encrypted, private_key=device_key, auth_secret=auth, version="aes128gcm"
    )
    return json.loads(plain)


def open_enc_payload(enc_key, enc_payload_b64):
    """Device side: decrypt `enc_payload` and split the bencoded list."""
    raw = base64.b64decode(enc_payload_b64)
    nonce, ct = raw[:24], raw[24:]
    padded = crypto_aead_xchacha20poly1305_ietf_decrypt(ct, None, nonce, enc_key)
    parts = oxenc.bt_deserialize(padded.rstrip(b"\0"))
    return json.loads(parts[0]), (parts[1] if len(parts) > 1 else None)


class ServiceInfoTests(unittest.TestCase):
    def setUp(self):
        _, self.pub, self.auth = device_keys()

    def test_valid(self):
        svcid, svcdata = up.parse_service_info(service_info(self.pub, self.auth))
        self.assertEqual(len(svcid), 64)
        self.assertEqual(svcid, up.endpoint_svcid(ENDPOINT))
        stored = oxenc.bt_deserialize(svcdata)
        self.assertEqual(stored, {b"a": self.auth, b"e": ENDPOINT.encode(), b"k": self.pub})

    def test_svcid_depends_only_on_endpoint(self):
        _, pub2, auth2 = device_keys()
        a, _ = up.parse_service_info(service_info(self.pub, self.auth))
        b, _ = up.parse_service_info(service_info(pub2, auth2))
        c, _ = up.parse_service_info(service_info(self.pub, self.auth, ENDPOINT + "x"))
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)

    def test_base64_variants(self):
        info = {
            "endpoint": ENDPOINT,
            "p256dh": base64.b64encode(self.pub).decode(),
            "auth": b64url(self.auth, pad=True),
        }
        self.assertEqual(
            up.parse_service_info(info)[1],
            up.parse_service_info(service_info(self.pub, self.auth))[1],
        )

    def test_missing_keys(self):
        for k in ("endpoint", "p256dh", "auth"):
            info = service_info(self.pub, self.auth)
            del info[k]
            with self.assertRaises(KeyError):
                up.parse_service_info(info)

    def test_bad_endpoints(self):
        bad = [
            "http://ntfy.example.org/up123",
            "ntfy.example.org/up123",
            "https://127.0.0.1/up",
            "https://10.1.2.3/up",
            "https://[::1]/up",
            "https://[2001:db8::1]/up",
            "https://8.8.8.8/up",
            "https://localhost/up",
            "https://foo.localhost/up",
            "https://intranet/up",
            "https://user:pw@ntfy.example.org/up",
            "https://ntfy.example.org/up#frag",
            "https://ntfy.example.org:99999/up",
            "https://ntfy.example.org/up\n",
            "https://ntfy.example.org/" + "a" * 2048,
            "",
            123,
        ]
        for e in bad:
            with self.assertRaises(ValueError, msg=repr(e)):
                up.parse_service_info(service_info(self.pub, self.auth, e))

    def test_allow_private(self):
        info = service_info(self.pub, self.auth, "https://ntfy/up123")
        with self.assertRaises(ValueError):
            up.parse_service_info(info)
        up.parse_service_info(info, allow_private=True)
        with self.assertRaises(ValueError):  # IP literals are never accepted
            up.parse_service_info(
                service_info(self.pub, self.auth, "https://10.0.0.1/up"), allow_private=True
            )

    def test_custom_port_accepted(self):
        up.parse_service_info(service_info(self.pub, self.auth, "https://up.example.org:8443/x"))

    def test_bad_keys(self):
        not_on_curve = b"\x04" + b"\x01" * 64
        cases = [
            {"p256dh": b64url(self.pub[:33])},
            {"p256dh": b64url(not_on_curve)},
            {"p256dh": "not base64!"},
            {"auth": b64url(self.auth[:15])},
            {"auth": ""},
        ]
        for c in cases:
            info = service_info(self.pub, self.auth)
            info.update(c)
            with self.assertRaises(ValueError, msg=repr(c)):
                up.parse_service_info(info)

    def test_not_an_object(self):
        with self.assertRaises(ValueError):
            up.parse_service_info([ENDPOINT])


class FakeMessage:
    def __init__(self, *parts):
        self.parts = [p if isinstance(p, bytes) else p.encode() for p in parts]
        self.replies = []

    def data(self):
        return self.parts

    def reply(self, *args):
        self.replies.append(args)


class ValidateTests(unittest.TestCase):
    def test_validate_ok(self):
        _, pub, auth = device_keys()
        msg = FakeMessage("unifiedpush", json.dumps(service_info(pub, auth)))
        up.UnifiedPushHandler.validate(None, msg)
        code, svcid, svcdata = msg.replies[0]
        self.assertEqual(code, "0")
        self.assertEqual(svcid, up.endpoint_svcid(ENDPOINT))
        self.assertEqual(oxenc.bt_deserialize(svcdata)[b"k"], pub)

    def test_validate_errors(self):
        _, pub, auth = device_keys()
        bad = FakeMessage("unifiedpush", json.dumps(service_info(pub, auth, "http://x.org/a")))
        up.UnifiedPushHandler.validate(None, bad)
        self.assertEqual(bad.replies[0][0], str(up.SUBSCRIBE.BAD_INPUT.value))
        self.assertIn("https", bad.replies[0][1])

        missing = FakeMessage("unifiedpush", json.dumps({"endpoint": ENDPOINT}))
        up.UnifiedPushHandler.validate(None, missing)
        self.assertEqual(missing.replies[0][0], str(up.SUBSCRIBE.BAD_INPUT.value))

        wrong = FakeMessage("apns", json.dumps(service_info(pub, auth)))
        up.UnifiedPushHandler.validate(None, wrong)
        self.assertEqual(wrong.replies[0][0], str(up.SUBSCRIBE.ERROR.value))


class PayloadTests(unittest.TestCase):
    def setUp(self):
        self.device_key, self.pub, self.auth = device_keys()
        self.enc_key = os.urandom(32)

    def round_trip(self, data):
        body = up.build_push_body(data)
        encrypted = up.encrypt_webpush(body, self.pub, self.auth)
        self.assertEqual(len(encrypted), len(body) + up.WEBPUSH_OVERHEAD)
        self.assertLessEqual(len(encrypted), up.MAX_PUSH_SIZE)
        fields = open_body(self.device_key, self.auth, encrypted)
        # Same shape as an FCM data message: a flat map of strings
        self.assertEqual(set(fields), {"enc_payload", "spns"})
        self.assertTrue(all(isinstance(v, str) for v in fields.values()))
        self.assertEqual(fields["spns"], "1")
        meta, msg = open_enc_payload(self.enc_key, fields["enc_payload"])
        return encrypted, meta, msg

    def test_max_size_message(self):
        body = os.urandom(up.MAX_MSG_SIZE)
        data = push_dict(self.enc_key, body)
        encrypted, meta, msg = self.round_trip(data)
        self.assertEqual(msg, body)
        self.assertEqual(meta["l"], up.MAX_MSG_SIZE)
        self.assertNotIn("B", meta)
        self.assertEqual(meta["@"], data[b"@"].hex())
        self.assertEqual(meta["n"], -32768)
        # The worst case in the PR description: 2816 padded + 40 = 2856, base64 3808, JSON 3837,
        # Web Push 3837 + 103 = 3940.
        self.assertEqual(len(encrypted), 3940)

    def test_too_big_message(self):
        data = push_dict(self.enc_key, os.urandom(up.MAX_MSG_SIZE + 1))
        _, meta, msg = self.round_trip(data)
        self.assertIsNone(msg)
        self.assertTrue(meta["B"])
        self.assertEqual(meta["l"], up.MAX_MSG_SIZE + 1)

    def test_no_data(self):
        _, meta, msg = self.round_trip(push_dict(self.enc_key))
        self.assertIsNone(msg)
        self.assertNotIn("l", meta)
        self.assertNotIn("B", meta)

    def test_oversized_metadata_drops_body(self):
        # Metadata large enough that the padded plaintext steps from 2816 to 3072 bytes, which
        # would not fit once encrypted: the message is dropped and flagged rather than sent over
        # the limit.
        body = os.urandom(up.MAX_MSG_SIZE)
        _, meta, msg = self.round_trip(push_dict(self.enc_key, body, msg_hash="h" * 200))
        self.assertIsNone(msg)
        self.assertTrue(meta["B"])

    def test_ttl(self):
        now = int(time.time())
        self.assertEqual(up.push_ttl({b"z": int((now + 30 * 86400) * 1000)}, now), up.TTL)
        self.assertEqual(up.push_ttl({b"z": int((now + 600) * 1000)}, now), 600)
        self.assertEqual(up.push_ttl({b"z": int((now - 10) * 1000)}, now), 0)
        self.assertEqual(up.push_ttl({}, now), up.TTL)


class VapidTests(unittest.TestCase):
    def test_load_and_sign(self):
        vapid = up.load_vapid_key(os.path.join(TMP, "vapid.pem"))
        signer = up.VapidSigner(vapid, "mailto:push@example.org")
        now = time.time()
        h = signer.headers("https://ntfy.example.org:8443/up123?up=1", now)
        auth = h["Authorization"]
        self.assertTrue(auth.startswith("vapid t="))
        self.assertTrue(Vapid02.verify(auth))
        jwt = auth.split("t=", 1)[1].split(",", 1)[0]
        claims = json.loads(base64.urlsafe_b64decode(jwt.split(".")[1] + "=="))
        self.assertEqual(claims["aud"], "https://ntfy.example.org:8443")
        self.assertEqual(claims["sub"], "mailto:push@example.org")
        self.assertEqual(claims["exp"], int(now) + up.VAPID_LIFETIME)
        self.assertIn("k=" + up.vapid_public_key(vapid), auth)

        # Cached per origin until close to expiry
        self.assertIs(signer.headers("https://ntfy.example.org:8443/other", now + 60), h)
        later = now + up.VAPID_LIFETIME - up.VAPID_RENEW + 1
        self.assertIsNot(signer.headers("https://ntfy.example.org:8443/other", later), h)

    def test_rejects_wrong_curve(self):
        path = os.path.join(TMP, "p384.pem")
        with open(path, "wb") as f:
            f.write(
                ec.generate_private_key(ec.SECP384R1()).private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
        with self.assertRaises(ValueError):
            up.load_vapid_key(path)

    def test_missing_key_file_is_an_error(self):
        path = os.path.join(TMP, "does-not-exist.pem")
        with self.assertRaises(FileNotFoundError):
            up.load_vapid_key(path)
        self.assertFalse(os.path.exists(path))


class AddressTests(unittest.TestCase):
    def test_is_public_address(self):
        for a in ("8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"):
            self.assertTrue(up.is_public_address(a), a)
        for a in (
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "::1",
            "fe80::1%eth0",
            "fd00::1",
            "::ffff:10.0.0.1",
            "64:ff9b::a00:1",
            "garbage",
        ):
            self.assertFalse(up.is_public_address(a), a)


class FakeResolver:
    def __init__(self, hosts):
        self.hosts = hosts

    async def resolve(self, host, port=0, family=0):
        return [{"hostname": host, "host": h, "port": port} for h in self.hosts]

    async def close(self):
        pass


class ResolverTests(unittest.IsolatedAsyncioTestCase):
    async def test_filters_private(self):
        r = up.PublicOnlyResolver()
        r.resolver = FakeResolver(["10.0.0.1", "8.8.8.8", "::1"])
        self.assertEqual([x["host"] for x in await r.resolve("a.example", 443)], ["8.8.8.8"])

    async def test_all_private_fails(self):
        r = up.PublicOnlyResolver()
        r.resolver = FakeResolver(["169.254.169.254", "127.0.0.1"])
        with self.assertRaises(OSError):
            await r.resolve("metadata.example", 443)


class FakeContent:
    async def read(self, n=-1):
        return b""


class FakeResponse:
    def __init__(self, status, headers=None):
        self.status = status
        self.headers = headers or {}
        self.content = FakeContent()


class FakeCtx:
    def __init__(self, r):
        self.r = r

    async def __aenter__(self):
        if isinstance(self.r, BaseException):
            raise self.r
        return self.r

    async def __aexit__(self, *exc):
        return False


class FakeSession:
    """Stands in for aiohttp.ClientSession: replays a list of responses (or exceptions)."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return FakeCtx(self.responses.pop(0))


class SenderTests(unittest.IsolatedAsyncioTestCase):
    def make_sender(self, *responses):
        self.session = FakeSession(*responses)
        self.stats = up.NotifyStats()
        self.gone = []
        self.sleeps = []

        async def fake_sleep(d):
            self.sleeps.append(d)

        signer = up.VapidSigner(
            up.load_vapid_key(os.path.join(TMP, "vapid.pem")), "mailto:push@example.org"
        )
        return up.Sender(
            self.session,
            signer,
            self.stats,
            self.gone.append,
            retries=2,
            retry_interval=1,
            sleep=fake_sleep,
        )

    async def test_success_and_headers(self):
        s = self.make_sender(FakeResponse(201))
        await s.send("svc", ENDPOINT, b"ciphertext", 300)
        self.assertEqual(self.stats.notifies, 1)
        url, kw = self.session.calls[0]
        self.assertEqual(url, ENDPOINT)
        self.assertEqual(kw["data"], b"ciphertext")
        self.assertFalse(kw["allow_redirects"])
        h = kw["headers"]
        self.assertEqual(h["TTL"], "300")
        self.assertEqual(h["Urgency"], "high")
        self.assertEqual(h["Content-Encoding"], "aes128gcm")
        self.assertTrue(h["Authorization"].startswith("vapid t="))

    async def test_gone_drops_registration(self):
        for status in (404, 410):
            s = self.make_sender(FakeResponse(status))
            await s.send("svc-" + str(status), ENDPOINT, b"x", 60)
            self.assertEqual(self.gone, ["svc-" + str(status)])
            self.assertEqual(len(self.session.calls), 1)
            self.assertEqual(self.stats.failures, 1)
            self.assertEqual(self.stats.notifies, 0)

    async def test_retry_after_429(self):
        s = self.make_sender(FakeResponse(429, {"Retry-After": "7"}), FakeResponse(201))
        await s.send("svc", ENDPOINT, b"x", 60)
        self.assertEqual(self.sleeps, [7.0])
        self.assertEqual(self.stats.notifies, 1)
        self.assertEqual(self.stats.notify_retries, 1)
        self.assertEqual(self.gone, [])

    async def test_5xx_backoff_then_give_up(self):
        s = self.make_sender(FakeResponse(500), FakeResponse(502), FakeResponse(503))
        await s.send("svc", ENDPOINT, b"x", 60)
        self.assertEqual(len(self.session.calls), 3)
        self.assertEqual(self.sleeps, [1, 2])
        self.assertEqual(self.stats.failures, 1)
        self.assertEqual(self.gone, [])

    async def test_network_error_retried(self):
        s = self.make_sender(aiohttp.ClientConnectionError("boom"), FakeResponse(200))
        await s.send("svc", ENDPOINT, b"x", 60)
        self.assertEqual(self.stats.notifies, 1)
        self.assertEqual(self.sleeps, [1])

    async def test_long_retry_after_gives_up(self):
        s = self.make_sender(FakeResponse(429, {"Retry-After": "3600"}))
        await s.send("svc", ENDPOINT, b"x", 60)
        self.assertEqual(len(self.session.calls), 1)
        self.assertEqual(self.sleeps, [])
        self.assertEqual(self.stats.failures, 1)

    async def test_client_errors_not_retried_or_dropped(self):
        for status in (400, 401, 403, 413, 301):
            s = self.make_sender(FakeResponse(status))
            await s.send("svc", ENDPOINT, b"x", 60)
            self.assertEqual(len(self.session.calls), 1, status)
            self.assertEqual(self.gone, [], status)
            self.assertEqual(self.stats.failures, 1, status)

    async def test_refuses_invalid_stored_endpoint(self):
        s = self.make_sender()
        await s.send("svc", "https://10.0.0.1/up", b"x", 60)
        self.assertEqual(self.session.calls, [])
        self.assertEqual(self.stats.failures, 1)


class FakeLoop:
    def __init__(self):
        self.calls = []

    def call_soon_threadsafe(self, fn, *args):
        self.calls.append(args)


class FakeOMQ:
    def __init__(self):
        self.sent = []

    def send(self, conn, cmd, *args):
        self.sent.append((cmd, *args))


class EndToEndTests(unittest.IsolatedAsyncioTestCase):
    """notifier.push from the hivemind through to the POSTed body, and the drop on a 410."""

    async def test_push_then_gone(self):
        device_key, pub, auth = device_keys()
        enc_key = os.urandom(32)
        svcid, svcdata = up.parse_service_info(service_info(pub, auth))
        msg_body = b"hello from the swarm"
        push = oxenc.bt_serialize(push_dict(enc_key, msg_body, svcid=svcid, svcdata=svcdata))

        handler = types.SimpleNamespace(loop=FakeLoop(), omq=FakeOMQ(), hivemind="hm")
        handler.drop_registration = lambda sid: up.UnifiedPushHandler.drop_registration(
            handler, sid
        )
        session = FakeSession(FakeResponse(201), FakeResponse(410))
        handler.sender = up.Sender(
            session,
            up.VapidSigner(
                up.load_vapid_key(os.path.join(TMP, "vapid.pem")), "mailto:push@example.org"
            ),
            up.NotifyStats(),
            handler.drop_registration,
        )

        for _ in range(2):
            up.UnifiedPushHandler.push_notification(handler, FakeMessage(push))
        self.assertEqual(len(handler.loop.calls), 2)
        for (coro,) in handler.loop.calls:
            await coro

        url, kw = session.calls[0]
        self.assertEqual(url, ENDPOINT)
        fields = open_body(device_key, auth, kw["data"])
        meta, data = open_enc_payload(enc_key, fields["enc_payload"])
        self.assertEqual(data, msg_body)
        self.assertEqual(meta["l"], len(msg_body))
        self.assertLessEqual(int(kw["headers"]["TTL"]), up.TTL)

        self.assertEqual(
            handler.omq.sent,
            [("admin.drop_registrations", "unifiedpush", oxenc.bt_serialize([svcid]))],
        )


if __name__ == "__main__":
    unittest.main()
