#
# UnifiedPush notifier
#
# Delivers notifications to devices that registered through a UnifiedPush distributor app (ntfy,
# NextPush, Gotify, an FCM-backed distributor, ...).  The distributor gives the app an endpoint URL;
# we deliver by POSTing a standard Web Push message (RFC 8030) to that URL, encrypted to the device
# with RFC 8291 (aes128gcm) and signed with VAPID (RFC 8292).
#
# Registration `service_info`:
#
#     {
#         "endpoint": "https://push.example.org/abc123...",
#         "p256dh": "BASE64URL(65-byte uncompressed P-256 public key)",
#         "auth": "BASE64URL(16-byte auth secret)"
#     }
#
# The decrypted Web Push body is the JSON encoding of the same data map that Android receives from
# FCM and Huawei:
#
#     {"enc_payload":"B64(NONCE+ENCRYPTED(l123:{...json...}456:...msg...e))","spns":"1"}
#
# so a client can parse it into a string map and hand it to the code that handles an FCM data
# message.  See apns.py for the contents of `enc_payload`.
#

import asyncio
import base64
import binascii
import email.utils
import ipaddress
import json
import signal
import socket
import time
from datetime import timedelta
from urllib.parse import urlsplit

import aiohttp
import aiohttp.abc
import http_ece
import oxenc
import systemd.daemon
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from nacl.encoding import HexEncoder
from nacl.hash import blake2b as blake2b_oneshot
from oxenmq import OxenMQ, Message, Address, AuthLevel
from py_vapid import Vapid02

from .. import config
from ..conf import looks_true
from ..config import logger
from spns_hivemind import SUBSCRIBE
from .util import encrypt_notify_payload, derive_notifier_key, warn_on_except, NotifyStats

SERVICE = "unifiedpush"

# Whenever we add/change fields we increment this so that a Session client could figure out what it
# is speaking to:
SPNS_UNIFIEDPUSH_VERSION = 1

# Same message data limit as the other notifiers.  The padded plaintext steps in 256-byte blocks and
# 2816 is the largest that still fits once encrypted and base64-encoded; 2500 bytes of message plus
# the metadata stays inside it.  build_push_body() drops the message if it ever would not.
MAX_MSG_SIZE = 2500

# UnifiedPush distributors accept at most 4096 bytes of encrypted body.
MAX_PUSH_SIZE = 4096

# aes128gcm (RFC 8188) overhead for a single record: an 86-byte header (16 salt, 4 record size, 1
# key id length, 65 key id, which is our ephemeral P-256 public key), a 1-byte padding delimiter and
# a 16-byte tag.  Anything under 4079 bytes of plaintext is a single record.
WEBPUSH_OVERHEAD = 86 + 1 + 16

# The hivemind accepts at most 99,999 bytes of service data; real endpoints are a few hundred bytes.
MAX_ENDPOINT_LENGTH = 2048

# Upper bound on any single retry delay, including one asked for by a Retry-After header.  A
# distributor asking for longer gets the notification dropped rather than queued.
MAX_RETRY_DELAY = 60.0

# VAPID tokens may live up to 24 hours (RFC 8292); we sign for 12 and re-sign an hour before expiry.
VAPID_LIFETIME = 12 * 3600
VAPID_RENEW = 3600
VAPID_CACHE_MAX = 4096

conf = config.NOTIFY.get(SERVICE, {})
MAX_RETRIES = int(conf.get("retries", 2))
RETRY_INTERVAL = float(conf.get("retry_interval", 5))
TTL = int(conf.get("ttl", 86400))
REQUEST_TIMEOUT = float(conf.get("timeout", 10))
MAX_CONCURRENT = int(conf.get("max_concurrent", 200))
MAX_PER_HOST = int(conf.get("max_per_host", 50))
ALLOW_PRIVATE = bool(looks_true(conf.get("allow_private", "no")))


def decode_b64(value, name: str) -> bytes:
    """Decodes base64url or standard base64, padded or not; raises ValueError on anything else."""
    if not isinstance(value, str) or not value:
        raise ValueError(f"Invalid {name}: expected a base64url string")
    s = value.strip().rstrip("=").replace("+", "-").replace("/", "_")
    try:
        return base64.b64decode(s + "=" * (-len(s) % 4), altchars=b"-_", validate=True)
    except binascii.Error:
        raise ValueError(f"Invalid {name}: expected a base64url string")


def is_public_address(addr: str) -> bool:
    """True if addr is a globally routable unicast address."""
    try:
        ip = ipaddress.ip_address(addr.split("%", 1)[0])
    except ValueError:
        return False
    if ip.version == 6:
        if ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        elif ip in ipaddress.ip_network("64:ff9b::/96"):
            # NAT64: the embedded IPv4 address is what actually gets reached
            ip = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return ip.is_global and not ip.is_multicast


def validate_endpoint(endpoint, *, allow_private: bool = False):
    """
    Checks a push endpoint URL; raises ValueError if it is unacceptable.  Only https is accepted,
    and the host must be a DNS name: IP literals would bypass the send-time address check (aiohttp
    does not resolve them), and py_vapid cannot sign an IPv6 literal audience.
    """
    if not isinstance(endpoint, str) or not endpoint:
        raise ValueError("Invalid endpoint: expected a URL string")
    if len(endpoint) > MAX_ENDPOINT_LENGTH:
        raise ValueError(f"Invalid endpoint: longer than {MAX_ENDPOINT_LENGTH} characters")
    if any(c <= " " or c > "~" for c in endpoint):
        raise ValueError("Invalid endpoint: must be printable ASCII (punycode for IDNs)")
    try:
        url = urlsplit(endpoint)
        url.port  # raises ValueError on an invalid port
    except ValueError:
        raise ValueError("Invalid endpoint: unparseable URL")
    if url.scheme != "https":
        raise ValueError("Invalid endpoint: only https:// endpoints are supported")
    if url.username is not None or url.password is not None:
        raise ValueError("Invalid endpoint: credentials in the URL are not supported")
    if url.fragment:
        raise ValueError("Invalid endpoint: URL fragments are not supported")
    host = url.hostname
    if not host:
        raise ValueError("Invalid endpoint: missing host")
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False
    if is_ip:
        raise ValueError("Invalid endpoint: the host must be a DNS name, not an IP address")
    if not allow_private:
        if "." not in host.rstrip(".") or host.rstrip(".").endswith(".localhost"):
            raise ValueError("Invalid endpoint: the host must be a public DNS name")


def endpoint_svcid(endpoint: str) -> str:
    """
    The unique service id for an endpoint.  Token services use the token itself; an endpoint can be
    shorter than the hivemind's 32-character minimum, so we use a fixed-size hash of it instead.
    """
    return blake2b_oneshot(
        endpoint.encode(), digest_size=32, key=b"UnifiedPush", encoder=HexEncoder
    ).decode()


def parse_service_info(info, *, allow_private: bool = False):
    """
    Validates registration `service_info`.  Returns (svcid, svcdata) where svcdata is the bencoded
    dict the hivemind stores and hands back with each push.  Raises KeyError for a missing field and
    ValueError for an invalid one.
    """
    if not isinstance(info, dict):
        raise ValueError("Invalid service_info: expected a JSON object")

    endpoint = info["endpoint"]
    validate_endpoint(endpoint, allow_private=allow_private)

    p256dh = decode_b64(info["p256dh"], "p256dh")
    if len(p256dh) != 65 or p256dh[0] != 0x04:
        raise ValueError("Invalid p256dh: expected a 65-byte uncompressed P-256 public key")
    try:
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), p256dh)
    except ValueError:
        raise ValueError("Invalid p256dh: not a valid P-256 public key")

    auth = decode_b64(info["auth"], "auth")
    if len(auth) != 16:
        raise ValueError("Invalid auth: expected a 16-byte auth secret")

    return endpoint_svcid(endpoint), oxenc.bt_serialize({"a": auth, "e": endpoint, "k": p256dh})


def build_push_body(data: dict) -> bytes:
    """
    Builds the plaintext Web Push body for a hivemind push dict.  If including the message would
    take the encrypted body past MAX_PUSH_SIZE, the message is left out and flagged as too big,
    exactly as for a message over MAX_MSG_SIZE.
    """
    for max_size in (MAX_MSG_SIZE, 0):
        enc_payload = encrypt_notify_payload(data, max_msg_size=max_size)
        body = json.dumps(
            {"enc_payload": oxenc.to_base64(enc_payload), "spns": f"{SPNS_UNIFIEDPUSH_VERSION}"},
            separators=(",", ":"),
        ).encode()
        if len(body) + WEBPUSH_OVERHEAD <= MAX_PUSH_SIZE:
            return body
    raise ValueError(f"notification body too large ({len(body)}B) even without message data")


def encrypt_webpush(body: bytes, p256dh: bytes, auth: bytes) -> bytes:
    """RFC 8291 aes128gcm encryption of body to the device's p256dh key and auth secret."""
    return http_ece.encrypt(
        body,
        private_key=ec.generate_private_key(ec.SECP256R1()),
        dh=p256dh,
        auth_secret=auth,
        version="aes128gcm",
    )


def push_ttl(data: dict, now: float | None = None) -> int:
    """The TTL for a push: the configured TTL, cut short by the message's own swarm expiry."""
    ttl = TTL
    expiry = data.get(b"z")
    if isinstance(expiry, int) and expiry > 0:
        if now is None:
            now = time.time()
        ttl = min(ttl, max(0, int(expiry / 1000 - now)))
    return ttl


def parse_retry_after(value) -> float | None:
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        return max(0.0, email.utils.parsedate_to_datetime(value).timestamp() - time.time())
    except (TypeError, ValueError):
        return None


def load_vapid_key(path: str) -> Vapid02:
    """Loads a PEM-encoded P-256 private key.  (py_vapid's own from_file creates a new key when the
    file is missing, which would silently invalidate every endpoint bound to the old one.)"""
    with open(path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError(f"{path} is not a P-256 (prime256v1) private key")
    return Vapid02(private_key=key)


def vapid_public_key(vapid: Vapid02) -> str:
    """The base64url VAPID public key that clients pass to the distributor when registering."""
    raw = vapid.public_key.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class VapidSigner:
    """Signs VAPID Authorization headers, cached per push service origin."""

    def __init__(self, vapid: Vapid02, contact: str):
        self.vapid = vapid
        self.contact = contact
        self.cache = {}

    def headers(self, endpoint: str, now: float | None = None) -> dict:
        url = urlsplit(endpoint)
        aud = f"{url.scheme}://{url.hostname}" + (f":{url.port}" if url.port else "")
        if now is None:
            now = time.time()
        cached = self.cache.get(aud)
        if cached and cached[1] - now > VAPID_RENEW:
            return cached[0]
        if len(self.cache) >= VAPID_CACHE_MAX:
            self.cache.clear()
        exp = int(now) + VAPID_LIFETIME
        headers = self.vapid.sign({"aud": aud, "sub": self.contact, "exp": exp})
        self.cache[aud] = (headers, exp)
        return headers


class PublicOnlyResolver(aiohttp.abc.AbstractResolver):
    """
    Resolver that drops non-global addresses, so that an endpoint whose name resolves (or later
    re-resolves) to a private, loopback or link-local address is never connected to.  The check has
    to happen here, at connection time, rather than at registration: DNS can change in between.
    """

    def __init__(self):
        self.resolver = aiohttp.ThreadedResolver()

    async def resolve(self, host, port=0, family=socket.AF_INET):
        results = await self.resolver.resolve(host, port, family)
        public = [r for r in results if is_public_address(r["host"])]
        if not public:
            raise OSError(f"{host} does not resolve to any public address")
        return public

    async def close(self):
        await self.resolver.close()


class Sender:
    """
    POSTs encrypted Web Push messages, with retries.  `on_gone(svcid)` is called when the push
    service reports the endpoint no longer exists (404/410).
    """

    def __init__(
        self,
        session,
        signer: VapidSigner,
        stats: NotifyStats,
        on_gone,
        *,
        retries: int = MAX_RETRIES,
        retry_interval: float = RETRY_INTERVAL,
        timeout: float = REQUEST_TIMEOUT,
        allow_private: bool = ALLOW_PRIVATE,
        sleep=asyncio.sleep,
    ):
        self.session = session
        self.signer = signer
        self.stats = stats
        self.on_gone = on_gone
        self.retries = retries
        self.retry_interval = retry_interval
        # Per-socket timeouts rather than a total: the connector's connection limits queue
        # requests, and time spent waiting for a free connection must not count against a push.
        self.timeout = aiohttp.ClientTimeout(total=None, sock_connect=timeout, sock_read=timeout)
        self.allow_private = allow_private
        self.sleep = sleep

    def _failed(self):
        with self.stats.lock:
            self.stats.failures += 1

    async def send(self, svcid: str, endpoint: str, encrypted: bytes, ttl: int):
        try:
            await self._send(svcid, endpoint, encrypted, ttl)
        except Exception as e:
            logger.warning(f"Push to {urlsplit(endpoint).hostname} failed: {type(e).__name__}: {e}")
            self._failed()

    async def _send(self, svcid: str, endpoint: str, encrypted: bytes, ttl: int):
        # Endpoints are bearer capabilities (anyone holding one can push to the device), so only the
        # host goes in the logs.
        host = urlsplit(endpoint).hostname
        try:
            validate_endpoint(endpoint, allow_private=self.allow_private)
        except ValueError as e:
            logger.warning(f"Not sending to stored endpoint at {host}: {e}")
            self._failed()
            return

        headers = {
            "TTL": str(ttl),
            "Urgency": "high",
            "Content-Encoding": "aes128gcm",
            "Content-Type": "application/octet-stream",
        }

        attempt = 0
        while True:
            status, retry_after, error = None, None, None
            try:
                headers.update(self.signer.headers(endpoint))
                async with self.session.post(
                    endpoint,
                    data=encrypted,
                    headers=headers,
                    allow_redirects=False,
                    timeout=self.timeout,
                ) as resp:
                    status = resp.status
                    retry_after = resp.headers.get("Retry-After")
                    # Bounded read so a hostile endpoint can't make us buffer a huge body; the
                    # connection is closed rather than reused if anything is left unread.
                    await resp.content.read(4096)
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as e:
                error = f"{type(e).__name__}: {e}"

            if status is not None and 200 <= status < 300:
                with self.stats.lock:
                    self.stats.notifies += 1
                    if attempt > 0:
                        self.stats.notify_retries += 1
                return

            if status in (404, 410):
                logger.debug(f"Push endpoint at {host} is gone ({status}); dropping {svcid}")
                self._failed()
                self.on_gone(svcid)
                return

            retryable = status is None or status == 429 or status >= 500
            if not retryable:
                hint = " (VAPID rejected?)" if status in (401, 403) else ""
                logger.warning(f"Push to {host} failed with HTTP {status}{hint}; not retrying")
                self._failed()
                return

            reason = error or f"HTTP {status}"
            if attempt >= self.retries:
                logger.warning(
                    f"Push to {host} failed ({reason}); giving up after {attempt} retries"
                )
                self._failed()
                return

            delay = self.retry_interval * (2**attempt)
            ra = parse_retry_after(retry_after) if status in (429, 503) else None
            if ra is not None:
                delay = max(delay, ra)
            if delay > MAX_RETRY_DELAY:
                logger.warning(
                    f"Push to {host} failed ({reason}); retry delay {delay:.0f}s too long"
                )
                self._failed()
                return

            logger.debug(f"Push to {host} failed ({reason}); retrying in {delay:.1f}s")
            attempt += 1
            await self.sleep(delay)


class UnifiedPushHandler:
    def __init__(self, loop, key, signer: VapidSigner):
        self.loop = loop
        self.stats = NotifyStats()
        self.signer = signer
        self.sender = None

        self.omq = OxenMQ(pubkey=key.public_key.encode(), privkey=key.encode())

        cat = self.omq.add_category("notifier", AuthLevel.basic)
        cat.add_request_command("validate", self.validate)
        cat.add_command("push", self.push_notification)

        self.omq.add_timer(self.ping, timedelta(seconds=5))

    async def start_http(self):
        """Creates the HTTP session; must run inside the event loop."""
        connector = aiohttp.TCPConnector(
            resolver=None if ALLOW_PRIVATE else PublicOnlyResolver(),
            limit=MAX_CONCURRENT,
            limit_per_host=MAX_PER_HOST,
        )
        session = aiohttp.ClientSession(connector=connector)
        self.sender = Sender(session, self.signer, self.stats, self.drop_registration)

    def start(self):
        self.omq.start()
        self.hivemind = self.omq.connect_remote(
            Address(config.config.hivemind_sock),
            auth_level=AuthLevel.basic,
            ephemeral_routing_id=False,
        )
        self.omq.send(self.hivemind, "admin.register_service", SERVICE)

    @warn_on_except
    def validate(self, msg: Message):
        parts = msg.data()
        if len(parts) != 2 or parts[0] != SERVICE.encode():
            logger.warning("Internal error: invalid input to notifier.validate")
            msg.reply(str(SUBSCRIBE.ERROR.value), "Internal error")
            return

        try:
            svcid, svcdata = parse_service_info(json.loads(parts[1]), allow_private=ALLOW_PRIVATE)
            msg.reply("0", svcid, svcdata)
        except KeyError as e:
            msg.reply(str(SUBSCRIBE.BAD_INPUT.value), f"Error: missing required key {e}")
        except ValueError as e:
            msg.reply(str(SUBSCRIBE.BAD_INPUT.value), str(e))
        except Exception as e:
            msg.reply(str(SUBSCRIBE.ERROR.value), str(e))

    @warn_on_except
    def push_notification(self, msg: Message):
        if self.sender is None:
            logger.warning("Dropping notification received before the HTTP session started")
            return

        data = oxenc.bt_deserialize(msg.data()[0])
        svcid = data[b"&"].decode()  # unique service id, as we returned from validate
        info = oxenc.bt_deserialize(data[b"!"])
        endpoint = info[b"e"].decode()

        encrypted = encrypt_webpush(build_push_body(data), info[b"k"], info[b"a"])

        self.loop.call_soon_threadsafe(
            asyncio.ensure_future,
            self.sender.send(svcid, endpoint, encrypted, push_ttl(data)),
        )

    def drop_registration(self, svcid: str):
        self.omq.send(
            self.hivemind, "admin.drop_registrations", SERVICE, oxenc.bt_serialize([svcid])
        )

    @warn_on_except
    def ping(self):
        """Makes sure we are registered and reports updated stats to hivemind; called every 5s"""
        self.omq.send(self.hivemind, "admin.register_service", SERVICE)
        self.omq.send(
            self.hivemind, "admin.service_stats", SERVICE, oxenc.bt_serialize(self.stats.collect())
        )
        systemd.daemon.notify(
            f"WATCHDOG=1\nSTATUS=Running; {self.stats.total_notifies} notifications, "
            f"{self.stats.total_retries} retries, {self.stats.total_failures} failures"
        )

    def stop(self):
        self.omq.disconnect(self.hivemind)
        self.hivemind = None
        self.omq = None
        if self.sender is not None:
            self.loop.run_until_complete(self.sender.session.close())


def run(startup_delay=4.0):
    """Runs the unifiedpush asyncio event loop, forever."""

    # These do not and *should* not match hivemind or any other notifier: that is, each notifier
    # needs its own unique keypair.  We do, however, want it to persist so that we can
    # restart/reconnect and receive messages sent while we where restarting.
    key = derive_notifier_key(SERVICE)

    if startup_delay > 0:
        time.sleep(startup_delay)

    logger.info(f"Starting {SERVICE} notifier")
    systemd.daemon.notify(f"STATUS=Initializing {SERVICE} notifier...")

    try:
        for opt in ("vapid_private_key", "vapid_contact"):
            if not conf.get(opt):
                raise RuntimeError(f"[notify-{SERVICE}] {opt} is required")
        signer = VapidSigner(load_vapid_key(conf["vapid_private_key"]), conf["vapid_contact"])
        # Fails now, rather than on the first push, if the contact is not a mailto: or https: URI
        signer.vapid.sign({"aud": "https://example.org", "sub": signer.contact})
        logger.info(f"VAPID public key (applicationServerKey): {vapid_public_key(signer.vapid)}")
        if ALLOW_PRIVATE:
            logger.warning("allow_private is enabled: pushes may be sent to private addresses")

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        handler = UnifiedPushHandler(loop, key, signer)
        loop.run_until_complete(handler.start_http())
        handler.start()

    except Exception as e:
        logger.critical(f"Failed to start up {SERVICE} notifier: {e}")
        raise e

    logger.info(f"{SERVICE} notifier started")
    systemd.daemon.notify("READY=1\nSTATUS=Started")

    def sig_die(signum, frame):
        raise OSError(f"Caught signal {signal.Signals(signum).name}")

    try:
        signal.signal(signal.SIGHUP, sig_die)
        signal.signal(signal.SIGINT, sig_die)

        loop.run_forever()
    except Exception as e:
        logger.critical(f"{SERVICE} run loop failed: {e}")

    logger.info(f"{SERVICE} notifier shut down")

    handler.stop()
    loop.close()


if __name__ == "__main__":
    run(startup_delay=0)
