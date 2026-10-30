"""Signing in to the admin with passkeys (WebAuthn), next to the password.

A passkey is bound to the domain it was created on: the browser only offers it there and the authenticator signs
that domain's hash, so each stored key keeps its rp_id and is checked against it. Browsers refuse WebAuthn on IP
addresses and outside HTTPS (localhost aside).
"""

import hashlib
import ipaddress
import json
import secrets
import time
from typing import Any
from urllib.parse import urlsplit

from fastapi import Request
from webauthn import (base64url_to_bytes, generate_authentication_options, generate_registration_options,
                      options_to_json, verify_authentication_response, verify_registration_response)
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import (AuthenticatorSelectionCriteria, PublicKeyCredentialDescriptor,
                                      ResidentKeyRequirement, UserVerificationRequirement)

from . import db
from .config import settings

CHALLENGE_TTL = 300
MAX_CHALLENGES = 1000  # asking for a login challenge needs no session
NOT_A_DOMAIN = "Passkeys работают только по домену и HTTPS: откройте админку по доменному имени"

# challenge id -> (challenge, purpose, rp_id, expires)
_challenges: dict[str, tuple[bytes, str, str, float]] = {}


class PasskeyError(Exception):
    pass


def unusable_reason(host: str | None, scheme: str = "https") -> str:
    """Why a browser would refuse passkeys on this address; empty when it will not."""
    if not host:
        return NOT_A_DOMAIN
    local = host == "localhost" or host.endswith(".localhost")
    try:
        ipaddress.ip_address(host)
        return NOT_A_DOMAIN
    except ValueError:
        return "" if scheme == "https" or local else NOT_A_DOMAIN


def _origin(request: Request) -> tuple[str, str]:
    """The page's origin and the domain passkeys are bound to there. What the browser signs is checked against both."""
    origin = request.headers.get("origin") or ""
    parts = urlsplit(origin)
    reason = unusable_reason(parts.hostname, parts.scheme)
    if reason:
        raise PasskeyError(reason)
    return origin, parts.hostname


def _keep(challenge: bytes, purpose: str, rp_id: str) -> str:
    now = time.time()
    for key in [k for k, v in _challenges.items() if v[3] < now]:
        del _challenges[key]
    while len(_challenges) >= MAX_CHALLENGES:
        del _challenges[next(iter(_challenges))]
    key = secrets.token_urlsafe(24)
    _challenges[key] = (challenge, purpose, rp_id, now + CHALLENGE_TTL)
    return key


def _take(key: str, purpose: str, rp_id: str) -> bytes:
    """Each challenge works once, for what and where it was given."""
    found = _challenges.pop(key, None)
    if not found or found[1] != purpose or found[2] != rp_id or found[3] < time.time():
        raise PasskeyError("Запрос устарел, попробуйте ещё раз")
    return found[0]


def available(request: Request) -> bool:
    """Whether a passkey exists for the domain this page is open on."""
    return any(k.rp_id == request.url.hostname for k in db.list_passkeys())


def registration_options(request: Request) -> dict[str, Any]:
    _, rp_id = _origin(request)
    username = settings.admin_username
    options = generate_registration_options(
        rp_id=rp_id, rp_name="VPN Admin", user_name=username,
        user_id=hashlib.sha256(f"vpn-admin:{username}".encode()).digest(),
        exclude_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(k.credential_id))
                             for k in db.list_passkeys() if k.rp_id == rp_id],
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED, user_verification=UserVerificationRequirement.REQUIRED),
    )
    return {"challenge_id": _keep(options.challenge, "register", rp_id), "options": json.loads(options_to_json(options))}


def register(request: Request, challenge_id: str, name: str, credential: dict[str, Any]) -> db.Passkey:
    origin, rp_id = _origin(request)
    challenge = _take(challenge_id, "register", rp_id)
    try:
        verified = verify_registration_response(credential=credential, expected_challenge=challenge,
                                                expected_rp_id=rp_id, expected_origin=origin,
                                                require_user_verification=True)
    except (WebAuthnException, ValueError, KeyError, TypeError) as exc:
        raise PasskeyError(f"Ключ не добавлен: {exc}") from exc
    return db.create_passkey(name.strip() or "Passkey", bytes_to_base64url(verified.credential_id),
                             bytes_to_base64url(verified.credential_public_key), verified.sign_count, rp_id)


def login_options(request: Request) -> dict[str, Any]:
    _, rp_id = _origin(request)
    # no list of keys: the browser offers what it holds for this domain, and nobody learns which keys exist
    options = generate_authentication_options(rp_id=rp_id, user_verification=UserVerificationRequirement.REQUIRED)
    return {"challenge_id": _keep(options.challenge, "login", rp_id), "options": json.loads(options_to_json(options))}


def login(request: Request, challenge_id: str, credential: dict[str, Any]) -> None:
    origin, rp_id = _origin(request)
    challenge = _take(challenge_id, "login", rp_id)
    key = db.get_passkey_by_credential(str(credential.get("id") or ""))
    if not key or key.rp_id != rp_id:
        raise PasskeyError("Этого ключа нет в админке: возможно, его удалили")
    try:
        verified = verify_authentication_response(credential=credential, expected_challenge=challenge,
                                                  expected_rp_id=rp_id, expected_origin=origin,
                                                  credential_public_key=base64url_to_bytes(key.public_key),
                                                  credential_current_sign_count=key.sign_count,
                                                  require_user_verification=True)
    except (WebAuthnException, ValueError, KeyError, TypeError) as exc:
        raise PasskeyError("Ключ не прошёл проверку") from exc
    db.touch_passkey(key.id, verified.new_sign_count)
