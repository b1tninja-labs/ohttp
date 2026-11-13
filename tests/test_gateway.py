"""The gateway as pure functions: errors, replay, Date, media types (RFC 9458 sec. 5, sec. 6)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from email.utils import format_datetime

import pytest

from ohttp import gateway
from ohttp.bhttp import Request, Response, decode_response, encode_request
from ohttp.gateway import (
    PROBLEM_DATE,
    PROBLEM_OHTTP_KEY,
    REQUEST_MEDIA_TYPE,
    RESPONSE_MEDIA_TYPE,
    ReplayCache,
    process_request,
)
from ohttp.keys import SymmetricSuite, generate_config
from ohttp.message import decapsulate_response, encapsulate

NOW = 1_700_000_000.0
SUITES = (SymmetricSuite(1, 1),)
PAIR = generate_config(SUITES, 3)
REQUEST = Request(b"GET", b"https", b"example.com", b"/", headers=((b"accept", b"*/*"),))


def http_date(stamp: float) -> bytes:
    return format_datetime(datetime.fromtimestamp(stamp, UTC), usegmt=True).encode("ascii")


def ask(request=REQUEST, *, forward=None, raw=None, **kwargs):
    """Encapsulate ``request`` for PAIR and run the gateway; return (response, client context)."""
    encapsulated = encapsulate(raw if raw is not None else encode_request(request), PAIR.config)
    content_type = kwargs.pop("content_type", REQUEST_MEDIA_TYPE)
    body = kwargs.pop("body", encapsulated.body)
    result = process_request(
        content_type,
        body,
        kwargs.pop("keys", [PAIR]),
        forward or (lambda _r: Response(200, content=b"ok")),
        now=kwargs.pop("now", NOW),
        **kwargs,
    )
    return result, encapsulated.context


def opened(result, context) -> Response:
    assert result.status == 200
    assert result.content_type == RESPONSE_MEDIA_TYPE
    return decode_response(decapsulate_response(context, result.body))


def test_success_is_a_bare_200_with_the_response_media_type():
    result, context = ask(forward=lambda _r: Response(201, ((b"x", b"y"),), b"made"))
    assert (result.status, result.content_type, result.headers) == (200, RESPONSE_MEDIA_TYPE, ())
    response = opened(result, context)
    assert (response.status, response.content, response.headers) == (201, b"made", ((b"x", b"y"),))


def test_the_forwarded_request_is_what_the_client_sent():
    seen = []
    ask(forward=lambda r: seen.append(r) or Response(200))
    assert seen == [REQUEST]


def test_error_status_codes():
    # before protection is removed: unprotected 4xx (sec. 5.2 para 2)
    wrong_type, _ = ask(content_type="application/octet-stream")
    assert (wrong_type.status, wrong_type.content_type) == (415, "text/plain")
    assert ask(content_type=None)[0].status == 415
    unknown, _ = ask(keys=[generate_config(SUITES, 9)])  # a different key identifier
    assert unknown.status == 422
    assert unknown.content_type == "application/problem+json"
    assert json.loads(unknown.body) == {
        "type": PROBLEM_OHTTP_KEY,
        "title": "key identifier unknown",
    }
    garbled, _ = ask(body=b"\x03" + b"\x00" * 80)
    assert garbled.status == 422
    assert garbled.content_type == "text/plain"  # a key id match, the KEM does not
    clone = generate_config(SUITES, 3)  # same identifier, other key: cannot decrypt
    cannot, _ = ask(keys=[clone])
    assert (cannot.status, cannot.content_type) == (422, "text/plain")
    short, _ = ask(body=b"")
    assert short.status == 422
    # after protection is removed: encapsulated (sec. 5.2 para 3)
    bad, context = ask(raw=b"\x01not binary http")
    assert opened(bad, context).status == 400

    def slow(request):
        raise TimeoutError

    assert opened(*ask(forward=slow)).status == 504

    def broken(request):
        raise RuntimeError("target fell over")

    assert opened(*ask(forward=broken)).status == 500


def test_media_type_enforced():
    for good in ("message/ohttp-req", "Message/OHTTP-REQ", " message/ohttp-req "):
        assert ask(content_type=good)[0].status == 200
    # sec. 9.2 defines no parameters; the response and keys types are not the request type
    for bad in ("message/ohttp-req; charset=utf-8", "message/ohttp-res", "application/ohttp-keys"):
        assert ask(content_type=bad)[0].status == 415
    assert (gateway.KEYS_MEDIA_TYPE, gateway.REQUEST_MEDIA_TYPE, gateway.RESPONSE_MEDIA_TYPE) == (
        "application/ohttp-keys",
        "message/ohttp-req",
        "message/ohttp-res",
    )


def test_replay_refused():
    cache = ReplayCache(window=60.0)
    encapsulated = encapsulate(encode_request(REQUEST), PAIR.config)

    def send(at):
        return process_request(
            REQUEST_MEDIA_TYPE,
            encapsulated.body,
            [PAIR],
            lambda _r: Response(200),
            now=at,
            replay=cache,
        )

    assert opened(send(NOW), encapsulated.context).status == 200
    replayed = send(NOW + 1)
    assert replayed.status == 200  # an encapsulated answer, so the relay learns nothing
    assert decode_response(decapsulate_response(encapsulated.context, replayed.body)).status == 400
    assert opened(send(NOW + 61), encapsulated.context).status == 200  # outside the window
    assert cache.check_and_record(b"other", NOW + 62)
    assert not cache.check_and_record(b"other", NOW + 63)
    with pytest.raises(ValueError, match="positive"):
        ReplayCache(0)


def test_date_window_and_the_correcting_response():
    fresh = Request(b"GET", b"https", b"h", b"/", headers=((b"date", http_date(NOW - 10)),))
    assert opened(*ask(fresh, date_window=300.0)).status == 200
    stale = Request(b"GET", b"https", b"h", b"/", headers=((b"date", http_date(NOW - 4000)),))
    result, context = ask(stale, date_window=300.0)
    response = opened(result, context)
    assert response.status == 400
    assert dict(response.headers)[b"date"] == http_date(NOW)  # lets the client correct its clock
    assert json.loads(response.content)["type"] == PROBLEM_DATE
    garbage = Request(b"GET", b"https", b"h", b"/", headers=((b"date", b"yesterday-ish"),))
    assert opened(*ask(garbage, date_window=300.0)).status == 400
    # no window configured: Date is ignored; no Date header: not refused (sec. 6.5.1 says SHOULD)
    assert opened(*ask(stale)).status == 200
    assert opened(*ask(date_window=300.0)).status == 200


def test_expect_100_continue_is_an_error():
    request = Request(b"POST", b"https", b"h", b"/", headers=((b"expect", b"100-continue"),))
    assert opened(*ask(request)).status == 400


def test_relay_is_still_a_loud_stub():
    import asyncio

    with pytest.raises(NotImplementedError):
        asyncio.run(gateway.relay(b"", "https://gateway.example/"))
