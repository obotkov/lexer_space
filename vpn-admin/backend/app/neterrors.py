"""Readable reasons for failed outgoing requests: httpx timeouts have an empty text, others say little."""

import re

import httpx

# what the system or TLS said anywhere in the exception chain -> what it means
_CAUSES = [
    (r"name or service not known|name resolution|nodename nor servname|no address associated|getaddrinfo failed",
     "имя не находится в DNS: проверьте DNS на сервере админки"),
    (r"connection refused|errno 111\b|errno 61\b", "подключение отклонено: на этом адресе порт закрыт"),
    (r"network is unreachable|no route to host|errno 101\b|errno 113\b", "нет маршрута: у сервера админки нет сети до этого адреса"),
    (r"certificate_verify_failed|certificate verify failed", "сертификат не прошёл проверку"),
    (r"connection reset|errno 104\b", "соединение сброшено: его обрывает сеть или файрвол"),
]


def _chain(exc: BaseException | None) -> str:
    """The texts of the exception and of everything that caused it."""
    seen, texts = set(), []

    def walk(e: BaseException | None) -> None:
        if e is None or id(e) in seen:
            return
        seen.add(id(e))
        if str(e) and str(e) not in texts:
            texts.append(str(e))
        for inner in getattr(e, "exceptions", ()):
            walk(inner)
        walk(e.__cause__ or e.__context__)

    walk(exc)
    return " | ".join(texts)


def _limit(exc: httpx.HTTPError, name: str) -> str:
    try:
        seconds = exc.request.extensions["timeout"][name]
    except (RuntimeError, KeyError, TypeError):
        return ""
    return f" за {seconds:g} с" if seconds else ""


def describe(exc: Exception) -> str:
    """Why the request failed and to which host; anything but an httpx error is just its own text."""
    if not isinstance(exc, httpx.HTTPError):
        return str(exc) or type(exc).__name__
    text = _chain(exc)
    if isinstance(exc, httpx.ConnectTimeout):
        reason = f"не удалось подключиться{_limit(exc, 'connect')} (таймаут подключения): проверьте сеть, DNS и файрвол сервера админки"
    elif isinstance(exc, httpx.ReadTimeout):
        reason = f"подключились, но ответа нет{_limit(exc, 'read')} (таймаут ответа): сервис перегружен или сеть теряет пакеты"
    elif isinstance(exc, httpx.WriteTimeout):
        reason = f"запрос не отправился{_limit(exc, 'write')} (таймаут отправки)"
    elif isinstance(exc, httpx.PoolTimeout):
        reason = "все подключения заняты (таймаут очереди)"
    elif isinstance(exc, httpx.ProxyError):
        reason = f"ошибка прокси: {text}"
    else:
        reason = next((why for pattern, why in _CAUSES if re.search(pattern, text, re.I)), "")
        reason = f"{reason} ({text})" if reason and text else reason or text or type(exc).__name__
    try:
        return f"{exc.request.url.host}: {reason}"
    except RuntimeError:  # raised outside a request
        return reason
