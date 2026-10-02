"""Extract hosts without making network requests or opening suspicious URLs."""

import ipaddress
import re
from email.utils import parseaddr
from urllib.parse import urlsplit

URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


def host(value: str) -> str:
    try:
        parsed = urlsplit(value if "://" in value else "//" + value)
        name = (parsed.hostname or "").lower().rstrip(".")
        if not name or len(name) > 253:
            return ""
        try:
            return str(ipaddress.ip_address(name))
        except ValueError:
            name = name.encode("idna").decode("ascii")
            if all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in name.split(".")):
                return name
    except (ValueError, UnicodeError):
        pass
    return ""


def event_hosts(event) -> list[str]:
    candidates = [event.url] if event.url else []
    candidates += [url.rstrip(".,;!?)］）") for url in URL_PATTERN.findall(event.body)]
    sender = parseaddr(event.sender)[1]
    if "@" in sender:
        candidates.append(sender.rsplit("@", 1)[1])
    return sorted({name for value in candidates if (name := host(value))})


def public_domain(name: str) -> bool:
    """Never send IPs, local names, or reserved demo domains to search."""
    try:
        ipaddress.ip_address(name)
        return False
    except ValueError:
        return bool(
            host(name) == name
            and "." in name
            and not name.endswith((".test", ".example", ".invalid", ".localhost", ".local", ".internal"))
            and name not in {"example.com", "example.net", "example.org"}
        )
