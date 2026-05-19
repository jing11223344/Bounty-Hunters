import time
import threading
from typing import Annotated

from annotated_doc import Doc
from fastapi.openapi.models import APIKey, APIKeyIn
from fastapi.security.base import SecurityBase
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.status import HTTP_401_UNAUTHORIZED, HTTP_429_TOO_MANY_REQUESTS


class APIKeyBase(SecurityBase):
    model: APIKey

    def __init__(
        self,
        location: APIKeyIn,
        name: str,
        description: str | None,
        scheme_name: str | None,
        auto_error: bool,
    ):
        self.auto_error = auto_error

        self.model: APIKey = APIKey(
            **{"in": location},  # ty: ignore[invalid-argument-type]
            name=name,
            description=description,
        )
        self.scheme_name = scheme_name or self.__class__.__name__

    def make_not_authenticated_error(self) -> HTTPException:
        """
        The WWW-Authenticate header is not standardized for API Key authentication but
        the HTTP specification requires that an error of 401 "Unauthorized" must
        include a WWW-Authenticate header.

        Ref: https://datatracker.ietf.org/doc/html/rfc9110#name-401-unauthorized

        For this, this method sends a custom challenge `APIKey`.
        """
        return HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "APIKey"},
        )

    def check_api_key(self, api_key: str | None) -> str | None:
        if not api_key:
            if self.auto_error:
                raise self.make_not_authenticated_error()
            return None
        return api_key


class APIKeyQuery(APIKeyBase):
    """
    API key authentication using a query parameter.

    This defines the name of the query parameter that should be provided in the request
    with the API key and integrates that into the OpenAPI documentation. It extracts
    the key value sent in the query parameter automatically and provides it as the
    dependency result. But it doesn't define how to send that API key to the client.

    ## Usage

    Create an instance object and use that object as the dependency in `Depends()`.

    The dependency result will be a string containing the key value.

    ## Example

    ```python
    from fastapi import Depends, FastAPI
    from fastapi.security import APIKeyQuery

    app = FastAPI()

    query_scheme = APIKeyQuery(name="api_key")


    @app.get("/items/")
    async def read_items(api_key: str = Depends(query_scheme)):
        return {"api_key": api_key}
    ```
    """

    def __init__(
        self,
        *,
        name: Annotated[
            str,
            Doc("Query parameter name."),
        ],
        scheme_name: Annotated[
            str | None,
            Doc(
                """
                Security scheme name.

                It will be included in the generated OpenAPI (e.g. visible at `/docs`).
                """
            ),
        ] = None,
        description: Annotated[
            str | None,
            Doc(
                """
                Security scheme description.

                It will be included in the generated OpenAPI (e.g. visible at `/docs`).
                """
            ),
        ] = None,
        auto_error: Annotated[
            bool,
            Doc(
                """
                By default, if the query parameter is not provided, `APIKeyQuery` will
                automatically cancel the request and send the client an error.

                If `auto_error` is set to `False`, when the query parameter is not
                available, instead of erroring out, the dependency result will be
                `None`.

                This is useful when you want to have optional authentication.

                It is also useful when you want to have authentication that can be
                provided in one of multiple optional ways (for example, in a query
                parameter or in an HTTP Bearer token).
                """
            ),
        ] = True,
    ):
        super().__init__(
            location=APIKeyIn.query,
            name=name,
            scheme_name=scheme_name,
            description=description,
            auto_error=auto_error,
        )

    async def __call__(self, request: Request) -> str | None:
        api_key = request.query_params.get(self.model.name)
        return self.check_api_key(api_key)


class APIKeyHeader(APIKeyBase):
    """
    API key authentication using a header.

    This defines the name of the header that should be provided in the request with
    the API key and integrates that into the OpenAPI documentation. It extracts
    the key value sent in the header automatically and provides it as the dependency
    result. But it doesn't define how to send that key to the client.

    ## Usage

    Create an instance object and use that object as the dependency in `Depends()`.

    The dependency result will be a string containing the key value.

    ## Example

    ```python
    from fastapi import Depends, FastAPI
    from fastapi.security import APIKeyHeader

    app = FastAPI()

    header_scheme = APIKeyHeader(name="x-key")


    @app.get("/items/")
    async def read_items(key: str = Depends(header_scheme)):
        return {"key": key}
    ```
    """

    def __init__(
        self,
        *,
        name: Annotated[str, Doc("Header name.")],
        scheme_name: Annotated[
            str | None,
            Doc(
                """
                Security scheme name.

                It will be included in the generated OpenAPI (e.g. visible at `/docs`).
                """
            ),
        ] = None,
        description: Annotated[
            str | None,
            Doc(
                """
                Security scheme description.

                It will be included in the generated OpenAPI (e.g. visible at `/docs`).
                """
            ),
        ] = None,
        auto_error: Annotated[
            bool,
            Doc(
                """
                By default, if the header is not provided, `APIKeyHeader` will
                automatically cancel the request and send the client an error.

                If `auto_error` is set to `False`, when the header is not available,
                instead of erroring out, the dependency result will be `None`.

                This is useful when you want to have optional authentication.

                It is also useful when you want to have authentication that can be
                provided in one of multiple optional ways (for example, in a header or
                in an HTTP Bearer token).
                """
            ),
        ] = True,
    ):
        super().__init__(
            location=APIKeyIn.header,
            name=name,
            scheme_name=scheme_name,
            description=description,
            auto_error=auto_error,
        )

    async def __call__(self, request: Request) -> str | None:
        api_key = request.headers.get(self.model.name)
        return self.check_api_key(api_key)


class APIKeyCookie(APIKeyBase):
    """
    API key authentication using a cookie.

    This defines the name of the cookie that should be provided in the request with
    the API key and integrates that into the OpenAPI documentation. It extracts
    the key value sent in the cookie automatically and provides it as the dependency
    result. But it doesn't define how to set that cookie.

    ## Usage

    Create an instance object and use that object as the dependency in `Depends()`.

    The dependency result will be a string containing the key value.

    ## Example

    ```python
    from fastapi import Depends, FastAPI
    from fastapi.security import APIKeyCookie

    app = FastAPI()

    cookie_scheme = APIKeyCookie(name="session")


    @app.get("/items/")
    async def read_items(session: str = Depends(cookie_scheme)):
        return {"session": session}
    ```
    """

    def __init__(
        self,
        *,
        name: Annotated[str, Doc("Cookie name.")],
        scheme_name: Annotated[
            str | None,
            Doc(
                """
                Security scheme name.

                It will be included in the generated OpenAPI (e.g. visible at `/docs`).
                """
            ),
        ] = None,
        description: Annotated[
            str | None,
            Doc(
                """
                Security scheme description.

                It will be included in the generated OpenAPI (e.g. visible at `/docs`).
                """
            ),
        ] = None,
        auto_error: Annotated[
            bool,
            Doc(
                """
                By default, if the cookie is not provided, `APIKeyCookie` will
                automatically cancel the request and send the client an error.

                If `auto_error` is set to `False`, when the cookie is not available,
                instead of erroring out, the dependency result will be `None`.

                This is useful when you want to have optional authentication.

                It is also useful when you want to have authentication that can be
                provided in one of multiple optional ways (for example, in a cookie or
                in an HTTP Bearer token).
                """
            ),
        ] = True,
    ):
        super().__init__(
            location=APIKeyIn.cookie,
            name=name,
            scheme_name=scheme_name,
            description=description,
            auto_error=auto_error,
        )

    async def __call__(self, request: Request) -> str | None:
        api_key = request.cookies.get(self.model.name)
        return self.check_api_key(api_key)


class RateLimitStore:
    """Thread-safe in-memory sliding window rate limit tracker."""

    def __init__(self):
        self._lock = threading.Lock()
        self._windows: dict[str, list[float]] = {}

    def check(self, key: str, max_requests: int, window_seconds: float) -> tuple[bool, float]:
        """Check if key is within rate limit. Returns (allowed, retry_after_seconds)."""
        now = time.time()
        cutoff = now - window_seconds
        with self._lock:
            if key not in self._windows:
                self._windows[key] = []
            timestamps = self._windows[key]
            # Remove expired timestamps
            while timestamps and timestamps[0] < cutoff:
                timestamps.pop(0)
            if len(timestamps) >= max_requests:
                retry_after = timestamps[0] + window_seconds - now
                return False, max(0.0, retry_after)
            timestamps.append(now)
            return True, 0.0


# Global rate limit store (shared across instances)
_rate_limit_store = RateLimitStore()


def _parse_rate_limit(rate_limit: str) -> tuple[int, float]:
    """Parse '100/minute', '1000/hour', or '5/10s' into (max_requests, window_seconds)."""
    _UNIT_TO_SECONDS = {
        "second": 1.0, "seconds": 1.0, "s": 1.0,
        "minute": 60.0, "minutes": 60.0, "m": 60.0,
        "hour": 3600.0, "hours": 3600.0, "h": 3600.0,
        "day": 86400.0, "days": 86400.0, "d": 86400.0,
    }
    parts = rate_limit.strip().split("/")
    if len(parts) != 2:
        raise ValueError(f"Invalid rate_limit format: '{rate_limit}'. Use format like '100/minute' or '1000/hour'.")
    try:
        count = int(parts[0])
    except ValueError:
        raise ValueError(f"Invalid count in rate_limit: '{parts[0]}'")
    unit_raw = parts[1].lower().strip()
    # Extract numeric prefix from unit (e.g., "10s" -> 10, "s")
    import re
    match = re.match(r"(\d+)\s*(.*)", unit_raw)
    if match:
        multiplier = int(match.group(1))
        unit = match.group(2).strip() or "s"
    else:
        multiplier = 1
        unit = unit_raw
    base_window = _UNIT_TO_SECONDS.get(unit)
    if base_window is None:
        raise ValueError(
            f"Invalid time unit in rate_limit: '{unit_raw}'. "
            f"Use second(s)/s, minute(s)/m, hour(s)/h, or day(s)/d."
        )
    return count, base_window * multiplier


class APIKeyWithRateLimit(APIKeyHeader):
    """
    API key authentication with rate limiting and deprecated key support.

    Extends `APIKeyHeader` with:
    - **Rate limiting**: limits requests per API key using a sliding window
    - **Deprecated keys**: old keys still authenticate but include a Warning header

    ## Usage

    ```python
    from fastapi import Depends, FastAPI
    from fastapi.security import APIKeyWithRateLimit

    app = FastAPI()

    # Allow 100 requests per minute, with one deprecated key
    api_key_scheme = APIKeyWithRateLimit(
        name="x-api-key",
        rate_limit="100/minute",
        deprecated_keys=["old-key-123"],
    )

    @app.get("/items/")
    async def read_items(api_key: str = Depends(api_key_scheme)):
        return {"api_key": api_key}
    ```
    """

    def __init__(
        self,
        *,
        name: Annotated[str, Doc("Header name.")],
        rate_limit: Annotated[
            str,
            Doc("Rate limit string, e.g. '100/minute' or '1000/hour'."),
        ],
        deprecated_keys: Annotated[
            list[str] | None,
            Doc(
                "List of deprecated API keys that still work "
                "but include a Warning header in the response."
            ),
        ] = None,
        scheme_name: Annotated[
            str | None,
            Doc("Security scheme name for OpenAPI."),
        ] = None,
        description: Annotated[
            str | None,
            Doc("Security scheme description for OpenAPI."),
        ] = None,
        auto_error: Annotated[
            bool,
            Doc(
                "By default, if the header is not provided, "
                "automatically cancel and send an error."
            ),
        ] = True,
    ):
        super().__init__(
            name=name,
            scheme_name=scheme_name,
            description=description,
            auto_error=auto_error,
        )
        self.max_requests, self.window_seconds = _parse_rate_limit(rate_limit)
        self.rate_limit_str = rate_limit
        self.deprecated_keys = set(deprecated_keys) if deprecated_keys else set()

    async def __call__(self, request: Request) -> str | None:
        api_key = request.headers.get(self.model.name)
        api_key = self.check_api_key(api_key)
        if api_key is None:
            return None

        # Check rate limit
        allowed, retry_after = _rate_limit_store.check(
            api_key, self.max_requests, self.window_seconds
        )
        if not allowed:
            raise HTTPException(
                status_code=HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests",
                headers={"Retry-After": str(int(retry_after))},
            )

        # Check deprecated keys
        if api_key in self.deprecated_keys:
            request.state.warning_header = (
                f'299 - "The API key \\"{api_key[:4]}...\\" is deprecated and will be deactivated soon"'
            )

        return api_key
