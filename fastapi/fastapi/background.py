import logging
import traceback
from collections.abc import Callable
from typing import Annotated, Any, Optional

from annotated_doc import Doc
from starlette.background import BackgroundTasks as StarletteBackgroundTasks
from typing_extensions import ParamSpec

P = ParamSpec("P")

logger = logging.getLogger("fastapi.background")


class BackgroundTasks(StarletteBackgroundTasks):
    """
    A collection of background tasks that will be called after a response has been
    sent to the client.

    Supports error handling and optional retry mechanism for robust background execution.

    Read more about it in the
    [FastAPI docs for Background Tasks](https://fastapi.tiangolo.com/tutorial/background-tasks/).
    """

    def __init__(
        self,
        tasks: Optional[list[tuple[Callable[..., Any], tuple[Any, ...], dict[str, Any]]]] = None,
        max_retries: int = 3,
        retry_delay_seconds: float = 1.0,
        on_error: Optional[Callable[[Exception, Callable[..., Any]], None]] = None,
    ):
        super().__init__(tasks=tasks)
        self._max_retries = max_retries
        self._retry_delay_seconds = retry_delay_seconds
        self._on_error = on_error

    def add_task(
        self,
        func: Annotated[Callable[..., Any], Doc("The function to run as a background task.")],
        *args: Annotated[Any, Doc("Positional arguments to pass to the function.")],
        **kwargs: Annotated[Any, Doc("Keyword arguments to pass to the function.")],
    ) -> None:
        """
        Add a function to be run as a background task.

        Supports the same interface as Starlette's BackgroundTasks.add_task,
        but wrapps the task with error handling and optional retry logic.
        """
        super().add_task(func, *args, **kwargs)

    async def __call__(self) -> None:
        """
        Run all background tasks with error handling and retry logic.

        Each task is wrapped in a try/except block that:
        1. Logs the exception with full traceback
        2. Retries up to `max_retries` times with exponential backoff
        3. Calls the optional `on_error` callback on final failure
        """
        for func, args, kwargs in self.tasks:
            await self._run_with_retry(func, args, kwargs)

    async def _run_with_retry(
        self,
        func: Callable[..., Any],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> None:
        """Run a single task with retry logic."""
        import asyncio

        last_exception: Optional[Exception] = None

        for attempt in range(self._max_retries + 1):
            try:
                if attempt > 0:
                    logger.info(
                        "Retrying background task %s.%s (attempt %d/%d)",
                        func.__module__ if hasattr(func, "__module__") else "?",
                        func.__name__,
                        attempt,
                        self._max_retries,
                    )

                result = func(*args, **kwargs)

                # Await if the result is a coroutine
                if result is not None and asyncio.iscoroutine(result):
                    await result

                return  # Success — exit retry loop

            except Exception as e:
                last_exception = e
                logger.error(
                    "Background task %s.%s failed on attempt %d/%d:\n%s",
                    func.__module__ if hasattr(func, "__module__") else "?",
                    func.__name__,
                    attempt + 1,
                    self._max_retries + 1,
                    traceback.format_exc(),
                )

                if attempt < self._max_retries:
                    # Exponential backoff: 1s, 2s, 4s, ...
                    delay = self._retry_delay_seconds * (2 ** attempt)
                    await asyncio.sleep(delay)

        # All retries exhausted — fire the on_error callback
        if self._on_error is not None and last_exception is not None:
            try:
                self._on_error(last_exception, func)
            except Exception as callback_error:
                logger.error(
                    "on_error callback itself raised: %s",
                    traceback.format_exc(),
                )

        logger.error(
            "Background task %s.%s failed after %d attempts. Giving up.",
            func.__module__ if hasattr(func, "__module__") else "?",
            func.__name__,
            self._max_retries + 1,
        )
