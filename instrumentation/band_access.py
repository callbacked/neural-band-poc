"""Coordinate ownership of the physical band across CLI and dashboard processes."""

from contextlib import contextmanager
import fcntl
from pathlib import Path


@contextmanager
def band_connection():
    directory = Path(__file__).resolve().parent.parent / "captures"
    directory.mkdir(exist_ok=True)
    with (directory / "band-connection.lock").open("a") as lease:
        try:
            fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("Another band check is active. Wait for it to finish.") from None
        try:
            yield
        finally:
            fcntl.flock(lease, fcntl.LOCK_UN)


def band_available():
    try:
        with band_connection():
            return True
    except RuntimeError:
        return False
