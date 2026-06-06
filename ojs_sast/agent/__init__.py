"""OJS-SAST agent package — runs on the OJS node.

The agent builds a filtered source snapshot (``source.tar.gz``) plus a
``meta.json`` (raw configuration payload and an upload-directory *manifest* — the
upload files themselves are never transmitted) and submits the bundle to a
remote OJS-SAST service.

The HTTP client imports its third-party dependency (``httpx``) lazily, so the
``build-bundle`` workflow works on a bare install without the ``agent`` extra.
"""

from .. import __version__ as AGENT_VERSION

__all__ = ["AGENT_VERSION"]
