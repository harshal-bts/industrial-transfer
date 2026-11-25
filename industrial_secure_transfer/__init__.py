"""Industrial Secure Data Transfer package."""

import os
import sys

__version__ = "1.2.0"

# Offline air-gapped fallback: if the active Python 3.14 interpreter does not have `cryptography`
# in its local site-packages, automatically append the local system Python 3.14 site-packages
# (e.g., from Microsoft SDKs\Azure\CLI2\Lib\site-packages) when present on the machine.
try:
    import cryptography as _crypto_check  # noqa: F401
except ImportError:
    _FALLBACK_SITE_PACKAGES = (
        r"C:\Program Files\Microsoft SDKs\Azure\CLI2\Lib\site-packages",
    )
    for _sp in _FALLBACK_SITE_PACKAGES:
        if os.path.isdir(_sp) and _sp not in sys.path:
            sys.path.append(_sp)

