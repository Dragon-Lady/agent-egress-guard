"""Local egress observation. No network activity at import time."""

__version__ = "0.1.0.dev0"
BANNER = (
    "observe mode is best-effort: traffic that ignores proxy settings can be missed. "
    "This draft has no bypass detector or enforcement; observed bytes are not total egress."
)
