"""Ошибки стадий pipeline."""


class PipelineCancelled(Exception):
    """Raised when cooperative cancellation was requested mid-run."""
