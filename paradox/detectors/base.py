from typing import Protocol

from paradox.config import Config
from paradox.models import CaptureState, Finding


class LocalDetector(Protocol):
    name: str

    def run(self, state: CaptureState, config: Config) -> list[Finding]: ...