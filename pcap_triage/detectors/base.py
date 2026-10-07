from typing import Protocol

from pcap_triage.config import Config
from pcap_triage.models import CaptureState, Finding


class LocalDetector(Protocol):
    name: str

    def run(self, state: CaptureState, config: Config) -> list[Finding]: ...