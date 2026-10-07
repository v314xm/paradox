from typing import Protocol

from pcap_triage.models import CaptureState


class Extractor(Protocol):
    name: str
    layer: int

    def process(self, pkt, state: CaptureState) -> None: ...