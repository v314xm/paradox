from typing import Protocol

from paradox.models import CaptureState


class Extractor(Protocol):
    name: str
    layer: int

    def process(self, pkt, state: CaptureState) -> None: ...