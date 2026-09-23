"""Recording stand-in for the Langfuse SDK surface LangfuseSink calls (FP-M6-24)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class _Generation:
    kwargs: dict[str, Any]
    ended: bool = False

    def end(self) -> None:
        self.ended = True


@dataclass
class RecordingLangfuseClient:
    generations: list[_Generation] = field(default_factory=list)

    def generation(self, **kwargs: Any) -> _Generation:
        gen = _Generation(kwargs=dict(kwargs))
        self.generations.append(gen)
        return gen

    @property
    def calls(self) -> list[dict[str, Any]]:
        return [g.kwargs for g in self.generations]
