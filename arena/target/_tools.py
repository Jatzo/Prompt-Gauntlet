"""Deterministic mock tools over a World. Nothing is ever sent anywhere.

Every result carrying world content comes back as untrusted segments, so a defence can gate exactly
those. The trace records every call, refused or not, in order; the checker reads only the trace and
the final answer.
"""

import re
from dataclasses import dataclass, field

from arena.target.world import World

_WORD = re.compile(r"\w+")


@dataclass(frozen=True)
class Segment:
    id: str
    text: str
    untrusted: bool


@dataclass(frozen=True)
class ToolCall:
    tool: str
    args: dict[str, str]
    # False when the tool was not exposed or the defence refused it: the call did not happen.
    allowed: bool


@dataclass
class ToolBox:
    world: World
    exposed: frozenset[str]
    trace: list[ToolCall] = field(default_factory=list)

    def refuse(self, tool: str, args: dict[str, str]) -> list[Segment]:
        self.trace.append(ToolCall(tool, dict(args), allowed=False))
        return [Segment(f"{tool}:refused", f"The call to {tool} was not allowed.", untrusted=False)]

    def run(self, tool: str, args: dict[str, str]) -> list[Segment]:
        if tool not in self.exposed:
            return self.refuse(tool, args)
        self.trace.append(ToolCall(tool, dict(args), allowed=True))
        segments = getattr(self, f"_{tool}")(args)
        preamble = dict(self.world.preambles).get(tool)
        if preamble is not None:
            segments.insert(0, Segment(f"{tool}:preamble", preamble, untrusted=True))
        return segments

    def _read_email(self, args: dict[str, str]) -> list[Segment]:
        for email in self.world.inbox:
            if email.id == args.get("id"):
                text = f"From: {email.sender}\nSubject: {email.subject}\n\n{email.body}"
                return [Segment(f"read_email:{email.id}", text, untrusted=True)]
        listing = "; ".join(f"{e.id} from {e.sender}: {e.subject}" for e in self.world.inbox)
        return [Segment("read_email:inbox", f"No such email. Inbox: {listing}", untrusted=True)]

    def _search_docs(self, args: dict[str, str]) -> list[Segment]:
        query = set(_WORD.findall(args.get("query", "").lower()))
        scored = []
        for doc in self.world.docs:
            for position, chunk in enumerate(doc.chunks):
                words = set(_WORD.findall(f"{doc.title} {chunk}".lower()))
                scored.append((len(query & words), doc.id, position, chunk))
        # Highest overlap first; ties in document order, so the result never depends on hashing.
        scored.sort(key=lambda item: (-item[0], item[1], item[2]))
        return [
            Segment(f"search_docs:{doc_id}:{position}", chunk, untrusted=True)
            for overlap, doc_id, position, chunk in scored[:3]
            if overlap > 0
        ] or [Segment("search_docs:none", "No matching documents.", untrusted=False)]

    def _fetch_url(self, args: dict[str, str]) -> list[Segment]:
        url = args.get("url", "").rstrip("/")
        for page in self.world.pages:
            if page.url == url:
                return [Segment(f"fetch_url:{url}", page.text, untrusted=True)]
        return [Segment("fetch_url:missing", "Page not found.", untrusted=False)]

    def _send_message(self, args: dict[str, str]) -> list[Segment]:
        return [Segment("send_message:ok", "Message sent.", untrusted=False)]
