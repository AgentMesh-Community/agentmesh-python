"""Tasks: the stateful unit of work a request creates (SPEC.md 7).

``submitted -> working -> input_required / auth_required -> completed / failed /
canceled``, plus ``rejected`` (the responder declined) and ``exhausted`` (a time
and materials cap was reached; terminal and not a failure).
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any, Optional

from .envelope import iso_now
from .errors import ErrorCode, MeshError

__all__ = ["TaskState", "TERMINAL_STATES", "VALID_TRANSITIONS", "is_valid_transition", "Task", "TaskTracker"]

TaskState = str

TERMINAL_STATES = frozenset({"completed", "failed", "canceled", "rejected", "exhausted"})

VALID_TRANSITIONS: dict[str, tuple[str, ...]] = {
    "submitted": ("working", "canceled", "rejected", "exhausted"),
    "working": ("completed", "failed", "input_required", "auth_required", "canceled", "exhausted"),
    "input_required": ("working", "canceled", "exhausted"),
    "auth_required": ("working", "canceled", "exhausted"),
    "completed": (),
    "failed": (),
    "canceled": (),
    "rejected": (),
    "exhausted": (),
}

MAX_TASK_HISTORY = 50


def is_valid_transition(frm: str, to: str) -> bool:
    return to in VALID_TRANSITIONS.get(frm, ())


@dataclass
class Task:
    id: str
    requester: str
    responder: str
    offering: str
    state: str
    created_at: str
    updated_at: str
    history: list[dict[str, Any]] = field(default_factory=list)
    artifacts: list[dict[str, Any]] = field(default_factory=list)
    context_id: Optional[str] = None
    budget: Optional[dict[str, Any]] = None

    @property
    def done(self) -> bool:
        return self.state in TERMINAL_STATES


class TaskTracker:
    """Local bookkeeping of the tasks this agent started."""

    def __init__(self) -> None:
        self._tasks: dict[str, Task] = {}

    def create(self, task: Task) -> None:
        if task.id in self._tasks:
            raise MeshError(ErrorCode.TASK_INVALID_TRANSITION, f"Task {task.id} is already tracked; refusing to replace it")
        self._tasks[task.id] = task

    def has(self, task_id: str) -> bool:
        return task_id in self._tasks

    def get(self, task_id: str) -> Task | None:
        t = self._tasks.get(task_id)
        return copy.deepcopy(t) if t else None

    def transition(self, task_id: str, new_state: str) -> None:
        t = self._tasks.get(task_id)
        if t is None:
            raise MeshError(ErrorCode.TASK_NOT_FOUND, f"Task {task_id} not found")
        if t.state == new_state:
            return
        if not is_valid_transition(t.state, new_state):
            raise MeshError(ErrorCode.TASK_INVALID_TRANSITION, f"Invalid transition {t.state} -> {new_state} for task {task_id}")
        t.state = new_state
        t.updated_at = iso_now()

    def add_to_history(self, task_id: str, envelope: dict[str, Any]) -> None:
        t = self._tasks.get(task_id)
        if t is None:
            return
        t.history.append(envelope)
        if len(t.history) > MAX_TASK_HISTORY:
            del t.history[: len(t.history) - MAX_TASK_HISTORY]
        if isinstance(envelope.get("artifacts"), list):
            t.artifacts.extend(envelope["artifacts"])
        t.updated_at = iso_now()

    def remove(self, task_id: str) -> None:
        self._tasks.pop(task_id, None)

    def all(self) -> list[Task]:
        return [copy.deepcopy(t) for t in self._tasks.values()]
