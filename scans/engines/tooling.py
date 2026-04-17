from __future__ import annotations

import json
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any


@dataclass
class ToolExecutionResult:
    tool: str
    command: str
    return_code: int
    stdout: str
    stderr: str
    timed_out: bool = False
    missing_binary: bool = False

    @property
    def ok(self) -> bool:
        return self.return_code == 0 and not self.missing_binary and not self.timed_out


class ExternalToolRunner:
    timeout_seconds = 240

    def is_available(self, tool: str) -> bool:
        return shutil.which(tool) is not None

    def run(self, tool: str, args: list[str], *, timeout: int | None = None) -> ToolExecutionResult:
        if not self.is_available(tool):
            return ToolExecutionResult(
                tool=tool,
                command=' '.join([tool, *args]),
                return_code=127,
                stdout='',
                stderr=f'Binary {tool} not found in PATH',
                missing_binary=True,
            )

        cmd = [tool, *args]
        effective_timeout = timeout or self.timeout_seconds
        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=effective_timeout,
                check=False,
            )
            return ToolExecutionResult(
                tool=tool,
                command=' '.join(shlex.quote(p) for p in cmd),
                return_code=completed.returncode,
                stdout=completed.stdout,
                stderr=completed.stderr,
            )
        except subprocess.TimeoutExpired as exc:
            return ToolExecutionResult(
                tool=tool,
                command=' '.join(shlex.quote(p) for p in cmd),
                return_code=124,
                stdout=exc.stdout or '',
                stderr=f'{tool} timed out after {effective_timeout}s',
                timed_out=True,
            )


def parse_json_lines(raw_text: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in (raw_text or '').splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                rows.append(obj)
        except json.JSONDecodeError:
            continue
    return rows
