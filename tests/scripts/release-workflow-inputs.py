#!/usr/bin/env python3
import re
from pathlib import Path

root = Path(__file__).resolve().parents[2]
workflow_paths = [
    root / ".github/workflows/tag-release-pr.yml",
    root / ".github/workflows/prepare-release-pr.yml",
]


def run_blocks(path: Path) -> list[str]:
    lines = path.read_text().splitlines()
    blocks = []
    index = 0
    while index < len(lines):
        line = lines[index]
        match = re.match(r"^(\s*)run:\s*\|\s*$", line)
        if not match:
            index += 1
            continue
        key_indent = len(match.group(1))
        index += 1
        body = []
        while index < len(lines):
            current = lines[index]
            if current.strip() and len(current) - len(current.lstrip()) <= key_indent:
                break
            body.append(current)
            index += 1
        blocks.append("\n".join(body))
    return blocks


for path in workflow_paths:
    blocks = run_blocks(path)
    assert blocks, f"no multiline run steps found in {path}"
    for block_index, block in enumerate(blocks, start=1):
        assert "${{" not in block, f"workflow expression embedded in shell source: {path}:{block_index}"

prepare = workflow_paths[1].read_text()
tag = workflow_paths[0].read_text()
version_pattern = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
for accepted in ("1.2.3", "0.10.20"):
    assert version_pattern.fullmatch(accepted)
for rejected in ("1.2.3$(touch /tmp/pwned)", "1.2.3\n::set-output name=x::y", "1.2.3; echo bad"):
    assert not version_pattern.fullmatch(rejected)

assert 'RELEASE_VERSION: ${{ inputs.version }}' in prepare
assert 'RELEASE_BRANCH: ${{ github.event.pull_request.head.ref }}' in tag
assert 'RELEASE_VERSION" =~ ^[0-9]+\\.[0-9]+\\.[0-9]+$' in prepare
assert '"$version" =~ ^[0-9]+\\.[0-9]+\\.[0-9]+$' in tag
assert 'git commit -m "chore: prepare release v$RELEASE_VERSION"' in prepare

print("release workflow input test passed")
