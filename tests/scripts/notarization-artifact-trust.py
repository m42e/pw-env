#!/usr/bin/env python3
import json
import re
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parents[2]
workflows = root / ".github/workflows"
tag_workflow = (workflows / "tag-release-pr.yml").read_text()
release_workflow = (workflows / "release.yml").read_text()
finalizer = (workflows / "finalize-notarization.yml").read_text()
release_skill = (root / ".github/skills/release-with-workflows/SKILL.md").read_text()
release_instructions = (root / ".github/instructions/release.instructions.md").read_text()


def run_blocks(source: str) -> list[str]:
    lines = source.splitlines()
    blocks = []
    index = 0
    while index < len(lines):
        match = re.match(r"^(\s*)run:\s*\|\s*$", lines[index])
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


assert "actions/create-github-app-token@64ab729a6294000f5aa4a4bc0b73d1f32bc45510" in tag_workflow
assert "RELEASE_APP_ID" in tag_workflow
assert "RELEASE_APP_PRIVATE_KEY" in tag_workflow
assert "repositories: ${{ github.event.repository.name }}" in tag_workflow
assert "permission-contents: write" in tag_workflow
assert "token: ${{ steps.release-token.outputs.token }}" in tag_workflow
assert "gh workflow run release.yml" not in tag_workflow
assert "actions: write" not in tag_workflow
assert "github.event.pull_request.head.repo.full_name == github.repository" in tag_workflow

assert re.search(r"(?ms)^on:\n  push:\n    tags: \[\"v\*\"\]\n", release_workflow)
assert "workflow_dispatch:" not in release_workflow
assert "RELEASE_TAG: ${{ github.ref_name }}" in release_workflow
assert "RELEASE_REF_TYPE: ${{ github.ref_type }}" in release_workflow
assert "^refs/tags/v[0-9]+\\.[0-9]+\\.[0-9]+$" in release_workflow
assert '"$object_sha" != "$RELEASE_SHA"' in release_workflow
assert "needs: validate-release" in release_workflow
assert "ref: ${{ github.sha }}" in release_workflow
assert "commit_sha: $commit_sha" in release_workflow
assert "ref: $ref" in release_workflow
assert "binary_sha256: $binary_sha256" in release_workflow
assert ".archive_sha256 = $archive_sha256" in release_workflow

assert "workflow_dispatch:" not in finalizer
assert "SELECTED_TAG" not in finalizer
assert 'actions/workflows/release.yml' in finalizer
assert '(.head_repository.id | tostring) == $repository_id' in finalizer
assert '(.workflow_id | tostring) == $workflow_id' in finalizer
assert '.event == "push"' in finalizer
assert '.status == "completed" and .conclusion == "success"' in finalizer
assert r'(.head_branch | test("^v[0-9]+\\.[0-9]+\\.[0-9]+$"))' in finalizer
assert 'repos/$GH_REPO/git/ref/tags/$tag' in finalizer
assert "resolve_tag_commit()" in finalizer
assert 'tag_object_sha=$(resolve_tag_commit "$source_tag")' in finalizer
assert '[ "$tag_object_sha" != "$source_sha" ]' in finalizer
assert '[ "$metadata_ref" != "refs/tags/$source_tag" ]' in finalizer
assert '[ "$metadata_sha" != "$source_sha" ]' in finalizer
assert '[ "$actual_archive_sha256" != "$archive_sha256" ]' in finalizer
assert '[ "$actual_binary_sha256" != "$binary_sha256" ]' in finalizer
assert 'if ! xcrun notarytool info' in finalizer
assert '"$asset_path" "$updated_checksums_path" --clobber' in finalizer
assert 'x86_64-apple-darwin|aarch64-apple-darwin' in finalizer
assert finalizer.index('.event == "push"') < finalizer.index("gh run download")
assert finalizer.index('metadata_ref=$(jq') < finalizer.index('xcrun notarytool info')
assert finalizer.index('current_tag_sha=$(resolve_tag_commit "$tag")') < finalizer.index('gh release upload')

run_filter = re.search(
    r'if ! jq -e \\\n(?:\s+--arg [^\n]+\\\n)+\s+\'(?P<program>.*?)\' \\\n\s+<<< "\$source_run"',
    finalizer,
    re.S,
)
assert run_filter, "could not extract source-run trust filter"
trusted_run = {
    "repository": {"id": 42},
    "head_repository": {"id": 42},
    "workflow_id": 7,
    "path": ".github/workflows/release.yml@v1.2.3",
    "event": "push",
    "status": "completed",
    "conclusion": "success",
    "head_branch": "v1.2.3",
    "head_sha": "0123456789012345678901234567890123456789",
}
filter_args = [
    "jq",
    "-e",
    "--arg",
    "repository_id",
    "42",
    "--arg",
    "workflow_id",
    "7",
    "--arg",
    "run_branch",
    "v1.2.3",
    "--arg",
    "run_sha",
    trusted_run["head_sha"],
    run_filter.group("program"),
]
subprocess.run(filter_args, input=json.dumps(trusted_run), text=True, check=True, capture_output=True)
for key, rejected_value in (
    ("event", "workflow_dispatch"),
    ("repository", {"id": 99}),
    ("conclusion", "failure"),
    ("head_branch", "v1.2.3-malicious"),
    ("head_sha", "ffffffffffffffffffffffffffffffffffffffff"),
):
    untrusted_run = trusted_run.copy()
    untrusted_run[key] = rejected_value
    result = subprocess.run(filter_args, input=json.dumps(untrusted_run), text=True, capture_output=True)
    assert result.returncode != 0, f"source-run filter accepted {key}={rejected_value!r}"

for document in (release_skill, release_instructions):
    assert "RELEASE_APP_ID" in document
    assert "RELEASE_APP_PRIVATE_KEY" in document
    assert "Contents: write" in document
    assert "tag" in document.lower() and "ruleset" in document.lower()

for source in (tag_workflow, release_workflow, finalizer):
    for block in run_blocks(source):
        if "${{" not in block:
            subprocess.run(["bash", "-n"], input=block, text=True, check=True)

print("notarization artifact trust checks passed")
