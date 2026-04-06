import { readdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import process from "node:process";
import { createInterface } from "node:readline/promises";

const root = resolve(import.meta.dirname, "..");
const workflowsDir = resolve(root, ".github", "workflows");
const args = new Set(process.argv.slice(2));
const forceWrite = args.has("--write") || args.has("-w");
const checkOnly = args.has("--check");
const interactive = !forceWrite && !checkOnly && process.stdin.isTTY && process.stdout.isTTY;

const usesLinePattern = /^(\s*-\s+uses:\s*)([^@\s]+)@([^\s#]+)(?:\s+(#.*))?$/;
const pinCommentPattern = /(?:^|\s)#\s*pin:\s*([^\s#]+)/;

function isCommitSha(value) {
  return /^[0-9a-f]{40}$/i.test(value);
}

function parseUsesLine(line) {
  const match = line.match(usesLinePattern);

  if (!match) {
    return null;
  }

  const [, prefix, repo, ref, comment = ""] = match;

  if (repo.startsWith("./") || repo.startsWith("docker://") || repo.split("/").length !== 2) {
    return null;
  }

  const pinMatch = comment.match(pinCommentPattern);
  const trackedRef = pinMatch?.[1] ?? (isCommitSha(ref) ? null : ref);

  return {
    prefix,
    repo,
    ref,
    trackedRef,
    hasPinComment: Boolean(pinMatch),
  };
}

async function resolveCommitSha(repo, ref, cache) {
  const cacheKey = `${repo}@${ref}`;

  if (cache.has(cacheKey)) {
    return cache.get(cacheKey);
  }

  const response = await fetch(`https://api.github.com/repos/${repo}/commits/${encodeURIComponent(ref)}`, {
    headers: {
      Accept: "application/vnd.github+json",
      "User-Agent": "pw-env-workflow-action-updater",
    },
  });

  if (!response.ok) {
    throw new Error(`GitHub API returned ${response.status} for ${repo}@${ref}`);
  }

  const payload = await response.json();
  const sha = payload.sha;

  if (!isCommitSha(sha)) {
    throw new Error(`GitHub API did not return a commit SHA for ${repo}@${ref}`);
  }

  cache.set(cacheKey, sha);
  return sha;
}

function buildUpdatedLine(prefix, repo, sha, trackedRef) {
  return `${prefix}${repo}@${sha} # pin: ${trackedRef}`;
}

function shortenSha(sha) {
  return sha.slice(0, 7);
}

const workflowEntries = (await readdir(workflowsDir))
  .filter((entry) => entry.endsWith(".yml") || entry.endsWith(".yaml"))
  .sort();

const files = new Map();
const groups = new Map();

for (const entry of workflowEntries) {
  const filePath = resolve(workflowsDir, entry);
  const content = await readFile(filePath, "utf8");
  const lines = content.split("\n");

  files.set(filePath, lines);

  for (const [lineIndex, line] of lines.entries()) {
    const parsed = parseUsesLine(line);

    if (!parsed || !parsed.trackedRef) {
      continue;
    }

    const groupKey = `${parsed.repo}@${parsed.trackedRef}`;
    const occurrence = {
      entry,
      filePath,
      lineIndex,
      ...parsed,
    };

    if (!groups.has(groupKey)) {
      groups.set(groupKey, {
        repo: parsed.repo,
        trackedRef: parsed.trackedRef,
        occurrences: [],
      });
    }

    groups.get(groupKey).occurrences.push(occurrence);
  }
}

if (groups.size === 0) {
  console.log("No external GitHub Actions were found in .github/workflows.");
  process.exit(0);
}

const shaCache = new Map();

for (const group of groups.values()) {
  group.latestSha = await resolveCommitSha(group.repo, group.trackedRef, shaCache);
  group.currentRefs = [...new Set(group.occurrences.map((occurrence) => occurrence.ref))];
  group.needsUpdate = group.occurrences.some(
    (occurrence) => occurrence.ref !== group.latestSha || !occurrence.hasPinComment,
  );
}

const outdatedGroups = [...groups.values()].filter((group) => group.needsUpdate);
const upToDateGroups = [...groups.values()].filter((group) => !group.needsUpdate);

for (const group of upToDateGroups) {
  console.log(`up-to-date  ${group.repo}@${group.trackedRef} -> ${shortenSha(group.latestSha)}`);
}

for (const group of outdatedGroups) {
  const currentRefs = group.currentRefs.join(", ");
  console.log(
    `update      ${group.repo}@${group.trackedRef} ${currentRefs} -> ${shortenSha(group.latestSha)} (${group.occurrences.length} use${group.occurrences.length === 1 ? "" : "s"})`,
  );
}

if (outdatedGroups.length === 0) {
  console.log("All tracked workflow action pins are current.");
  process.exit(0);
}

if (checkOnly) {
  process.exit(1);
}

let applyAll = forceWrite;
let writeCount = 0;
const readline = interactive
  ? createInterface({
      input: process.stdin,
      output: process.stdout,
    })
  : null;

try {
  for (const group of outdatedGroups) {
    let shouldApply = forceWrite;

    if (!forceWrite && interactive) {
      if (!applyAll) {
        const answer = (await readline.question(
          `Update ${group.repo}@${group.trackedRef} to ${group.latestSha}? [Y]es/[n]o/[a]ll/[q]uit `,
        ))
          .trim()
          .toLowerCase();

        if (answer === "q") {
          break;
        }

        if (answer === "a") {
          applyAll = true;
          shouldApply = true;
        } else {
          shouldApply = answer === "" || answer === "y" || answer === "yes";
        }
      } else {
        shouldApply = true;
      }
    }

    if (!shouldApply) {
      continue;
    }

    for (const occurrence of group.occurrences) {
      const lines = files.get(occurrence.filePath);
      lines[occurrence.lineIndex] = buildUpdatedLine(
        occurrence.prefix,
        occurrence.repo,
        group.latestSha,
        group.trackedRef,
      );
      writeCount += 1;
    }
  }
} finally {
  await readline?.close();
}

if (writeCount === 0) {
  console.log(interactive ? "No workflow action pins were changed." : "Run with --write to apply the available updates.");
  process.exit(0);
}

for (const [filePath, lines] of files) {
  await writeFile(filePath, `${lines.join("\n")}`, "utf8");
}

console.log(`Updated ${writeCount} workflow action use${writeCount === 1 ? "" : "s"}.`);