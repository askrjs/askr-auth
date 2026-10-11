import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  realpathSync,
  statfsSync,
  writeFileSync,
} from "node:fs";
import { release, version } from "node:os";
import { dirname, join, resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";

export const FLOOR = 8 * 1024 ** 3;
export const HELPER = "release/auth65-lock-prune/measure.mjs";
export const WORKFLOW = ".github/workflows/auth65-lock-prune.yml";
export const REPOSITORY = "askrjs/askr-auth";
export const PUBLIC_GIT = "https://github.com/askrjs/askr-auth.git";
export const REGISTRY = "https://registry.npmjs.org/";
export const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
export const gitBlob = (bytes) =>
  createHash("sha1")
    .update(Buffer.from(`blob ${bytes.length}\0`))
    .update(bytes)
    .digest("hex");
export const json = (file, value) =>
  writeFileSync(file, JSON.stringify(value, null, 2) + "\n", { mode: 0o600 });
const sha = (value, length, label) =>
  assert.ok(
    typeof value === "string" &&
      new RegExp(`^[0-9a-f]{${length}}$`, "u").test(value) &&
      !/^0+$/u.test(value),
    `${label} requires an actual immutable lowercase hash.`,
  );

export function validateBinding(binding) {
  assert.ok(binding && typeof binding === "object" && !Array.isArray(binding));
  const fields = [
    "schemaVersion",
    "repository",
    "sourceCommitX",
    "sourceTree",
    "packageSha256",
    "oldLockSha256",
    "measurementCommitY",
    "measurementTree",
    "helperSha256",
    "carryForwardReviewSha256",
    "oldTestDeletionReviewSha256",
    "carryForwardGreen",
    "oldTestDeletionApproved",
  ];
  assert.deepEqual(
    Object.keys(binding).sort(),
    fields.sort(),
    "Only the reviewed literal binding fields are allowed.",
  );
  assert.equal(binding.schemaVersion, 1);
  assert.equal(binding.repository, REPOSITORY);
  for (const key of ["sourceCommitX", "sourceTree", "measurementCommitY", "measurementTree"])
    sha(binding[key], 40, key);
  for (const key of [
    "packageSha256",
    "oldLockSha256",
    "helperSha256",
    "carryForwardReviewSha256",
    "oldTestDeletionReviewSha256",
  ])
    sha(binding[key], 64, key);
  assert.notEqual(binding.sourceCommitX, binding.measurementCommitY);
  assert.equal(
    binding.carryForwardGreen,
    true,
    "Actual reviewed carry-forward GREEN must precede removal source X.",
  );
  assert.equal(
    binding.oldTestDeletionApproved,
    true,
    "Old test deletion requires prior explicit reviewed approval.",
  );
  return binding;
}

export function requireCapacity(available) {
  assert.ok(
    Number.isSafeInteger(available) && available >= FLOOR,
    "At least 8 GiB available is mandatory.",
  );
  return available;
}

export function validateConfig(config, home, cache) {
  assert.equal(config.registry, REGISTRY);
  for (const key of ["ignore-scripts", "force", "legacy-peer-deps", "offline", "dry-run", "global"])
    assert.equal(config[key], false, `${key} must remain false.`);
  assert.equal(config["package-lock"], true);
  assert.equal(config["strict-ssl"], true);
  assert.deepEqual(config.omit, []);
  assert.deepEqual(config.include, []);
  assert.equal(config.userconfig, join(home, ".npmrc"));
  assert.equal(config.globalconfig, join(home, "global-npmrc"));
  assert.equal(config.cache, cache);
  for (const [key, value] of Object.entries(config)) {
    if (
      /(?:^|:)_(?:auth|authToken|password)$|(?:^|:)username$|password|(?:^|-)proxy$|cafile|certfile|keyfile/iu.test(
        key,
      )
    ) {
      assert.ok(
        value === null || value === undefined || value === "" || value === false,
        `Credential/network override config is forbidden: ${key}`,
      );
    }
  }
  return config;
}

export function assertOnlyLockChanged(before, after) {
  assert.deepEqual(
    Object.keys(after).sort(),
    Object.keys(before).sort(),
    "No created/deleted source paths are allowed.",
  );
  for (const path of Object.keys(before)) {
    if (path !== "package-lock.json")
      assert.deepEqual(after[path], before[path], `Unexpected source change: ${path}`);
  }
  assert.equal(after["package-lock.json"].kind, "file");
  assert.equal(after["package-lock.json"].mode, before["package-lock.json"].mode);
  assert.equal(after["package-lock.json"].permissions, before["package-lock.json"].permissions);
}

export function lockDelta(before, after) {
  assert.ok(
    before.packages &&
      after.packages &&
      typeof before.packages === "object" &&
      typeof after.packages === "object",
  );
  const paths = [
    ...new Set([...Object.keys(before.packages), ...Object.keys(after.packages)]),
  ].sort();
  return paths
    .filter(
      (path) => JSON.stringify(before.packages[path]) !== JSON.stringify(after.packages[path]),
    )
    .map((path) => ({
      path,
      before: before.packages[path] ?? null,
      after: after.packages[path] ?? null,
    }));
}

export function assertRootLock(manifest, lock) {
  assert.equal(lock.name, manifest.name);
  assert.equal(lock.version, manifest.version);
  assert.equal(lock.lockfileVersion, 3);
  for (const key of [
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "peerDependenciesMeta",
    "optionalDependencies",
  ])
    assert.deepEqual(
      lock.packages[""][key] ?? {},
      manifest[key] ?? {},
      `Generated root lock ${key} must match the unchanged manifest.`,
    );
}

function inventory(root) {
  const files = {};
  function walk(directory, prefix) {
    for (const name of readdirSync(directory).sort()) {
      if (!prefix && name === ".git") continue;
      assert.notEqual(
        name,
        "node_modules",
        `Physical node_modules is forbidden: ${join(prefix, name)}`,
      );
      const relative = prefix ? `${prefix}/${name}` : name;
      const path = join(directory, name);
      const stat = lstatSync(path);
      if (stat.isDirectory()) walk(path, relative);
      else if (stat.isSymbolicLink()) {
        const bytes = Buffer.from(readlinkSync(path));
        files[relative] = {
          kind: "symlink",
          mode: "120000",
          permissions: stat.mode & 0o7777,
          target: bytes.toString(),
          sha256: sha256(bytes),
          gitBlob: gitBlob(bytes),
          size: bytes.length,
        };
      } else {
        assert.ok(stat.isFile(), `Unexpected source object: ${relative}`);
        const bytes = readFileSync(path);
        files[relative] = {
          kind: "file",
          mode: stat.mode & 0o111 ? "100755" : "100644",
          permissions: stat.mode & 0o7777,
          sha256: sha256(bytes),
          gitBlob: gitBlob(bytes),
          size: bytes.length,
        };
      }
    }
  }
  walk(root, "");
  return files;
}

export async function measure({ binding, root, source, code, evidence, inherited }) {
  mkdirSync(evidence, { recursive: true, mode: 0o700 });
  const receipt = {
    schemaVersion: 1,
    measurementOnly: true,
    adoptionApproved: false,
    status: "STARTED",
    startedAt: new Date().toISOString(),
    binding,
    commands: [],
    freeBytes: [],
    platform: {
      platform: process.platform,
      arch: process.arch,
      osRelease: release(),
      osVersion: version(),
      node: process.version,
      executable: process.execPath,
    },
    github: inherited,
  };
  const home = join(root, "private-home");
  const cache = join(root, "npm-cache");
  mkdirSync(home, { recursive: true, mode: 0o700 });
  mkdirSync(cache, { recursive: true, mode: 0o700 });
  const npmrc = "registry=https://registry.npmjs.org/\nignore-scripts=false\n";
  writeFileSync(join(home, ".npmrc"), npmrc, { mode: 0o600 });
  writeFileSync(join(home, "global-npmrc"), "", { mode: 0o600 });
  writeFileSync(join(home, "gitconfig"), "", { mode: 0o600 });
  const env = {
    PATH: process.env.PATH,
    HOME: home,
    TMPDIR: join(root, "tmp"),
    CI: "true",
    NPM_CONFIG_USERCONFIG: join(home, ".npmrc"),
    NPM_CONFIG_GLOBALCONFIG: join(home, "global-npmrc"),
    NPM_CONFIG_CACHE: cache,
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: join(home, "gitconfig"),
    GIT_TERMINAL_PROMPT: "0",
    NODE_DISABLE_COMPILE_CACHE: "1",
  };
  mkdirSync(env.TMPDIR, { mode: 0o700 });
  json(join(evidence, "subprocess-environment.json"), env);
  function capacity(phase) {
    const stat = statfsSync(root);
    const row = {
      phase,
      completedAt: new Date().toISOString(),
      availableBytes: stat.bavail * stat.bsize,
      floorBytes: FLOOR,
    };
    receipt.freeBytes.push(row);
    requireCapacity(row.availableBytes);
  }
  function command(label, executable, args, cwd = source, allowFailure = false) {
    const started = performance.now();
    const result = spawnSync(executable, args, {
      cwd,
      env,
      encoding: "utf8",
      timeout: 15 * 60 * 1000,
      maxBuffer: 64 * 1024 * 1024,
    });
    writeFileSync(join(evidence, `${label}.stdout.log`), result.stdout ?? "", { mode: 0o600 });
    writeFileSync(join(evidence, `${label}.stderr.log`), result.stderr ?? "", { mode: 0o600 });
    const row = {
      label,
      executable,
      args,
      cwd,
      status: result.status,
      signal: result.signal,
      elapsedMs: performance.now() - started,
      error: result.error
        ? { name: result.error.name, message: result.error.message, code: result.error.code }
        : null,
    };
    receipt.commands.push(row);
    json(join(evidence, "measurement.json"), receipt);
    if (!allowFailure)
      assert.ok(
        result.status === 0 && !result.error && result.signal === null,
        `Command failed: ${label}`,
      );
    return result;
  }
  const git = (args, cwd = code) =>
    command(`git-${receipt.commands.length}`, "git", args, cwd).stdout.trim();
  const bodyParents = (commit) =>
    git(["cat-file", "-p", commit])
      .split("\n\n")[0]
      .split("\n")
      .filter((line) => line.startsWith("parent "))
      .map((line) => line.slice(7));
  let before;
  try {
    validateBinding(binding);
    assert.equal(process.version, "v24.21.0");
    assert.equal(process.platform, "linux");
    capacity("before-identities");
    assert.equal(inherited.eventName, "pull_request");
    assert.equal(inherited.repository, REPOSITORY);
    assert.equal(inherited.headRepository, REPOSITORY);
    sha(inherited.requestedHeadZ, 40, "Actual request head Z");
    sha(inherited.workflowCommit, 40, "Actual workflow code commit");
    assert.match(inherited.runId, /^[1-9][0-9]*$/u);
    assert.match(inherited.runAttempt, /^[1-9][0-9]*$/u);
    assert.equal(git(["rev-parse", "HEAD"]), binding.measurementCommitY);
    assert.equal(
      git(["rev-parse", `${binding.measurementCommitY}^{tree}`]),
      binding.measurementTree,
    );
    assert.deepEqual(
      bodyParents(binding.measurementCommitY),
      [binding.sourceCommitX],
      "Y must add only the reviewed measurement helper after X.",
    );
    assert.equal(
      git(["diff", "--name-status", binding.sourceCommitX, binding.measurementCommitY]),
      `A\t${HELPER}`,
    );
    assert.deepEqual(
      bodyParents(inherited.requestedHeadZ),
      [binding.measurementCommitY],
      "Z must add only the literal workflow after Y.",
    );
    assert.equal(
      git(["diff", "--name-status", binding.measurementCommitY, inherited.requestedHeadZ]),
      `A\t${WORKFLOW}`,
    );
    const workflowRequested = command(
      "requested-workflow",
      "git",
      ["show", `${inherited.requestedHeadZ}:${WORKFLOW}`],
      code,
    ).stdout;
    const workflowExecuting = command(
      "executing-workflow",
      "git",
      ["show", `${inherited.workflowCommit}:${WORKFLOW}`],
      code,
    ).stdout;
    assert.equal(
      workflowExecuting,
      workflowRequested,
      "Synthetic PR workflow code must equal reviewed Z bytes.",
    );
    receipt.workflowSha256 = sha256(Buffer.from(workflowRequested));
    assert.equal(sha256(readFileSync(join(code, HELPER))), binding.helperSha256);
    assert.equal(git(["rev-parse", "HEAD"], source), binding.sourceCommitX);
    assert.equal(git(["rev-parse", "HEAD^{tree}"], source), binding.sourceTree);
    assert.equal(git(["status", "--porcelain=v1", "--untracked-files=all"], source), "");
    assert.equal(git(["remote", "get-url", "origin"]), PUBLIC_GIT);
    const packageBytes = readFileSync(join(source, "package.json"));
    const lockBytes = readFileSync(join(source, "package-lock.json"));
    assert.equal(sha256(packageBytes), binding.packageSha256);
    assert.equal(sha256(lockBytes), binding.oldLockSha256);
    assert.ok(!existsSync(join(source, ".npmrc")), "Source X must not supply a project npmrc.");
    before = inventory(source);
    json(join(evidence, "source-before.json"), before);
    copyFileSync(join(source, "package.json"), join(evidence, "package.before.json"));
    copyFileSync(join(source, "package-lock.json"), join(evidence, "package-lock.before.json"));
    const manifest = JSON.parse(packageBytes);
    assert.equal(manifest.name, "@askrjs/auth");
    for (const path of [
      "tests/browser-session.test.ts",
      "tests/auth0-session.test.ts",
      "tests/browser/oidc.spec.js",
      "tests/browser/auth0.spec.js",
    ])
      assert.ok(
        !existsSync(join(source, path)),
        "X must follow approved old-test deletion: " + path,
      );
    assert.ok(
      existsSync(join(source, "tests/browser/oidc-primitives.spec.js")),
      "Retained primitive controls must exist in X.",
    );
    assert.ok(
      !Object.hasOwn(manifest.exports, "./browser") && !Object.hasOwn(manifest.exports, "./auth0"),
    );
    assert.ok(
      Object.hasOwn(manifest.exports, "./oidc") &&
        Object.hasOwn(manifest.exports, "./providers/auth0"),
    );
    for (const field of [
      "dependencies",
      "devDependencies",
      "peerDependencies",
      "optionalDependencies",
      "peerDependenciesMeta",
    ])
      assert.ok(!Object.hasOwn(manifest[field] ?? {}, "@auth0/auth0-spa-js"));
    receipt.package = {
      name: manifest.name,
      version: manifest.version,
      sha256: sha256(packageBytes),
    };
    const npm = realpathSync(join(dirname(process.execPath), "npm"));
    const npmExpected = realpathSync(
      join(dirname(process.execPath), "../lib/node_modules/npm/bin/npm-cli.js"),
    );
    assert.equal(npm, npmExpected, "Use only setup-node bundled npm; no bootstrap/replacement.");
    const npmManifest = JSON.parse(readFileSync(join(dirname(npm), "../package.json"), "utf8"));
    receipt.npm = {
      executable: npm,
      packageVersion: npmManifest.version,
      version: command("npm-version", process.execPath, [npm, "--version"]).stdout.trim(),
    };
    assert.equal(receipt.npm.version, receipt.npm.packageVersion);
    assert.match(receipt.npm.version, /^\d+\.\d+\.\d+$/u);
    const configRaw = command("npm-config-before", process.execPath, [
      npm,
      "config",
      "list",
      "--json",
    ]).stdout;
    receipt.config = validateConfig(JSON.parse(configRaw), home, cache);
    receipt.ignoreScripts = command("npm-ignore-scripts", process.execPath, [
      npm,
      "config",
      "get",
      "ignore-scripts",
    ]).stdout.trim();
    assert.equal(receipt.ignoreScripts, "false");
    copyFileSync(join(home, ".npmrc"), join(evidence, "private-user-npmrc.txt"));
    copyFileSync(join(home, "global-npmrc"), join(evidence, "private-global-npmrc.txt"));
    capacity("immediately-before-npm");
    const installed = command(
      "npm-install-package-lock-only",
      process.execPath,
      [npm, "install", "--package-lock-only"],
      source,
      true,
    );
    receipt.npmInstall = {
      status: installed.status,
      signal: installed.signal,
      spawnError: installed.error
        ? { code: installed.error.code, message: installed.error.message }
        : null,
    };
    assert.ok(
      installed.status === 0 && installed.signal === null && !installed.error,
      "Ordinary npm install --package-lock-only must succeed.",
    );
    capacity("immediately-after-npm");
    const after = inventory(source);
    json(join(evidence, "source-after.json"), after);
    assertOnlyLockChanged(before, after);
    assert.equal(readFileSync(join(home, ".npmrc"), "utf8"), npmrc);
    assert.equal(readFileSync(join(home, "global-npmrc"), "utf8"), "");
    const configAfter = JSON.parse(
      command("npm-config-after", process.execPath, [npm, "config", "list", "--json"]).stdout,
    );
    validateConfig(configAfter, home, cache);
    assert.deepEqual(configAfter, receipt.config);
    const lockBefore = JSON.parse(lockBytes);
    const lockAfter = JSON.parse(readFileSync(join(source, "package-lock.json"), "utf8"));
    assertRootLock(manifest, lockAfter);
    json(join(evidence, "lock-record-delta.json"), lockDelta(lockBefore, lockAfter));
    json(join(evidence, "lock-records.before.json"), lockBefore.packages);
    json(join(evidence, "lock-records.after.json"), lockAfter.packages);
    receipt.afterLockSha256 = sha256(readFileSync(join(source, "package-lock.json")));
    receipt.physicalNodeModules = false;
    receipt.sourceUnchangedExceptRootLock = true;
    receipt.sdkRecordsAfter = Object.keys(lockAfter.packages).filter(
      (path) =>
        path === "node_modules/@auth0/auth0-spa-js" ||
        path.endsWith("/node_modules/@auth0/auth0-spa-js"),
    );
    command("lock-binary-diff", "git", ["diff", "--binary", "--", "package-lock.json"]);
    command("source-status-after", "git", ["status", "--porcelain=v1", "--untracked-files=all"]);
    receipt.status = "MEASUREMENT_PASS_LOCK_NOT_ADMITTED";
  } catch (error) {
    receipt.status = "MEASUREMENT_FAILED_LOCK_NOT_ADMITTED";
    receipt.error = { name: error.name, message: error.message, stack: error.stack };
    process.exitCode = 1;
  } finally {
    for (const name of ["package.json", "package-lock.json"])
      if (existsSync(join(source, name)))
        copyFileSync(
          join(source, name),
          join(
            evidence,
            name === "package.json" ? "package.after.json" : "package-lock.after.json",
          ),
        );
    try {
      const after = inventory(source);
      json(join(evidence, "source-final.json"), after);
      if (before) assertOnlyLockChanged(before, after);
      assert.equal(git(["rev-parse", "HEAD"], source), binding.sourceCommitX);
      assert.equal(git(["rev-parse", "HEAD^{tree}"], source), binding.sourceTree);
      assert.equal(git(["rev-parse", "HEAD"]), binding.measurementCommitY);
      assert.equal(sha256(readFileSync(join(code, HELPER))), binding.helperSha256);
      receipt.finalPhysicalNodeModules = false;
    } catch (error) {
      receipt.status = "MEASUREMENT_FAILED_LOCK_NOT_ADMITTED";
      receipt.finalSourceGuardError = { name: error.name, message: error.message };
      process.exitCode = 1;
    }
    try {
      capacity("final-after-evidence");
    } catch (error) {
      receipt.status = "MEASUREMENT_FAILED_LOCK_NOT_ADMITTED";
      receipt.finalCapacityError = error.message;
      process.exitCode = 1;
    }
    const logs = join(cache, "_logs");
    if (existsSync(logs)) {
      const out = join(evidence, "npm-debug-logs");
      mkdirSync(out, { mode: 0o700 });
      for (const file of readdirSync(logs).sort()) {
        assert.ok(lstatSync(join(logs, file)).isFile());
        copyFileSync(join(logs, file), join(out, file));
      }
    }
    receipt.completedAt = new Date().toISOString();
    json(join(evidence, "measurement.json"), receipt);
  }
  return receipt;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const root = process.env.LOCK_PRUNE_ROOT;
  assert.ok(root && root.startsWith(process.env.RUNNER_TEMP + sep));
  await measure({
    binding: JSON.parse(process.env.LOCK_BINDING_JSON),
    root,
    source: join(root, "source"),
    code: join(root, "code"),
    evidence: join(root, "evidence"),
    inherited: JSON.parse(process.env.LOCK_GITHUB_JSON),
  });
}
