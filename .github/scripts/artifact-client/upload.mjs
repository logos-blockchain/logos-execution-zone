import {
  appendFile,
  lstat,
  readFile,
  realpath,
  rm,
  statfs,
  writeFile,
} from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";

import { DefaultArtifactClient } from "@actions/artifact";

const GIB = 1024 ** 3;
const MIB = 1024 ** 2;

function humanSize(size) {
  if (size >= GIB) return `${(size / GIB).toFixed(2)} GiB`;
  return `${(size / MIB).toFixed(2)} MiB`;
}

export async function buildAndUploadIntegrationTargets({ core, exec }) {
  const artifactDirectory = await realpath(
    resolve(process.env.INTEGRATION_ARTIFACT_DIR ?? ""),
  );
  const manifest = resolve(process.env.INTEGRATION_ARTIFACT_MANIFEST ?? "");
  const targetsPath = resolve(process.env.INTEGRATION_TARGETS_FILE ?? "");

  if (dirname(manifest) !== artifactDirectory) {
    throw new Error(`integration manifest is outside staging: ${manifest}`);
  }
  if (dirname(targetsPath) !== artifactDirectory) {
    throw new Error(`integration target list is outside staging: ${targetsPath}`);
  }
  await writeFile(manifest, "");

  const targets = (await readFile(targetsPath, "utf8"))
    .split("\n")
    .filter(Boolean);
  if (targets.length === 0 || targets.length > 64) {
    throw new Error(`invalid integration target count: ${targets.length}`);
  }

  const artifact = new DefaultArtifactClient();
  let totalArchiveSize = 0;

  for (const target of targets) {
    if (!/^[a-z0-9_]+$/.test(target)) {
      throw new Error(`invalid integration target: ${target}`);
    }

    const artifactName = `integration-test-${target}.tar.zst`;
    const archive = join(artifactDirectory, artifactName);

    try {
      const exitCode = await exec.exec("cargo", [
        "nextest",
        "archive",
        "-p",
        "integration_tests",
        "--test",
        target,
        "-E",
        `binary(=${target})`,
        "--archive-file",
        archive,
        "--no-pager",
      ]);
      if (exitCode !== 0) {
        throw new Error(`nextest archive failed for ${target}`);
      }

      const archiveStat = await lstat(archive);
      if (!archiveStat.isFile()) {
        throw new Error(`integration artifact is not a file: ${archive}`);
      }
      if (archiveStat.size > 128 * MIB) {
        throw new Error(`${target} archive exceeds the 128 MiB limit`);
      }

      totalArchiveSize += archiveStat.size;
      if (totalArchiveSize > 4 * GIB) {
        throw new Error("integration archives exceed the 4 GiB total limit");
      }

      await appendFile(
        process.env.GITHUB_STEP_SUMMARY,
        `| \`${target}\` | ${humanSize(archiveStat.size)} |\n`,
      );

      const { artifacts } = await artifact.listArtifacts({ latest: true });
      if (artifacts.some(({ name }) => name === artifactName)) {
        await artifact.deleteArtifact(artifactName);
      }

      const { digest, id } = await artifact.uploadArtifact(
        artifactName,
        [archive],
        artifactDirectory,
        {
          retentionDays: 1,
          skipArchive: true,
        },
      );
      if (!digest || !id) {
        throw new Error(`upload returned incomplete metadata: ${artifactName}`);
      }

      await appendFile(
        manifest,
        `${JSON.stringify({
          archive: artifactName,
          artifact_id: id,
          target,
        })}\n`,
      );
      core.info(`Uploaded ${artifactName} (artifact ${id}, digest ${digest}).`);
    } finally {
      await rm(archive, { force: true });
    }

    const disk = await statfs(artifactDirectory);
    if (disk.bavail * disk.bsize < 6 * GIB) {
      throw new Error("less than 6 GiB remains while building archives");
    }
  }

  await appendFile(
    process.env.GITHUB_STEP_SUMMARY,
    `\nBuilt ${targets.length} integration targets exactly once.\n`,
  );
}
