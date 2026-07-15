import { appendFile, lstat, realpath } from "node:fs/promises";
import { basename, dirname, resolve } from "node:path";

import { DefaultArtifactClient } from "@actions/artifact";

const [input, ...extra] = process.argv.slice(2);

if (!input || extra.length > 0) {
  throw new Error("usage: node upload.mjs <integration-test archive>");
}

const archive = await realpath(resolve(input));
const artifactDirectory = await realpath(
  resolve(process.env.INTEGRATION_ARTIFACT_DIR ?? ""),
);
if (dirname(archive) !== artifactDirectory) {
  throw new Error(`integration artifact is outside staging: ${archive}`);
}

const artifactName = basename(archive);
const artifactMatch = /^integration-test-([a-z0-9_]+)\.tar\.zst$/.exec(
  artifactName,
);
if (!artifactMatch) {
  throw new Error(`invalid integration artifact name: ${artifactName}`);
}

const archiveStat = await lstat(archive);
if (!archiveStat.isFile()) {
  throw new Error(`integration artifact is not a regular file: ${archive}`);
}

const artifact = new DefaultArtifactClient();
const { artifacts } = await artifact.listArtifacts({ latest: true });
if (artifacts.some(({ name }) => name === artifactName)) {
  await artifact.deleteArtifact(artifactName);
}

const { digest, id } = await artifact.uploadArtifact(
  artifactName,
  [archive],
  dirname(archive),
  {
    retentionDays: 1,
    skipArchive: true,
  },
);
if (!digest || !id) {
  throw new Error(`artifact upload returned incomplete metadata: ${artifactName}`);
}

const manifest = resolve(process.env.INTEGRATION_ARTIFACT_MANIFEST ?? "");
if (dirname(manifest) !== artifactDirectory) {
  throw new Error(`integration manifest is outside staging: ${manifest}`);
}
await appendFile(
  manifest,
  `${JSON.stringify({
    archive: artifactName,
    artifact_id: id,
    target: artifactMatch[1],
  })}\n`,
);

console.log(`Uploaded ${artifactName} (artifact ${id}, digest ${digest}).`);
