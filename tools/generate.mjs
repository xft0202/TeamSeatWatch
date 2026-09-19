import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join, relative, resolve } from 'node:path';

const root = fileURLToPath(new URL('../', import.meta.url));
const goContracts = [
  { output: 'internal/generated/ownerapi/openapi.gen.go', packageName: 'ownerapi', source: 'api/openapi/owner.yaml' },
  { output: 'internal/generated/publicapi/openapi.gen.go', packageName: 'publicapi', source: 'api/openapi/public.yaml' },
  { output: 'internal/generated/internalapi/openapi.gen.go', packageName: 'internalapi', source: 'api/openapi/internal.yaml' },
];
const typescriptContracts = [
  { output: 'web/src/generated/owner.ts', source: 'api/openapi/owner.yaml' },
  { output: 'web/src/generated/public.ts', source: 'api/openapi/public.yaml' },
  { output: 'web/src/generated/internal.ts', source: 'api/openapi/internal.yaml' },
];
const sqlcOutputs = [
  'internal/generated/store/db.go',
  'internal/generated/store/models.go',
  'internal/generated/store/readiness.sql.go',
];
const outputs = [...goContracts, ...typescriptContracts].map(({ output }) => output).concat(sqlcOutputs);
const mode = process.argv[2];
if (mode !== '--check' && mode !== '--write') {
  throw new Error('usage: node tools/generate.mjs --write|--check');
}

function run(command, args) {
  const useWindowsShell = process.platform === 'win32' && command === 'pnpm';
  const executable = useWindowsShell ? 'cmd.exe' : command;
  const commandArgs = useWindowsShell ? ['/d', '/s', '/c', `pnpm ${args.join(' ')}`] : args;
  const result = spawnSync(executable, commandArgs, { cwd: root, stdio: 'inherit' });
  if (result.error || result.status !== 0) {
    throw new Error(`${command} generation failed`);
  }
}

const temporaryBase = process.env.TSW_GENERATION_TMP ?? join(dirname(root), '.teamseatwatch-generation');
await mkdir(temporaryBase, { recursive: true });
// Keep generated output on the repository's volume. sqlc resolves schema paths
// relative to its temporary config and cannot safely cross Windows drive roots.
const temporaryRoot = await mkdtemp(join(temporaryBase, 'teamseatwatch-generation-'));
const destination = (relative) => mode === '--check' ? join(temporaryRoot, relative) : join(root, relative);

try {
  for (const item of goContracts) {
    const output = destination(item.output);
    await mkdir(dirname(output), { recursive: true });
    run('oapi-codegen', [
      '-generate', 'types,std-http', '-package', item.packageName,
      '-o', output, resolve(root, item.source),
    ]);
  }
  for (const item of typescriptContracts) {
    const output = destination(item.output);
    await mkdir(dirname(output), { recursive: true });
    run('pnpm', [
      '--dir', 'web/tools/openapi', 'exec', 'openapi-typescript',
      resolve(root, item.source), '-o', output,
    ]);
  }

  const sqlcOutput = destination('internal/generated/store');
  await mkdir(sqlcOutput, { recursive: true });
  const sqlcConfig = join(temporaryRoot, 'sqlc.json');
  await writeFile(sqlcConfig, JSON.stringify({
    version: '2',
    sql: [{
      engine: 'postgresql',
      schema: relative(temporaryRoot, resolve(root, 'internal/store/schema')),
      queries: relative(temporaryRoot, resolve(root, 'internal/store/query')),
      gen: { go: {
        package: 'store',
        out: relative(temporaryRoot, sqlcOutput),
        sql_package: 'pgx/v5',
        emit_sql_as_comment: true,
      } },
    }],
  }));
  run('sqlc', ['generate', '-f', sqlcConfig]);

  if (mode === '--check') {
    for (const output of outputs) {
      const expected = await readFile(join(root, output));
      const actual = await readFile(destination(output));
      if (!expected.equals(actual)) {
        throw new Error(`generated source is stale: ${output}`);
      }
    }
  }
} finally {
  await rm(temporaryRoot, { recursive: true, force: true });
}
