import { spawnSync } from 'node:child_process';

const generatedOwnerPackage = 'github.com/teamseatwatch/teamseatwatch/internal/generated/ownerapi';

function run(command, args, capture = false) {
  const result = spawnSync(command, args, {
    encoding: capture ? 'utf8' : undefined,
    stdio: capture ? ['ignore', 'pipe', 'inherit'] : 'inherit',
  });
  if (result.error || result.status !== 0) {
    process.exit(result.status ?? 1);
  }
  return result.stdout ?? '';
}

const packages = run('go', ['list', './...'], true)
  .split(/\r?\n/u)
  .filter(Boolean);
const handwrittenPackages = packages.filter((name) => name !== generatedOwnerPackage);

if (handwrittenPackages.length > 0) {
  run('staticcheck', handwrittenPackages);
}

if (packages.includes(generatedOwnerPackage)) {
  // oapi-codegen v2.8.0 emits capitalized required-parameter errors. Keep the
  // exception on that generated package so ST1005 still protects handwritten code.
  run('staticcheck', ['-checks=all,-ST1005', generatedOwnerPackage]);
}
