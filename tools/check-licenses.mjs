import { readFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { platform } from 'node:os';

function runPnpm(args) {
  const windows = platform() === 'win32';
  const command = windows ? 'cmd.exe' : 'pnpm';
  const commandArgs = windows ? ['/d', '/s', '/c', `pnpm ${args.join(' ')}`] : args;
  const result = spawnSync(command, commandArgs, { encoding: 'utf8' });
  if (result.error || result.status !== 0) {
    throw result.error ?? new Error('pnpm license scan failed');
  }
  return result.stdout;
}

try {
  const policy = JSON.parse(await readFile(new URL('./license-policy.json', import.meta.url), 'utf8'));
  const runtimeLicenses = JSON.parse(runPnpm(['--dir', 'web', 'licenses', 'list', '--prod', '--json']));
  const disallowed = Object.keys(runtimeLicenses).filter((license) => !policy.runtime.includes(license));
  if (disallowed.length > 0) {
    throw new Error(`disallowed runtime licenses: ${disallowed.join(', ')}`);
  }

  const allLicenses = JSON.parse(runPnpm(['--dir', 'web', 'licenses', 'list', '--json', '--long']));
  for (const [name, exception] of Object.entries(policy.buildExceptions)) {
    const packages = allLicenses[exception.license];
    const found = (Array.isArray(packages) ? packages : [packages]).some((pkg) =>
      pkg?.name === name && pkg?.versions?.includes(exception.version));
    if (!found) {
      throw new Error(`approved build exception is missing or changed: ${name}@${exception.version}`);
    }
  }
  process.stdout.write(`runtime dependency licenses approved: ${Object.keys(runtimeLicenses).join(', ')}\n`);
  process.stdout.write(`build license exceptions verified: ${Object.keys(policy.buildExceptions).join(', ')}\n`);
} catch (error) {
  const message = error instanceof Error ? error.message : 'license scan failed';
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
}
