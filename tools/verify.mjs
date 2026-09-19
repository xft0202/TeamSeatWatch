import { existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { platform } from 'node:os';

const windows = platform() === 'win32';
const hasLocalTests = existsSync('tests/frontend');
const commands = [
  ['node', ['tools/generate.mjs', '--check']],
  ['go', ['test', '-count=1', './...']],
  ['node', ['tools/run-race.mjs']],
  ['node', ['tools/verify-oci.mjs']],
  ['go', ['vet', './...']],
  ['staticcheck', ['./...']],
  ['govulncheck', ['./...']],
  ['node', ['tools/check-licenses.mjs']],
  ['pnpm', ['--dir', 'web', 'peers', 'check']],
  ['pnpm', ['--dir', 'web', 'lint']],
  ['pnpm', ['--dir', 'web', 'typecheck']],
  ['pnpm', ['--dir', 'web', 'build']],
  ...(hasLocalTests ? [
    ['pnpm', ['--dir', 'web', 'test']],
    ['pnpm', ['--dir', 'web', 'exec', 'playwright', 'test', '--config', 'playwright.config.ts']],
  ] : []),
];

for (const [command, args] of commands) {
  process.stdout.write(`verify: ${command} ${args.join(' ')}\n`);
  const useWindowsShell = windows && command === 'pnpm';
  const executable = useWindowsShell ? 'cmd.exe' : command;
  const commandArgs = useWindowsShell
    ? ['/d', '/s', '/c', `pnpm ${args.join(' ')}`]
    : args;
  const result = spawnSync(executable, commandArgs, { stdio: 'inherit' });
  if (result.error || result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}
