import { existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { platform } from 'node:os';

const windows = platform() === 'win32';
const preflightOnly = process.argv[2] === '--preflight';
if (process.argv[2] && !preflightOnly) {
  throw new Error('usage: node tools/verify.mjs [--preflight]');
}
const fixedGo = process.env.TSW_GO_BIN ?? 'E:\\TeamSeatWatchTools\\go\\1.27.1\\go\\bin\\go.exe';
const toolBin = 'E:\\TeamSeatWatchTools\\bin';
const goBin = 'E:\\TeamSeatWatchTools\\go\\1.27.1\\go\\bin';
const goPathBin = 'E:\\TeamSeatWatchTools\\gopath\\bin';
const inheritedPath = process.env.Path ?? process.env.PATH ?? '';
const verificationEnv = {
  ...process.env,
  GOPATH: 'E:\\TeamSeatWatchTools\\gopath',
  GOMODCACHE: 'E:\\TeamSeatWatchTools\\gomodcache',
  GOCACHE: 'E:\\TeamSeatWatchTools\\gocache',
  GOTMPDIR: 'E:\\TeamSeatWatchTools\\gotmp',
  Path: windows ? [toolBin, goBin, goPathBin, inheritedPath].join(';') : inheritedPath,
};
const goCommand = windows && existsSync(fixedGo) ? fixedGo : 'go';
const hasLocalTests = existsSync('tests/frontend');

if (windows && goCommand === 'go') {
  process.stderr.write(`verify: fixed Go executable not found: ${fixedGo}\n`);
  process.exit(1);
}
if (windows) {
  const preflight = spawnSync(goCommand, ['version'], { cwd: process.cwd(), env: verificationEnv, encoding: 'utf8' });
  if (preflight.error || preflight.status !== 0 || !String(preflight.stdout).includes('go1.27.1')) {
    process.stderr.write(`verify: Go preflight failed\n${preflight.stderr ?? ''}`);
    process.exit(preflight.status ?? 1);
  }
}
if (preflightOnly) {
  process.stdout.write(`verify: Go preflight passed (${goCommand})\n`);
  process.exit(0);
}
const commands = [
  ['node', ['tools/generate.mjs', '--check']],
  ['go', ['test', '-count=1', './...']],
  ['node', ['tools/run-race.mjs']],
  ['node', ['tools/verify-oci.mjs']],
  ['go', ['vet', './...']],
  ['node', ['tools/run-staticcheck.mjs']],
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
  const selectedCommand = command === 'go' ? goCommand : command;
  const executable = useWindowsShell ? 'cmd.exe' : selectedCommand;
  const commandArgs = useWindowsShell
    ? ['/d', '/s', '/c', `corepack pnpm@12.4.2 ${args.join(' ')}`]
    : args;
  const result = spawnSync(executable, commandArgs, { cwd: process.cwd(), env: verificationEnv, stdio: 'inherit' });
  if (result.error || result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}
