import { existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';

const image = 'golang@sha256:648f440f42a0958804efb24df176f806f9d353b41f1c0627f666428e40310f6b';
const root = resolve(process.cwd());
const args = [
  'run', '--rm',
  '-v', '/var/run/docker.sock:/var/run/docker.sock',
  '--add-host', 'host.docker.internal:host-gateway',
  '-e', 'TESTCONTAINERS_HOST_OVERRIDE=host.docker.internal',
  '-e', 'TESTCONTAINERS_RYUK_DISABLED=true',
  '-v', `${root}:/src`,
  '-w', '/src',
];
if (process.env.TSW_GO_MODULE_CACHE) {
  args.push('-v', `${resolve(process.env.TSW_GO_MODULE_CACHE)}:/go/pkg/mod:ro`);
}
if (process.env.TSW_GO_BUILD_CACHE) {
  args.push('-v', `${resolve(process.env.TSW_GO_BUILD_CACHE)}:/root/.cache/go-build`);
}
const racePackages = ['./cmd/...', './internal/...'];
if (existsSync('tests/app')) racePackages.push('./tests/app');
if (existsSync('tests/runtime')) racePackages.push('./tests/runtime');
args.push(image, 'go', 'test', '-race', ...racePackages);
const result = spawnSync('docker', args, { stdio: 'inherit' });
if (result.error || result.status !== 0) {
  process.exit(result.status ?? 1);
}
