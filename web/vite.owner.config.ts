import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';
import type { Plugin } from 'vite';
import react from '@vitejs/plugin-react';

const ownerEntry = fileURLToPath(new URL('./owner/index.html', import.meta.url));
const ownerApiProxy = process.env.TSW_OWNER_API_PROXY;

function flattenOwnerEntry(): Plugin {
  return {
    name: 'teamseatwatch-owner-entry-output',
    apply: 'build',
    enforce: 'post',
    generateBundle(_options, bundle) {
      const html = bundle['owner/index.html'];
      if (html?.type === 'asset') {
        // The source directory names the role; the deployed static root already
        // provides /owner, so its HTML entry must be directly under that root.
        delete bundle['owner/index.html'];
        this.emitFile({ type: 'asset', fileName: 'index.html', source: html.source });
      }
    },
  };
}

function ownerSpaFallback(): Plugin {
  return {
    name: 'teamseatwatch-owner-spa-fallback',
    apply: 'serve',
    configureServer(server) {
      // Vite's default fallback only resolves root-level HTML. Rewrite Owner
      // history URLs to the isolated entry without changing script/module URLs.
      server.middlewares.use((request, _response, next) => {
        if (request.url?.startsWith('/owner/') && request.headers.accept?.includes('text/html')) {
          request.url = '/owner/index.html';
        }
        next();
      });
    },
  };
}

export default defineConfig(({ command }) => ({
  root: '.',
  base: command === 'serve' ? '/' : '/owner/',
  plugins: [ownerSpaFallback(), react(), flattenOwnerEntry()],
  server: {
    // A proxy is opt-in for local end-to-end fixtures; production never receives this setting.
    ...(ownerApiProxy
      ? { proxy: { '/api/owner': { target: ownerApiProxy, changeOrigin: false } } }
      : {}),
  },
  build: {
    outDir: 'dist/owner',
    emptyOutDir: true,
    rollupOptions: { input: { index: ownerEntry } },
  },
}));
