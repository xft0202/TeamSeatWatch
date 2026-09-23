import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';
import type { Plugin } from 'vite';
import react from '@vitejs/plugin-react';

const publicEntry = fileURLToPath(new URL('./public/index.html', import.meta.url));

function flattenPublicEntry(): Plugin {
  return {
    name: 'teamseatwatch-public-entry-output',
    apply: 'build',
    enforce: 'post',
    generateBundle(_options, bundle) {
      const html = bundle['public/index.html'];
      if (html?.type === 'asset') {
        delete bundle['public/index.html'];
        this.emitFile({ type: 'asset', fileName: 'index.html', source: html.source });
      }
    },
  };
}

function publicSpaFallback(): Plugin {
  return {
    name: 'teamseatwatch-public-spa-fallback',
    apply: 'serve',
    configureServer(server) {
      server.middlewares.use((request, _response, next) => {
        if (request.url?.startsWith('/redeem/') && request.headers.accept?.includes('text/html')) {
          request.url = '/public/index.html';
        }
        next();
      });
    },
  };
}

export default defineConfig(({ command }) => ({
  root: '.',
  base: command === 'serve' ? '/' : '/redeem/',
  plugins: [publicSpaFallback(), react(), flattenPublicEntry()],
  build: {
    outDir: 'dist/public',
    emptyOutDir: true,
    rollupOptions: { input: { public: publicEntry } },
  },
}));
