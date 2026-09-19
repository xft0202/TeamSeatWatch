import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  root: 'owner',
  base: '/owner/',
  plugins: [react()],
  build: { outDir: '../dist/owner', emptyOutDir: true },
});
