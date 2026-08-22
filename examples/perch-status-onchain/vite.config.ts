import { defineConfig } from 'vite';
import { nodePolyfills } from 'vite-plugin-node-polyfills';

// base defaults to '/' for local dev + apex previews; the GitHub Pages build
// passes --base explicitly (see build:pages / build:preview).
export default defineConfig({
  plugins: [
    // @stellar/stellar-sdk (and @nidohq/*) expect Buffer + process globals.
    nodePolyfills({ include: ['buffer'], globals: { Buffer: true, process: true } }),
  ],
  build: { target: 'esnext' },
});
