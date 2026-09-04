import path from "node:path"
import tailwindcss from "@tailwindcss/vite"
import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"
import { viteSingleFile } from "vite-plugin-singlefile"

// The whole point of this build is one file a QA engineer can download and
// open from disk, so every asset -- JS, CSS and the JetBrains Mono woff2
// subsets -- is inlined. `assetsInlineLimit: Infinity` covers those, which are
// well past Vite's 4 kB default and would otherwise be emitted as siblings
// that a shared-by-email HTML file could never find.
export default defineConfig(({ command }) => ({
  // Build only. The plugin's config hook sets `base: "./"` unconditionally,
  // which is right for a file:// artifact and wrong for the dev server: in
  // dev Vite normalises "./" to "/", so it emits root-absolute asset URLs
  // like /@vite/client. Behind Caddy those miss the /journeybook route (see
  // ../Caddyfile.local), fall through to the RocketVault API on :8774, and
  // 404 -- the page loads its shell and then mounts nothing.
  plugins: [
    react(),
    tailwindcss(),
    ...(command === "build" ? [viteSingleFile()] : []),
  ],
  // Dev only, in practice. Caddy proxies /journeybook to this server without
  // stripping the prefix, so asset and HMR URLs have to carry it -- the same
  // contract ../web keeps with base "/app/". The build overrides this to
  // "./" via the plugin above, which is what the offline file needs.
  base: "/journeybook/",
  build: {
    assetsInlineLimit: Number.POSITIVE_INFINITY,
    cssCodeSplit: false,
  },
  server: {
    host: "127.0.0.1",
    port: 5174,
    strictPort: true,
    allowedHosts: ["localhost", "127.0.0.1", "numericlabs.lxd"],
    // Caddy terminates TLS on 443, so the browser must be told to open the
    // HMR socket there rather than on the dev server's own port.
    hmr: {
      protocol: "wss",
      host: "numericlabs.lxd",
      clientPort: 443,
    },
  },
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "./src"),
    },
  },
}))
