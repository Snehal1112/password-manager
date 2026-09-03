import path from "node:path"
import tailwindcss from "@tailwindcss/vite"
import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  // The app is served behind Caddy at https://numericlabs.lxd/app (see
  // ../Caddyfile.local), so every asset and HMR URL needs the /app prefix.
  base: "/app/",
  server: {
    host: "127.0.0.1",
    port: 5173,
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
})
