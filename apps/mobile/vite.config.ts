import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath } from "node:url";

const mobileRoot = fileURLToPath(new URL(".", import.meta.url));
const appsRoot = fileURLToPath(new URL("..", import.meta.url));

export default defineConfig({
  root: mobileRoot,
  plugins: [react()],
  clearScreen: false,
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
  server: {
    port: 1421,
    strictPort: true,
    fs: {
      allow: [appsRoot],
    },
    watch: { ignored: ["**/src-tauri/target/**"] },
  },
});
