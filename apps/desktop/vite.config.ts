import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath } from "node:url";

const desktopRoot = fileURLToPath(new URL(".", import.meta.url));

export default defineConfig({
  root: desktopRoot,
  plugins: [react()],
  clearScreen: false,
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
  server: {
    port: 1420,
    strictPort: true,
    watch: { ignored: ["**/src-tauri/target/**"] },
  },
});
