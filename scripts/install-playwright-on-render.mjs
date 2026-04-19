import { spawnSync } from "node:child_process";

if (!process.env.RENDER && process.env.PLAYWRIGHT_INSTALL_BROWSER !== "true") {
  process.exit(0);
}

const result = spawnSync("npx", ["playwright", "install", "chromium"], {
  stdio: "inherit",
  shell: process.platform === "win32"
});

process.exit(result.status ?? 1);
