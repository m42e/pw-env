import { copyFile, mkdir } from "node:fs/promises";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const publicDir = resolve(root, "docs", "public");
const installSource = resolve(root, "scripts", "install.sh");
const installDestination = resolve(publicDir, "install.sh");
const logoSource = resolve(root, "docs", "assets", "images", "Logo-pw-env.svg");
const logoDestinationDir = resolve(publicDir, "assets", "images");
const logoDestination = resolve(logoDestinationDir, "Logo-pw-env.svg");

await mkdir(publicDir, { recursive: true });
await mkdir(logoDestinationDir, { recursive: true });

await copyFile(installSource, installDestination);
await copyFile(logoSource, logoDestination);
