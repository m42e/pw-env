import { copyFile, mkdir } from "node:fs/promises";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const source = resolve(root, "scripts", "install.sh");
const destinationDir = resolve(root, "docs", "public");
const destination = resolve(destinationDir, "install.sh");

await mkdir(destinationDir, { recursive: true });
await copyFile(source, destination);
