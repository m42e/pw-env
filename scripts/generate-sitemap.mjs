import { readdir, stat, writeFile } from "node:fs/promises";
import { join, relative, resolve, sep } from "node:path";

const root = resolve(import.meta.dirname, "..");
const siteDir = resolve(root, "site");
const siteUrl = new URL(process.env.SITE_URL ?? "https://m42e.de/pw-env/");
const base = `/${(process.env.SITE_BASE ?? "/").replace(/^\//, "").replace(/\/$/, "")}`.replace(/\/+/g, "/");
const normalizedBase = base === "/" ? "/" : `${base}/`;

if (normalizedBase !== "/" && !siteUrl.pathname.endsWith(normalizedBase)) {
  siteUrl.pathname = normalizedBase;
}

function buildUrl(pathname) {
  return new URL(pathname.replace(/^\//, ""), siteUrl).toString();
}

async function collectHtmlFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];

  for (const entry of entries) {
    const entryPath = join(directory, entry.name);

    if (entry.isDirectory()) {
      files.push(...(await collectHtmlFiles(entryPath)));
      continue;
    }

    if (entry.isFile() && entry.name.endsWith(".html") && entry.name !== "404.html") {
      files.push(entryPath);
    }
  }

  return files;
}

function filePathToUrl(filePath) {
  const relativePath = relative(siteDir, filePath).split(sep).join("/");

  if (relativePath === "index.html") {
    return buildUrl("/");
  }

  if (relativePath.endsWith("/index.html")) {
    const pagePath = relativePath.slice(0, -"/index.html".length);
    return buildUrl(`${pagePath}/`);
  }

  return buildUrl(relativePath.replace(/\.html$/, ""));
}

const htmlFiles = await collectHtmlFiles(siteDir);

if (htmlFiles.length === 0) {
  throw new Error("No HTML files found in site output; sitemap was not generated.");
}

const urlEntries = await Promise.all(
  htmlFiles.map(async (filePath) => {
    const { mtime } = await stat(filePath);
    const url = filePathToUrl(filePath);
    return [url, mtime.toISOString().slice(0, 10)];
  }),
);

const sitemap = `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urlEntries
  .sort(([left], [right]) => left.localeCompare(right))
  .map(
    ([url, lastmod]) => `  <url>\n    <loc>${url}</loc>\n    <lastmod>${lastmod}</lastmod>\n  </url>`,
  )
  .join("\n")}\n</urlset>\n`;

await writeFile(join(siteDir, "sitemap.xml"), sitemap, "utf8");
