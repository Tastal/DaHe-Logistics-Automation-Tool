import { readFile } from "node:fs/promises";

const packageUrl = new URL("../package.json", import.meta.url);
const packageJson = JSON.parse(await readFile(packageUrl, "utf8"));

if (packageJson.private !== true) {
  throw new Error("The operator console package must remain private.");
}

const runtimeDependencies = Object.keys(packageJson.dependencies ?? {}).sort();
if (
  JSON.stringify(runtimeDependencies) !==
  JSON.stringify(["lucide-react", "react", "react-dom"])
) {
  throw new Error("Only the approved operator-console runtime dependencies are allowed.");
}

const forbiddenPackages = [
  "axios",
  "paddle",
  "paddleocr",
  "selenium-webdriver",
];
if (Object.hasOwn(packageJson.dependencies ?? {}, "@playwright/test")) {
  throw new Error("Playwright must remain a development-only dependency.");
}
const allDependencies = {
  ...(packageJson.dependencies ?? {}),
  ...(packageJson.devDependencies ?? {}),
};
for (const packageName of forbiddenPackages) {
  if (Object.hasOwn(allDependencies, packageName)) {
    throw new Error(`Forbidden Loop 2 frontend package: ${packageName}`);
  }
}

process.stdout.write("operator-console dependency boundary check passed\n");
