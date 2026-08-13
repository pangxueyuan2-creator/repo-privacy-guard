import path from "node:path";

const DEFAULT_IGNORES = [
  ".git/",
  "node_modules/",
  "coverage/",
  "dist/",
  "build/",
  ".next/",
  ".cache/",
  "vendor/",
];

function normalize(value) {
  return value.split(path.sep).join("/").replace(/^\.\//, "");
}

function escapeRegExp(value) {
  return value.replace(/[|\\{}()[\]^$+?.]/g, "\\$&");
}

function compileGlob(base) {
  let expression = "";

  for (let index = 0; index < base.length; index += 1) {
    if (base[index] !== "*") {
      expression += escapeRegExp(base[index]);
      continue;
    }

    if (base[index + 1] !== "*") {
      expression += "[^/]*";
      continue;
    }

    if (base[index + 2] === "/") {
      expression += "(?:.*/)?";
      index += 2;
    } else {
      expression += ".*";
      index += 1;
    }
  }

  return expression;
}

function globToRegExp(glob) {
  const normalized = normalize(glob.trim()).replace(/^\//, "");
  const directoryOnly = normalized.endsWith("/");
  const base = directoryOnly ? normalized.slice(0, -1) : normalized;
  const expression = compileGlob(base);
  const prefix = base.includes("/") ? "^" : "(?:^|/)";
  const suffix = directoryOnly ? "(?:/|$)" : "$";
  return new RegExp(`${prefix}${expression}${suffix}`);
}

export function parseIgnoreFile(text = "") {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"));
}

export function createIgnoreMatcher(extraPatterns = []) {
  const patterns = [...DEFAULT_IGNORES, ...extraPatterns].map(globToRegExp);
  return (relativePath) => {
    const candidate = normalize(relativePath);
    return patterns.some((pattern) => pattern.test(candidate));
  };
}

export { DEFAULT_IGNORES };
