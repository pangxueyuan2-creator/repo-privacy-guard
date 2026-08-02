import assert from "node:assert/strict";
import test from "node:test";
import { createIgnoreMatcher } from "../src/ignore.mjs";

test("double-star ignore patterns match across directory levels", () => {
  const isIgnored = createIgnoreMatcher(["fixtures/**/generated/*.json"]);

  assert.equal(isIgnored("fixtures/generated/result.json"), true);
  assert.equal(isIgnored("fixtures/a/b/generated/result.json"), true);
  assert.equal(isIgnored("fixtures/a/b/generated/result.txt"), false);
});

test("single-star ignore patterns do not cross directory boundaries", () => {
  const isIgnored = createIgnoreMatcher(["fixtures/*/result.json"]);

  assert.equal(isIgnored("fixtures/a/result.json"), true);
  assert.equal(isIgnored("fixtures/a/b/result.json"), false);
});
