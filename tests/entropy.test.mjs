import assert from "node:assert/strict";
import test from "node:test";
import { findHighEntropyAssignments, shannonEntropy } from "../src/entropy.mjs";

test("entropy distinguishes repetitive and varied values", () => {
  assert.equal(shannonEntropy("aaaaaaaaaaaaaaaa"), 0);
  assert.ok(shannonEntropy("aB3/xY9+qP2-zK7_mN4") > 4);
});

test("contextual entropy check only reports likely secret assignments", () => {
  const risky = `client_secret="${"aB3/xY9+qP2-zK7_mN4".repeat(2)}"`;
  const ordinary = `description="${"aB3/xY9+qP2-zK7_mN4".repeat(2)}"`;
  assert.equal(findHighEntropyAssignments(risky).length, 1);
  assert.equal(findHighEntropyAssignments(ordinary).length, 0);
});
