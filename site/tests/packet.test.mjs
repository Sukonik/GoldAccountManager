// Runs the browser packet reader against the cases shared with the Go reader.
// Run with: node --test site/tests/
import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const GP = createRequire(import.meta.url)("../assets/gold-packet.js");
const parity = JSON.parse(readFileSync(path.join(here, "../../packet/testdata/parity.json"), "utf8"));
const baseText = readFileSync(path.join(here, "../examples/attested.gold"), "utf8");
const basicText = readFileSync(path.join(here, "../examples/basic.gold"), "utf8");

const clone = (v) => JSON.parse(JSON.stringify(v));

function resolve(root, p) {
  const parts = p.split(".");
  let cur = root;
  for (const part of parts.slice(0, -1)) cur = cur[part];
  return [cur, parts[parts.length - 1]];
}
function expand(v) {
  if (v && typeof v === "object" && !Array.isArray(v) && "$deep" in v) {
    let out = 1;
    for (let i = 0; i < v.$deep; i++) out = { a: out };
    return out;
  }
  return v;
}
function applyOp(doc, op) {
  if ("set" in op) { const [c, k] = resolve(doc, op.set); c[k] = expand(op.value); }
  else if ("delete" in op) { const [c, k] = resolve(doc, op.delete); delete c[k]; }
  else if ("rename" in op) { const [c, k] = resolve(doc, op.rename); c[op.to] = c[k]; delete c[k]; }
  else if ("repeat" in op) {
    const [c, k] = resolve(doc, op.repeat);
    doc[op.into] = Array.from({ length: op.times }, () => clone(c[k]));
  } else throw new Error("unknown op " + JSON.stringify(op));
}

test("canonical JSON and checksums match the Go reader and Payout Lab", async () => {
  for (const v of parity.canonical) {
    const input = JSON.parse(v.input);
    assert.equal(GP.canonicalJson(input), v.canon, v.input);
    assert.equal(await GP.checksumOf(input), v.sum, v.input);
  }
});

test("parity: every shared case gives the same outcome as Go", async (t) => {
  assert.ok(parity.parse.length >= 50);
  for (const c of parity.parse) {
    await t.test(c.name, async () => {
      let text;
      if (c.raw !== undefined && c.raw !== null) text = c.raw;
      else {
        const doc = JSON.parse(baseText);
        for (const op of c.ops) applyOp(doc, op);
        text = JSON.stringify(doc);
      }
      if (c.bom) text = "﻿" + text;
      const r = await GP.parse(text, { expectAppId: c.expectApp || "" });
      if (c.expect.ok) {
        assert.equal(r.ok, true, r.ok ? "" : `want ok, got ${r.error.code}: ${r.error.message}`);
        assert.deepEqual(r.warnings.map((w) => w.code), c.expect.warnings);
      } else {
        assert.equal(r.ok, false, "want " + c.expect.code + ", got ok");
        assert.equal(r.error.code, c.expect.code, r.error.message);
      }
    });
  }
});

test("the example files written by Go open without warnings", async () => {
  for (const text of [baseText, basicText]) {
    const r = await GP.parse(text, { expectAppId: "notes-demo" });
    assert.equal(r.ok, true);
    assert.deepEqual(r.warnings, []);
  }
});

test("a packet made here round-trips and its checksum verifies", async () => {
  const p = GP.create("notes-demo", "Sam's notes", { name: "Test", version: "1" });
  p.payload = { theme: "dark" };
  const text = await GP.serialize(p);
  const r = await GP.parse(text, { expectAppId: "notes-demo" });
  assert.equal(r.ok, true);
  assert.deepEqual(r.warnings, []);
  assert.equal(r.packet.packetId, p.packetId);
  assert.deepEqual(r.packet.payload, { theme: "dark" });
});

test("a checksum written here is the one Go computes", async () => {
  // basic.gold was written by Go. Re-serializing the parsed packet must reproduce its checksum.
  const original = JSON.parse(basicText);
  const r = await GP.parse(basicText);
  const again = JSON.parse(await GP.serialize(r.packet));
  assert.equal(again.checksum.value, original.checksum.value);
});

test("revision comparison names", () => {
  const a = GP.create("notes-demo", "A");
  const b = GP.nextRevision(a);
  const c = GP.nextRevision(a);
  assert.equal(GP.compare(a, a), "identical");
  assert.equal(GP.compare(a, b), "incoming-newer");
  assert.equal(GP.compare(b, a), "incoming-older");
  assert.equal(GP.compare(b, c), "diverged");
  assert.equal(GP.compare(a, GP.create("notes-demo", "Other")), "different-packet");
});

test("a separate copy is a new packet and drops attestations", async () => {
  const r = await GP.parse(baseText);
  const copy = GP.asSeparateCopy(r.packet, " (copy)");
  assert.notEqual(copy.packetId, r.packet.packetId);
  assert.equal(copy.origin.packetId, r.packet.packetId);
  assert.equal(copy.attestations.length, 0);
  assert.equal(GP.compare(r.packet, copy), "different-packet");
});

test("ids have the same shape as the Go ones", () => {
  const seen = new Set();
  for (let i = 0; i < 1000; i++) {
    const id = GP.newId("pk");
    assert.match(id, /^pk_[0-9a-z]{13}$/);
    assert.ok(!seen.has(id));
    seen.add(id);
  }
});

test("creating a packet rejects a bad app id", () => {
  assert.throws(() => GP.create("Bad App", "x"), (e) => e.code === "bad_value");
});
