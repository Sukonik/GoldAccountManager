// Gold packet reader for the browser (and Node). Version 0.1.0.
//
// This is a second implementation of the format in docs/packet-format.md. The Go package
// `packet` is the reference. Both are run against the same cases in packet/testdata/parity.json
// (Go: packet/parity_test.go, JavaScript: site/tests/packet.test.mjs), so a file one accepts
// or rejects, the other accepts or rejects for the same reason.
//
// What it does NOT do: verify attestation signatures. Browsers' Ed25519 support is recent and
// uneven, and the server (or Go code) is the right place to trust a signature. Here an attestation
// is only checked for shape.
//
// Everything runs locally. No network request is made.
(function (root) {
  "use strict";

  var FORMAT = "gold-packet";
  var SCHEMA_VERSION = 1;
  var LIMITS = { maxBytes: 5 * 1024 * 1024, maxPayloadBytes: 4 * 1024 * 1024, maxPayloadDepth: 32, maxLineage: 200, maxName: 80, maxAttestations: 8 };

  var KINDS = ["email", "phone", "device"];
  var METHODS = ["google", "email-link", "email-reply", "telegram", "whatsapp", "sms", "passkey"];

  var APP_ID_RE = /^[a-z0-9][a-z0-9-]{1,39}$/;
  var PK_RE = /^pk_[0-9a-z]{8,32}$/;
  var RV_RE = /^rv_[0-9a-z]{8,32}$/;
  var SUBJECT_RE = /^[0-9a-f]{64}$/;
  var KEY_ID_RE = /^[0-9a-z-]{1,32}$/;
  var SIG_RE = /^[A-Za-z0-9_-]{16,200}$/;
  var TS_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

  var KNOWN_KEYS = {
    "": ["format", "schemaVersion", "appId", "packetId", "name", "revisionId", "parentRevisionId", "lineage",
      "createdAt", "savedAt", "app", "origin", "payload", "attestations", "checksum"],
    app: ["name", "version"],
    origin: ["packetId", "revisionId", "relation"],
    attestation: ["kind", "method", "subject", "issuedAt", "expiresAt", "keyId", "signature"],
    checksum: ["alg", "value"]
  };

  // ---- errors ----
  function PacketError(code, message, path) {
    this.code = code; this.message = message; this.path = path || "";
  }
  function bad(code, path, message) { throw new PacketError(code, message, path); }

  // ---- helpers ----
  function isObj(v) { return v !== null && typeof v === "object" && !Array.isArray(v); }
  function has(o, k) { return Object.prototype.hasOwnProperty.call(o, k); }

  // Canonical JSON: sorted keys, no whitespace, JSON.stringify for scalars. Same as Payout Lab's
  // canonicalJson and the Go CanonicalJSON.
  function canonicalJson(v) {
    if (Array.isArray(v)) return "[" + v.map(canonicalJson).join(",") + "]";
    if (isObj(v)) {
      return "{" + Object.keys(v).sort().filter(function (k) { return v[k] !== undefined; })
        .map(function (k) { return JSON.stringify(k) + ":" + canonicalJson(v[k]); }).join(",") + "}";
    }
    return JSON.stringify(v);
  }

  function toHex(buf) {
    return Array.prototype.map.call(new Uint8Array(buf), function (b) { return ("0" + b.toString(16)).slice(-2); }).join("");
  }
  function subtle() {
    var c = root.crypto;
    if (!c || !c.subtle) throw new Error("This browser has no secure crypto (needs https or localhost)");
    return c.subtle;
  }
  function sha256Hex(text) {
    return subtle().digest("SHA-256", new TextEncoder().encode(text)).then(toHex);
  }
  function checksumOf(withoutChecksum) { return sha256Hex(canonicalJson(withoutChecksum)); }

  var B32 = "0123456789abcdefghjkmnpqrstvwxyz";
  function newId(prefix) {
    var raw = new Uint8Array(13);
    root.crypto.getRandomValues(raw);
    var out = "";
    for (var i = 0; i < raw.length; i++) out += B32[raw[i] & 31]; // 256 is a multiple of 32: unbiased
    return prefix + "_" + out;
  }

  function isLeap(y) { return (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0; }
  function validTimestamp(s) {
    if (typeof s !== "string") return false;
    var m = TS_RE.exec(s);
    if (!m) return false;
    var y = +m[1], mo = +m[2], d = +m[3], h = +m[4], mi = +m[5], se = +m[6];
    var dim = [31, isLeap(y) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][mo - 1];
    if (mo < 1 || mo > 12 || d < 1 || d > dim || h > 23 || mi > 59 || se > 59) return false;
    if (m[8] !== "Z") {
      var oh = +m[8].slice(1, 3), om = +m[8].slice(4, 6);
      if (oh > 23 || om > 59) return false;
    }
    return true;
  }

  function stamp(date) { return (date || new Date()).toISOString(); } // UTC with milliseconds, ends in Z

  function cleanName(s, fallback) {
    s = String(s).replace(/[\u0000-\u001f\u007f-\u009f]/g, "").trim();
    var chars = Array.from(s);
    if (chars.length > LIMITS.maxName) s = chars.slice(0, LIMITS.maxName).join("");
    return s === "" ? fallback : s;
  }
  function truncate(s, n) { var c = Array.from(s); return c.length <= n ? s : c.slice(0, n).join(""); }

  function depth(v) {
    if (Array.isArray(v) || isObj(v)) {
      var m = 0, items = Array.isArray(v) ? v : Object.keys(v).map(function (k) { return v[k]; });
      for (var i = 0; i < items.length; i++) { var d = depth(items[i]); if (d > m) m = d; }
      return m + 1;
    }
    return 0;
  }

  // Field names are case-sensitive. A name that differs from a known one only by case is rejected,
  // so every reader of a file sees the same fields.
  function checkKeyCase(obj) {
    function check(level, prefix, m) {
      Object.keys(m).forEach(function (k) {
        KNOWN_KEYS[level].forEach(function (known) {
          if (k !== known && k.toLowerCase() === known.toLowerCase()) {
            bad("bad_value", prefix + k, "field names are case-sensitive: use \"" + known + "\"");
          }
        });
      });
    }
    check("", "", obj);
    ["app", "origin", "checksum"].forEach(function (level) {
      if (isObj(obj[level])) check(level, level + ".", obj[level]);
    });
    if (Array.isArray(obj.attestations)) {
      obj.attestations.forEach(function (a, i) { if (isObj(a)) check("attestation", "attestations[" + i + "].", a); });
    }
  }

  function str(v, path) { if (typeof v !== "string") bad("bad_type", path, "a field has the wrong type"); return v; }

  function validateAttestation(a, i) {
    var p = "attestations[" + i + "].";
    if (!isObj(a)) bad("bad_type", "attestations[" + i + "]", "a field has the wrong type");
    ["kind", "method", "subject", "issuedAt", "keyId", "signature"].forEach(function (k) { str(a[k] === undefined ? "" : a[k], p + k); });
    if (a.expiresAt !== undefined) str(a.expiresAt, p + "expiresAt");
    if (KINDS.indexOf(a.kind) < 0) bad("bad_value", p + "kind", "unknown attestation kind");
    if (METHODS.indexOf(a.method) < 0) bad("bad_value", p + "method", "unknown confirmation method");
    if (!SUBJECT_RE.test(a.subject)) bad("bad_value", p + "subject", "subject must be a 64-character hex hash");
    if (!KEY_ID_RE.test(a.keyId)) bad("bad_value", p + "keyId", "invalid key id");
    if (!SIG_RE.test(a.signature)) bad("bad_value", p + "signature", "invalid signature encoding");
    if (!validTimestamp(a.issuedAt)) bad("bad_value", p + "issuedAt", "must be an ISO 8601 date and time");
    if (a.expiresAt !== undefined && a.expiresAt !== "" && !validTimestamp(a.expiresAt)) bad("bad_value", p + "expiresAt", "must be an ISO 8601 date and time");
    var out = { kind: a.kind, method: a.method, subject: a.subject, issuedAt: a.issuedAt, keyId: a.keyId, signature: a.signature };
    if (a.expiresAt) out.expiresAt = a.expiresAt;
    return out;
  }

  // Rebuild a packet from known fields only.
  function validate(raw, opt) {
    if (typeof raw.appId !== "string" || !APP_ID_RE.test(raw.appId)) {
      if (raw.appId !== undefined && typeof raw.appId !== "string") bad("bad_type", "", "a field has the wrong type");
      bad("bad_value", "appId", "invalid app id");
    }
    if (opt.expectAppId && raw.appId !== opt.expectAppId) bad("app_mismatch", "appId", "this packet belongs to a different app");
    if (typeof raw.packetId !== "string" || !PK_RE.test(raw.packetId)) bad("bad_value", "packetId", "invalid packet id");
    if (typeof raw.revisionId !== "string" || !RV_RE.test(raw.revisionId)) bad("bad_value", "revisionId", "invalid revision id");
    var parent = null;
    if (raw.parentRevisionId !== undefined && raw.parentRevisionId !== null) {
      if (typeof raw.parentRevisionId !== "string" || !RV_RE.test(raw.parentRevisionId)) bad("bad_value", "parentRevisionId", "invalid revision id");
      parent = raw.parentRevisionId;
    }

    var lineage = raw.lineage === undefined || raw.lineage === null ? [raw.revisionId] : raw.lineage;
    if (!Array.isArray(lineage)) bad("bad_type", "", "a field has the wrong type");
    lineage.forEach(function (id, i) { if (typeof id !== "string" || !RV_RE.test(id)) bad("bad_value", "lineage", "invalid revision id at position " + i); });
    if (lineage.length > LIMITS.maxLineage) lineage = lineage.slice(-LIMITS.maxLineage);
    if (lineage.length === 0 || lineage[lineage.length - 1] !== raw.revisionId) {
      lineage = lineage.concat([raw.revisionId]);
      if (lineage.length > LIMITS.maxLineage) lineage = lineage.slice(-LIMITS.maxLineage);
    }
    lineage = lineage.slice();

    ["createdAt", "savedAt"].forEach(function (k) {
      if (raw[k] !== undefined && raw[k] !== null && typeof raw[k] !== "string") bad("bad_type", "", "a field has the wrong type");
      if (!validTimestamp(raw[k])) bad("bad_value", k, "must be an ISO 8601 date and time");
    });

    var payload = raw.payload === undefined ? {} : raw.payload;
    if (!isObj(payload)) bad("bad_payload", "payload", "payload must be an object");
    if (new TextEncoder().encode(JSON.stringify(payload)).length > LIMITS.maxPayloadBytes) bad("too_large", "payload", "payload is too large");
    if (depth(payload) > LIMITS.maxPayloadDepth) bad("bad_payload", "payload", "payload is nested too deeply (max " + LIMITS.maxPayloadDepth + ")");
    if (opt.validatePayload) {
      try { payload = opt.validatePayload(payload); } catch (e) { bad("bad_payload", "payload", String(e && e.message || e)); }
    }

    var atts = raw.attestations === undefined || raw.attestations === null ? [] : raw.attestations;
    if (!Array.isArray(atts)) bad("bad_type", "", "a field has the wrong type");
    if (atts.length > LIMITS.maxAttestations) bad("too_many", "attestations", "too many attestations (max " + LIMITS.maxAttestations + ")");
    atts = atts.map(validateAttestation);

    var app = raw.app === undefined || raw.app === null ? {} : raw.app;
    if (!isObj(app)) bad("bad_type", "", "a field has the wrong type");
    var name = raw.name === undefined || raw.name === null ? "" : str(raw.name, "name");

    var p = {
      format: FORMAT, schemaVersion: SCHEMA_VERSION,
      appId: raw.appId, packetId: raw.packetId, name: cleanName(name, "My account"),
      revisionId: raw.revisionId, parentRevisionId: parent, lineage: lineage,
      createdAt: raw.createdAt, savedAt: raw.savedAt,
      app: { name: cleanName(app.name === undefined ? "" : str(app.name, "app.name"), ""), version: truncate(cleanName(app.version === undefined ? "" : str(app.version, "app.version"), ""), 20) },
      payload: payload, attestations: atts
    };
    if (raw.origin !== undefined && raw.origin !== null) {
      if (!isObj(raw.origin)) bad("bad_type", "", "a field has the wrong type");
      if (typeof raw.origin.packetId !== "string" || !PK_RE.test(raw.origin.packetId) ||
          typeof raw.origin.revisionId !== "string" || !RV_RE.test(raw.origin.revisionId)) bad("bad_value", "origin", "invalid origin ids");
      p.origin = { packetId: raw.origin.packetId, revisionId: raw.origin.revisionId, relation: "copy" };
    }
    return p;
  }

  // parse reads the text of a .gold file. It resolves to { ok: true, packet, warnings } or
  // { ok: false, error: { code, message, path } }, and never rejects for bad input.
  function parse(text, opt) {
    opt = opt || {};
    return Promise.resolve().then(function () {
      try {
        if (typeof text !== "string") bad("not_packet", "", "this file could not be read as text");
        if (new TextEncoder().encode(text).length > LIMITS.maxBytes) bad("too_large", "", "this file is too large to be a packet");
        if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
        var raw;
        // Numbers too large for a double become Infinity in JSON.parse. The Go reader rejects them as
        // invalid JSON, so this one does too.
        try { raw = JSON.parse(text, function (k, v) { if (typeof v === "number" && !isFinite(v)) throw new Error("number out of range"); return v; }); } catch (e) { bad("bad_json", "", "this file is not valid packet data (it could not be read as JSON)"); }
        if (!isObj(raw) || raw.format !== FORMAT) bad("not_packet", "", "this file is not a Gold packet");
        var ver = raw.schemaVersion;
        if (typeof ver !== "number" || ver < 1 || Math.floor(ver) !== ver) bad("bad_version", "schemaVersion", "this packet has no valid version number");
        if (ver > SCHEMA_VERSION) bad("future_version", "schemaVersion", "this packet was saved by a newer version (format " + ver + "; this build reads up to " + SCHEMA_VERSION + "). Nothing was changed");
        checkKeyCase(raw);
        var packet = validate(raw, opt);
        var warnings = [];
        if (isObj(raw.checksum)) {
          var rest = {};
          Object.keys(raw).forEach(function (k) { if (k !== "checksum") rest[k] = raw[k]; });
          return checksumOf(rest).then(function (want) {
            var got = typeof raw.checksum.value === "string" ? raw.checksum.value.toLowerCase() : "";
            if (raw.checksum.alg === "sha-256" && got !== want) {
              warnings.push({ code: "checksum_mismatch", message: "The file changed after it was saved. That can mean accidental damage or a deliberate edit. Check the summary before opening it." });
            }
            return { ok: true, packet: packet, warnings: warnings };
          });
        }
        warnings.push({ code: "no_checksum", message: "This file has no integrity check." });
        return { ok: true, packet: packet, warnings: warnings };
      } catch (e) {
        if (e instanceof PacketError) return { ok: false, error: { code: e.code, message: e.message, path: e.path } };
        return { ok: false, error: { code: "unexpected", message: "This file could not be opened.", path: "" } };
      }
    });
  }

  // serialize writes the packet with a SHA-256 checksum. The checksum catches accidents only.
  function serialize(packet) {
    var body = JSON.parse(JSON.stringify(packet));
    return checksumOf(body).then(function (value) {
      body.checksum = { alg: "sha-256", value: value };
      return JSON.stringify(body, null, 1) + "\n";
    });
  }

  function create(appId, name, appInfo, now) {
    if (!APP_ID_RE.test(appId)) throw new PacketError("bad_value", "app id must be 2-40 characters: lowercase letters, digits and hyphens, starting with a letter or digit", "appId");
    var rev = newId("rv"), ts = stamp(now);
    return {
      format: FORMAT, schemaVersion: SCHEMA_VERSION, appId: appId, packetId: newId("pk"),
      name: cleanName(name || "", "My account"), revisionId: rev, parentRevisionId: null, lineage: [rev],
      createdAt: ts, savedAt: ts, app: appInfo || { name: "", version: "" }, payload: {}, attestations: []
    };
  }

  function nextRevision(p, now) {
    var n = JSON.parse(JSON.stringify(p));
    n.revisionId = newId("rv");
    n.parentRevisionId = p.revisionId;
    n.lineage = p.lineage.concat([n.revisionId]).slice(-LIMITS.maxLineage);
    n.savedAt = stamp(now);
    return n;
  }

  // compare classifies incoming against local by revision history. There is no silent last-write-wins.
  function compare(local, incoming) {
    if (local.packetId !== incoming.packetId) return "different-packet";
    if (local.revisionId === incoming.revisionId) return "identical";
    if (incoming.lineage.indexOf(local.revisionId) >= 0) return "incoming-newer";
    if (local.lineage.indexOf(incoming.revisionId) >= 0) return "incoming-older";
    return "diverged";
  }

  // asSeparateCopy returns p as a new packet that remembers where it came from. Attestations are
  // dropped: they were issued for the original packet id and would not verify on the copy.
  function asSeparateCopy(p, suffix, now) {
    var n = JSON.parse(JSON.stringify(p)), rev = newId("rv"), ts = stamp(now);
    n.origin = { packetId: p.packetId, revisionId: p.revisionId, relation: "copy" };
    n.packetId = newId("pk");
    n.name = cleanName(p.name + (suffix === undefined ? " (copy)" : suffix), p.name);
    n.revisionId = rev; n.parentRevisionId = null; n.lineage = [rev];
    n.createdAt = ts; n.savedAt = ts; n.attestations = [];
    return n;
  }

  var api = {
    FORMAT: FORMAT, SCHEMA_VERSION: SCHEMA_VERSION, LIMITS: LIMITS, FILE_EXTENSION: ".gold",
    canonicalJson: canonicalJson, sha256Hex: sha256Hex, checksumOf: checksumOf,
    newId: newId, create: create, parse: parse, serialize: serialize,
    nextRevision: nextRevision, compare: compare, asSeparateCopy: asSeparateCopy, PacketError: PacketError
  };

  if (typeof module === "object" && module.exports) module.exports = api;
  root.GoldPacket = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
