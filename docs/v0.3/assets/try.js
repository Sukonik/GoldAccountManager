// Interactive demo for the Try it page. Uses GoldPacket (gold-packet.js).
// Packet contents are untrusted input, so everything is written with textContent. Nothing is
// ever put into the page as HTML, and nothing is sent anywhere.
(function () {
  "use strict";
  var GP = window.GoldPacket;
  if (!GP) return;

  var $ = function (id) { return document.getElementById(id); };
  var state = { current: null, incoming: null };

  function el(tag, attrs, children) {
    var n = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      if (k === "text") n.textContent = attrs[k];
      else if (k === "class") n.className = attrs[k];
      else n.setAttribute(k, attrs[k]);
    });
    (children || []).forEach(function (c) { n.appendChild(typeof c === "string" ? document.createTextNode(c) : c); });
    return n;
  }
  function clear(n) { while (n.firstChild) n.removeChild(n.firstChild); }

  function setError(msg) {
    var e = $("make-error");
    e.hidden = !msg;
    e.textContent = msg || "";
    $("payload").setAttribute("aria-invalid", msg ? "true" : "false");
  }

  // Read the edit fields. Returns null (and shows why) when the data is not a JSON object.
  function readFields() {
    var payload;
    try { payload = JSON.parse($("payload").value || "{}"); } catch (e) { setError("The data is not valid JSON: " + e.message); return null; }
    if (payload === null || typeof payload !== "object" || Array.isArray(payload)) { setError("The data must be a JSON object, like {\"note\": \"hello\"}."); return null; }
    setError("");
    return { name: $("name").value, payload: payload };
  }

  function row(dl, k, v) { dl.appendChild(el("dt", { text: k })); dl.appendChild(el("dd", {}, [typeof v === "string" ? v : v])); }

  function renderCurrent() {
    var p = state.current, box = $("current");
    box.hidden = !p;
    $("rev-btn").disabled = !p;
    $("dl-btn").disabled = !p;
    if (!p) return;
    var dl = $("current-list"); clear(dl);
    row(dl, "Name", p.name);
    row(dl, "App", p.appId);
    row(dl, "Packet id", p.packetId);
    row(dl, "Revision", p.revisionId);
    row(dl, "Revisions in history", String(p.lineage.length));
    row(dl, "Saved", p.savedAt);
    if (p.origin) row(dl, "Copied from", p.origin.packetId);
  }

  function useIncoming(p) {
    state.current = p;
    $("name").value = p.name;
    $("payload").value = JSON.stringify(p.payload, null, 2);
    setError("");
    renderCurrent();
  }

  function notice(kind, title, body, extra) {
    var cls = "bb-notice" + (kind ? " bb-notice--" + kind : "");
    var n = el("div", { class: cls }, [el("strong", { text: title }), el("p", { text: body })]);
    (extra || []).forEach(function (x) { n.appendChild(x); });
    return n;
  }

  var RELATION = {
    "identical": ["ok", "Identical", "This file is the same revision as your packet. Nothing to do."],
    "incoming-newer": ["", "Newer", "This file is a newer revision of your packet: your revision is in its history."],
    "incoming-older": ["warn", "Older", "This file is an older revision of your packet: its revision is in your history. Opening it as a separate copy keeps your newer work."],
    "diverged": ["warn", "Diverged", "Both copies changed from a common starting point. There is no safe automatic winner, so the page never picks one for you."],
    "different-packet": ["", "A different packet", "This is another account (a different packet id)."]
  };

  function button(label, cls, onclick) {
    var b = el("button", { type: "button", class: cls || "" , text: label });
    b.addEventListener("click", onclick);
    return b;
  }

  function showOpened(r, fileLabel) {
    var out = $("result"); clear(out);
    if (!r.ok) {
      out.appendChild(notice("error", "Could not open " + fileLabel, r.error.message + (r.error.path ? " (" + r.error.path + ")" : "") + "  [" + r.error.code + "]"));
      return;
    }
    var p = r.packet;
    state.incoming = p;

    var card = el("article", { class: "bb-card" });
    card.appendChild(el("h3", { text: "Opened: " + fileLabel, style: "margin-top:0" }));
    var dl = el("dl", { class: "bb-kv" });
    row(dl, "Name", p.name); row(dl, "App", p.appId); row(dl, "Packet id", p.packetId);
    row(dl, "Revision", p.revisionId); row(dl, "Saved", p.savedAt);
    row(dl, "Data", JSON.stringify(p.payload));
    card.appendChild(dl);
    out.appendChild(card);

    r.warnings.forEach(function (w) {
      out.appendChild(notice("warn", w.code === "checksum_mismatch" ? "Checksum does not match" : "No integrity check", w.message +
        (w.code === "checksum_mismatch" ? " A checksum is not a signature: anyone can edit a file and recompute it." : "")));
    });

    if (p.attestations.length) {
      var list = el("ul");
      p.attestations.forEach(function (a) {
        list.appendChild(el("li", { text: a.kind + " confirmed by " + a.method + ", issued " + a.issuedAt + (a.expiresAt ? ", expires " + a.expiresAt : "") }));
      });
      out.appendChild(notice("", "Attestations (shape only)", "This page does not verify signatures. Only a server or the Go code holding the public key can.", [list]));
    }

    var cur = state.current, actions = el("div", { class: "bb-row" });
    if (!cur) {
      out.appendChild(notice("", "No packet yet", "You have not made a packet on this page, so this one can become your current packet.", [actions]));
      actions.appendChild(button("Use this packet", "", function () { useIncoming(p); }));
      return;
    }
    var rel = GP.compare(cur, p), info = RELATION[rel];
    var holder = notice(info[0], "Compared with your packet: " + info[1], info[2], [actions]);
    out.appendChild(holder);
    if (rel === "incoming-newer") actions.appendChild(button("Continue from this file", "", function () { useIncoming(p); }));
    if (rel === "incoming-older" || rel === "diverged") actions.appendChild(button("Open as a separate copy", "", function () { useIncoming(GP.asSeparateCopy(p, " (copy)")); }));
    if (rel === "incoming-older") actions.appendChild(button("Replace mine with it", "bb-btn--ghost", function () { useIncoming(p); }));
    if (rel === "different-packet") actions.appendChild(button("Open it as another account", "", function () { useIncoming(p); }));
    if (!actions.firstChild) holder.removeChild(actions);
  }

  function openText(text, label) {
    GP.parse(text, { expectAppId: $("app-id").value.trim() }).then(function (r) { showOpened(r, label); });
  }

  // ---- wiring ----
  $("make-form").addEventListener("submit", function (e) {
    e.preventDefault();
    var f = readFields(); if (!f) return;
    try {
      var p = GP.create($("app-id").value.trim(), f.name, { name: "Try it", version: "0.2" });
      p.payload = f.payload;
      state.current = p; setError(""); renderCurrent();
    } catch (err) { setError(err.message); }
  });

  $("rev-btn").addEventListener("click", function () {
    var f = readFields(); if (!f || !state.current) return;
    var n = GP.nextRevision(state.current);
    n.name = f.name.trim() || n.name; n.payload = f.payload;
    state.current = n; renderCurrent();
  });

  $("dl-btn").addEventListener("click", function () {
    var p = state.current; if (!p) return;
    GP.serialize(p).then(function (text) {
      var url = URL.createObjectURL(new Blob([text], { type: "application/json" }));
      var a = el("a", { href: url, download: (p.name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "packet") + GP.FILE_EXTENSION });
      document.body.appendChild(a); a.click(); document.body.removeChild(a);
      setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
    });
  });

  $("open-file").addEventListener("change", function (e) {
    var f = e.target.files && e.target.files[0]; if (!f) return;
    f.text().then(function (t) { openText(t, f.name); }, function () { showOpened({ ok: false, error: { code: "unreadable", message: "This file could not be read.", path: "" } }, f.name); });
    e.target.value = ""; // so choosing the same file again still fires
  });

  $("example-btn").addEventListener("click", function () {
    fetch("examples/attested.gold").then(function (r) { if (!r.ok) throw new Error("status " + r.status); return r.text(); })
      .then(function (t) { openText(t, "attested.gold (made by the Go code)"); })
      .catch(function () { showOpened({ ok: false, error: { code: "unreadable", message: "The example could not be loaded. Use the download link instead, then choose the file.", path: "" } }, "attested.gold"); });
  });
})();
