// Blue Bolt UI: optional progressive enhancement. The site works without it.
// 1. Theme toggle: light, dark, or follow the device. The choice is kept in localStorage when allowed.
// 2. Copy buttons on code blocks (only when the Clipboard API is available).
(function () {
  "use strict";
  var KEY = "bb-theme", root = document.documentElement;

  function stored() { try { return localStorage.getItem(KEY); } catch (e) { return null; } }
  function store(v) { try { if (v) localStorage.setItem(KEY, v); else localStorage.removeItem(KEY); } catch (e) { /* private mode */ } }
  function apply(v) { if (v === "light" || v === "dark") root.setAttribute("data-bb-theme", v); else root.removeAttribute("data-bb-theme"); }

  apply(stored());

  document.addEventListener("DOMContentLoaded", function () {
    var btn = document.querySelector("[data-bb-theme-toggle]");
    if (btn) {
      var label = function () {
        var cur = root.getAttribute("data-bb-theme");
        btn.textContent = cur === "dark" ? "Theme: dark" : cur === "light" ? "Theme: light" : "Theme: auto";
      };
      label();
      btn.addEventListener("click", function () {
        var cur = root.getAttribute("data-bb-theme");
        var next = cur === null ? "light" : cur === "light" ? "dark" : null;
        apply(next); store(next); label();
      });
    }

    if (navigator.clipboard && navigator.clipboard.writeText) {
      document.querySelectorAll("pre").forEach(function (pre) {
        var b = document.createElement("button");
        pre.classList.add("bb-has-copy");
        b.type = "button"; b.className = "bb-copy"; b.textContent = "Copy";
        b.setAttribute("aria-label", "Copy code to clipboard");
        b.addEventListener("click", function () {
          var code = pre.querySelector("code");
          navigator.clipboard.writeText((code || pre).textContent).then(function () {
            b.textContent = "Copied";
            setTimeout(function () { b.textContent = "Copy"; }, 1500);
          }, function () { b.textContent = "Press Ctrl+C"; });
        });
        pre.appendChild(b);
      });
    }
  });
})();
