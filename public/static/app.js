// Progressive enhancement only: every page works without JavaScript.
(function () {
  "use strict";

  // ---------------------------------------------------------------- loader
  // Postie walks with a parcel while the server analyses the email (live DNS can take a
  // few seconds). Steps describe what PhishKit actually checks, in order.
  var LOADER_STEPS = [
    "Opening the envelope…",
    "Reading the headers…",
    "Checking SPF, DKIM and DMARC…",
    "Comparing who it claims to be from…",
    "Sniffing every link…",
    "Weighing the attachments…",
    "Adding up the score…"
  ];
  var loader = document.querySelector("[data-loader]");
  var loaderTimer = null;

  function showLoader() {
    if (!loader) return;
    var step = loader.querySelector("[data-loader-step]");
    var i = 0;
    step.textContent = LOADER_STEPS[0];
    loader.hidden = false;
    clearInterval(loaderTimer);
    loaderTimer = setInterval(function () {
      i = Math.min(i + 1, LOADER_STEPS.length - 1);
      step.textContent = LOADER_STEPS[i];
    }, 900);
  }

  function hideLoader() {
    if (!loader) return;
    loader.hidden = true;
    clearInterval(loaderTimer);
  }

  document.querySelectorAll("form[data-loading]").forEach(function (form) {
    form.addEventListener("submit", function () {
      // The browser has already validated required fields when submit fires.
      showLoader();
    });
  });
  // Coming back with the Back button restores the page from cache with the loader still up.
  window.addEventListener("pageshow", hideLoader);

  // ---------------------------------------------------------------- Postie
  // A "live" Postie has every mood rendered; switching mood is a class change. The bubble
  // and mood follow what the visitor is doing with the upload form.
  var reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var livePostie = document.querySelector("[data-postie-live]");
  var bubble = document.querySelector("[data-bubble]");
  var currentMood = "idle";

  function setMood(mood, sayKey) {
    if (livePostie && mood !== currentMood) {
      livePostie.classList.remove("postie--" + currentMood);
      livePostie.classList.add("postie--" + mood);
      livePostie.classList.remove("is-reacting");
      void livePostie.getBoundingClientRect();  // restart the squash animation
      livePostie.classList.add("is-reacting");
      currentMood = mood;
    }
    if (bubble && sayKey) {
      var text = bubble.getAttribute("data-say-" + sayKey);
      if (text && bubble.textContent !== text) {
        bubble.textContent = text;
        bubble.classList.remove("is-new");
        void bubble.offsetWidth;
        bubble.classList.add("is-new");
      }
    }
  }

  // Pupils follow the pointer a little. Only the wrapper group moves, so the CSS glance
  // and blink animations on the inner groups keep running.
  if (livePostie && !reduceMotion) {
    var pending = false;
    var lastEvent = null;
    var follow = function () {
      pending = false;
      var box = livePostie.getBoundingClientRect();
      if (!box.width) return;
      var cx = box.left + box.width * 0.5;
      var cy = box.top + box.height * 0.48;
      var dx = lastEvent.clientX - cx;
      var dy = lastEvent.clientY - cy;
      var dist = Math.sqrt(dx * dx + dy * dy) || 1;
      var reach = Math.min(1, dist / 300) * 4;  // at most 4 SVG units
      var transform = "translate(" + (dx / dist * reach).toFixed(2) + "px," + (dy / dist * reach * 0.8).toFixed(2) + "px)";
      livePostie.querySelectorAll(".postie-gaze").forEach(function (g) { g.style.transform = transform; });
    };
    document.addEventListener("pointermove", function (e) {
      lastEvent = e;
      if (!pending) {
        pending = true;
        window.requestAnimationFrame(follow);
      }
    }, { passive: true });
  }

  var zone = document.querySelector("[data-dropzone]");
  if (zone) {
    var input = zone.querySelector("input[type=file]");
    var label = zone.querySelector("[data-filename]");
    var sub = zone.querySelector("[data-filename-sub]");
    var defaultSub = sub ? sub.innerHTML : "";
    var form = zone.closest("form");
    var submit = form && form.querySelector("[data-submit]");
    var hint = form && form.querySelector("[data-submit-hint]");

    var sync = function () {
      var has = !!(input.files && input.files.length);
      if (has) {
        var f = input.files[0];
        label.textContent = f.name;
        if (sub) sub.textContent = (f.size < 1024 * 1024 ? Math.max(1, Math.round(f.size / 1024)) + " KB" :
          (f.size / 1024 / 1024).toFixed(1) + " MB") + " · click to choose a different file";
        zone.classList.add("has-file");
        setMood("eager", "ready");
      } else if (sub) {
        sub.innerHTML = defaultSub;  // our own markup, captured at load
      }
      if (submit) submit.disabled = !has;
      if (hint) hint.hidden = has;
    };
    input.addEventListener("change", sync);
    ["dragenter", "dragover"].forEach(function (type) {
      zone.addEventListener(type, function (e) {
        e.preventDefault();
        zone.classList.add("is-over");
        setMood("eager", "over");
      });
    });
    ["dragleave", "drop"].forEach(function (type) {
      zone.addEventListener(type, function (e) {
        e.preventDefault();
        if (type === "dragleave" && e.relatedTarget && zone.contains(e.relatedTarget)) return;  // moved onto a child
        zone.classList.remove("is-over");
        if (type === "dragleave" && !(input.files && input.files.length)) setMood("idle", "idle");
      });
    });
    zone.addEventListener("drop", function (e) {
      if (e.dataTransfer && e.dataTransfer.files.length) {
        input.files = e.dataTransfer.files;
        sync();
      }
    });
    sync();
    // Back/forward can restore the page with a file still selected.
    window.addEventListener("pageshow", sync);
  }

  // ---------------------------------------------------------------- browser history
  // Hosted mode stores nothing on the server. Each report page embeds its data; we keep the
  // most recent reports in this browser's localStorage and build the dashboard from them.
  // Everything from the email is inserted with textContent, never as HTML.
  var HISTORY_KEY = "phishkit.history.v1";
  var HISTORY_MAX = 25;
  var VERDICT_CLASS = { "Clean": "clean", "Suspicious": "suspicious", "Likely phishing": "phishing" };

  function loadHistory() {
    var raw = window.localStorage.getItem(HISTORY_KEY);  // throws when storage is blocked
    if (!raw) return [];
    try {
      var list = JSON.parse(raw);
      return Array.isArray(list) ? list.filter(function (e) { return e && e.report && e.id; }) : [];
    } catch (err) {
      return [];
    }
  }

  function saveHistory(list) {
    // Drop the oldest entries until the list fits the browser's storage quota.
    while (list.length) {
      try {
        window.localStorage.setItem(HISTORY_KEY, JSON.stringify(list));
        return true;
      } catch (err) {
        if (list.length === 1) break;
        list = list.slice(0, list.length - 1);
      }
    }
    return false;
  }

  function newId() {
    if (window.crypto && window.crypto.randomUUID) return window.crypto.randomUUID();
    return String(Date.now()) + "-" + Math.random().toString(16).slice(2);
  }

  var embedded = document.getElementById("phishkit-report");
  if (embedded) {
    try {
      var entry = JSON.parse(embedded.textContent);
      entry.id = newId();
      saveHistory([entry].concat(loadHistory()).slice(0, HISTORY_MAX));
    } catch (err) {
      // Storage blocked or unreadable: the report itself is still on screen.
    }
  }

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function scoreBar(score, verdictClass) {
    var ns = "http://www.w3.org/2000/svg";
    var svg = document.createElementNS(ns, "svg");
    svg.setAttribute("class", "mini");
    svg.setAttribute("viewBox", "0 0 100 8");
    svg.setAttribute("preserveAspectRatio", "none");
    svg.setAttribute("aria-hidden", "true");
    var track = document.createElementNS(ns, "rect");
    track.setAttribute("class", "mini-track");
    track.setAttribute("width", "100");
    track.setAttribute("height", "8");
    var fill = document.createElementNS(ns, "rect");
    fill.setAttribute("class", "mini-fill " + verdictClass);
    fill.setAttribute("width", String(Math.max(0, Math.min(100, Number(score) || 0))));
    fill.setAttribute("height", "8");
    svg.appendChild(track);
    svg.appendChild(fill);
    return svg;
  }

  function formatDate(iso) {
    return String(iso || "").replace("T", " ").replace("+00:00", " UTC");
  }

  var historyRoot = document.querySelector("[data-browser-history]");
  if (historyRoot) {
    var part = function (name) { return historyRoot.querySelector("[data-history-" + name + "]"); };
    var viewForm = part("view");

    var render = function () {
      var list;
      try {
        list = loadHistory();
      } catch (err) {
        part("unavailable").hidden = false;
        return;
      }
      var rows = part("rows");
      rows.textContent = "";
      var counts = { "Likely phishing": 0, "Suspicious": 0, "Clean": 0 };

      list.forEach(function (entry) {
        var report = entry.report || {};
        var summary = report.summary || {};
        var verdict = String(report.verdict || "");
        var vclass = VERDICT_CLASS[verdict] || "";
        if (counts[verdict] !== undefined) counts[verdict] += 1;

        var tr = el("tr");
        var cell = el("td");
        var open = el("button", "row-link link-button", summary.subject || "(no subject)");
        open.type = "button";
        open.addEventListener("click", function () {
          viewForm.elements.entry.value = JSON.stringify(entry);
          showLoader();
          viewForm.submit();
        });
        cell.appendChild(open);
        cell.appendChild(el("span", "muted mono small", summary.from || entry.filename || ""));
        tr.appendChild(cell);

        var vcell = el("td");
        vcell.appendChild(el("span", "verdict-pill " + vclass, verdict));
        tr.appendChild(vcell);

        var scell = el("td", "num");
        scell.appendChild(scoreBar(report.score, vclass));
        scell.appendChild(document.createTextNode(" " + (Number(report.score) || 0)));
        tr.appendChild(scell);

        tr.appendChild(el("td", "muted small", formatDate(entry.created_at)));

        var acell = el("td", "num");
        var remove = el("button", "copy", "Remove");
        remove.type = "button";
        remove.setAttribute("aria-label", "Remove " + (summary.subject || "this report") + " from history");
        remove.addEventListener("click", function () {
          saveHistory(loadHistory().filter(function (e) { return e.id !== entry.id; }));
          render();
        });
        acell.appendChild(remove);
        tr.appendChild(acell);
        rows.appendChild(tr);
      });

      var has = list.length > 0;
      part("table").hidden = !has;
      part("actions").hidden = !has;
      part("empty").hidden = has;
      var tally = part("tally");
      tally.hidden = !has;
      tally.textContent = has
        ? list.length + " email" + (list.length === 1 ? "" : "s") + " analysed in this browser: " +
          counts["Likely phishing"] + " likely phishing, " + counts["Suspicious"] + " suspicious, " +
          counts["Clean"] + " clean"
        : "";
    };

    part("clear").addEventListener("click", function () {
      if (window.confirm("Remove every report from this browser's history?")) {
        try { window.localStorage.removeItem(HISTORY_KEY); } catch (err) { /* nothing stored */ }
        render();
      }
    });
    render();
  }

  document.querySelectorAll("button[data-copy]").forEach(function (button) {
    button.addEventListener("click", function () {
      if (!navigator.clipboard) return;
      navigator.clipboard.writeText(button.getAttribute("data-copy")).then(function () {
        button.textContent = "Copied";
        setTimeout(function () { button.textContent = "Copy"; }, 1500);
      });
    });
  });
})();
