// Progressive enhancement only: every page works without JavaScript.
(function () {
  "use strict";

  var zone = document.querySelector("[data-dropzone]");
  if (zone) {
    var input = zone.querySelector("input[type=file]");
    var label = zone.querySelector("[data-filename]");
    var showName = function () {
      if (input.files && input.files.length) {
        label.textContent = input.files[0].name;
        zone.classList.add("has-file");
      }
    };
    input.addEventListener("change", showName);
    ["dragenter", "dragover"].forEach(function (type) {
      zone.addEventListener(type, function (e) { e.preventDefault(); zone.classList.add("is-over"); });
    });
    ["dragleave", "drop"].forEach(function (type) {
      zone.addEventListener(type, function (e) { e.preventDefault(); zone.classList.remove("is-over"); });
    });
    zone.addEventListener("drop", function (e) {
      if (e.dataTransfer && e.dataTransfer.files.length) {
        input.files = e.dataTransfer.files;
        showName();
      }
    });
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
