(function () {
  var t = null;
  var q = /[?&]theme=(light|dark)/.exec(location.search);
  if (q) t = q[1];
  else try { t = localStorage.getItem("wintrace-theme"); } catch (e) { /* storage blocked */ }
  if (!t) t = window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", t);
  if (/[?&]static\b/.test(location.search)) document.documentElement.classList.add("static");
})();
