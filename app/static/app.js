// Rückfrage vor Löschen o. Ä.
document.addEventListener("submit", function (e) {
  var msg = e.target.getAttribute("data-confirm");
  if (msg && !window.confirm(msg)) e.preventDefault();
});
// Filter-Selects sofort anwenden
document.querySelectorAll("form.filters select, form.filters input[type=checkbox]").forEach(function (s) {
  s.addEventListener("change", function () { s.form.submit(); });
});
// Seite neu laden, solange ein Scan läuft
if (document.querySelector("[data-running]")) {
  setTimeout(function () { window.location.reload(); }, 8000);
}
// Quellen-Formular: Felder je Option ein-/ausblenden
document.querySelectorAll("[data-toggle]").forEach(function (el) {
  var target = document.getElementById(el.getAttribute("data-toggle"));
  function upd() { if (target) target.hidden = !el.checked; }
  el.addEventListener("change", upd); upd();
});
