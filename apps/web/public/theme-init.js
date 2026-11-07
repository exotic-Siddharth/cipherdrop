/* global document, window */
// CipherDrop: apply the saved theme before first paint (R22). Loaded as an external, render-blocking script
// because the CSP (script-src 'self') forbids inline scripts. Mirrors resolveTheme() in src/stores/theme.ts.
(function () {
  var preference = 'light'; // light-first (spec 11.1)
  try {
    var saved = localStorage.getItem('cd-theme');
    if (saved === 'light' || saved === 'dark' || saved === 'system') preference = saved;
  } catch (_err) {
    // Storage unavailable: keep the default.
  }
  var dark =
    preference === 'dark' ||
    (preference === 'system' &&
      typeof window.matchMedia === 'function' &&
      window.matchMedia('(prefers-color-scheme: dark)').matches);
  var root = document.documentElement;
  if (dark) root.classList.add('dark');
  else root.classList.remove('dark');
  root.style.colorScheme = dark ? 'dark' : 'light';
  var meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.setAttribute('content', dark ? '#0b1014' : '#f6f7f9');
})();
