/* global document, window */
// CipherDrop: the Trusted Types 'default' policy (crypto-7). Loaded first, as an external script, because the CSP
// (script-src 'self') forbids inline scripts. The production headers ship Trusted Types in report-only mode
// (Content-Security-Policy-Report-Only: require-trusted-types-for 'script'; trusted-types default, see
// securityHeaders.ts): a DOM sink that gets a plain string calls this policy, a null answer logs a violation in the
// console, and the value is still used. The e2e leak guard fails on any such message.
//
// The app's only script-URL sinks are its two module workers, which Vite emits as same-origin /assets/*.js files
// (new Worker(new URL(..., import.meta.url))). It writes no HTML and no script text to a sink, so createHTML and
// createScript answer null for everything. Browsers without Trusted Types skip this file.
(function () {
  var tt = window.trustedTypes;
  if (!tt || typeof tt.createPolicy !== 'function') return;
  tt.createPolicy('default', {
    createScriptURL: function (input) {
      var url = new URL(input, document.baseURI);
      var bundled =
        url.origin === window.location.origin &&
        /^\/assets\/[\w.-]+\.js$/.test(url.pathname) &&
        url.search === '' &&
        url.hash === '';
      return bundled ? input : null;
    },
    createHTML: function () {
      return null;
    },
    createScript: function () {
      return null;
    },
  });
})();
