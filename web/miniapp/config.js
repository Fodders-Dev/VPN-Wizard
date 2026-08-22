// Keep externally hosted static builds pointing at the production API.
// Bundled /wizard deployments should stay same-origin and therefore leave window.API_BASE unset.
if (!window.API_BASE && /(?:^|\\.)vercel\\.app$/i.test(window.location.hostname)) {
  window.API_BASE = "https://77-67-89-164.nip.io";
}
