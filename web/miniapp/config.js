// Keep externally hosted static builds pointing at the production API.
// Bundled /wizard deployments should stay same-origin and therefore leave window.API_BASE unset.
if (!window.API_BASE && /(?:^|\\.)vercel\\.app$/i.test(window.location.hostname)) {
  window.API_BASE = "https://212-69-84-167.nip.io";
}
