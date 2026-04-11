// Keep Vercel-hosted static builds pointing at the production API.
// Bundled /miniapp deployments should stay same-origin and therefore leave window.API_BASE unset.
if (!window.API_BASE && /(?:^|\\.)vercel\\.app$/i.test(window.location.hostname)) {
  window.API_BASE = "https://vpn-wizard-production.up.railway.app";
}
