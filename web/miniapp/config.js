// Default Vercel-hosted miniapp traffic to the production Railway API.
// Bundled /miniapp still uses same-origin because resolveApiBase prefers /miniapp first.
window.API_BASE = window.API_BASE || "https://vpn-wizard-production.up.railway.app";
