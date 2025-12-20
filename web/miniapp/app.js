const form = document.getElementById("provision-form");
const statusEl = document.getElementById("status");
const progressCard = document.getElementById("progress-card");
const resultCard = document.getElementById("result-card");
const downloadLink = document.getElementById("download-link");
const qrImage = document.getElementById("qr-image");
const button = document.getElementById("provision-btn");
const progressLog = document.getElementById("progress-log");
const rollbackBtn = document.getElementById("rollback-btn");
const simpleToggle = document.getElementById("simple-toggle");
const advancedFields = document.querySelectorAll(".advanced");
const rememberToggle = document.getElementById("remember-toggle");
const pinInput = document.getElementById("pin-input");
const unlockBtn = document.getElementById("unlock-btn");
const addClientBtn = document.getElementById("add-client-btn");

const tg = window.Telegram && window.Telegram.WebApp;
if (tg) {
  tg.expand();
  const theme = tg.themeParams || {};
  const root = document.documentElement.style;
  const secondary = theme.secondary_bg_color;
  const bg = theme.bg_color;
  if (bg) {
    root.setProperty("--bg-top", bg);
    root.setProperty("--bg-bottom", bg);
  }
  if (secondary) {
    root.setProperty("--card-bg", secondary);
    root.setProperty("--input-bg", secondary);
  }
  if (theme.text_color) {
    root.setProperty("--ink", theme.text_color);
    root.setProperty("--input-text", theme.text_color);
  }
  if (theme.hint_color) {
    root.setProperty("--muted", theme.hint_color);
    root.setProperty("--border", theme.hint_color);
  }
  if (theme.button_color) {
    root.setProperty("--accent", theme.button_color);
    root.setProperty("--accent-dark", theme.button_color);
  }
  if (theme.button_text_color) {
    root.setProperty("--button-text", theme.button_text_color);
  }
  if (secondary) {
    root.setProperty("--hero-bg", secondary);
    root.setProperty("--hero-text", theme.text_color || "#f8fafc");
  }
  if (!secondary && theme.button_color) {
    root.setProperty("--hero-bg", theme.button_color);
    root.setProperty("--hero-text", theme.button_text_color || "#f8fafc");
  }
  if (bg && !secondary) {
    const hex = bg.startsWith("#") ? bg.slice(1) : bg;
    if (hex.length === 6) {
      const r = parseInt(hex.slice(0, 2), 16);
      const g = parseInt(hex.slice(2, 4), 16);
      const b = parseInt(hex.slice(4, 6), 16);
      const luminance = (0.299 * r + 0.587 * g + 0.114 * b) / 255;
      if (luminance < 0.4) {
        root.setProperty("--card-bg", "#1f2937");
        root.setProperty("--input-bg", "#111827");
        root.setProperty("--border", "#334155");
        root.setProperty("--muted", "#94a3b8");
        root.setProperty("--hero-bg", "#0f172a");
        root.setProperty("--hero-text", "#e2e8f0");
        root.setProperty("--button-text", "#f8fafc");
      }
    }
  }
}

function setStatus(text) {
  statusEl.textContent = text;
}

function setProgress(lines) {
  progressLog.textContent = lines.join("\n");
}

let pollTimer = null;

function resolveApiBase() {
  const url = new URL(window.location.href);
  const param = url.searchParams.get("api");
  if (param) {
    localStorage.setItem("vpnw_api_base", param);
  }
  return localStorage.getItem("vpnw_api_base") || window.API_BASE || "";
}

const API_BASE = resolveApiBase();

async function fetchJson(url, options) {
  const response = await fetch(`${API_BASE}${url}`, options);
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.detail || "Request failed");
  }
  return payload;
}

function setSimpleMode(enabled) {
  advancedFields.forEach((field) => {
    field.classList.toggle("hidden", enabled);
  });
}

setSimpleMode(true);
simpleToggle.addEventListener("change", () => {
  setSimpleMode(simpleToggle.checked);
});

function bufToBase64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

function base64ToBuf(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

async function deriveKey(pin, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(pin), "PBKDF2", false, [
    "deriveKey",
  ]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function saveCredentials(pin, data) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(pin, salt);
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    enc.encode(JSON.stringify(data))
  );
  localStorage.setItem("vpnw_creds", bufToBase64(encrypted));
  localStorage.setItem("vpnw_salt", bufToBase64(salt));
  localStorage.setItem("vpnw_iv", bufToBase64(iv));
}

async function loadCredentials(pin) {
  const cipher = localStorage.getItem("vpnw_creds");
  const salt = localStorage.getItem("vpnw_salt");
  const iv = localStorage.getItem("vpnw_iv");
  if (!cipher || !salt || !iv) {
    throw new Error("No saved credentials");
  }
  const key = await deriveKey(pin, new Uint8Array(base64ToBuf(salt)));
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: new Uint8Array(base64ToBuf(iv)) },
    key,
    base64ToBuf(cipher)
  );
  const dec = new TextDecoder();
  return JSON.parse(dec.decode(decrypted));
}

function clearCredentials() {
  localStorage.removeItem("vpnw_creds");
  localStorage.removeItem("vpnw_salt");
  localStorage.removeItem("vpnw_iv");
}

function populateForm(creds) {
  if (!creds) {
    return;
  }
  form.elements.host.value = creds.host || "";
  form.elements.user.value = creds.user || "";
  form.elements.password.value = creds.password || "";
  form.elements.key_content.value = creds.key_content || "";
}

unlockBtn.addEventListener("click", async () => {
  try {
    const pin = pinInput.value.trim();
    if (pin.length < 4) {
      alert("PIN must be at least 4 digits.");
      setStatus("PIN required to unlock.");
      return;
    }
    const creds = await loadCredentials(pin);
    populateForm(creds);
    setStatus("Credentials unlocked.");
    alert("Credentials unlocked successfully!");
    unlockBtn.disabled = true;
  } catch (err) {
    console.error(err);
    setStatus("Unlock failed.");
    alert("Unlock failed. Wrong PIN?");
  }
});

if (!localStorage.getItem("vpnw_creds")) {
  unlockBtn.disabled = true;
}

async function pollJob(jobId, clientName) {
  const status = await fetchJson(`/api/jobs/${jobId}`);
  const lines = status.progress || [];
  setProgress(lines);
  const last = lines.length ? lines[lines.length - 1] : status.status;
  setStatus(`${status.status}: ${last}`);

  if (status.status === "error") {
    setStatus(`Failed: ${status.error || "unknown error"}`);
    clearInterval(pollTimer);
    pollTimer = null;
    button.disabled = false;
    return;
  }

  if (status.status === "done") {
    clearInterval(pollTimer);
    pollTimer = null;
    const result = await fetchJson(`/api/jobs/${jobId}/result`);
    const blob = new Blob([result.config], { type: "text/plain" });
    const name = clientName || "client1";
    downloadLink.download = `${name}.conf`;
    downloadLink.href = URL.createObjectURL(blob);
    qrImage.src = `data:image/png;base64,${result.qr_png_base64}`;
    const checks = result.checks || [];
    if (checks.length) {
      const checkText = checks
        .map((item) => `${item.name}: ${item.ok ? "ok" : "fail"}`)
        .join(" | ");
      setStatus(`Ready. ${checkText}`);
    } else {
      setStatus("Ready. Download your config and scan the QR.");
    }
    resultCard.style.display = "block";
    button.disabled = false;
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  button.disabled = true;
  resultCard.style.display = "none";
  setStatus("Creating job...");
  setProgress([]);

  const data = Object.fromEntries(new FormData(form).entries());
  const keyContent = simpleToggle.checked ? null : data.key_content;
  if (rememberToggle.checked) {
    const pin = pinInput.value.trim();
    if (pin.length < 4) {
      setStatus("PIN must be at least 4 digits to save credentials.");
      button.disabled = false;
      return;
    }
    await saveCredentials(pin, {
      host: data.host,
      user: data.user,
      password: data.password || "",
      key_content: keyContent || "",
    });
    unlockBtn.disabled = false;
  } else {
    clearCredentials();
    unlockBtn.disabled = true;
  }
  const payload = {
    ssh: {
      host: data.host,
      user: data.user,
      password: data.password || null,
      key_content: keyContent || null,
    },
    options: {
      client_name: data.client_name || undefined,
      auto_mtu: true,
      tune: true,
      check: true,
    },
  };

  const currentClientName = data.client_name || "client1";

  try {
    const result = await fetchJson("/api/provision", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    setStatus("Provisioning... this can take a few minutes.");
    if (pollTimer) {
      clearInterval(pollTimer);
    }
    pollTimer = setInterval(() => {
      pollJob(result.job_id, currentClientName).catch((err) => {
        setStatus(`Failed: ${err}`);
        clearInterval(pollTimer);
        pollTimer = null;
        button.disabled = false;
      });
    }, 2000);
    await pollJob(result.job_id, currentClientName);
  } catch (err) {
    setStatus(`Failed: ${err}`);
    button.disabled = false;
  } finally {
    if (!pollTimer) {
      button.disabled = false;
    }
  }
});

addClientBtn.addEventListener("click", async () => {
  const data = Object.fromEntries(new FormData(form).entries());
  const keyContent = simpleToggle.checked ? null : data.key_content;
  setStatus("Adding client...");
  setProgress([]);
  try {
    const result = await fetchJson("/api/clients/add", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ssh: {
          host: data.host,
          user: data.user,
          password: data.password || null,
          key_content: keyContent || null,
        },
        client_name: data.client_name || null,
      }),
    });
    if (!result.ok) {
      setStatus(`Failed: ${result.error || "unknown error"}`);
      return;
    }
    const blob = new Blob([result.config], { type: "text/plain" });
    downloadLink.download = `${result.client_name}.conf`;
    downloadLink.href = URL.createObjectURL(blob);
    qrImage.src = `data:image/png;base64,${result.qr_png_base64}`;
    resultCard.style.display = "block";
    setStatus(`Client ready: ${result.client_name}`);
  } catch (err) {
    setStatus(`Failed: ${err}`);
  }
});

rollbackBtn.addEventListener("click", async () => {
  const data = Object.fromEntries(new FormData(form).entries());
  const keyContent = simpleToggle.checked ? null : data.key_content;
  setStatus("Rolling back...");
  try {
    const result = await fetchJson("/api/rollback", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ssh: {
          host: data.host,
          user: data.user,
          password: data.password || null,
          key_content: keyContent || null,
        },
      }),
    });
    if (result.ok) {
      setStatus(`Rollback OK: ${result.backup}`);
    } else {
      setStatus(`Rollback failed: ${result.error || "unknown error"}`);
    }
  } catch (err) {
    setStatus(`Rollback failed: ${err}`);
  }
});
