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

const tg = window.Telegram && window.Telegram.WebApp;
if (tg) {
  tg.expand();
  const theme = tg.themeParams || {};
  const root = document.documentElement.style;
  const bg = theme.bg_color;
  const secondary = theme.secondary_bg_color;
  if (theme.bg_color) {
    root.setProperty("--bg-top", theme.bg_color);
    root.setProperty("--bg-bottom", theme.bg_color);
    root.setProperty("--input-bg", theme.bg_color);
  }
  if (secondary) {
    root.setProperty("--card-bg", secondary);
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
    root.setProperty("--hero-bg", theme.button_color);
  }
  if (theme.button_text_color) {
    root.setProperty("--button-text", theme.button_text_color);
    root.setProperty("--hero-text", theme.button_text_color);
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

async function pollJob(jobId) {
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
  const payload = {
    ssh: {
      host: data.host,
      user: data.user,
      password: data.password || null,
      key_content: keyContent || null,
    },
    options: {
      auto_mtu: true,
      tune: true,
      check: true,
    },
  };

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
      pollJob(result.job_id).catch((err) => {
        setStatus(`Failed: ${err}`);
        clearInterval(pollTimer);
        pollTimer = null;
        button.disabled = false;
      });
    }, 2000);
    await pollJob(result.job_id);
  } catch (err) {
    setStatus(`Failed: ${err}`);
    button.disabled = false;
  } finally {
    if (!pollTimer) {
      button.disabled = false;
    }
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
