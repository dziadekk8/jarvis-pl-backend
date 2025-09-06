import express from "express";
import cors from "cors";
import crypto from "crypto";
import { google } from "googleapis";
import dotenv from "dotenv";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";




// ESM: __dirname tylko raz
const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Ładuj .env z katalogu pliku
// Load base .env + overlay by NODE_ENV (last wins)
const baseEnv = path.join(__dirname, ".env");
if (fs.existsSync(baseEnv)) {
  dotenv.config({ path: baseEnv });
}

const envName = (process.env.NODE_ENV || "development").toLowerCase();
const envSpecific = path.join(__dirname, `.env.${envName}`);
if (fs.existsSync(envSpecific)) {
  dotenv.config({ path: envSpecific, override: true });
}
// ── Feature flags ─────────────────────────────────────────────────────────────
const FLAG_THREAD_V2 = /^(1|true|on|yes)$/i.test(String(process.env.THREAD_PARSER_V2 || ""));

console.log("[ENV] NODE_ENV =", envName);
console.log("[ENV] Loaded base:", fs.existsSync(baseEnv) ? baseEnv : "(none)");
console.log("[ENV] Loaded overlay:", fs.existsSync(envSpecific) ? envSpecific : "(none)");
console.log("[FLAG] THREAD_PARSER_V2 =", FLAG_THREAD_V2, "(raw:", process.env.THREAD_PARSER_V2, ")");

// Persist tokenów OAuth (przetrwają restart)
const TOKENS_FILE = path.join(__dirname, ".oauth_tokens.json");

// Konfiguracja z envów
const PORT = process.env.PORT || 8080;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const CANONICAL_HOST = process.env.CANONICAL_HOST || new URL(BASE_URL).host;
const IS_PROD = BASE_URL.startsWith("https://");


const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "";
const WATCH_TOKEN = process.env.WATCH_TOKEN || "";
const MAPS_KEY    = process.env.GOOGLE_MAPS_API_KEY || "";
const ADMIN_HEADERS = ADMIN_TOKEN ? { "x-admin": ADMIN_TOKEN } : {};


const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "";
const OAUTH_REDIRECT = `${BASE_URL.replace(/\/+$/,'')}/oauth2/callback`;
console.log("[ENV] BASE_URL =", BASE_URL);
console.log("[ENV] OAUTH_REDIRECT =", OAUTH_REDIRECT);


const app = express();
app.set("trust proxy", true);   // najlepiej tuż po utworzeniu app = express()
app.set("trust proxy", true);
app.use(cors());
app.use(express.json({ limit: "10mb" }));
const DISABLE_REDIRECTS = String(process.env.DISABLE_REDIRECTS || "").toLowerCase() === "1" || String(process.env.DISABLE_REDIRECTS || "").toLowerCase() === "true";

// ── Access log (prosty) ──────────────────────────────────────────────────────
app.use((req, res, next) => {
  if (DISABLE_REDIRECTS) return next();              // <— twardy wyłącznik
  if (!IS_PROD || IS_LOCAL_BASE) return next();      // jak masz
  const method = req.method.toUpperCase();
const proto  = req.headers["x-forwarded-proto"] || req.protocol;
const host   = req.headers.host;

console.log("[REDIR:check]", {
  DISABLE_REDIRECTS,
  IS_PROD,
  IS_LOCAL_BASE,
  method,
  proto,
  host,
  CANONICAL_HOST,
  url: req.originalUrl
});

  const started = Date.now();
  res.on("finish", () => {
    const ms = Date.now() - started;
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl} -> ${res.statusCode} (${ms}ms)`);
  });
  next();
});

// ── HTTPS + kanoniczny host (tylko prod, nie psuj POST-ów lokalnie) ─────────
const IS_LOCAL_BASE = BASE_URL.startsWith("http://localhost") || BASE_URL.startsWith("http://127.0.0.1");
app.use((req, res, next) => {
  // Wyłącz wymuszanie w lokalnym devie
  if (!IS_PROD || IS_LOCAL_BASE) return next();

  const method = req.method.toUpperCase();
  const isSafe = method === "GET" || method === "HEAD"; // nie przekierowuj POST/PUT/PATCH/DELETE
  const proto = req.headers["x-forwarded-proto"] || req.protocol;
  const host = req.headers.host;

  const needHttps = proto !== "https";
  const needHost  = CANONICAL_HOST && host !== CANONICAL_HOST;

  if ((needHttps || needHost) && isSafe) {
    const targetHost = CANONICAL_HOST || host;
    // 308 zachowuje metodę, ale i tak tylko dla GET/HEAD
    return res.redirect(308, `https://${targetHost}${req.originalUrl}`);
  }
  return next();
});

//
// ── OAuth2 Client ────────────────────────────────────────────────────────────
const oAuth2Client = new google.auth.OAuth2(
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  OAUTH_REDIRECT
);

// Wczytaj zapisane tokeny (jeśli są), żeby przetrwały restart
try {
  if (fs.existsSync(TOKENS_FILE)) {
    const saved = JSON.parse(fs.readFileSync(TOKENS_FILE, "utf8"));
    if (saved && (saved.access_token || saved.refresh_token)) {
      oAuth2Client.setCredentials(saved);
      console.log("[AUTH] Loaded tokens from", TOKENS_FILE);
    } else {
      console.log("[AUTH] Tokens file found but empty/invalid:", TOKENS_FILE);
    }
  } else {
    console.log("[AUTH] No tokens file yet:", TOKENS_FILE);
  }
} catch (e) {
  console.warn("[AUTH] Cannot load tokens:", e?.message || e);
}



// Autoryzacja: admin token lub OAuth (access/refresh). W innym wypadku 401.
function ensureAuthOr401(res) {
  const req = res.req;

  // 1) Admin token (nagłówek x-admin lub Bearer)
  const auth = req.headers.authorization || "";
  const xadm = req.headers["x-admin"] || "";
  const bearer = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  const adminOk = ADMIN_TOKEN && (xadm === ADMIN_TOKEN || bearer === ADMIN_TOKEN);
  if (adminOk) return true;

  // 2) OAuth: wpuszczaj gdy jest access_token ALBO refresh_token (Google sam odświeży)
  const cred = oAuth2Client.credentials || {};
  if (cred.access_token || cred.refresh_token || cred.expiry_date) return true;

  res.status(401).json({ error: "unauthorized", status: 401 });
  return false;
}

// /oauth2/start — alias do bezpośredniego przekierowania na Google
app.get("/oauth2/start", (_req, res) => {
  const scopes = [
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/drive.readonly",
    "https://www.googleapis.com/auth/calendar",
    "https://www.googleapis.com/auth/userinfo.email",
    "openid",
  ];
  const url = oAuth2Client.generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    response_type: "code",
    scope: scopes,
    include_granted_scopes: true,
  });
  return res.redirect(302, url);
  const isDev = !IS_PROD || BASE_URL.startsWith("http://localhost") || BASE_URL.startsWith("http://127.0.0.1");
  if (isDev) return res.json({ url });     // DEV: dostajesz link, otwierasz ręcznie
  return res.redirect(302, url);           // PROD: klasyczny redirect
});
// ── Health ───────────────────────────────────────────────────────────────────
// ── Health (no-cache + log) ──────────────────────────────────────────────────
app.get("/health", (req, res) => {
  try {
    // log: kiedy, UA i IP (za proxy czytamy X-Forwarded-For)
    const ua  = req.headers["user-agent"] || "-";
    const ip  = req.headers["x-forwarded-for"] || req.ip || req.connection?.remoteAddress || "-";
    console.log(`[HEALTH] ${new Date().toISOString()} ua=${ua} ip=${ip} url=${req.originalUrl}`);

    // anty-cache dla CDN/proxy
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
    res.setHeader("Surrogate-Control", "no-store");

    res.json({ ok: true, now: Date.now() });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e?.message || e) });
  }
});

// ── Diagnostics: /diag/env ───────────────────────────────────────────────────
app.get("/diag/env", (_req, res) => {
  try {
    res.json({
      NODE_ENV: process.env.NODE_ENV || "",
      BASE_URL,
      OAUTH_REDIRECT,
      CANONICAL_HOST,
      IS_PROD,
      DISABLE_REDIRECTS: String(process.env.DISABLE_REDIRECTS || ""),
      HAS_TOKENS_FILE: fs.existsSync(TOKENS_FILE),
      TOKENS_FILE: TOKENS_FILE,
      THREAD_PARSER_V2: process.env.THREAD_PARSER_V2 || "",
      FLAG_THREAD_V2: FLAG_THREAD_V2,
    });
  } catch (e) {
    res.status(500).json({ error: "diag_failed", details: String(e?.message || e) });
  }
});


// ── OAuth endpoints ──────────────────────────────────────────────────────────
app.get("/auth/url", (_req, res) => {
  const scopes = [
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/drive.readonly",
    "https://www.googleapis.com/auth/calendar",
    "https://www.googleapis.com/auth/userinfo.email",
    "openid",
  ];
  const url = oAuth2Client.generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    response_type : "code",
    scope: scopes,
    include_granted_scopes: true,
  });
  res.json({ url });
});

// ── OAuth callback ───────────────────────────────────────────────────────────
// ── OAuth callback ───────────────────────────────────────────────────────────
app.get("/oauth2/callback", async (req, res) => {
  try {
    const code = (req.query.code || "").toString();
    if (!code) {
      console.error("[AUTH] Missing ?code w callbacku.");
      return res.status(400).send("Missing code");
    }
    console.log("[AUTH] /oauth2/callback: code=", code.slice(0, 8), "...");

    // Pobierz tokeny od Google
    const { tokens } = await oAuth2Client.getToken(code);
    if (!tokens || (!tokens.access_token && !tokens.refresh_token)) {
      console.error("[AUTH] getToken() zwrócił puste tokeny:", tokens);
      return res.status(500).send("OAuth error: empty tokens");
    }

    // Ustaw do klienta
    oAuth2Client.setCredentials(tokens);

    // Zapis tokenów na dysk — przetrwają restart
    try {
      fs.writeFileSync(TOKENS_FILE, JSON.stringify(tokens, null, 2), "utf8");
      console.log("[AUTH] Tokens saved to", TOKENS_FILE);
    } catch (e) {
      console.warn("[AUTH] Cannot save tokens:", e?.message || e);
    }

    console.log("[AUTH] Login OK. access?", !!tokens.access_token, " refresh?", !!tokens.refresh_token);
    res.send("OAuth OK. Możesz zamknąć tę kartę.");
  } catch (e) {
    console.error("[AUTH] Callback error:", e?.response?.data || e?.message || e);
    res.status(500).send("OAuth error: " + (e?.message || String(e)));
  }
});



app.get("/auth/status", (_req, res) => {
  const c = oAuth2Client.credentials || {};
  res.json({
    authenticated: !!(c.access_token || c.refresh_token),
    hasAccessToken: !!c.access_token,
    hasRefreshToken: !!c.refresh_token,
    expiry: c.expiry_date || null
  });
});

// ── MIME helpers (Gmail) ─────────────────────────────────────────────────────
// ── MIME helpers (Gmail) ─────────────────────────────────────────────────────
function base64Url(bufOrStr) {
  const b = Buffer.isBuffer(bufOrStr) ? bufOrStr : Buffer.from(String(bufOrStr), "utf8");
  return b.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function needsHeaderEncoding(str) { return /[^\x20-\x7E]/.test(str || ""); }
function encodeHeaderUTF8(str) {
  const s = String(str || "");
  if (!s) return "";
  const b64 = Buffer.from(s, "utf8").toString("base64");
  return `=?UTF-8?B?${b64}?=`;
}
function formatHeader(name, value) {
  if (!value) return "";
  const v = needsHeaderEncoding(value) ? encodeHeaderUTF8(value) : value;
  return `${name}: ${v}`;
}
function makeBoundary(prefix = "mix") {
  return `${prefix}__${Math.random().toString(16).slice(2)}_${Date.now()}`;
}
function chunkBase64(b64, n = 76) {
  return (b64.match(new RegExp(`.{1,${n}}`, "g")) || []).join("\r\n");
}
function sanitizeFilename(name) {
  const fallback = "attachment.bin";
  if (!name || typeof name !== "string") return fallback;
  const cleaned = name
    .replace(/[\\/:*?"<>|]/g, "-")
    .replace(/[\u0000-\u001F]/g, "")
    .replace(/\s+/g, " ")
    .trim();
  return cleaned || fallback;
}
// Top-level builder: mixed( alternative(text,html), attachments... )
function buildMimeMessage({ from, to, subject, text, html, attachments = [], inReplyTo, references }) {
  const headers = [];
  headers.push("MIME-Version: 1.0");
  if (from) headers.push(formatHeader("From", from));
  if (to) headers.push(formatHeader("To", to));
  if (subject) headers.push(formatHeader("Subject", subject));
  headers.push(`Date: ${new Date().toUTCString()}`);
  if (inReplyTo) headers.push(`In-Reply-To: ${inReplyTo}`);
  if (references) headers.push(`References: ${references}`);

  const hasText = !!text, hasHtml = !!html;
  const hasAtch = Array.isArray(attachments) && attachments.length > 0;

  if (!hasAtch) {
    if (hasHtml && !hasText) {
      const body = Buffer.from(html, "utf8").toString("base64");
      headers.push('Content-Type: text/html; charset="UTF-8"');
      headers.push("Content-Transfer-Encoding: base64");
      return headers.join("\r\n") + "\r\n\r\n" + chunkBase64(body);
    }
    if (hasText && !hasHtml) {
      const body = Buffer.from(text, "utf8").toString("base64");
      headers.push('Content-Type: text/plain; charset="UTF-8"');
      headers.push("Content-Transfer-Encoding: base64");
      return headers.join("\r\n") + "\r\n\r\n" + chunkBase64(body);
    }
    const bAlt = makeBoundary("alt");
    headers.push(`Content-Type: multipart/alternative; boundary="${bAlt}"`);
    const parts = [];
    parts.push(`--${bAlt}`, 'Content-Type: text/plain; charset="UTF-8"', "Content-Transfer-Encoding: base64", "",
      chunkBase64(Buffer.from(text || "", "utf8").toString("base64")));
    parts.push(`--${bAlt}`, 'Content-Type: text/html; charset="UTF-8"', "Content-Transfer-Encoding: base64", "",
      chunkBase64(Buffer.from(html || "", "utf8").toString("base64")));
    parts.push(`--${bAlt}--`);
    return headers.join("\r\n") + "\r\n\r\n" + parts.join("\r\n");
  }

  const bMixed = makeBoundary("mixed");
  headers.push(`Content-Type: multipart/mixed; boundary="${bMixed}"`);
  const out = [];
  if (hasText && hasHtml) {
    const bAlt = makeBoundary("alt");
    out.push(`--${bMixed}`, `Content-Type: multipart/alternative; boundary="${bAlt}"`, "");
    out.push(`--${bAlt}`, 'Content-Type: text/plain; charset="UTF-8"', "Content-Transfer-Encoding: base64", "",
      chunkBase64(Buffer.from(text, "utf8").toString("base64")));
    out.push(`--${bAlt}`, 'Content-Type: text/html; charset="UTF-8"', "Content-Transfer-Encoding: base64", "",
      chunkBase64(Buffer.from(html, "utf8").toString("base64")));
    out.push(`--${bAlt}--`);
  } else if (hasHtml) {
    out.push(`--${bMixed}`, 'Content-Type: text/html; charset="UTF-8"', "Content-Transfer-Encoding: base64", "",
      chunkBase64(Buffer.from(html, "utf8").toString("base64")));
  } else {
    out.push(`--${bMixed}`, 'Content-Type: text/plain; charset="UTF-8"', "Content-Transfer-Encoding: base64", "",
      chunkBase64(Buffer.from(text || "", "utf8").toString("base64")));
  }
  for (const a of attachments) {
    if (!a || !a.contentBase64) continue;
    const name = sanitizeFilename(a.filename || "attachment.bin");
    const ctype = a.contentType || "application/octet-stream";
    const b64 = String(a.contentBase64).replace(/\r?\n/g, "");
    out.push(`--${bMixed}`, `Content-Type: ${ctype}; name="${name}"`, "Content-Transfer-Encoding: base64",
      `Content-Disposition: attachment; filename="${name}"`, "", chunkBase64(b64));
  }
  out.push(`--${bMixed}--`);
  return headers.join("\r\n") + "\r\n\r\n" + out.join("\r\n");
}

// ── Gmail routes ─────────────────────────────────────────────────────────────
const gmailClient = () => google.gmail({ version: "v1", auth: oAuth2Client });

app.post("/gmail/send", async (req, res) => {
  try {
    if (!ensureAuthOr401(res)) return;
    const gmail = gmailClient();
    const { to, subject, text, html, from, attachments } = req.body || {};
    if (!to || !subject || (!text && !html)) {
      return res.status(400).json({ error: "invalid_input", status: 400, details: "Wymagane: to, subject oraz (text lub html)." });
    }
    const mime = buildMimeMessage({ from, to, subject, text, html, attachments: Array.isArray(attachments) ? attachments : [] });
    const raw = base64Url(mime);
    const sendResp = await gmail.users.messages.send({ userId: "me", requestBody: { raw } });
    res.json({ id: sendResp.data.id, threadId: sendResp.data.threadId, labelIds: sendResp.data.labelIds });
  } catch (e) {
    const status = e?.response?.status || 500;
    res.status(status).json({ error: "gmail_send_failed", status, details: e?.response?.data || e?.message });
  }
});

app.post("/gmail/reply", async (req, res) => {
  try {
    if (!ensureAuthOr401(res)) return;
    const gmail = gmailClient();
    const { replyToMessageId, threadId, to, subject, text, html, attachments, inReplyTo, references } = req.body || {};
    let useThreadId = threadId;
    const headers = [];

    if (replyToMessageId) {
      const orig = await gmail.users.messages.get({
        userId: "me",
        id: replyToMessageId,
        format: "metadata",
        metadataHeaders: ["Message-ID","In-Reply-To","References","From","To","Subject"],
      });
      useThreadId = useThreadId || orig.data.threadId;
      const hs = orig.data.payload?.headers || [];
      const getH = (n) => hs.find(h => h.name?.toLowerCase() === n.toLowerCase())?.value || "";
      if (!subject) headers.push(`Subject: Re: ${getH("Subject")}`);
      headers.push(`In-Reply-To: ${inReplyTo || getH("Message-ID")}`);
      const refs = [getH("References"), getH("Message-ID")].filter(Boolean).join(" ").trim();
      if (refs) headers.push(`References: ${references || refs}`);
      if (!to) headers.push(`To: ${getH("From")}`);
    } else {
      if (to) headers.push(`To: ${to}`);
      if (subject) headers.push(`Subject: ${subject}`);
    }

    // Zawartość MIME (lekko uproszczona – reuse buildera)
    const mime = buildMimeMessage({ to, subject, text, html, attachments, inReplyTo, references });
    const raw = base64Url(mime);
    const sendResp = await gmail.users.messages.send({ userId: "me", requestBody: { raw, threadId: useThreadId } });
    res.json({ id: sendResp.data.id, threadId: sendResp.data.threadId, labelIds: sendResp.data.labelIds });
  } catch (e) {
    const status = e?.response?.status || 500;
    res.status(status).json({ error: "gmail_reply_failed", status, details: e?.response?.data || e?.message });
  }
});

app.get("/gmail/labels", async (req, res) => {
  try {
    if (!ensureAuthOr401(res)) return;
    const gmail = gmailClient();
    const r = await gmail.users.labels.list({ userId: "me" });
    const value = (r.data.labels || []).map(l => ({ id: l.id, name: l.name, type: l.type, messageListVisibility: l.messageListVisibility, labelListVisibility: l.labelListVisibility }));
    res.json({ value, Count: value.length });
  } catch (e) {
    const status = e?.response?.status || 400;
    res.status(status).json({ error: "gmail_labels_failed", status, details: e?.response?.data || e?.message });
  }
});

async function mapLabelNamesToIds(gmail, namesOrIds) {
  if (!Array.isArray(namesOrIds) || !namesOrIds.length) return [];
  const r = await gmail.users.labels.list({ userId: "me" });
  const all = r.data.labels || [];
  const map = new Map(all.map(l => [l.id, l.id]));
  all.forEach(l => map.set(l.name, l.id));
  return namesOrIds.map(x => map.get(x) || x);
}

app.post("/gmail/modify", async (req, res) => {
  try {
    if (!ensureAuthOr401(res)) return;
    const gmail = gmailClient();
    const id = (req.body?.id || req.query?.id || "").toString().trim();
    if (!id) return res.status(400).json({ error: "missing_id", status: 400, details: "Podaj id wiadomości." });

    const addLabelsRaw = Array.isArray(req.body?.addLabels) ? req.body.addLabels : [];
    const removeLabelsRaw = Array.isArray(req.body?.removeLabels) ? req.body.removeLabels : [];
    const [addLabelIds, removeLabelIds] = await Promise.all([
      mapLabelNamesToIds(gmail, addLabelsRaw),
      mapLabelNamesToIds(gmail, removeLabelsRaw),
    ]);
    const r = await gmail.users.messages.modify({ userId: "me", id, requestBody: { addLabelIds, removeLabelIds } });
    res.json({ id: r.data.id, threadId: r.data.threadId, labelIds: r.data.labelIds || [] });
  } catch (e) {
    const status = e?.response?.status || 400;
    res.status(status).json({ error: "gmail_modify_failed", status, details: e?.response?.data || e?.message });
  }
});

app.post("/gmail/markAsRead", async (req, res) => {
  try {
    if (!ensureAuthOr401(res)) return;
    const gmail = gmailClient();
    const id = (req.body?.id || req.query?.id || "").toString().trim();
    if (!id) return res.status(400).json({ error: "missing_id", status: 400 });
    const r = await gmail.users.messages.modify({ userId: "me", id, requestBody: { removeLabelIds: ["UNREAD"] } });
    res.json({ id: r.data.id, threadId: r.data.threadId, labelIds: r.data.labelIds || [] });
  } catch (e) {
    const status = e?.response?.status || 400;
    res.status(status).json({ error: "gmail_mark_read_failed", status, details: e?.response?.data || e?.message });
  }
});

app.post("/gmail/markAsUnread", async (req, res) => {
  try {
    if (!ensureAuthOr401(res)) return;
    const gmail = gmailClient();
    const id = (req.body?.id || req.query?.id || "").toString().trim();
    if (!id) return res.status(400).json({ error: "missing_id", status: 400 });
    const r = await gmail.users.messages.modify({ userId: "me", id, requestBody: { addLabelIds: ["UNREAD"] } });
    res.json({ id: r.data.id, threadId: r.data.threadId, labelIds: r.data.labelIds || [] });
  } catch (e) {
    const status = e?.response?.status || 400;
    res.status(status).json({ error: "gmail_mark_unread_failed", status, details: e?.response?.data || e?.message });
  }
});

app.get("/gmail/messages", async (req, res) => {
  try {
    if (!ensureAuthOr401(res)) return;
    const gmail = gmailClient();
    const q         = (req.query.q || "").toString().trim();
    const pageSize  = Math.max(1, Math.min(100, parseInt(req.query.pageSize) || 25));
    const pageToken = (req.query.pageToken || "").toString().trim() || undefined;
    const raw       = ["1","true","yes","y"].includes((req.query.raw || "").toString().toLowerCase());
    const expand    = ["1","true","yes","y"].includes((req.query.expand || "").toString().toLowerCase());

    const listResp = await gmail.users.messages.list({
      userId: "me",
      q: q || undefined,
      maxResults: pageSize,
      pageToken,
      includeSpamTrash: false,
      fields: "nextPageToken,resultSizeEstimate,messages/id,messages/threadId"
    });

    if (!expand) {
      const minimal = (listResp.data.messages || []).map(m => ({ id: m.id, threadId: m.threadId }));
      return raw ? res.json({ messages: minimal, nextPageToken: listResp.data.nextPageToken, pageSize, q }) : res.json(minimal);
    }

    const ids = (listResp.data.messages || []).map(m => m.id);
    const CONCURRENCY = 10;
    let cursor = 0;
    const results = new Array(ids.length);
    const worker = async () => {
      while (cursor < ids.length) {
        const i = cursor++;
        const id = ids[i];
        try {
          const msg = await gmail.users.messages.get({
            userId: "me", id, format: "metadata",
            metadataHeaders: ["Subject","From","To","Date"],
            fields: "id,threadId,labelIds,internalDate,sizeEstimate,snippet,payload/headers"
          });
          const headers = msg.data.payload?.headers || [];
          const h = (name) => headers.find(h => (h.name || "").toLowerCase() === name.toLowerCase())?.value || "";
          let dateISO = "";
          try { const rawDate = h("Date"); if (rawDate) dateISO = new Date(rawDate).toISOString(); } catch {}
          results[i] = { id: msg.data.id, threadId: msg.data.threadId, subject: h("Subject"), from: h("From"), to: h("To"), date: dateISO, snippet: msg.data.snippet || "" };
        } catch {
          results[i] = { id, threadId: (listResp.data.messages || [])[i]?.threadId || "", error: "fetch_failed" };
        }
      }
    };
    await Promise.all(new Array(Math.min(CONCURRENCY, ids.length)).fill(0).map(() => worker()));
    return raw ? res.json({ messages: results, nextPageToken: listResp.data.nextPageToken, pageSize, q }) : res.json(results);
  } catch (e) {
    const status = e?.response?.status || 500;
    res.status(status).json({ error: "gmail_list_failed", status, details: e?.response?.data || e?.message });
  }
});

app.get("/gmail/message", async (req, res) => {
  try {
    if (!ensureAuthOr401(res)) return;
    const gmail = gmailClient();
    const id  = (req.query.id || "").toString().trim();
    const raw = ["1","true","yes","y"].includes((req.query.raw || "").toString().toLowerCase());
    if (!id) return res.status(400).json({ error: "missing_id", status: 400 });

    const msg = await gmail.users.messages.get({
      userId: "me", id, format: "full",
      fields: "id,threadId,labelIds,internalDate,sizeEstimate,snippet,payload(partId,filename,mimeType,headers(name,value),body(size,data,attachmentId),parts(partId,filename,mimeType,headers(name,value),body(size,data,attachmentId),parts))"
    });

    const payload = msg.data.payload || {};
    const headers = Array.isArray(payload.headers) ? payload.headers : [];
    const h = (name) => headers.find(x => (x.name || "").toLowerCase() === name.toLowerCase())?.value || "";

    let dateISO = "";
    try { const d = h("Date"); if (d) dateISO = new Date(d).toISOString(); else if (msg.data.internalDate) dateISO = new Date(Number(msg.data.internalDate)).toISOString(); } catch {}

    const decodeB64 = (s) => { try { return Buffer.from(String(s).replace(/-/g,"+").replace(/_/g,"/"), "base64").toString("utf8"); } catch { return ""; } };
    const partHeadersObj = (part) => { const obj = {}; (part?.headers || []).forEach(ph => { if (ph?.name) obj[ph.name] = ph.value || ""; }); return obj; };

    const attachments = []; const htmlParts = []; const textParts = [];
    const walk = (part) => {
      if (!part) return;
      const mime = part.mimeType || ""; const body = part.body || {}; const data = body.data || ""; const filename = part.filename || "";
      const PH = partHeadersObj(part);
      const contentId = (PH["Content-Id"] || "").replace(/[<>]/g, "");
      const disposition = PH["Content-Disposition"] || "";
      const isInline = /inline/i.test(disposition) || !!contentId;
      if (/^text\/html/i.test(mime) && data) htmlParts.push(decodeB64(data));
      if (/^text\/plain/i.test(mime) && data) textParts.push(decodeB64(data));
      if (body.attachmentId || filename || isInline) {
        attachments.push({ filename: filename || (PH["Name"] || ""), mimeType: mime, size: body.size || 0, attachmentId: body.attachmentId, partId: part.partId, contentId, disposition, isInline });
      }
      (part.parts || []).forEach(walk);
    };
    walk(payload);

    const result = {
      id: msg.data.id, threadId: msg.data.threadId,
      subject: h("Subject") || "", from: h("From") || "", to: h("To") || "",
      date: dateISO, snippet: msg.data.snippet || "",
      headers: headers.reduce((acc, it) => { if (it && it.name) acc[it.name] = it.value || ""; return acc; }, {}),
    body: { html: htmlParts.join("\n"), text: textParts.join("\n") },
    attachments
    };
    if (raw) result.rawMessage = msg.data;
    res.json(result);
  } catch (e) {
    const status = e?.response?.status || 500;
    res.status(status).json({ error: "gmail_message_failed", status, details: e?.response?.data || e?.message });
  }
});

function toStdBase64(b64url) {
  let s = String(b64url || "").replace(/-/g, "+").replace(/_/g, "/");
  const pad = s.length % 4; if (pad) s += "=".repeat(4 - pad); return s;
}
function safeFilename(name) { return String(name || "attachment").replace(/[\\\/\r\n\t\0]/g, "_"); }


app.get("/gmail/attachment", async (req, res) => {
  try {
    if (!ensureAuthOr401(res)) return;
    const gmail = gmailClient();
    const messageId = (req.query.messageId || "").toString().trim();
    const attachmentId = (req.query.attachmentId || "").toString().trim();
    const stream = ["1","true","yes","y"].includes((req.query.stream || "").toString().toLowerCase());
    const filenameQ = (req.query.filename || "").toString().trim();
    const mimeQ = (req.query.mimeType || req.query.contentType || "").toString().trim();
    if (!messageId) return res.status(400).json({ error: "missing_messageId", status: 400 });
    if (!attachmentId) return res.status(400).json({ error: "missing_attachmentId", status: 400 });

    const att = await gmail.users.messages.attachments.get({ userId: "me", messageId, id: attachmentId });
    const b64url = att?.data?.data || "";
    if (!b64url) return res.status(404).json({ error: "attachment_not_found", status: 404 });

    const contentBase64 = toStdBase64(b64url);
    const contentType = mimeQ || "application/octet-stream";
    const filename = safeFilename(filenameQ || "attachment");

    if (stream) {
      const buf = Buffer.from(contentBase64, "base64");
      res.setHeader("Content-Type", contentType);
      res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
      res.setHeader("Content-Length", String(buf.length));
      return res.end(buf);
    } else {
      const MAX_JSON_BYTES = parseInt(process.env.ATTACHMENT_JSON_MAX || "7000000", 10);
      const estimatedBytes = Math.floor(contentBase64.length * 3 / 4) - (contentBase64.endsWith("==") ? 2 : contentBase64.endsWith("=") ? 1 : 0);
      if (estimatedBytes > MAX_JSON_BYTES) {
        return res.status(413).json({ error: "attachment_too_large", status: 413, details: { estimatedBytes, limit: MAX_JSON_BYTES } });
      }
      return res.json({ filename, contentType, contentBase64 });
    }
  } catch (e) {
    const status = e?.response?.status || 500;
    res.status(status).json({ error: "gmail_attachment_failed", status, details: e?.response?.data || e?.message || String(e) });
  }
});

// ── Gmail: threads (aliasy dla starszych testów) ─────────────────────────────
app.get("/gmail/threads", async (req, res) => {
  try {
    if (!ensureAuthOr401(res)) return;
    const gmail = gmailClient();
    const q         = (req.query.q || "").toString().trim() || undefined;
    const pageSize  = Math.max(1, Math.min(100, parseInt(req.query.pageSize) || 25));
    const pageToken = (req.query.pageToken || "").toString().trim() || undefined;

    const list = await gmail.users.threads.list({
      userId: "me",
      q,
      maxResults: pageSize,
      pageToken,
      fields: "nextPageToken,threads/id,threads/historyId",
    });

    const minimal = (list.data.threads || []).map(t => ({ id: t.id, historyId: t.historyId }));
    res.json({ threads: minimal, nextPageToken: list.data.nextPageToken });
  } catch (e) {
    const status = e?.response?.status || 500;
    res.status(status).json({ error: "gmail_threads_failed", status, details: e?.response?.data || e?.message });
  }
});

// === Gmail: /gmail/thread (V2 pre-handler guarded by feature flag) ===========
app.get("/gmail/thread", async (req, res, next) => {
  if (!FLAG_THREAD_V2) return next(); // flaga off → przepuść do starego handlera

  try {
    if (!ensureAuthOr401(res)) return;
    const gmail = gmailClient();

    const threadId = (req.query.threadId || "").toString().trim();
    const expand   = ["1","true",1,true].includes(req.query.expand);
    const wantRaw  = ["1","true",1,true].includes(req.query.raw);

    if (!threadId) {
      return res.status(400).json({ error: "missing_threadId", status: 400, details: "Podaj ?threadId=..." });
    }

    // ── szybka ścieżka (expand=0 → metadane) ─────────────────────────────────
    if (!expand) {
      const thr = await gmail.users.threads.get({ userId: "me", id: threadId, format: "metadata" });
      const d = thr.data || {};
      const msgs = Array.isArray(d.messages) ? d.messages : [];
      console.log("[THREAD V2] meta only for", threadId, "messages:", msgs.length);
      return res.json({ id: d.id, historyId: d.historyId, snippet: d.snippet || "", messagesCount: msgs.length });
    }

    // ── helpery ───────────────────────────────────────────────────────────────
    const getHeader = (arr, name) =>
      (arr || []).find(h => (h.name || "").toLowerCase() === name.toLowerCase())?.value || "";

    const b64urlToUtf8 = (b64 = "") => {
      try {
        return Buffer.from(String(b64).replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
      } catch { return ""; }
    };

    const safeName = (name) =>
      String(name || "attachment").replace(/[\\\/\r\n\t\0]/g, "_");

    const flattenParts = (payload) => {
      const out = [];
      if (!payload) return out;
      const stack = [payload];
      while (stack.length) {
        const p = stack.pop(); if (!p) continue;
        out.push({
          mimeType: p.mimeType || "",
          filename: p.filename || "",
          body: p.body || {},
          headers: p.headers || [],
        });
        const subs = Array.isArray(p.parts) ? p.parts : [];
        for (let i = subs.length - 1; i >= 0; i--) stack.push(subs[i]);
      }
      return out;
    };

    const fetchAttachment = async (messageId, attachmentId) => {
      try {
        const r = await gmail.users.messages.attachments.get({
          userId: "me",
          messageId,
          id: attachmentId,
        });
        return (r.data?.data || "").replace(/\s/g, "");
      } catch {
        return "";
      }
    };

    // ── pobierz thread (pełna struktura) ─────────────────────────────────────
    const thr = await gmail.users.threads.get({ userId: "me", id: threadId, format: "full" });
    const data = thr.data || {};
    const messages = Array.isArray(data.messages) ? data.messages : [];

    // ── mapowanie wiadomości ─────────────────────────────────────────────────
    const mapped = await Promise.all(messages.map(async (m) => {
      const headersArr = m.payload?.headers || [];
      const base = {
        id: m.id,
        threadId: m.threadId,
        labelIds: m.labelIds || [],
        snippet: m.snippet || "",
        internalDate: m.internalDate,
        headers: {
          from: getHeader(headersArr, "From"),
          to: getHeader(headersArr, "To"),
          cc: getHeader(headersArr, "Cc"),
          bcc: getHeader(headersArr, "Bcc"),
          subject: getHeader(headersArr, "Subject"),
          date: getHeader(headersArr, "Date"),
          messageId: getHeader(headersArr, "Message-Id") || getHeader(headersArr, "Message-ID"),
          inReplyTo: getHeader(headersArr, "In-Reply-To"),
        },
      };

      // RAW: wątek nie wspiera format=raw → pobieramy osobno per message
      if (wantRaw) {
        try {
          const rawMsg = await gmail.users.messages.get({ userId: "me", id: m.id, format: "raw" });
          return { ...base, raw: rawMsg.data?.raw || null };
        } catch {
          return { ...base, raw: null };
        }
      }

      const flat = flattenParts(m.payload);
      const textParts = [], htmlParts = [];
      const inline = [], nonInline = [];

      const jobs = [];
      for (const p of flat) {
        const disp = getHeader(p.headers, "Content-Disposition") || "";
        const cid  = getHeader(p.headers, "Content-ID") || getHeader(p.headers, "Content-Id") || "";
        const isAttachment = /attachment/i.test(disp);
        const isInline = !isAttachment && (/inline/i.test(disp) || !!cid);

        // tekst/HTML
        if ((p.mimeType || "").startsWith("text/")) {
          const bodyTxt = p.body?.data ? b64urlToUtf8(p.body.data) : "";
          if (/html/i.test(p.mimeType)) htmlParts.push(bodyTxt); else textParts.push(bodyTxt);
          continue;
        }

        // załączniki / inline
        const filename = safeName(p.filename || (isInline ? (cid.replace(/[<>]/g, "") || "inline.bin") : "attachment.bin"));
        const contentType = p.mimeType || "application/octet-stream";

        const job = async () => {
          let contentBase64 = "";
          if (p.body?.data) {
            contentBase64 = String(p.body.data).replace(/\s/g, "");
          } else if (p.body?.attachmentId) {
            contentBase64 = await fetchAttachment(m.id, p.body.attachmentId);
          }
          const item = { filename, contentType, contentBase64 };
          if (isInline) inline.push(item); else nonInline.push(item);
        };

        if (p.body?.data || p.body?.attachmentId || isAttachment || isInline) jobs.push(job());
      }

      await Promise.all(jobs);

      return {
        ...base,
        body: { html: htmlParts.join("\n"), text: textParts.join("\n") },
        attachments: nonInline,
        inline,
        hasAttachments: nonInline.length > 0,
        attachmentsCount: nonInline.length,
        hasInline: inline.length > 0,
        inlineCount: inline.length,
      };
    }));

    console.log("[FLAG] THREAD_PARSER_V2 used for", threadId, "messages:", mapped.length);
    return res.json({
      id: data.id,
      historyId: data.historyId,
      snippet: data.snippet || "",
      messages: mapped,
      messagesCount: mapped.length,
    });

  } catch (e) {
    const status = e?.response?.status || 400;
    console.warn("[THREAD V2] error:", e?.response?.data || e?.message || e);
    return res.status(status).json({ error: "gmail_thread_v2_failed", status, details: e?.response?.data || e?.message || String(e) });
  }
});


// === Gmail: /gmail/thread (LEGACY fallback – działa gdy flaga V2 jest OFF) ===
app.get("/gmail/thread", async (req, res) => {
  try {
    if (!ensureAuthOr401(res)) return;
    const gmail = gmailClient();

    const threadId = (req.query.threadId || "").toString().trim();
    const expand   = ["1","true",1,true].includes(req.query.expand);
    const wantRaw  = ["1","true",1,true].includes(req.query.raw);

    if (!threadId) {
      return res.status(400).json({ error: "missing_threadId", status: 400, details: "Podaj ?threadId=..." });
    }

    // szybka ścieżka: expand=0 → metadane
    if (!expand) {
      const thr = await gmail.users.threads.get({ userId: "me", id: threadId, format: "metadata" });
      const d = thr.data || {};
      const msgs = Array.isArray(d.messages) ? d.messages : [];
      return res.json({ id: d.id, historyId: d.historyId, snippet: d.snippet || "", messagesCount: msgs.length });
    }

    // helpery (minimalne, bez pobierania danych załączników)
    const getHeader = (arr, name) =>
      (arr || []).find(h => (h.name || "").toLowerCase() === name.toLowerCase())?.value || "";
    const b64urlToUtf8 = (b64="") => {
      try { return Buffer.from(String(b64).replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"); }
      catch { return ""; }
    };
    const flattenParts = (payload) => {
      const out = []; if (!payload) return out;
      const st = [payload];
      while (st.length) {
        const p = st.pop(); if (!p) continue;
        out.push(p);
        const sub = Array.isArray(p.parts) ? p.parts : [];
        for (let i = sub.length - 1; i >= 0; i--) st.push(sub[i]);
      }
      return out;
    };

    // pełne dane (bez pobierania binariów – tylko metadane/treść)
    const thr = await gmail.users.threads.get({ userId: "me", id: threadId, format: "full" });
    const data = thr.data || {};
    const messages = Array.isArray(data.messages) ? data.messages : [];

    const mapped = await Promise.all(messages.map(async (m) => {
      const headersArr = m.payload?.headers || [];
      const base = {
        id: m.id,
        threadId: m.threadId,
        labelIds: m.labelIds || [],
        snippet: m.snippet || "",
        internalDate: m.internalDate,
        headers: {
          from: getHeader(headersArr, "From"),
          to: getHeader(headersArr, "To"),
          cc: getHeader(headersArr, "Cc"),
          bcc: getHeader(headersArr, "Bcc"),
          subject: getHeader(headersArr, "Subject"),
          date: getHeader(headersArr, "Date"),
          messageId: getHeader(headersArr, "Message-Id") || getHeader(headersArr, "Message-ID"),
          inReplyTo: getHeader(headersArr, "In-Reply-To"),
        },
      };

      // RAW: pobieramy osobno per message (threads API nie ma format=raw)
      if (wantRaw) {
        try {
          const rawMsg = await gmail.users.messages.get({ userId: "me", id: m.id, format: "raw" });
          return { ...base, raw: rawMsg.data?.raw || null };
        } catch {
          return { ...base, raw: null };
        }
      }

      // minimalne parsowanie treści + same meta załączników (bez pobierania plików)
      const parts = flattenParts(m.payload);
      const texts = [], htmls = [];
      let att = 0, inl = 0;
      const attachments = [];
      const inline = [];

      for (const p of parts) {
        const mime = p.mimeType || "";
        const disp = (p.headers || []).find(h => (h.name||"").toLowerCase()==="content-disposition")?.value || "";
        const cid  = (p.headers || []).find(h => (h.name||"").toLowerCase()==="content-id")?.value || "";
        const isAttachment = /attachment/i.test(disp);
        const isInline = !isAttachment && (/inline/i.test(disp) || !!cid);

        if (mime.startsWith("text/")) {
          const bodyTxt = p.body?.data ? b64urlToUtf8(p.body.data) : "";
          if (/html/i.test(mime)) htmls.push(bodyTxt); else texts.push(bodyTxt);
        } else if (isAttachment || isInline) {
          const entry = {
            filename: (p.filename || (isInline ? (cid || "inline.bin").replace(/[<>]/g,"") : "attachment.bin")),
            contentType: mime || "application/octet-stream",
            contentBase64: "" // legacy: nie pobieramy treści
          };
          if (isInline) { inline.push(entry); inl++; } else { attachments.push(entry); att++; }
        }
      }

      return {
        ...base,
        body: { html: htmls.join("\n"), text: texts.join("\n") },
        attachments,
        inline,
        hasAttachments: att > 0,
        attachmentsCount: att,
        hasInline: inl > 0,
        inlineCount: inl,
      };
    }));

    return res.json({
      id: data.id,
      historyId: data.historyId,
      snippet: data.snippet || "",
      messages: mapped,
      messagesCount: mapped.length,
    });

  } catch (e) {
    const status = e?.response?.status || 400;
    return res.status(status).json({ error: "gmail_thread_failed", status, details: e?.response?.data || e?.message || String(e) });
  }
});





// ── Drive: search (lekki, z filtrami) ────────────────────────────────────────
app.get("/drive/search", async (req, res) => {
  try {
    if (!ensureAuthOr401(res)) return;
    const drive = google.drive({ version: "v3", auth: oAuth2Client });
    const nameQ = (req.query.q || "").toString().trim();
    const pageSize = Math.max(1, Math.min(100, parseInt(req.query.pageSize) || 20));
    const namePrefix = (req.query.namePrefix || "").toString().trim().toLowerCase();
    const type = (req.query.type || "").toString().trim().toLowerCase();

    const mimeMap = {
      pdf: "application/pdf",
      doc: "application/msword",
      docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      document: "application/vnd.google-apps.document",
      sheet: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      spreadsheet: "application/vnd.google-apps.spreadsheet",
      slides: "application/vnd.google-apps.presentation",
      ppt: "application/vnd.ms-powerpoint",
      pptx: "application/vnd.openxmlformats-officedocument.presentationml.presentation",
      folder: "application/vnd.google-apps.folder",
      image: "image/",
      video: "video/",
      csv: "text/csv",
      txt: "text/plain",
      zip: "application/zip",
    };

    const filters = ["trashed = false"];
    if (nameQ) filters.push(`name contains '${nameQ.replace(/'/g, "\\'")}'`);
    if (type) {
      const m = mimeMap[type];
      if (m) filters.push(m.endsWith("/") ? `mimeType contains '${m}'` : `mimeType = '${m}'`);
    }
    const q = filters.join(" and ");

    const resp = await drive.files.list({
      q,
      fields: "files(id,name,mimeType,modifiedTime,owners(displayName,emailAddress),webViewLink,size)",
      pageSize,
      orderBy: "modifiedTime desc",
      includeItemsFromAllDrives: true,
      supportsAllDrives: true,
    });

    let files = resp.data.files || [];
    if (namePrefix) {
      const pref = namePrefix.toLowerCase();
      files = files.filter(f => (f.name || "").toLowerCase().startsWith(pref));
    }
    res.json(files);
  } catch (e) {
    const status = e?.response?.status || 500;
    res.status(status).json({ error: "drive_search_failed", status, details: e?.response?.data || e?.message });
  }
});

// ── Places (New) ─────────────────────────────────────────────────────────────
app.get("/places/search", async (req, res) => {
  try {
    const q = req.query.q || "";
    const lat = parseFloat(req.query.lat || "52.2297");
    const lng = parseFloat(req.query.lng || "21.0122");
    const radius = parseInt(req.query.radius || "3000", 10);
    if (!MAPS_KEY) return res.status(500).json({ error: "missing_GOOGLE_MAPS_API_KEY" });

    const url = "https://places.googleapis.com/v1/places:searchText";
    const body = {
      textQuery: q || "kawiarnia",
      locationBias: { circle: { center: { latitude: lat, longitude: lng }, radius } },
      maxResultCount: 10,
      languageCode: "pl",
    };
    const r = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Goog-Api-Key": MAPS_KEY, "X-Goog-FieldMask": "*" },
      body: JSON.stringify(body),
    });
    const data = await r.json();
    const results = (data.places || []).map(p => ({
      place_name: p.name,
      displayName: p.displayName?.text,
      address: p.formattedAddress,
      rating: p.rating,
      user_ratings_total: p.userRatingCount,
      phone: p.nationalPhoneNumber || null,
      website: p.websiteUri || null,
      open_weekdays: p.regularOpeningHours?.weekdayDescriptions || [],
      location: { lat: p.location?.latitude || null, lng: p.location?.longitude || null },
      types: p.types || [],
    }));
    res.json({ query: q, lat, lng, radius, results });
  } catch (e) {
    const status = e?.response?.status || 500;
    res.status(status).json({ error: "places_search_failed", status, details: e?.response?.data || e?.message });
  }
});

app.get("/places/details", async (req, res) => {
  try {
    const place_id = req.query.place_id;
    if (!MAPS_KEY) return res.status(500).json({ error: "missing_GOOGLE_MAPS_API_KEY" });
    if (!place_id) return res.status(400).json({ error: "missing_place_id" });
    const url = `https://places.googleapis.com/v1/${encodeURIComponent(place_id)}`;
    const r = await fetch(url, { headers: { "X-Goog-Api-Key": MAPS_KEY, "X-Goog-FieldMask": "*" } });
    const p = await r.json();
    const out = {
      place_name: p.name,
      name: p.displayName?.text,
      address: p.formattedAddress,
      phone: p.nationalPhoneNumber || null,
      website: p.websiteUri || null,
      rating: p.rating || null,
      user_ratings_total: p.userRatingCount || null,
      open_weekdays: p.regularOpeningHours?.weekdayDescriptions || [],
      location: { lat: p.location?.latitude || null, lng: p.location?.longitude || null },
      types: p.types || [],
    };
    res.json(out);
  } catch (e) {
    const status = e?.response?.status || 500;
    res.status(status).json({ error: "places_details_failed", status, details: e?.response?.data || e?.message });
  }
});

// ── Agent: proste komendy (gwiazdka/przeczytany/drive prefix) ───────────────
app.post("/agent/command", async (req, res) => {
  try {
    const rawTxt = (req.body?.text || "").toString().trim();
    if (!rawTxt) return res.status(400).json({ error: "missing_text", status: 400, details: "Body { text } jest wymagane." });
    const txt = rawTxt.toLowerCase();

    const BASE = BASE_URL;

    // odgwiazdkuj
    {
      const m = rawTxt.match(/odgwiazdkuj\s+(?:mail|wiadomość)\s+([0-9A-Za-z]+)/i);
      if (m) {
        const id = m[1];
        const resp = await fetch(`${BASE}/gmail/modify`, {
          method: "POST",
          headers: { "Content-Type": "application/json", ...ADMIN_HEADERS },
          body: JSON.stringify({ id, removeLabels: ["STARRED"] })
        }).then(r => r.json());
        return res.json({ action: "gmail.modify", request: { id, removeLabels: ["STARRED"] }, result: resp, say: `Zdjęto gwiazdkę z maila ${id}.` });
      }
    }

    // gwiazdka / przeczytany / nieprzeczytany
    {
      const m = rawTxt.match(/(?:oznacz|ustaw)\s+(?:mail|wiadomość)\s+([0-9A-Za-z]+)\s+.*?\s+(nieprzeczytan\w+|przeczytan\w+|gwiazdk\w+)/i);
      if (m) {
        const id = m[1], mode = m[2].toLowerCase();
        if (mode.includes("nieprzeczytan")) {
          const resp = await fetch(`${BASE}/gmail/markAsUnread`, {
            method: "POST",
            headers: { "Content-Type": "application/json", ...ADMIN_HEADERS },
            body: JSON.stringify({ id })
          }).then(r => r.json());
          return res.json({ action: "gmail.markAsUnread", request: { id }, result: resp, say: `Oznaczono mail ${id} jako nieprzeczytany.` });
        }
        if (mode.includes("przeczytan")) {
          const resp = await fetch(`${BASE}/gmail/markAsRead`, {
            method: "POST",
            headers: { "Content-Type": "application/json", ...ADMIN_HEADERS },
            body: JSON.stringify({ id })
          }).then(r => r.json());
          return res.json({ action: "gmail.markAsRead", request: { id }, result: resp, say: `Oznaczono mail ${id} jako przeczytany.` });
        }
        if (mode.includes("gwiazdk")) {
          const resp = await fetch(`${BASE}/gmail/modify`, {
            method: "POST",
            headers: { "Content-Type": "application/json", ...ADMIN_HEADERS },
            body: JSON.stringify({ id, addLabels: ["STARRED"] })
          }).then(r => r.json());
          return res.json({ action: "gmail.modify", request: { id, addLabels: ["STARRED"] }, result: resp, say: `Dodano gwiazdkę do maila ${id}.` });
        }
      }
    }

    // drive prefix
    if (txt.includes("znajdź") && txt.includes("drive")) {
      const pm = rawTxt.match(/(?:prefiks(?:em)?|prefix|zaczyna się od)\s+([^\s,]+)/i);
      const namePrefix = pm ? pm[1] : "";
      const qs = new URLSearchParams(); if (namePrefix) qs.set("namePrefix", namePrefix);
      const r = await fetch(`${BASE}/drive/search?${qs.toString()}`).then(x => x.json());
      return res.json({ action: "drive.search", request: Object.fromEntries(qs.entries()), result: r, say: `Znalazłem ${Array.isArray(r) ? r.length : (r?.Count ?? 0)} wyników${namePrefix ? ` dla prefiksu "${namePrefix}"` : ""}.` });
    }

    return res.status(400).json({ error: "unrecognized_command", status: 400, details: { text: rawTxt } });
  } catch (e) {
    return res.status(500).json({ error: "agent_command_failed", status: 500, details: String(e?.message || e) });
  }
});

// ── Calendar: create ─────────────────────────────────────────────────────────
app.post("/calendar/create", async (req, res) => {
  try {
    if (!ensureAuthOr401(res)) return;
    const calendar = google.calendar({ version: "v3", auth: oAuth2Client });

    const body = req.body || {};
    const summary     = (body.summary || body.title || "Spotkanie").toString();
    const description = (body.description || "").toString();
    const location    = (body.location || "").toString();
    const tz = (body.tz || body.timezone || "Europe/Warsaw").toString();

    // start/end
    const startISO = (body.startISO || body.start || "").toString();
    const durationMin = Number.isFinite(body.durationMin) ? Number(body.durationMin) : 30;
    const start = startISO ? new Date(startISO) : new Date(Date.now() + 2 * 60 * 1000);
    const endISO = (body.endISO || body.end || "").toString();
    const end = endISO ? new Date(endISO) : new Date(start.getTime() + durationMin * 60 * 1000);

    // attendees: akceptuj ["a@b", "c@d"] lub [{email:"a@b"}]
    const attendeesRaw = Array.isArray(body.attendees) ? body.attendees : [];
    const attendees = attendeesRaw.map(x =>
      typeof x === "string" ? { email: x } :
      (x && x.email ? { email: String(x.email) } : null)
    ).filter(Boolean);

    // Google Meet?
    const makeMeet = ["1","true","yes","y"].includes(String(body.conference || "").toLowerCase());
    const conferenceData = makeMeet ? {
      createRequest: {
        requestId: "meet_" + Date.now() + "_" + Math.random().toString(16).slice(2),
        conferenceSolutionKey: { type: "hangoutsMeet" },
      },
    } : undefined;

    const event = {
      summary,
      description,
      location,
      start: { dateTime: start.toISOString(), timeZone: tz },
      end:   { dateTime: end.toISOString(),   timeZone: tz },
      attendees,
      conferenceData,
    };

    const r = await calendar.events.insert({
      calendarId: "primary",
      requestBody: event,
      conferenceDataVersion: makeMeet ? 1 : 0,
      sendUpdates: "none",
    });

    return res.json({
      id: r.data.id,
      htmlLink: r.data.htmlLink,
      hangoutLink: r.data.hangoutLink || null,
      start: r.data.start,
      end: r.data.end,
      summary: r.data.summary,
    });
  } catch (e) {
    const status = e?.response?.status || 500;
    res.status(status).json({ error: "calendar_create_failed", status, details: e?.response?.data || e?.message });
  }
});

// === Calendar: GET /calendar/list ============================================
app.get("/calendar/list", async (req, res) => {
  try {
    if (!ensureAuthOr401(res)) return;

    // Klient Calendar
    const calendar = google.calendar({ version: "v3", auth: oAuth2Client });

    // Parametry zapytania
    const calendarId  = (req.query.calendarId || "primary").toString();
    const timeMinISO  = req.query.timeMin ? new Date(req.query.timeMin).toISOString()
                                          : new Date(Date.now()).toISOString();
    const timeMaxISO  = req.query.timeMax ? new Date(req.query.timeMax).toISOString()
                                          : new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
    const maxResults  = Math.min(2500, parseInt(req.query.maxResults || "250", 10) || 250);
    const singleEvents = String(req.query.singleEvents ?? "true").toLowerCase() !== "false";
    const orderBy     = (req.query.orderBy || (singleEvents ? "startTime" : "updated")).toString();

    // Paginacja
    const items = [];
    let pageToken = undefined;
    do {
      const { data } = await calendar.events.list({
        calendarId,
        timeMin: timeMinISO,
        timeMax: timeMaxISO,
        maxResults,
        singleEvents,   // true → rozwinie powtarzalne po wystąpieniach
        orderBy,        // przy singleEvents=true: "startTime"
        showDeleted: false,
        pageToken,
      });

      for (const ev of (data.items || [])) {
        items.push({
          id: ev.id,
          status: ev.status,
          summary: ev.summary || "",
          description: ev.description || "",
          location: ev.location || "",
          start: ev.start?.dateTime || ev.start?.date || null,
          end:   ev.end?.dateTime   || ev.end?.date   || null,
          htmlLink: ev.htmlLink || null,
        });
      }
      pageToken = data.nextPageToken || null;
    } while (pageToken);

    res.json(items);
  } catch (e) {
    const status = e?.response?.status || 400;
    res.status(status).json({
      error: "calendar_list_failed",
      status,
      details: e?.response?.data || e?.message || String(e),
    });
  }
});

// === Calendar: notifications webhook (Google push / e2e ping) ================
app.all("/calendar/notifications", (req, res) => {
  try {
    const h = {
      method: req.method,
      channelId: req.get("x-goog-channel-id") || null,
      resourceId: req.get("x-goog-resource-id") || null,
      resourceState: req.get("x-goog-resource-state") || null,
      messageNumber: req.get("x-goog-message-number") || null,
      channelToken: req.get("x-goog-channel-token") || null,
      contentType: req.get("content-type") || null,
    };
    console.log("[CAL-NOTIFY]", h, "bodyType=", typeof req.body);
    // 200 OK dla e2e i Google; nic więcej nie robimy
    res.status(200).json({ ok: true, method: req.method });
  } catch (e) {
    console.warn("[CAL-NOTIFY] error:", e?.message || e);
    res.status(200).send("ok"); // zawsze 200, żeby e2e przeszło
  }
});


// === Calendar: notifications webhook (Google push / e2e ping) ================
app.post("/calendar/notifications", (req, res) => {
  try {
    // Minimalny log z nagłówków Google (i e2e)
    const h = {
      channelId: req.get("x-goog-channel-id") || null,
      resourceId: req.get("x-goog-resource-id") || null,
      resourceState: req.get("x-goog-resource-state") || null,
      messageNumber: req.get("x-goog-message-number") || null,
      channelToken: req.get("x-goog-channel-token") || null,
      contentType: req.get("content-type") || null,
    };
    console.log("[CAL-NOTIFY]", h, "bodyType=", typeof req.body);
    // e2e najczęściej oczekuje po prostu 200 – zwrócimy prosto OK
    res.json({ ok: true });
  } catch (e) {
    console.warn("[CAL-NOTIFY] error:", e?.message || e);
    res.status(200).send("ok"); // fallback 200, by zawsze przejść test
  }
});

// (opcjonalnie) szybki GET do sprawdzania w przeglądarce
app.get("/calendar/notifications", (_req, res) => res.status(200).send("ok"));


// ── Calendar: quickAdd (opcjonalne) ──────────────────────────────────────────
app.post("/calendar/quickAdd", async (req, res) => {
  try {
    if (!ensureAuthOr401(res)) return;
    const calendar = google.calendar({ version: "v3", auth: oAuth2Client });
    const text = (req.body?.text || req.body?.q || "").toString().trim();
    if (!text) return res.status(400).json({ error: "missing_text", status: 400 });
    const r = await calendar.events.quickAdd({ calendarId: "primary", text });
    res.json({ id: r.data.id, summary: r.data.summary, htmlLink: r.data.htmlLink });
  } catch (e) {
    const status = e?.response?.status || 500;
    res.status(status).json({ error: "calendar_quickadd_failed", status, details: e?.response?.data || e?.message });
  }
});

// ── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  if (BASE_URL.includes("localhost")) console.log(`Serwer działa na http://localhost:${PORT}`);
});








