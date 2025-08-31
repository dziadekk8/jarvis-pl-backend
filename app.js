// app.js
import express from "express";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";
import { google } from "googleapis";
import crypto from "crypto";
import { Redis } from "@upstash/redis";
import swaggerUi from "swagger-ui-express";


dotenv.config();

// ── Redis (Upstash) ────────────────────────────────────────────────
const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
});
const TOKENS_KEY = process.env.REDIS_TOKENS_KEY || "jarvis:tokens";
const PUSH_KEY   = process.env.REDIS_PUSH_KEY   || "jarvis:push";

async function kvGet(key){ try { return await redis.get(key); } catch(e){ console.error("redis.get", e?.message||e); return null; } }
async function kvSet(key,val){ try { await redis.set(key, val); } catch(e){ console.error("redis.set", e?.message||e); } }
async function kvDel(key){ try { await redis.del(key); } catch(e){ console.error("redis.del", e?.message||e); } }

// --- Globalne łapacze błędów / logi startowe ---
process.on("uncaughtException", (err) => console.error("❌ uncaughtException:", err));
process.on("unhandledRejection", (reason) => console.error("❌ unhandledRejection:", reason));

// ── ŚCIEŻKI I PODSTAWY ──────────────────────────────────────────────
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();

const PORT = process.env.PORT || 8080;
const TZ = "Europe/Warsaw";

// Body parser (większy limit na załączniki)
app.use(express.json({ limit: "25mb" }));
app.use(express.urlencoded({ extended: true, limit: "25mb" }));

// Proste endpointy zdrowia i specyfikacji
app.get("/", (_req, res) => res.send("OK"));
app.get("/health", (_req, res) => res.json({ ok: true }));
app.get("/openapi-public.yaml", (_req, res) => {
  res.type("text/yaml; charset=utf-8");
  res.sendFile(path.join(__dirname, "openapi-public.yaml"));
});

// Swagger UI – interaktywna dokumentacja pod /docs
import swaggerUi from "swagger-ui-express";
app.use(
  "/docs",
  swaggerUi.serve,
  swaggerUi.setup(null, {
    swaggerOptions: { url: "/openapi-public.yaml" }, // wskazanie na plik YAML
    customSiteTitle: "Jarvis-PL API Docs",
    customCss: ".swagger-ui .topbar { display:none }"
  })
);

app.get("/openapi.yaml", (_req, res) => {
  res.type("text/yaml; charset=utf-8");
  res.sendFile(path.join(__dirname, "openapi.yaml"));
});
app.get("/debug/routes", (_req, res) => {
  const routes = app._router?.stack
    ?.filter((r) => r.route && r.route.path)
    ?.map((r) => ({ method: Object.keys(r.route.methods)[0]?.toUpperCase(), path: r.route.path })) || [];
  res.json(routes);
});

// ── GOOGLE OAUTH2 ──────────────────────────────────────────────────
const SCOPES = [
  "https://www.googleapis.com/auth/gmail.readonly",
  "https://www.googleapis.com/auth/gmail.send",
  "https://www.googleapis.com/auth/drive.readonly",
  "https://www.googleapis.com/auth/calendar" // pełny R/W do kalendarza
];

const oAuth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  (process.env.GOOGLE_REDIRECT_URI || "").trim()
);

// tokens bootstrap (persistent in Redis)
let userTokens = null;
(async () => { userTokens = (await kvGet(TOKENS_KEY)) || null; })();
oAuth2Client.on("tokens", async (tokens) => {
  userTokens = { ...(userTokens || {}), ...tokens };
  await kvSet(TOKENS_KEY, userTokens);
});

// ── POMOCNICZE ─────────────────────────────────────────────────────
function isoDayRange(offsetDays = 0) {
  const now = new Date();
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: TZ, year: "numeric", month: "2-digit", day: "2-digit",
  }).formatToParts(now);
  const y = Number(parts.find((p) => p.type === "year").value);
  const m = Number(parts.find((p) => p.type === "month").value);
  const d = Number(parts.find((p) => p.type === "day").value);
  const startUTC = new Date(Date.UTC(y, m - 1, d + offsetDays, 0, 0, 0, 0));
  const endUTC   = new Date(Date.UTC(y, m - 1, d + offsetDays + 1, 0, 0, 0, 0));
  return { timeMin: startUTC.toISOString(), timeMax: endUTC.toISOString() };
}
const fmtTime = (iso) => {
  try { if (!iso) return "brak"; const d = new Date(iso); if (isNaN(d)) return "brak";
    return new Intl.DateTimeFormat("pl-PL", { timeZone: TZ, hour: "2-digit", minute: "2-digit" }).format(d);
  } catch { return "brak"; }
};
const fmtDate = (iso) => {
  try { if (!iso) return "brak"; const d = new Date(iso); if (isNaN(d)) return "brak";
    return new Intl.DateTimeFormat("pl-PL", { timeZone: TZ, dateStyle: "long" }).format(d);
  } catch { return "brak"; }
};

// Gmail: MIME builder – HTML + plain text + attachments
function buildRawEmail({ to, subject, text, html, from, attachments = [], headersExtra = {} }) {
  const encSubject = subject ? `=?UTF-8?B?${Buffer.from(subject, "utf-8").toString("base64")}?=` : "";
  const fallbackText = text || (html ? html.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim() : "");
  const b64wrap = (s) => (s || "").match(/.{1,76}/g)?.join("\r\n") || "";
  const altBoundary = "bndry_alt_" + Date.now().toString(36);
  const altPart = [
    `--${altBoundary}`,
    "Content-Type: text/plain; charset=UTF-8",
    "Content-Transfer-Encoding: 8bit",
    "", fallbackText || "", "",
    `--${altBoundary}`,
    "Content-Type: text/html; charset=UTF-8",
    "Content-Transfer-Encoding: 8bit",
    "", html || `<html><body><pre style="font-family: inherit">${(text || "").replace(/</g, "&lt;").trim()}</pre></body></html>`, "",
    `--${altBoundary}--`, ""
  ].join("\r\n");

  let headers = [ `To: ${to}`, from ? `From: ${from}` : "", `Subject: ${encSubject}`, "MIME-Version: 1.0" ].filter(Boolean);
  if (headersExtra && typeof headersExtra === "object") {
    for (const [k, v] of Object.entries(headersExtra)) if (v) headers.push(`${k}: ${v}`);
  }

  let finalMime = "";
  if (attachments.length > 0) {
    const mixBoundary = "bndry_mix_" + Math.random().toString(36).slice(2);
    headers.push(`Content-Type: multipart/mixed; boundary="${mixBoundary}"`);
    const parts = [ "", `--${mixBoundary}`, `Content-Type: multipart/alternative; boundary="${altBoundary}"`, "", altPart.trim() ];
    for (const att of attachments) {
      const filename = att.filename || "attachment";
      const mimeType = att.mimeType || "application/octet-stream";
      const dataB64 = att.data || att.dataBase64 || "";
      parts.push(`--${mixBoundary}`,
        `Content-Type: ${mimeType}; name="${filename}"`,
        "Content-Transfer-Encoding: base64",
        `Content-Disposition: attachment; filename="${filename}"`,
        "", b64wrap(dataB64), "");
    }
    parts.push(`--${mixBoundary}--`, "");
    finalMime = headers.join("\r\n") + "\r\n" + parts.join("\r\n");
  } else {
    headers.push(`Content-Type: multipart/alternative; boundary="${altBoundary}"`);
    finalMime = headers.join("\r\n") + "\r\n\r\n" + altPart;
  }

  return Buffer.from(finalMime, "utf-8").toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

// ── ROUTES: AUTH ───────────────────────────────────────────────────
app.get("/oauth2/start", (_req, res) => {
  const url = oAuth2Client.generateAuthUrl({ access_type: "offline", prompt: "consent", scope: SCOPES });
  res.redirect(url);
});

app.get("/oauth2/callback", async (req, res) => {
  const code = req.query.code;
  if (!code) return res.status(400).send("Brak ?code w URL");
  try {
    const { tokens } = await oAuth2Client.getToken(code);
    userTokens = tokens;
    oAuth2Client.setCredentials(userTokens);
    await kvSet(TOKENS_KEY, userTokens); // zapis do Redis
    res.send("✅ Autoryzacja OK. Token zapisany w Redis. Sprawdź /auth/status");
  } catch (e) {
    console.error("Błąd pobierania tokenów:", e);
    res.status(500).send("❌ Błąd pobierania tokenów");
  }
});

app.get("/auth/status", async (_req, res) => {
  if (!userTokens) return res.send("🔴 Brak tokenów. Zaloguj: /oauth2/start");
  const hasRefresh = Boolean(userTokens.refresh_token);
  res.send(`🟢 Tokeny obecne. refresh_token: ${hasRefresh ? "TAK" : "NIE"}`);
});

app.get("/auth/tokeninfo", async (_req, res) => {
  try {
    if (!userTokens?.access_token) return res.status(400).json({ error: "Brak access_token – zaloguj: /oauth2/start" });
    const oauth2 = google.oauth2({ version: "v2", auth: oAuth2Client });
    const info = await oauth2.tokeninfo({ access_token: userTokens.access_token });
    return res.json({
      scopes: (info.data?.scope || "").split(" "),
      expires_in: info.data?.expires_in,
      issued_to: info.data?.issued_to,
      audience: info.data?.audience,
    });
  } catch (e) {
    console.error("tokeninfo error:", e?.response?.data || e);
    return res.status(500).json({ error: "Nie można pobrać tokeninfo", details: e?.response?.data?.error_description || e?.message || "unknown" });
  }
});

// RESET autoryzacji i webhooka (tylko dla admina)
app.get("/auth/reset", async (req, res) => {
  try {
    const provided = req.get("x-admin-token") || req.get("x-admin");
    const expected  = process.env.ADMIN_TOKEN || process.env.SESSION_SECRET || process.env.WATCH_TOKEN;
    if (!expected || provided !== expected) {
      return res.status(403).json({ error: "forbidden", message: "Brak lub zły x-admin-token" });
    }
    userTokens = null;
    try { oAuth2Client.setCredentials(null); } catch {}
    await kvDel(TOKENS_KEY);
    await kvDel(PUSH_KEY);
    CAL_PUSH = { channelId: null, resourceId: null, expiration: null, syncToken: null, lastChanges: [], history: [] };
    return res.json({ ok: true, cleared: ["TOKENS_KEY", "PUSH_KEY"] });
  } catch (e) {
    const msg = e?.response?.data || e?.message || "unknown";
    console.error("auth/reset error:", msg);
    return res.status(500).json({ error: "auth_reset_failed", details: msg });
  }
});

// ── ROUTES: CALENDAR ───────────────────────────────────────────────
app.get("/calendar/events/json", async (_req, res) => {
  try {
    if (!userTokens) return res.status(401).json({ error: "Brak autoryzacji", fix: "Przejdź /oauth2/start" });
    oAuth2Client.setCredentials(userTokens);
    const calendar = google.calendar({ version: "v3", auth: oAuth2Client });
    const events = await calendar.events.list({
      calendarId: "primary",
      timeMin: new Date().toISOString(),
      maxResults: 10,
      singleEvents: true,
      orderBy: "startTime",
    });
    const result = (events.data.items || []).map((ev) => ({
      id: ev.id,
      summary: ev.summary || "(bez tytułu)",
      start: ev.start?.dateTime || ev.start?.date || null,
    }));
    return res.json({ events: result });
  } catch (e) {
    console.error("calendar/events error:", e?.response?.data || e);
    const status = e?.response?.status || e?.code || 500;
    return res.status(Number.isInteger(status) ? status : 500).json({
      error: "Błąd pobierania wydarzeń",
      details: e?.response?.data?.error?.message || e?.message || "unknown",
    });
  }
});

app.get("/calendar/event", async (req, res) => {
  const id = (req.query.id || "").trim();
  if (!id) return res.status(400).json({ error: "Brak parametru ?id" });
  try {
    oAuth2Client.setCredentials(userTokens);
    const calendar = google.calendar({ version: "v3", auth: oAuth2Client });
    const ev = await calendar.events.get({ calendarId: "primary", eventId: id });
    return res.json(ev.data);
  } catch (e) {
    const status = e?.code || e?.response?.status || 500;
    if (status === 404) return res.status(404).json({ error: "Wydarzenie nie znalezione", id });
    return res.status(500).json({ error: "Błąd pobierania wydarzenia" });
  }
});

app.get("/calendar/today", async (_req, res) => {
  try {
    if (!userTokens) return res.status(401).json({ error: "Brak autoryzacji", fix: "Wejdź na /oauth2/start" });
    oAuth2Client.setCredentials(userTokens);
    const { timeMin, timeMax } = isoDayRange(0);
    const calendar = google.calendar({ version: "v3", auth: oAuth2Client });
    const events = await calendar.events.list({ calendarId: "primary", timeMin, timeMax, singleEvents: true, orderBy: "startTime" });
    const result = (events.data.items || []).map((ev) => {
      const startISO = ev.start?.dateTime || ev.start?.date || null;
      return `${fmtTime(startISO)} - ${ev.summary || "Bez tytułu"} (${fmtDate(startISO)})`;
    });
    res.json({ today: result });
  } catch (e) {
    const status = e?.response?.status || e?.code || 500;
    res.status(Number.isInteger(status) ? status : 500).json({ error: "Błąd /calendar/today", details: e?.response?.data?.error?.message || e?.message || "unknown" });
  }
});

app.get("/calendar/tomorrow", async (_req, res) => {
  try {
    if (!userTokens) return res.status(401).json({ error: "Brak autoryzacji", fix: "Wejdź na /oauth2/start" });
    oAuth2Client.setCredentials(userTokens);
    const { timeMin, timeMax } = isoDayRange(1);
    const calendar = google.calendar({ version: "v3", auth: oAuth2Client });
    const events = await calendar.events.list({ calendarId: "primary", timeMin, timeMax, singleEvents: true, orderBy: "startTime" });
    const result = (events.data.items || []).map((ev) => {
      const startISO = ev.start?.dateTime || ev.start?.date || null;
      return `${fmtTime(startISO)} - ${ev.summary || "Bez tytułu"} (${fmtDate(startISO)})`;
    });
    res.json({ tomorrow: result });
  } catch (e) {
    const status = e?.response?.status || e?.code || 500;
    res.status(Number.isInteger(status) ? status : 500).json({ error: "Błąd /calendar/tomorrow", details: e?.response?.data?.error?.message || e?.message || "unknown" });
  }
});

// Pomocniczo: budowa pól start/end (obsługa all-day vs dateTime)
function makeStartEnd({ startISO, endISO, timeZone = "Europe/Warsaw" }) {
  const isDate = (v) => typeof v === "string" && /^\d{4}-\d{2}-\d{2}$/.test(v);
  const start = startISO ? (isDate(startISO) ? { date: startISO, timeZone } : { dateTime: startISO, timeZone }) : undefined;
  const end   = endISO   ? (isDate(endISO)   ? { date: endISO,   timeZone } : { dateTime: endISO,   timeZone }) : undefined;
  return { start, end };
}

// CREATE
app.post("/calendar/create", async (req, res) => {
  try {
    if (!userTokens) return res.status(401).json({ error: "Brak autoryzacji – /oauth2/start" });
    oAuth2Client.setCredentials(userTokens);

    const {
      summary, description, location, startISO, endISO,
      timeZone = "Europe/Warsaw",
      attendeesEmails = [],
      remindersMinutes,
      recurrence = [],
      createMeet = false,
      sendUpdates = "none",
    } = req.body || {};
    if (!summary || !startISO || !endISO) return res.status(400).json({ error: "Wymagane: summary, startISO, endISO" });

    const { start, end } = makeStartEnd({ startISO, endISO, timeZone });
    const event = { summary, description, location, start, end };

    if (Array.isArray(attendeesEmails) && attendeesEmails.length > 0) {
      event.attendees = attendeesEmails.filter((e) => typeof e === "string" && e.includes("@")).map((email) => ({ email }));
    }
    if (typeof remindersMinutes === "number" && remindersMinutes >= 0) {
      event.reminders = { useDefault: false, overrides: [{ method: "popup", minutes: Math.floor(remindersMinutes) }] };
    }
    if (Array.isArray(recurrence) && recurrence.length > 0) event.recurrence = recurrence;

    let confOpt = {};
    if (createMeet === true) {
      event.conferenceData = { createRequest: { requestId: crypto.randomUUID(), conferenceSolutionKey: { type: "hangoutsMeet" } } };
      confOpt = { conferenceDataVersion: 1 };
    }

    const calendar = google.calendar({ version: "v3", auth: oAuth2Client });
    const resp = await calendar.events.insert({ calendarId: "primary", requestBody: event, sendUpdates, ...confOpt });

    return res.json({
      id: resp.data.id, htmlLink: resp.data.htmlLink, status: resp.data.status,
      start: resp.data.start, end: resp.data.end, summary: resp.data.summary,
      hangoutLink: resp.data.hangoutLink || null, conferenceData: resp.data.conferenceData || null,
    });
  } catch (e) {
    const status = e?.response?.status || 500;
    const details = e?.response?.data || { message: e?.message || "unknown" };
    console.error("calendar/create error:", details);
    return res.status(status).json({ error: "calendar_create_failed", status, details });
  }
});

// UPDATE (partial)
app.post("/calendar/update", async (req, res) => {
  try {
    if (!userTokens) return res.status(401).json({ error: "Brak autoryzacji – /oauth2/start" });
    oAuth2Client.setCredentials(userTokens);

    const {
      id, summary, description, location,
      startISO, endISO, timeZone = "Europe/Warsaw",
      attendeesEmails = [],
      remindersMinutes,
      recurrence,
      createMeet = undefined,
      sendUpdates = "none",
    } = req.body || {};
    if (!id) return res.status(400).json({ error: "Wymagane pole: id" });

    const body = {};
    if (summary !== undefined) body.summary = summary;
    if (description !== undefined) body.description = description;
    if (location !== undefined) body.location = location;
    if (startISO || endISO) {
      const { start, end } = makeStartEnd({ startISO, endISO, timeZone });
      if (start) body.start = start;
      if (end) body.end = end;
    }
    if (Array.isArray(attendeesEmails) && attendeesEmails.length > 0) {
      body.attendees = attendeesEmails.filter((e) => typeof e === "string" && e.includes("@")).map((email) => ({ email }));
    }
    if (typeof remindersMinutes === "number" && remindersMinutes >= 0) {
      body.reminders = { useDefault: false, overrides: [{ method: "popup", minutes: Math.floor(remindersMinutes) }] };
    }
    if (recurrence !== undefined) {
      if (Array.isArray(recurrence)) body.recurrence = recurrence;
      else return res.status(400).json({ error: "recurrence musi być tablicą stringów" });
    }
    let confOpt = {};
    if (createMeet === true) {
      body.conferenceData = { createRequest: { requestId: crypto.randomUUID(), conferenceSolutionKey: { type: "hangoutsMeet" } } };
      confOpt = { conferenceDataVersion: 1 };
    }

    const calendar = google.calendar({ version: "v3", auth: oAuth2Client });
    const resp = await calendar.events.patch({ calendarId: "primary", eventId: id, requestBody: body, sendUpdates, ...confOpt });

    return res.json({
      id: resp.data.id, htmlLink: resp.data.htmlLink, status: resp.data.status,
      start: resp.data.start, end: resp.data.end, summary: resp.data.summary, updated: resp.data.updated,
      hangoutLink: resp.data.hangoutLink || null, conferenceData: resp.data.conferenceData || null,
    });
  } catch (e) {
    const status = e?.response?.status || 500;
    const details = e?.response?.data || { message: e?.message || "unknown" };
    console.error("calendar/update error:", details);
    return res.status(status).json({ error: "calendar_update_failed", status, details });
  }
});

// DELETE
app.post("/calendar/delete", async (req, res) => {
  try {
    if (!userTokens) return res.status(401).json({ error: "Brak autoryzacji – /oauth2/start" });
    oAuth2Client.setCredentials(userTokens);
    const { id, sendUpdates = "none" } = req.body || {};
    if (!id) return res.status(400).json({ error: "Wymagane pole: id" });

    const calendar = google.calendar({ version: "v3", auth: oAuth2Client });
    await calendar.events.delete({ calendarId: "primary", eventId: id, sendUpdates });
    return res.json({ ok: true, deletedId: id });
  } catch (e) {
    const status = e?.response?.status || 500;
    const details = e?.response?.data || { message: e?.message || "unknown" };
    console.error("calendar/delete error:", details);
    return res.status(status).json({ error: "calendar_delete_failed", status, details });
  }
});

// QUICKADD
app.post("/calendar/quickadd", async (req, res) => {
  try {
    if (!userTokens) return res.status(401).json({ error: "Brak autoryzacji – /oauth2/start" });
    oAuth2Client.setCredentials(userTokens);
    const { text, sendUpdates = "none" } = req.body || {};
    if (!text || !text.trim()) return res.status(400).json({ error: "Wymagane pole: text" });

    const calendar = google.calendar({ version: "v3", auth: oAuth2Client });
    const resp = await calendar.events.quickAdd({ calendarId: "primary", text, sendUpdates });
    return res.json({ id: resp.data.id, htmlLink: resp.data.htmlLink, status: resp.data.status, start: resp.data.start, end: resp.data.end, summary: resp.data.summary });
  } catch (e) {
    const status = e?.response?.status || 500;
    const details = e?.response?.data || { message: e?.message || "unknown" };
    console.error("calendar/quickadd error:", details);
    return res.status(status).json({ error: "calendar_quickadd_failed", status, details });
  }
});

// INSTANCES (dla serii)
app.get("/calendar/instances", async (req, res) => {
  try {
    if (!userTokens) return res.status(401).json({ error: "Brak autoryzacji – /oauth2/start" });
    oAuth2Client.setCredentials(userTokens);
    const { id, timeMin, timeMax } = req.query || {};
    if (!id) return res.status(400).json({ error: "Wymagane pole query: id (SERIES_ID)" });

    const now = new Date();
    const startDef = timeMin || new Date(now.setHours(0,0,0,0)).toISOString();
    const endDef   = timeMax || new Date(Date.now() + 30*24*3600*1000).toISOString();

    const calendar = google.calendar({ version: "v3", auth: oAuth2Client });
    const resp = await calendar.events.instances({
      calendarId: "primary", eventId: id, timeMin: startDef, timeMax: endDef, showDeleted: true, maxResults: 2500,
    });

    const items = (resp.data.items || []).map(ev => ({
      id: ev.id, recurringEventId: ev.recurringEventId, summary: ev.summary, status: ev.status,
      start: ev.start, end: ev.end, htmlLink: ev.htmlLink,
    }));

    return res.json({ seriesId: id, timeMin: startDef, timeMax: endDef, instances: items });
  } catch (e) {
    const status = e?.response?.status || 500;
    const details = e?.response?.data || { message: e?.message || "unknown" };
    console.error("calendar/instances error:", details);
    return res.status(status).json({ error: "calendar_instances_failed", status, details });
  }
});

// Free/Busy
app.post("/calendar/freebusy", async (req, res) => {
  try {
    if (!userTokens) return res.status(401).json({ error: "Brak autoryzacji – /oauth2/start" });
    oAuth2Client.setCredentials(userTokens);

    const { timeMin, timeMax, attendeesCalendars = [] } = req.body || {};
    const start = timeMin ? new Date(timeMin) : new Date();
    const end   = timeMax ? new Date(timeMax) : new Date(Date.now() + 7 * 24 * 3600 * 1000);
    if (isNaN(start) || isNaN(end) || end <= start) return res.status(400).json({ error: "Nieprawidłowe timeMin/timeMax" });

    const ids = Array.from(new Set(["primary", ...attendeesCalendars])).map(id => ({ id }));
    const calendar = google.calendar({ version: "v3", auth: oAuth2Client });
    const resp = await calendar.freebusy.query({ requestBody: { timeMin: start.toISOString(), timeMax: end.toISOString(), items: ids } });

    const calendars = resp.data.calendars || {};
    const allBusy = [];
    Object.values(calendars).forEach(c => { (c.busy || []).forEach(b => allBusy.push({ start: new Date(b.start), end: new Date(b.end) })); });
    allBusy.sort((a,b)=>a.start-b.start);
    const merged = [];
    for (const iv of allBusy) {
      if (!merged.length || iv.start > merged[merged.length-1].end) merged.push({ ...iv });
      else if (iv.end > merged[merged.length-1].end) merged[merged.length-1].end = iv.end;
    }
    return res.json({
      timeMin: start.toISOString(), timeMax: end.toISOString(),
      calendars, busyCombined: merged.map(iv => ({ start: iv.start.toISOString(), end: iv.end.toISOString() })),
    });
  } catch (e) {
    const status = e?.response?.status || 500;
    const details = e?.response?.data || { message: e?.message || "unknown" };
    console.error("calendar/freebusy error:", details);
    return res.status(status).json({ error: "calendar_freebusy_failed", status, details });
  }
});

// Suggest slots
app.post("/calendar/suggest", async (req, res) => {
  try {
    if (!userTokens) return res.status(401).json({ error: "Brak autoryzacji – /oauth2/start" });
    oAuth2Client.setCredentials(userTokens);

    const {
      timeMin, timeMax, durationMinutes,
      attendeesCalendars = [],
      workHours = { start: "08:00", end: "18:00", timeZone: "Europe/Warsaw" },
      includeWeekends = false,
      bufferMinutesBefore = 0, bufferMinutesAfter = 0,
      stepMinutes = 30, limit = 20,
    } = req.body || {};

    if (!durationMinutes || durationMinutes <= 0) return res.status(400).json({ error: "Wymagane: durationMinutes > 0" });

    const TZloc = workHours.timeZone || "Europe/Warsaw";
    const start = timeMin ? new Date(timeMin) : new Date();
    const end   = timeMax ? new Date(timeMax) : new Date(Date.now() + 7 * 24 * 3600 * 1000);
    if (isNaN(start) || isNaN(end) || end <= start) return res.status(400).json({ error: "Nieprawidłowe timeMin/timeMax" });

    const ids = Array.from(new Set(["primary", ...attendeesCalendars])).map(id => ({ id }));
    const calendar = google.calendar({ version: "v3", auth: oAuth2Client });
    const fb = await calendar.freebusy.query({ requestBody: { timeMin: start.toISOString(), timeMax: end.toISOString(), items: ids } });

    const busy = [];
    Object.values(fb.data.calendars || {}).forEach(c => {
      (c.busy || []).forEach(b => {
        const s = new Date(b.start).getTime() - bufferMinutesBefore * 60000;
        const e = new Date(b.end).getTime()   + bufferMinutesAfter  * 60000;
        busy.push({ start: new Date(s), end: new Date(e) });
      });
    });
    busy.sort((a,b)=>a.start-b.start);
    const merged = [];
    for (const iv of busy) {
      if (!merged.length || iv.start > merged[merged.length-1].end) merged.push({ ...iv });
      else if (iv.end > merged[merged.length-1].end) merged[merged.length-1].end = iv.end;
    }

    const parseHM = (s) => { const [h,m]=String(s).split(":").map(Number); return {h:h||0,m:m||0}; };
    const whStart = parseHM(workHours.start || "08:00");
    const whEnd   = parseHM(workHours.end   || "18:00");
    const dayStartTZ = (d) => { const x = new Date(d.toLocaleString("en-CA", { timeZone: TZloc })); x.setHours(0,0,0,0); return x; };
    const addDays = (d, n) => { const x = new Date(d); x.setDate(x.getDate()+n); return x; };

    const slots = [];
    let cursor = new Date(start);
    const stepMS = stepMinutes * 60000;
    const durMS  = durationMinutes * 60000;

    while (cursor < end && slots.length < limit) {
      const ds = dayStartTZ(cursor);
      const we = ds.getDay(); // 0 nd, 6 sb
      if (!includeWeekends && (we === 0 || we === 6)) { cursor = addDays(ds, 1); continue; }

      const windowStart = new Date(ds); windowStart.setHours(whStart.h, whStart.m, 0, 0);
      const windowEnd   = new Date(ds); windowEnd.setHours(whEnd.h,   whEnd.m,   0, 0);

      const wStart = windowStart < start ? start : windowStart;
      const wEnd   = windowEnd   > end   ? end   : windowEnd;
      if (wEnd <= wStart) { cursor = addDays(ds, 1); continue; }

      let t = new Date(Math.ceil(wStart.getTime() / stepMS) * stepMS);
      while (t.getTime() + durMS <= wEnd.getTime() && slots.length < limit) {
        const slotEnd = new Date(t.getTime() + durMS);
        let conflict = false;
        for (const iv of merged) {
          if (iv.end <= t) continue;
          if (iv.start >= slotEnd) break;
          conflict = true; break;
        }
        if (!conflict) slots.push({ startISO: t.toISOString(), endISO: slotEnd.toISOString() });
        t = new Date(t.getTime() + stepMS);
      }
      cursor = addDays(ds, 1);
    }

    return res.json({
      timeMin: start.toISOString(), timeMax: end.toISOString(),
      durationMinutes, workHours: { start: workHours.start || "08:00", end: workHours.end || "18:00", timeZone: TZloc },
      includeWeekends, stepMinutes, limitRequested: limit, slots,
    });
  } catch (e) {
    const status = e?.response?.status || 500;
    const details = e?.response?.data || { message: e?.message || "unknown" };
    console.error("calendar/suggest error:", details);
    return res.status(status).json({ error: "calendar_suggest_failed", status, details });
  }
});

// ── KALENDARZ: PUSH (webhooki) ─────────────────────────────────────
const PUBLIC_URL = process.env.PUBLIC_URL || process.env.BASE_URL || "https://ai.aneuroasystent.pl";
const WATCH_TOKEN = process.env.WATCH_TOKEN || process.env.SESSION_SECRET || "dev-token";

let CAL_PUSH = { channelId: null, resourceId: null, expiration: null, syncToken: null, lastChanges: [], history: [] };
// wczytaj stan z Redis
(async () => { const saved = await kvGet(PUSH_KEY); if (saved) CAL_PUSH = { ...CAL_PUSH, ...saved }; })();

async function getFreshSyncToken(calendar) {
  let pageToken; let nextSyncToken=null;
  do {
    const resp = await calendar.events.list({ calendarId: "primary", showDeleted: true, singleEvents: true, maxResults: 2500, pageToken });
    pageToken = resp.data.nextPageToken || null;
    nextSyncToken = resp.data.nextSyncToken || nextSyncToken;
  } while (pageToken);
  return nextSyncToken;
}

app.post("/calendar/watch", async (_req, res) => {
  try {
    if (!userTokens) return res.status(401).json({ error: "Brak autoryzacji – /oauth2/start" });
    oAuth2Client.setCredentials(userTokens);
    const calendar = google.calendar({ version: "v3", auth: oAuth2Client });

    const channelId = crypto.randomUUID();
    const address = `${PUBLIC_URL}/calendar/notifications`; // HTTPS publiczny
    const watchResp = await calendar.events.watch({
      calendarId: "primary",
      requestBody: { id: channelId, type: "web_hook", address, token: WATCH_TOKEN }
    });

    CAL_PUSH.channelId = watchResp.data.id || channelId;
    CAL_PUSH.resourceId = watchResp.data.resourceId || null;
    CAL_PUSH.expiration = watchResp.data.expiration || null;
    CAL_PUSH.syncToken = await getFreshSyncToken(calendar);
    await kvSet(PUSH_KEY, CAL_PUSH);

    return res.json({ ok: true, channelId: CAL_PUSH.channelId, resourceId: CAL_PUSH.resourceId, expiration: CAL_PUSH.expiration, syncToken: CAL_PUSH.syncToken, callback: address });
  } catch (e) {
    const status = e?.response?.status || 500;
    const details = e?.response?.data || { message: e?.message || e?.toString() || "unknown" };
    console.error("calendar/watch error:", details);
    return res.status(status).json({ error: "calendar_watch_failed", status, details });
  }
});

app.post("/calendar/watch/stop", async (_req, res) => {
  try {
    if (!userTokens) return res.status(401).json({ error: "Brak autoryzacji – /oauth2/start" });
    if (!CAL_PUSH.channelId || !CAL_PUSH.resourceId) return res.json({ ok: true, alreadyStopped: true });

    oAuth2Client.setCredentials(userTokens);
    const calendar = google.calendar({ version: "v3", auth: oAuth2Client });
    await calendar.channels.stop({ requestBody: { id: CAL_PUSH.channelId, resourceId: CAL_PUSH.resourceId } });

    CAL_PUSH.channelId = null; CAL_PUSH.resourceId = null; CAL_PUSH.expiration = null;
    await kvSet(PUSH_KEY, CAL_PUSH);
    return res.json({ ok: true });
  } catch (e) {
    const status = e?.response?.status || 500;
    const details = e?.response?.data || { message: e?.message || "unknown" };
    console.error("calendar/watch/stop error:", details);
    return res.status(status).json({ error: "calendar_watch_stop_failed", status, details });
  }
});

app.get("/calendar/watch/state", async (_req, res) => {
  return res.json({
    channelId: CAL_PUSH.channelId, resourceId: CAL_PUSH.resourceId, expiration: CAL_PUSH.expiration,
    hasSyncToken: Boolean(CAL_PUSH.syncToken), lastChangesCount: (CAL_PUSH.lastChanges || []).length,
    history: CAL_PUSH.history.slice(-20)
  });
});

app.post("/calendar/notifications", async (req, res) => {
  try {
    const hdr = {
      state: req.get("X-Goog-Resource-State"),
      resId: req.get("X-Goog-Resource-Id"),
      chanId: req.get("X-Goog-Channel-Id"),
      token: req.get("X-Goog-Channel-Token"),
      msgNo: req.get("X-Goog-Message-Number"),
      exp: req.get("X-Goog-Channel-Expiration"),
      uri: req.get("X-Goog-Resource-URI")
    };
    CAL_PUSH.history.push({ ts: new Date().toISOString(), ...hdr });
    if (CAL_PUSH.history.length > 200) CAL_PUSH.history = CAL_PUSH.history.slice(-200);

    if (hdr.chanId && CAL_PUSH.channelId && hdr.chanId !== CAL_PUSH.channelId) return res.status(202).send("Different channel; ignoring");
    if (WATCH_TOKEN && hdr.token && hdr.token !== WATCH_TOKEN) return res.status(403).send("Invalid channel token");

    res.status(200).send("OK"); // szybka odpowiedź

    if (!userTokens || !CAL_PUSH.syncToken) return;
    oAuth2Client.setCredentials(userTokens);
    const calendar = google.calendar({ version: "v3", auth: oAuth2Client });

    let pageToken; const changes = [];
    while (true) {
      try {
        const resp = await calendar.events.list({ calendarId: "primary", syncToken: CAL_PUSH.syncToken, showDeleted: true, singleEvents: true, pageToken });
        (resp.data.items || []).forEach(ev => {
          changes.push({ id: ev.id, status: ev.status, summary: ev.summary, start: ev.start, end: ev.end, updated: ev.updated });
        });
        if (resp.data.nextPageToken) pageToken = resp.data.nextPageToken;
        else { CAL_PUSH.syncToken = resp.data.nextSyncToken || CAL_PUSH.syncToken; break; }
      } catch (err) {
        if (err?.code === 410 || err?.response?.status === 410) { CAL_PUSH.syncToken = await getFreshSyncToken(calendar); break; }
        console.error("notifications diff error:", err?.response?.data || err?.message || err); break;
      }
    }
    CAL_PUSH.lastChanges = changes;
    await kvSet(PUSH_KEY, CAL_PUSH);
  } catch (e) {
    console.error("notifications handler error:", e?.message || e);
  }
});

// ── ROUTES: GMAIL ──────────────────────────────────────────────────
app.get("/gmail/messages", async (req, res) => {
  try {
    const gmail = google.gmail({ version: "v1", auth: oAuth2Client });
    const q = req.query.q || ""; // newer_than:7d subject:faktura
    const resp = await gmail.users.messages.list({ userId: "me", q, maxResults: 10 });

    const items = resp.data.messages || [];
    const details = [];
    for (const m of items) {
      const msg = await gmail.users.messages.get({ userId: "me", id: m.id, format: "metadata", metadataHeaders: ["Subject", "From", "Date"] });
      const headers = msg.data.payload?.headers || [];
      const pick = (name) => headers.find((h) => h.name?.toLowerCase() === name.toLowerCase())?.value || "";
      details.push({ id: m.id, snippet: msg.data.snippet, subject: pick("Subject"), from: pick("From"), date: pick("Date") });
    }
    res.json({ messages: details });
  } catch (e) {
    console.error(e);
    res.status(500).send("Błąd przy pobieraniu Gmaila.");
  }
});

app.post("/gmail/send", async (req, res) => {
  const { to, subject, text, html, from, attachments = [] } = req.body || {};
  if (!to || !subject) return res.status(400).json({ error: "Wymagane pola: to, subject" });
  try {
    const gmail = google.gmail({ version: "v1", auth: oAuth2Client });
    const raw = buildRawEmail({ to, subject, text, html, from, attachments });
    const sendResp = await gmail.users.messages.send({ userId: "me", requestBody: { raw } });
    res.json({ id: sendResp.data.id, labelIds: sendResp.data.labelIds || [] });
  } catch (e) {
    console.error("Błąd wysyłki maila:", e?.response?.data || e);
    res.status(500).send("Błąd wysyłania wiadomości");
  }
});

app.post("/gmail/reply", async (req, res) => {
  try {
    if (!userTokens) return res.status(401).json({ error: "Brak autoryzacji – /oauth2/start" });
    oAuth2Client.setCredentials(userTokens);

    const gmail = google.gmail({ version: "v1", auth: oAuth2Client });
    const { replyToMessageId, threadId: threadIdInput, to: toInput, subject: subjectInput, text, html, attachments = [], inReplyTo: inReplyToInput, references: referencesInput } = req.body || {};
    if (!text && !html) return res.status(400).json({ error: "Wymagane: text lub html" });

    let orig = null;
    if (replyToMessageId) {
      const m = await gmail.users.messages.get({ userId: "me", id: replyToMessageId, format: "metadata", metadataHeaders: ["Message-ID", "References", "Subject", "From", "Reply-To"] });
      orig = { threadId: m.data.threadId, headers: (m.data.payload?.headers || []).reduce((acc, h) => { acc[h.name.toLowerCase()] = h.value; return acc; }, {}) };
    }

    let threadId = threadIdInput || orig?.threadId;
    if (!threadId) return res.status(400).json({ error: "Brak threadId lub replyToMessageId" });

    const origMsgId = orig?.headers?.["message-id"];
    const inReplyTo = inReplyToInput || origMsgId || null;
    let references = referencesInput || null;
    if (!references) { const prevRefs = (orig?.headers?.["references"] || "").trim(); references = [prevRefs, origMsgId].filter(Boolean).join(" ").trim() || null; }

    let subject = subjectInput;
    if (!subject) { const origSubj = orig?.headers?.["subject"] || ""; subject = /^Re:/i.test(origSubj) ? origSubj : `Re: ${origSubj}`; }

    let to = toInput;
    if (!to) to = orig?.headers?.["reply-to"] || orig?.headers?.["from"] || null;
    if (!to) return res.status(400).json({ error: "Nie udało się ustalić odbiorcy (to). Podaj 'to' w body." });

    const headersExtra = {};
    if (inReplyTo) headersExtra["In-Reply-To"] = inReplyTo;
    if (references) headersExtra["References"] = references;

    const raw = buildRawEmail({ to, subject, text, html, attachments, headersExtra });
    const sendResp = await gmail.users.messages.send({ userId: "me", requestBody: { raw, threadId } });
    return res.json({ id: sendResp.data.id, threadId: sendResp.data.threadId || threadId, labelIds: sendResp.data.labelIds || [] });
  } catch (e) {
    const status = e?.response?.status || 500;
    const details = e?.response?.data || { message: e?.message || "unknown" };
    console.error("gmail/reply error:", details);
    return res.status(status).json({ error: "gmail_reply_failed", status, details });
  }
});

// ── ROUTES: DRIVE ──────────────────────────────────────────────────
app.get("/drive/search", async (req, res) => {
  try {
    const drive = google.drive({ version: "v3", auth: oAuth2Client });
    const q = req.query.q || "";
    const resp = await drive.files.list({ q: `name contains '${q.replace(/'/g, "\\'")}'`, pageSize: 10, fields: "files(id, name, mimeType, modifiedTime)" });
    res.json(resp.data.files || []);
  } catch (e) {
    console.error(e);
    res.status(500).send("Błąd wyszukiwania Drive");
  }
});

// ── ROUTES: PLACES (Google Places API – NEW) ───────────────────────
app.get("/places/search", async (req, res) => {
  try {
    const apiKey = process.env.GOOGLE_MAPS_API_KEY;
    if (!apiKey) return res.status(500).json({ error: "Brak GOOGLE_MAPS_API_KEY w zmiennych środowiskowych (.env)" });

    const { q = "", lat = 52.2297, lng = 21.0122, radius = 3000 } = req.query;
    const url = "https://places.googleapis.com/v1/places:searchText";
    const fieldMask = [
      "places.id","places.displayName","places.formattedAddress","places.location",
      "places.rating","places.userRatingCount","places.types",
      "places.currentOpeningHours.weekdayDescriptions","places.nationalPhoneNumber","places.websiteUri",
    ].join(",");
    const body = {
      textQuery: String(q), languageCode: "pl",
      locationBias: { circle: { center: { latitude: Number(lat), longitude: Number(lng) }, radius: Number(radius) } },
    };
    const resp = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Goog-Api-Key": apiKey, "X-Goog-FieldMask": fieldMask },
      body: JSON.stringify(body),
    });
    const data = await resp.json();
    if (!resp.ok) return res.status(502).json({ error: "Błąd Google Places (New)", status: resp.status, message: data?.error?.message || null });

    const results = (data.places || []).map((p) => ({
      place_name: p.id || null, displayName: p.displayName?.text || null, address: p.formattedAddress || null,
      rating: p.rating ?? null, user_ratings_total: p.userRatingCount ?? null, phone: p.nationalPhoneNumber || null, website: p.websiteUri || null,
      open_weekdays: p.currentOpeningHours?.weekdayDescriptions || [],
      location: { lat: p.location?.latitude ?? null, lng: p.location?.longitude ?? null }, types: p.types || [],
    }));
    res.json({ query: q, lat: Number(lat), lng: Number(lng), radius: Number(radius), results });
  } catch (e) {
    console.error("Places NEW search error:", e);
    res.status(500).json({ error: "Błąd wyszukiwania miejsc (New API)" });
  }
});

app.get("/places/details", async (req, res) => {
  try {
    const apiKey = process.env.GOOGLE_MAPS_API_KEY;
    let { place_id } = req.query; // w New API: "places/XXXX"
    if (!apiKey) return res.status(500).json({ error: "Brak GOOGLE_MAPS_API_KEY" });
    if (!place_id) return res.status(400).json({ error: "Brak parametru place_id" });
    if (!String(place_id).startsWith("places/")) place_id = `places/${place_id}`;

    const fieldMask = [
      "id","displayName","formattedAddress","location","rating","userRatingCount",
      "currentOpeningHours.weekdayDescriptions","nationalPhoneNumber","internationalPhoneNumber","websiteUri","types",
    ].join(",");
    const url = `https://places.googleapis.com/v1/${encodeURIComponent(place_id)}?languageCode=pl&fields=${encodeURIComponent(fieldMask)}`;
    const resp = await fetch(url, { headers: { "X-Goog-Api-Key": apiKey } });
    const data = await resp.json();
    if (!resp.ok) return res.status(502).json({ error: "Błąd Google Places Details (New)", status: resp.status, message: data?.error?.message || null });

    const p = data || {};
    const details = {
      place_name: p.id || null, name: p.displayName?.text || null, address: p.formattedAddress || null,
      phone: p.nationalPhoneNumber || p.internationalPhoneNumber || null, website: p.websiteUri || null,
      rating: p.rating ?? null, user_ratings_total: p.userRatingCount ?? null,
      open_weekdays: p.currentOpeningHours?.weekdayDescriptions || [],
      location: { lat: p.location?.latitude ?? null, lng: p.location?.longitude ?? null }, types: p.types || [],
    };
    res.json(details);
  } catch (e) {
    console.error("Places NEW details error:", e);
    res.status(500).json({ error: "Błąd pobierania szczegółów miejsca (New API)" });
  }
});

// ── START ──────────────────────────────────────────────────────────
const server = app.listen(PORT, () => {
  console.log(`✅ Serwer nasłuchuje na http://localhost:${PORT}`);
  console.log("DEBUG REDIRECT_URI =", (process.env.GOOGLE_REDIRECT_URI || "").trim());
  console.log("MAPS KEY set?:", Boolean(process.env.GOOGLE_MAPS_API_KEY));
});
server.on("error", (err) => console.error("❌ Błąd przy app.listen:", err));
