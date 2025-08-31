// app.js
import express from "express";
import dotenv from "dotenv";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { google } from "googleapis";

dotenv.config();

// --- Globalne łapacze błędów / logi startowe ---
process.on("uncaughtException", (err) => {
  console.error("❌ uncaughtException:", err);
});
process.on("unhandledRejection", (reason) => {
  console.error("❌ unhandledRejection:", reason);
});

// ── ŚCIEŻKI I PODSTAWY ──────────────────────────────────────────────
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();

const PORT = process.env.PORT || 8080;
const TZ = "Europe/Warsaw";
const TOKEN_PATH = path.join(__dirname, "tokens.json");

// Body parser do POST /gmail/send (większy limit na załączniki)
app.use(express.json({ limit: "25mb" }));
app.use(express.urlencoded({ extended: true, limit: "25mb" }));

// Proste endpointy zdrowia
app.get("/", (_req, res) => res.send("OK"));
app.get("/health", (_req, res) => res.json({ ok: true }));

// Serwowanie PUBLICZNEJ specyfikacji OpenAPI (tylko bezpieczne endpointy)
app.get("/openapi-public.yaml", (_req, res) => {
  res.type("text/yaml; charset=utf-8");
  res.sendFile(path.join(__dirname, "openapi-public.yaml"));
});

// Serwowanie specyfikacji OpenAPI (plik obok app.js)
app.get("/openapi.yaml", (_req, res) => {
  res.type("text/yaml; charset=utf-8");
  res.sendFile(path.join(__dirname, "openapi.yaml"));
});

// Debug: pokaż zarejestrowane trasy
app.get("/debug/routes", (_req, res) => {
  const routes =
    app._router?.stack
      ?.filter((r) => r.route && r.route.path)
      ?.map((r) => ({
        method: Object.keys(r.route.methods)[0]?.toUpperCase(),
        path: r.route.path,
      })) || [];
  res.json(routes);
});

// ── GOOGLE OAUTH2 ──────────────────────────────────────────────────
// --- SCOPES: pełny dostęp do Kalendarza + Gmail (wysyłka/odczyt) + Drive readonly ---
const SCOPES = [
  "https://www.googleapis.com/auth/gmail.readonly",
  "https://www.googleapis.com/auth/gmail.send",
  "https://www.googleapis.com/auth/drive.readonly",
  "https://www.googleapis.com/auth/calendar" // <-- pełny R/W do kalendarza (zamiast calendar.readonly)
];


const oAuth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  (process.env.GOOGLE_REDIRECT_URI || "").trim()
);

// Wczytaj tokeny z pliku (jeśli są)
let userTokens = null;
if (fs.existsSync(TOKEN_PATH)) {
  try {
    userTokens = JSON.parse(fs.readFileSync(TOKEN_PATH, "utf-8"));
    oAuth2Client.setCredentials(userTokens);
  } catch (e) {
    console.error("Nie udało się wczytać tokens.json:", e);
  }
}

// ── POMOCNICZE ─────────────────────────────────────────────────────
function isoDayRange(offsetDays = 0) {
  // Bezpieczne wyznaczenie północy w strefie TZ, bez parsowania locale-stringów
  const now = new Date();
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: TZ,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).formatToParts(now);
  const y = Number(parts.find((p) => p.type === "year").value);
  const m = Number(parts.find((p) => p.type === "month").value);
  const d = Number(parts.find((p) => p.type === "day").value);
  const startUTC = new Date(Date.UTC(y, m - 1, d + offsetDays, 0, 0, 0, 0));
  const endUTC = new Date(Date.UTC(y, m - 1, d + offsetDays + 1, 0, 0, 0, 0));
  return { timeMin: startUTC.toISOString(), timeMax: endUTC.toISOString() };
}

const fmtTime = (iso) => {
  try {
    if (!iso) return "brak";
    const d = new Date(iso);
    if (isNaN(d)) return "brak";
    return new Intl.DateTimeFormat("pl-PL", {
      timeZone: TZ,
      hour: "2-digit",
      minute: "2-digit",
    }).format(d);
  } catch {
    return "brak";
  }
};

const fmtDate = (iso) => {
  try {
    if (!iso) return "brak";
    const d = new Date(iso);
    if (isNaN(d)) return "brak";
    return new Intl.DateTimeFormat("pl-PL", {
      timeZone: TZ,
      dateStyle: "long",
    }).format(d);
  } catch {
    return "brak";
  }
};

// Gmail: MIME builder – HTML + plain text + attachments (multipart/mixed) + extra headers
function buildRawEmail({ to, subject, text, html, from, attachments = [], headersExtra = {} }) {
  const encSubject = subject
    ? `=?UTF-8?B?${Buffer.from(subject, "utf-8").toString("base64")}?=`
    : "";

  const fallbackText =
    text ||
    (html ? html.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim() : "");

  const b64wrap = (s) => (s || "").match(/.{1,76}/g)?.join("\r\n") || "";

  // multipart/alternative (text + html)
  const altBoundary = "bndry_alt_" + Date.now().toString(36);
  const altPart = [
    `--${altBoundary}`,
    "Content-Type: text/plain; charset=UTF-8",
    "Content-Transfer-Encoding: 8bit",
    "",
    fallbackText || "",
    "",
    `--${altBoundary}`,
    "Content-Type: text/html; charset=UTF-8",
    "Content-Transfer-Encoding: 8bit",
    "",
    html ||
      `<html><body><pre style="font-family: inherit">${(text || "")
        .replace(/</g, "&lt;")
        .trim()}</pre></body></html>`,
    "",
    `--${altBoundary}--`,
    "",
  ].join("\r\n");

  // Bazowe nagłówki
  let headers = [
    `To: ${to}`,
    from ? `From: ${from}` : "",
    `Subject: ${encSubject}`,
    "MIME-Version: 1.0",
  ].filter(Boolean);

  // Dodatkowe nagłówki (np. In-Reply-To, References)
  if (headersExtra && typeof headersExtra === "object") {
    for (const [k, v] of Object.entries(headersExtra)) {
      if (v) headers.push(`${k}: ${v}`);
    }
  }

  let finalMime = "";

  if (attachments.length > 0) {
    // multipart/mixed: najpierw alternative, potem każdy załącznik
    const mixBoundary = "bndry_mix_" + Math.random().toString(36).slice(2);
    headers.push(`Content-Type: multipart/mixed; boundary="${mixBoundary}"`);

    const parts = [
      "", // pusta linia po nagłówkach
      `--${mixBoundary}`,
      `Content-Type: multipart/alternative; boundary="${altBoundary}"`,
      "",
      altPart.trim(),
    ];

    for (const att of attachments) {
      const filename = att.filename || "attachment";
      const mimeType = att.mimeType || "application/octet-stream";
      const dataB64 = att.data || att.dataBase64 || ""; // oczekujemy czystej base64

      parts.push(
        `--${mixBoundary}`,
        `Content-Type: ${mimeType}; name="${filename}"`,
        "Content-Transfer-Encoding: base64",
        `Content-Disposition: attachment; filename="${filename}"`,
        "",
        b64wrap(dataB64),
        ""
      );
    }

    parts.push(`--${mixBoundary}--`, "");
    finalMime = headers.join("\r\n") + "\r\n" + parts.join("\r\n");
  } else {
    // tylko multipart/alternative
    headers.push(`Content-Type: multipart/alternative; boundary="${altBoundary}"`);
    finalMime = headers.join("\r\n") + "\r\n\r\n" + altPart;
  }

  return Buffer.from(finalMime, "utf-8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

// ── ROUTES: AUTH ────────────────────────────────────────────────────
app.get("/oauth2/start", (_req, res) => {
  const url = oAuth2Client.generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    scope: SCOPES,
  });
  res.redirect(url);
});

app.get("/oauth2/callback", async (req, res) => {
  const code = req.query.code;
  if (!code) return res.status(400).send("Brak ?code w URL");
  try {
    const { tokens } = await oAuth2Client.getToken(code);
    userTokens = tokens;
    oAuth2Client.setCredentials(tokens);
    fs.writeFileSync(TOKEN_PATH, JSON.stringify(tokens, null, 2));
    res.send("✅ Autoryzacja OK. Token zapisany. Możesz sprawdzić /auth/status");
  } catch (e) {
    console.error("Błąd pobierania tokenów:", e);
    res.status(500).send("❌ Błąd pobierania tokenów");
  }
});

// Sprawdzenie statusu autoryzacji (tekstowo)
app.get("/auth/status", async (_req, res) => {
  if (!userTokens) return res.send("🔴 Brak tokenów. Zaloguj: /oauth2/start");
  const hasRefresh = Boolean(userTokens.refresh_token);
  res.send(`🟢 Tokeny obecne. refresh_token: ${hasRefresh ? "TAK" : "NIE"}`);
});

// Podgląd scope’ów (jakie uprawnienia ma token)
app.get("/auth/tokeninfo", async (_req, res) => {
  try {
    if (!userTokens?.access_token) {
      return res.status(400).json({ error: "Brak access_token – zaloguj: /oauth2/start" });
    }
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
    return res.status(500).json({
      error: "Nie można pobrać tokeninfo",
      details: e?.response?.data?.error_description || e?.message || "unknown",
    });
  }
});

// Reset tokenów z prostym zabezpieczeniem nagłówkiem
app.get("/auth/reset", (req, res) => {
  try {
    const adminToken = process.env.RESET_TOKEN || "";
    const provided = req.header("x-admin-token") || "";
    if (!adminToken || provided !== adminToken) {
      return res.status(403).json({ error: "Forbidden: invalid x-admin-token" });
    }

    if (fs.existsSync(TOKEN_PATH)) fs.unlinkSync(TOKEN_PATH);
    userTokens = null;
    res.send("✅ tokens.json usunięty. Zaloguj ponownie: /oauth2/start");
  } catch (err) {
    console.error("Błąd przy usuwaniu tokenów:", err);
    res.status(500).send("❌ Błąd przy usuwaniu tokenów.");
  }
});


// ── ROUTES: CALENDAR ───────────────────────────────────────────────
app.get("/calendar/events/json", async (_req, res) => {
  try {
    if (!userTokens) {
      return res.status(401).json({
        error: "Brak autoryzacji",
        fix: "Przejdź /oauth2/start, a jeśli wcześniej autoryzowałaś/eś bez Kalendarza → /auth/reset i ponownie /oauth2/start",
      });
    }

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
      hint:
        "Najczęściej: brak scope calendar.readonly, nieważny token, wyłączone Calendar API. Spróbuj /auth/reset → /oauth2/start.",
    });
  }
});

// Pojedyncze wydarzenie (z lepszą walidacją i 404)
app.get("/calendar/event", async (req, res) => {
  const id = (req.query.id || "").trim();

  if (!id || /^TU_WKLEJ_ID$/i.test(id)) {
    return res.status(400).json({
      error: "Brak poprawnego parametru ?id",
      hint:
        "Najpierw wywołaj /calendar/events/json i skopiuj pole 'id' z któregoś wydarzenia.",
      example: "/calendar/event?id=7k2q3l8f9n3p4t...",
    });
  }

  try {
    const calendar = google.calendar({ version: "v3", auth: oAuth2Client });
    const ev = await calendar.events.get({ calendarId: "primary", eventId: id });
    return res.json(ev.data);
  } catch (e) {
    console.error("calendar/event error:", e?.response?.data || e);
    const status = e?.code || e?.response?.status || 500;

    if (status === 404) {
      return res.status(404).json({
        error: "Wydarzenie nie znalezione",
        id,
        hint:
          "Upewnij się, że ID pochodzi z /calendar/events/json i należy do kalendarza 'primary'.",
      });
    }
    return res.status(500).json({ error: "Błąd pobierania wydarzenia" });
  }
});

// Dzisiejsze wydarzenia
app.get("/calendar/today", async (_req, res) => {
  try {
    if (!userTokens) {
      return res.status(401).json({
        error: "Brak autoryzacji",
        fix: "Wejdź na /oauth2/start (albo /auth/reset → /oauth2/start jeśli wcześniej brakowało zgody na Kalendarz)"
      });
    }
    // dla pewności ustawiamy kredencjały (gdyby proces się przeładował)
    oAuth2Client.setCredentials(userTokens);

    const { timeMin, timeMax } = isoDayRange(0);
    const calendar = google.calendar({ version: "v3", auth: oAuth2Client });
    const events = await calendar.events.list({
      calendarId: "primary",
      timeMin,
      timeMax,
      singleEvents: true,
      orderBy: "startTime",
    });
    const result = (events.data.items || []).map((ev) => {
      const startISO = ev.start?.dateTime || ev.start?.date || null;
      return `${fmtTime(startISO)} - ${ev.summary || "Bez tytułu"} (${fmtDate(startISO)})`;
    });
    res.json({ today: result });
  } catch (e) {
    console.error("calendar/today error:", e?.response?.data || e);
    const status = e?.response?.status || e?.code || 500;
    res.status(Number.isInteger(status) ? status : 500).json({
      error: "Błąd /calendar/today",
      details: e?.response?.data?.error?.message || e?.message || "unknown"
    });
  }
});

// Jutrzejsze wydarzenia
app.get("/calendar/tomorrow", async (_req, res) => {
  try {
    if (!userTokens) {
      return res.status(401).json({
        error: "Brak autoryzacji",
        fix: "Wejdź na /oauth2/start (albo /auth/reset → /oauth2/start jeśli wcześniej brakowało zgody na Kalendarz)"
      });
    }
    oAuth2Client.setCredentials(userTokens);

    const { timeMin, timeMax } = isoDayRange(1);
    const calendar = google.calendar({ version: "v3", auth: oAuth2Client });
    const events = await calendar.events.list({
      calendarId: "primary",
      timeMin,
      timeMax,
      singleEvents: true,
      orderBy: "startTime",
    });
    const result = (events.data.items || []).map((ev) => {
      const startISO = ev.start?.dateTime || ev.start?.date || null;
      return `${fmtTime(startISO)} - ${ev.summary || "Bez tytułu"} (${fmtDate(startISO)})`;
    });
    res.json({ tomorrow: result });
  } catch (e) {
    console.error("calendar/tomorrow error:", e?.response?.data || e);
    const status = e?.response?.status || e?.code || 500;
    res.status(Number.isInteger(status) ? status : 500).json({
      error: "Błąd /calendar/tomorrow",
      details: e?.response?.data?.error?.message || e?.message || "unknown"
    });
  }
});

// Tworzenie wydarzenia: POST /calendar/create
// Body JSON: { summary, startISO, endISO, timeZone? }
app.post("/calendar/create", async (req, res) => {
  try {
    if (!userTokens) {
      return res.status(401).json({
        error: "Brak autoryzacji",
        fix: "Wejdź na /oauth2/start (albo /auth/reset → /oauth2/start)"
      });
    }
    oAuth2Client.setCredentials(userTokens);

    const { summary, startISO, endISO, timeZone = "Europe/Warsaw", description } = req.body || {};
    if (!summary || !startISO || !endISO) {
      return res.status(400).json({
        error: "Wymagane pola: summary, startISO, endISO",
        example: {
          summary: "Spotkanie",
          startISO: "2025-09-01T10:00:00+02:00",
          endISO: "2025-09-01T11:00:00+02:00",
          timeZone: "Europe/Warsaw"
        }
      });
    }

    const calendar = google.calendar({ version: "v3", auth: oAuth2Client });
    const resp = await calendar.events.insert({
      calendarId: "primary",
      requestBody: {
        summary,
        description: description || undefined,
        start: { dateTime: startISO, timeZone },
        end: { dateTime: endISO, timeZone }
      }
    });

    return res.json({
      id: resp.data.id,
      htmlLink: resp.data.htmlLink,
      status: resp.data.status
    });
  } catch (e) {
    console.error("calendar/create error:", e?.response?.data || e);
    res.status(500).json({ error: "Błąd tworzenia wydarzenia" });
  }
});

// Pomocniczo: budowa pól start/end (obsługa all-day vs dateTime)
function makeStartEnd({ startISO, endISO, timeZone = "Europe/Warsaw" }) {
  const isDate = (v) => typeof v === "string" && /^\d{4}-\d{2}-\d{2}$/.test(v);
  const start = startISO
    ? (isDate(startISO)
        ? { date: startISO, timeZone }
        : { dateTime: startISO, timeZone })
    : undefined;
  const end = endISO
    ? (isDate(endISO)
        ? { date: endISO, timeZone }
        : { dateTime: endISO, timeZone })
    : undefined;
  return { start, end };
}

/**
 * Aktualizacja (partial, PATCH) wydarzenia w kalendarzu
 * POST /calendar/update
 * Body JSON: {
 *   id: string (wymagane),
 *   summary?, description?, location?,
 *   startISO?, endISO?, timeZone?,
 *   attendeesEmails?: string[],         // ["a@b.pl","c@d.pl"]
 *   remindersMinutes?: number,          // np. 10 (popup)
 *   sendUpdates?: "all"|"externalOnly"|"none" (domyślnie "none")
 * }
 */
app.post("/calendar/update", async (req, res) => {
  try {
    if (!userTokens) {
      return res.status(401).json({ error: "Brak autoryzacji – /oauth2/start" });
    }
    oAuth2Client.setCredentials(userTokens);

    const {
      id,
      summary,
      description,
      location,
      startISO,
      endISO,
      timeZone = "Europe/Warsaw",
      attendeesEmails = [],
      remindersMinutes,
      sendUpdates = "none",
    } = req.body || {};

    if (!id) {
      return res.status(400).json({ error: "Wymagane pole: id" });
    }

    // requestBody tylko z polami, które podano
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
      body.attendees = attendeesEmails
        .filter((e) => typeof e === "string" && e.includes("@"))
        .map((email) => ({ email }));
    }

    if (typeof remindersMinutes === "number" && remindersMinutes >= 0) {
      body.reminders = {
        useDefault: false,
        overrides: [{ method: "popup", minutes: Math.floor(remindersMinutes) }],
      };
    }

    const calendar = google.calendar({ version: "v3", auth: oAuth2Client });
    const resp = await calendar.events.patch({
      calendarId: "primary",
      eventId: id,
      requestBody: body,
      sendUpdates,
    });

    return res.json({
      id: resp.data.id,
      htmlLink: resp.data.htmlLink,
      status: resp.data.status,
      start: resp.data.start,
      end: resp.data.end,
      summary: resp.data.summary,
      updated: resp.data.updated,
    });
  } catch (e) {
    const status = e?.response?.status || 500;
    const details = e?.response?.data || { message: e?.message || "unknown" };
    console.error("calendar/update error:", details);
    return res.status(status).json({ error: "calendar_update_failed", status, details });
  }
});

/**
 * Usuwanie wydarzenia
 * POST /calendar/delete
 * Body JSON: { id: string (wymagane), sendUpdates?: "all"|"externalOnly"|"none" }
 *
 * Uwaga: dla wydarzeń cyklicznych możesz przekazać ID instancji
 * w postaci "SERIES_ID_YYYYMMDDTHHMMSSZ", aby skasować TYLKO tę instancję.
 */
app.post("/calendar/delete", async (req, res) => {
  try {
    if (!userTokens) {
      return res.status(401).json({ error: "Brak autoryzacji – /oauth2/start" });
    }
    oAuth2Client.setCredentials(userTokens);

    const { id, sendUpdates = "none" } = req.body || {};
    if (!id) return res.status(400).json({ error: "Wymagane pole: id" });

    const calendar = google.calendar({ version: "v3", auth: oAuth2Client });
    await calendar.events.delete({
      calendarId: "primary",
      eventId: id,
      sendUpdates,
    });

    return res.json({ ok: true, deletedId: id });
  } catch (e) {
    const status = e?.response?.status || 500;
    const details = e?.response?.data || { message: e?.message || "unknown" };
    console.error("calendar/delete error:", details);
    return res.status(status).json({ error: "calendar_delete_failed", status, details });
  }
});

/**
 * (BONUS) Szybkie dodawanie "naturalnym językiem"
 * POST /calendar/quickadd
 * Body JSON: { text: string (wymagane), sendUpdates?: "all"|"externalOnly"|"none" }
 * Przykład: "Spotkanie z Kasią jutro 10:00-11:00"
 */
app.post("/calendar/quickadd", async (req, res) => {
  try {
    if (!userTokens) {
      return res.status(401).json({ error: "Brak autoryzacji – /oauth2/start" });
    }
    oAuth2Client.setCredentials(userTokens);

    const { text, sendUpdates = "none" } = req.body || {};
    if (!text || !text.trim()) {
      return res.status(400).json({ error: "Wymagane pole: text" });
    }

    const calendar = google.calendar({ version: "v3", auth: oAuth2Client });
    const resp = await calendar.events.quickAdd({
      calendarId: "primary",
      text,
      sendUpdates,
    });

    return res.json({
      id: resp.data.id,
      htmlLink: resp.data.htmlLink,
      status: resp.data.status,
      start: resp.data.start,
      end: resp.data.end,
      summary: resp.data.summary,
    });
  } catch (e) {
    const status = e?.response?.status || 500;
    const details = e?.response?.data || { message: e?.message || "unknown" };
    console.error("calendar/quickadd error:", details);
    return res.status(status).json({ error: "calendar_quickadd_failed", status, details });
  }
});


// ── ROUTES: GMAIL (READ + SEND) ────────────────────────────────────
app.get("/gmail/messages", async (req, res) => {
  try {
    const gmail = google.gmail({ version: "v1", auth: oAuth2Client });
    const q = req.query.q || ""; // np. newer_than:7d subject:faktura
    const resp = await gmail.users.messages.list({
      userId: "me",
      q,
      maxResults: 10,
    });

    const items = resp.data.messages || [];
    const details = [];
    for (const m of items) {
      const msg = await gmail.users.messages.get({
        userId: "me",
        id: m.id,
        format: "metadata",
        metadataHeaders: ["Subject", "From", "Date"],
      });
      const headers = msg.data.payload?.headers || [];
      const pick = (name) =>
        headers.find((h) => h.name?.toLowerCase() === name.toLowerCase())?.value ||
        "";
      details.push({
        id: m.id,
        snippet: msg.data.snippet,
        subject: pick("Subject"),
        from: pick("From"),
        date: pick("Date"),
      });
    }
    res.json({ messages: details });
  } catch (e) {
    console.error(e);
    res.status(500).send("Błąd przy pobieraniu Gmaila.");
  }
});

// Wysyłka maila: POST /gmail/send  { to, subject, text, html, [from] }
app.post("/gmail/send", async (req, res) => {
  const { to, subject, text, html, from, attachments = [] } = req.body || {};
  if (!to || !subject) {
    return res.status(400).json({ error: "Wymagane pola: to, subject" });
  }
  try {
    const gmail = google.gmail({ version: "v1", auth: oAuth2Client });
    const raw = buildRawEmail({ to, subject, text, html, from, attachments });
    const sendResp = await gmail.users.messages.send({
      userId: "me",
      requestBody: { raw },
    });
    res.json({ id: sendResp.data.id, labelIds: sendResp.data.labelIds || [] });
  } catch (e) {
    console.error("Błąd wysyłki maila:", e?.response?.data || e);
    res.status(500).send("Błąd wysyłania wiadomości");
  }
});

// Odpowiedź w wątku: POST /gmail/reply
// Body JSON: { replyToMessageId?, threadId?, to?, subject?, text?, html?, attachments?[] }
app.post("/gmail/reply", async (req, res) => {
  try {
    if (!userTokens) {
      return res.status(401).json({ error: "Brak autoryzacji – /oauth2/start" });
    }
    oAuth2Client.setCredentials(userTokens);

    const gmail = google.gmail({ version: "v1", auth: oAuth2Client });
    const {
      replyToMessageId, // ID wiadomości z Gmail API (z naszego /gmail/messages)
      threadId: threadIdInput,
      to: toInput,
      subject: subjectInput,
      text,
      html,
      attachments = [],
      inReplyTo: inReplyToInput,  // opcjonalnie surowy Message-ID z nagłówka
      references: referencesInput // opcjonalnie References
    } = req.body || {};

    if (!text && !html) {
      return res.status(400).json({ error: "Wymagane: text lub html" });
    }

    // Jeżeli mamy replyToMessageId – pobierz metadane, żeby:
    // - znać prawdziwy Message-ID (nagłówek), References, Subject, Reply-To/From
    // - znać threadId, jeżeli nie podano
    let orig = null;
    if (replyToMessageId) {
      const m = await gmail.users.messages.get({
        userId: "me",
        id: replyToMessageId,
        format: "metadata",
        metadataHeaders: ["Message-ID", "References", "Subject", "From", "Reply-To"]
      });
      orig = {
        threadId: m.data.threadId,
        headers: (m.data.payload?.headers || []).reduce((acc, h) => {
          acc[h.name.toLowerCase()] = h.value;
          return acc;
        }, {})
      };
    }

    // Ustal threadId
    let threadId = threadIdInput || orig?.threadId;
    if (!threadId) {
      return res.status(400).json({ error: "Brak threadId lub replyToMessageId" });
    }

    // Ustal In-Reply-To i References
    const origMsgId = orig?.headers?.["message-id"]; // np. "<xxxx@mail.gmail.com>"
    const inReplyTo = inReplyToInput || origMsgId || null;

    // References: stare + bieżące Message-ID
    let references = referencesInput || null;
    if (!references) {
      const prevRefs = (orig?.headers?.["references"] || "").trim();
      references = [prevRefs, origMsgId].filter(Boolean).join(" ").trim() || null;
    }

    // Ustal Subject (Re: ...)
    let subject = subjectInput;
    if (!subject) {
      const origSubj = orig?.headers?.["subject"] || "";
      subject = /^Re:/i.test(origSubj) ? origSubj : `Re: ${origSubj}`;
    }

    // Ustal To (Reply-To > From)
    let to = toInput;
    if (!to) {
      to = orig?.headers?.["reply-to"] || orig?.headers?.["from"] || null;
    }

    if (!to) {
      return res.status(400).json({ error: "Nie udało się ustalić odbiorcy (to). Podaj 'to' w body." });
    }

    // Zbuduj MIME z dodatkowymi nagłówkami
    const headersExtra = {};
    if (inReplyTo) headersExtra["In-Reply-To"] = inReplyTo;
    if (references) headersExtra["References"] = references;

    const raw = buildRawEmail({
      to, subject, text, html, attachments,
      headersExtra
    });

    // Wyślij w obrębie wątku
    const sendResp = await gmail.users.messages.send({
      userId: "me",
      requestBody: { raw, threadId }
    });

    return res.json({
      id: sendResp.data.id,
      threadId: sendResp.data.threadId || threadId,
      labelIds: sendResp.data.labelIds || []
    });
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
    const resp = await drive.files.list({
      q: `name contains '${q.replace(/'/g, "\\'")}'`,
      pageSize: 10,
      fields: "files(id, name, mimeType, modifiedTime)",
    });
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
    if (!apiKey) {
      return res
        .status(500)
        .json({ error: "Brak GOOGLE_MAPS_API_KEY w zmiennych środowiskowych (.env)" });
    }

    const {
      q = "",
      lat = 52.2297,
      lng = 21.0122,
      radius = 3000, // metry
    } = req.query;

    const url = "https://places.googleapis.com/v1/places:searchText";

    // Pola, które chcemy dostać (FieldMask - wymagane w Places API New)
    const fieldMask = [
      "places.id",
      "places.displayName",
      "places.formattedAddress",
      "places.location",
      "places.rating",
      "places.userRatingCount",
      "places.types",
      "places.currentOpeningHours.weekdayDescriptions",
      "places.nationalPhoneNumber",
      "places.websiteUri",
    ].join(",");

    const body = {
      textQuery: String(q),
      languageCode: "pl",
      locationBias: {
        circle: {
          center: { latitude: Number(lat), longitude: Number(lng) },
          radius: Number(radius),
        },
      },
    };

    const resp = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Goog-Api-Key": apiKey,
        "X-Goog-FieldMask": fieldMask,
      },
      body: JSON.stringify(body),
    });

    const data = await resp.json();

    if (!resp.ok) {
      return res.status(502).json({
        error: "Błąd Google Places (New)",
        status: resp.status,
        message: data?.error?.message || null,
      });
    }

    const results = (data.places || []).map((p) => ({
      // Uwaga: w nowym API ID ma postać "places/XXXX"
      place_name: p.id || null, // np. "places/ChIJ..."
      displayName: p.displayName?.text || null,
      address: p.formattedAddress || null,
      rating: p.rating ?? null,
      user_ratings_total: p.userRatingCount ?? null,
      phone: p.nationalPhoneNumber || null,
      website: p.websiteUri || null,
      open_weekdays: p.currentOpeningHours?.weekdayDescriptions || [],
      location: {
        lat: p.location?.latitude ?? null,
        lng: p.location?.longitude ?? null,
      },
      types: p.types || [],
    }));

    res.json({
      query: q,
      lat: Number(lat),
      lng: Number(lng),
      radius: Number(radius),
      results,
    });
  } catch (e) {
    console.error("Places NEW search error:", e);
    res.status(500).json({ error: "Błąd wyszukiwania miejsc (New API)" });
  }
});

// Szczegóły miejsca (Google Places API – NEW)
app.get("/places/details", async (req, res) => {
  try {
    const apiKey = process.env.GOOGLE_MAPS_API_KEY;
    let { place_id } = req.query; // UWAGA: w New API to tak naprawdę "resource name"

    if (!apiKey) {
      return res
        .status(500)
        .json({ error: "Brak GOOGLE_MAPS_API_KEY w zmiennych środowiskowych (.env)" });
    }
    if (!place_id) {
      return res.status(400).json({ error: "Brak parametru place_id" });
    }

    // W Places API New identyfikator ma postać "places/XXXX".
    // Jeśli użytkownik podał stare ID (bez prefiksu), dodajmy "places/".
    if (!String(place_id).startsWith("places/")) {
      place_id = `places/${place_id}`;
    }

    const fieldMask = [
      "id",
      "displayName",
      "formattedAddress",
      "location",
      "rating",
      "userRatingCount",
      "currentOpeningHours.weekdayDescriptions",
      "nationalPhoneNumber",
      "internationalPhoneNumber",
      "websiteUri",
      "types",
    ].join(",");

    const url = `https://places.googleapis.com/v1/${encodeURIComponent(
      place_id
    )}?languageCode=pl&fields=${encodeURIComponent(fieldMask)}`;

    const resp = await fetch(url, {
      headers: { "X-Goog-Api-Key": apiKey },
    });
    const data = await resp.json();

    if (!resp.ok) {
      return res.status(502).json({
        error: "Błąd Google Places Details (New)",
        status: resp.status,
        message: data?.error?.message || null,
      });
    }

    const p = data || {};
    const details = {
      place_name: p.id || null, // "places/XXXX"
      name: p.displayName?.text || null,
      address: p.formattedAddress || null,
      phone: p.nationalPhoneNumber || p.internationalPhoneNumber || null,
      website: p.websiteUri || null,
      rating: p.rating ?? null,
      user_ratings_total: p.userRatingCount ?? null,
      open_weekdays: p.currentOpeningHours?.weekdayDescriptions || [],
      location: {
        lat: p.location?.latitude ?? null,
        lng: p.location?.longitude ?? null,
      },
      types: p.types || [],
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
server.on("error", (err) => {
  console.error("❌ Błąd przy app.listen:", err);
});
