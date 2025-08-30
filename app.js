// app.js
import express from "express";
import session from "express-session";
import dotenv from "dotenv";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { google } from "googleapis";

dotenv.config();

// ── ŚCIEŻKI I PODSTAWY ──────────────────────────────────────────────
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const PORT = process.env.PORT || 8080;
const TZ = "Europe/Warsaw";
const TOKEN_PATH = path.join(__dirname, "tokens.json");

// ── MIDDLEWARE ─────────────────────────────────────────────────────
app.use(express.json()); // potrzebne do POST /gmail/send
app.use(
  session({
    secret: process.env.SESSION_SECRET || "secret",
    resave: false,
    saveUninitialized: true,
  })
);

// ── GOOGLE OAUTH2 ──────────────────────────────────────────────────
// Uwaga: mamy uprawnienia do: Kalendarz (read), Gmail (read + send), Drive (metadata read)
const SCOPES = [
  "https://www.googleapis.com/auth/calendar.readonly",
  "https://www.googleapis.com/auth/gmail.readonly",
  "https://www.googleapis.com/auth/gmail.send",
  "https://www.googleapis.com/auth/drive.metadata.readonly",
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

// Gmail: budowa surowej wiadomości (MIME) i kodowanie base64url
function buildRawEmail({ to, subject, text, from }) {
  const headers = [
    `To: ${to}`,
    from ? `From: ${from}` : "",
    `Subject: ${subject}`,
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=UTF-8",
    "",
    text || "",
  ]
    .filter(Boolean)
    .join("\r\n");

  const base64 = Buffer.from(headers, "utf-8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");

  return base64;
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

// Reset tokenów (usuwa tokens.json i czyści pamięć)
app.get("/auth/reset", (req, res) => {
  try {
    if (fs.existsSync(TOKEN_PATH)) {
      fs.unlinkSync(TOKEN_PATH);
    }
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
      summary: ev.summary,
      start: ev.start?.dateTime || ev.start?.date || null,
    }));
    res.json({ events: result });
  } catch (e) {
    console.error(e);
    res.status(500).send("Błąd pobierania wydarzeń");
  }
});

app.get("/calendar/event", async (req, res) => {
  const id = req.query.id;
  if (!id) return res.status(400).send("Missing id");
  try {
    const calendar = google.calendar({ version: "v3", auth: oAuth2Client });
    const ev = await calendar.events.get({ calendarId: "primary", eventId: id });
    res.json(ev.data);
  } catch (e) {
    console.error(e);
    res.status(500).send("Błąd pobierania wydarzenia");
  }
});

app.get("/calendar/today", async (_req, res) => {
  try {
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
      return `${fmtTime(startISO)} - ${ev.summary || "Bez tytułu"} (${fmtDate(
        startISO
      )})`;
    });
    res.json({ today: result });
  } catch (e) {
    console.error(e);
    res.status(500).send("Błąd /calendar/today");
  }
});

app.get("/calendar/tomorrow", async (_req, res) => {
  try {
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
      return `${fmtTime(startISO)} - ${ev.summary || "Bez tytułu"} (${fmtDate(
        startISO
      )})`;
    });
    res.json({ tomorrow: result });
  } catch (e) {
    console.error(e);
    res.status(500).send("Błąd /calendar/tomorrow");
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

    // dociągniemy headery Temat/Nadawca (opcjonalnie)
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
        headers.find((h) => h.name?.toLowerCase() === name.toLowerCase())?.value || "";
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

// Wysyłka maila: POST /gmail/send  { to, subject, text }
app.post("/gmail/send", async (req, res) => {
  const { to, subject, text, from } = req.body || {};
  if (!to || !subject) {
    return res.status(400).json({ error: "Wymagane pola: to, subject" });
  }
  try {
    const gmail = google.gmail({ version: "v1", auth: oAuth2Client });
    const raw = buildRawEmail({ to, subject, text, from });
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

// ── ROUTES: PLACES (Google Places API) ─────────────────────────────
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
      radius = 3000,
      pageToken // opcjonalnie, do paginacji
    } = req.query;

    // Użyjemy Text Search z biasem lokalizacji i radius
    const params = new URLSearchParams({
      query: String(q),
      location: `${lat},${lng}`,
      radius: String(radius),
      key: apiKey,
      language: "pl"
    });
    if (pageToken) params.set("pagetoken", String(pageToken));

    const url = `https://maps.googleapis.com/maps/api/place/textsearch/json?${params.toString()}`;

    // Node 22 ma globalny fetch — nie potrzebujemy node-fetch
    const resp = await fetch(url);
    const data = await resp.json();

    if (data.status !== "OK" && data.status !== "ZERO_RESULTS") {
      return res.status(502).json({
        error: "Błąd Google Places",
        status: data.status,
        message: data.error_message || null
      });
    }

    // Zmapujmy wyniki do czytelnego formatu
    const results = (data.results || []).slice(0, 10).map((p) => ({
      place_id: p.place_id,
      name: p.name,
      address: p.formatted_address,
      rating: p.rating ?? null,
      user_ratings_total: p.user_ratings_total ?? null,
      open_now: p.opening_hours?.open_now ?? null,
      location: {
        lat: p.geometry?.location?.lat ?? null,
        lng: p.geometry?.location?.lng ?? null
      },
      types: p.types ?? []
    }));

    res.json({
      query: q,
      lat: Number(lat),
      lng: Number(lng),
      radius: Number(radius),
      next_page_token: data.next_page_token || null,
      results
    });
  } catch (e) {
    console.error("Places error:", e);
    res.status(500).json({ error: "Błąd wyszukiwania miejsc" });
  }
});