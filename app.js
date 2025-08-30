import express from "express";
import dotenv from "dotenv";
import { google } from "googleapis";
import fetch from "node-fetch";
import fs from "fs/promises";

dotenv.config();

console.log("DEBUG REDIRECT_URI =", process.env.GOOGLE_REDIRECT_URI);


const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const PORT = process.env.PORT || 8080;
const TOKENS_PATH = "./tokens.json";

// === Narzędzia do zapisu/odczytu tokenów ===
async function loadTokens() {
  try {
    const raw = await fs.readFile(TOKENS_PATH, "utf-8");
    return JSON.parse(raw);
  } catch {
    return null; // brak pliku = brak tokenów
  }
}
async function saveTokens(tokens) {
  await fs.writeFile(TOKENS_PATH, JSON.stringify(tokens, null, 2), "utf-8");
}

const redirectUri = (process.env.GOOGLE_REDIRECT_URI || "").trim();

const oauth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  redirectUri
);

console.log("DEBUG REDIRECT_URI =", redirectUri);

// Trzymaj tokeny w pamięci procesu
let userTokens = await loadTokens();
if (userTokens) {
  oauth2Client.setCredentials(userTokens);
  console.log("🔐 Załadowano tokeny z pliku tokens.json");
}

// Zapisuj automatycznie nowe/odświeżone tokeny
oauth2Client.on("tokens", async (tokens) => {
  userTokens = { ...(userTokens || {}), ...tokens };
  await saveTokens(userTokens);
  console.log("💾 Zapisano zaktualizowane tokeny (on(tokens))");
});

// === ENDPOINTY ===


// Test serwera
app.get("/", (_req, res) => {
  res.send("Jarvis-PL backend działa 🚀");
});

// Sprawdzenie statusu autoryzacji
app.get("/auth/status", async (_req, res) => {
  if (!userTokens) return res.send("🔴 Brak tokenów. Zaloguj: /oauth2/start");
  const hasRefresh = Boolean(userTokens.refresh_token);
  res.send(`🟢 Tokeny obecne. refresh_token: ${hasRefresh ? "TAK" : "NIE"}`);
});

// Wylogowanie (usuń tokeny)
app.get("/auth/logout", async (_req, res) => {
  try {
    await fs.unlink(TOKENS_PATH);
  } catch (_) {}
  userTokens = null;
  res.send("🚪 Wylogowano. Tokeny usunięte. Zaloguj ponownie: /oauth2/start");
});

// Rozpoczęcie logowania do Google (wymuś offline + consent)
app.get("/oauth2/start", (_req, res) => {
  const scopes = [
    "https://www.googleapis.com/auth/calendar.readonly",
    "https://www.googleapis.com/auth/drive.readonly"
    // "https://www.googleapis.com/auth/gmail.readonly"
  ];
  const url = oauth2Client.generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    scope: scopes
  });
  console.log("DEBUG AUTH_URL =", url);
  res.redirect(url);
});


// Callback po logowaniu — zapisz tokeny do pliku
app.get("/oauth2/callback", async (req, res) => {
  try {
    const code = req.query.code;
    const { tokens } = await oauth2Client.getToken(code);
    userTokens = tokens;
    await saveTokens(userTokens);
    oauth2Client.setCredentials(userTokens);
    res.send("✅ Połączono z Google. Tokeny zapisane (tokens.json).");
  } catch (err) {
    console.error(err);
    res.send("❌ Błąd przy logowaniu.");
  }
});

// --- Pomocnicze formatowanie czasu (PL, Europe/Warsaw) ---
const TZ = "Europe/Warsaw";
const fmtDate = (iso) => {
  if (!iso) return "brak";
  const d = new Date(iso);
  return new Intl.DateTimeFormat("pl-PL", { timeZone: TZ, dateStyle: "long" }).format(d);
};
const fmtTime = (iso) => {
  if (!iso) return "brak";
  const d = new Date(iso);
  return new Intl.DateTimeFormat("pl-PL", { timeZone: TZ, hour: "2-digit", minute: "2-digit" }).format(d);
};
const fmtRange = (startIso, endIso) => `${fmtDate(startIso)}, ${fmtTime(startIso)} – ${fmtTime(endIso)}`;

function isoDayRange(offsetDays = 0) {
  // Wyznacz yyyy-mm-dd w strefie TZ bez parsowania stringów
  const now = new Date();
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: TZ,
    year: "numeric",
    month: "2-digit",
    day: "2-digit"
  }).formatToParts(now);

  const y = Number(parts.find(p => p.type === "year").value);
  const m = Number(parts.find(p => p.type === "month").value);
  const d = Number(parts.find(p => p.type === "day").value);

  // Ustal północ w TZ jako północ UTC dla tej daty
  const startUTC = new Date(Date.UTC(y, m - 1, d + offsetDays, 0, 0, 0, 0));
  const endUTC   = new Date(Date.UTC(y, m - 1, d + offsetDays + 1, 0, 0, 0, 0));

  return {
    timeMin: startUTC.toISOString(),
    timeMax: endUTC.toISOString()
  };
}


// === Google Calendar: wydarzenia ===
app.get("/calendar/events", async (_req, res) => {
  try {
    if (!userTokens) return res.send("❌ Brak tokenów. Najpierw /oauth2/start.");
    oauth2Client.setCredentials(userTokens);
    const calendar = google.calendar({ version: "v3", auth: oauth2Client });

    const now = new Date().toISOString();
    const response = await calendar.events.list({
      calendarId: "primary",
      timeMin: now,
      maxResults: 5,
      singleEvents: true,
      orderBy: "startTime",
      timeZone: TZ
    });

    const events = response.data.items || [];
    if (events.length === 0) return res.send("📅 Brak nadchodzących wydarzeń.");

    const lista = events.map(e => {
      const s = e.start?.dateTime || e.start?.date || null;
      const t = e.end?.dateTime || e.end?.date || null;
      const line = (s && t) ? fmtRange(s, t) : (s ? fmtDate(s) : "brak daty");
      return `• ${e.summary || "(brak tytułu)"} — ${line}`;
    });
    res.send("📅 Nadchodzące wydarzenia:\n" + lista.join("\n"));
  } catch (err) {
    console.error(err);
    res.status(500).send("❌ Błąd przy pobieraniu wydarzeń.");
  }
});

// JSON z ID (dla GPT)
app.get("/calendar/events/json", async (_req, res) => {
  try {
    if (!userTokens) return res.json({ events: [] });
    oauth2Client.setCredentials(userTokens);
    const calendar = google.calendar({ version: "v3", auth: oauth2Client });

    const now = new Date().toISOString();
    const response = await calendar.events.list({
      calendarId: "primary",
      timeMin: now,
      maxResults: 10,
      singleEvents: true,
      orderBy: "startTime",
      timeZone: TZ
    });

    const events = (response.data.items || []).map(e => ({
      id: e.id,
      summary: e.summary || "(brak tytułu)",
      start: e.start?.dateTime || e.start?.date || null,
      end: e.end?.dateTime || e.end?.date || null
    }));
    res.json({ events });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "❌ Błąd przy pobieraniu wydarzeń (JSON)." });
  }
});

// DZISIAJ (ładny tekst)
app.get("/calendar/today", async (_req, res) => {
  try {
    if (!userTokens) return res.send("❌ Brak tokenów. Najpierw /oauth2/start.");
    oauth2Client.setCredentials(userTokens);
    const calendar = google.calendar({ version: "v3", auth: oauth2Client });

    const { timeMin, timeMax } = isoDayRange(0);
    const r = await calendar.events.list({
      calendarId: "primary",
      timeMin,
      timeMax,
      singleEvents: true,
      orderBy: "startTime",
      maxResults: 20, // bezpieczny limit
    });

    const items = r.data.items || [];
    if (items.length === 0) return res.send("📅 Dziś brak wydarzeń.");

    const out = items.map(e => {
      const s = e.start?.dateTime || e.start?.date || null;
      const t = e.end?.dateTime   || e.end?.date   || null;
      return `• ${e.summary || "(brak tytułu)"} — ${s && t ? fmtRange(s,t) : (s ? fmtDate(s) : "brak daty")}`;
    });
    res.send("📅 Dzisiaj:\n" + out.join("\n"));
  } catch (e) {
    console.error("ERR /calendar/today:", e?.message || e);
    res.status(500).send("❌ Błąd /calendar/today: " + (e?.message || "nieznany"));
  }
});

// JUTRO (ładny tekst)
app.get("/calendar/tomorrow", async (_req, res) => {
  try {
    if (!userTokens) return res.send("❌ Brak tokenów. Najpierw /oauth2/start.");
    oauth2Client.setCredentials(userTokens);
    const calendar = google.calendar({ version: "v3", auth: oauth2Client });

    const { timeMin, timeMax } = isoDayRange(1);
    const r = await calendar.events.list({
      calendarId: "primary",
      timeMin,
      timeMax,
      singleEvents: true,
      orderBy: "startTime",
      maxResults: 20,
    });

    const items = r.data.items || [];
    if (items.length === 0) return res.send("📅 Jutro brak wydarzeń.");

    const out = items.map(e => {
      const s = e.start?.dateTime || e.start?.date || null;
      const t = e.end?.dateTime   || e.end?.date   || null;
      return `• ${e.summary || "(brak tytułu)"} — ${s && t ? fmtRange(s,t) : (s ? fmtDate(s) : "brak daty")}`;
    });
    res.send("📅 Jutro:\n" + out.join("\n"));
  } catch (e) {
    console.error("ERR /calendar/tomorrow:", e?.message || e);
    res.status(500).send("❌ Błąd /calendar/tomorrow: " + (e?.message || "nieznany"));
  }
});

// Szczegóły jednego wydarzenia (JSON)
app.get("/calendar/event", async (req, res) => {
  try {
    if (!userTokens) return res.status(401).json({ error: "Brak tokenów" });
    oauth2Client.setCredentials(userTokens);
    const calendar = google.calendar({ version: "v3", auth: oauth2Client });

    const id = String(req.query.id || "").trim();
    if (!id) return res.status(400).json({ error: "Podaj ?id=..." });

    const ev = await calendar.events.get({ calendarId: "primary", eventId: id });
    const e = ev.data;
    res.json({
      id: e.id,
      summary: e.summary || "(brak tytułu)",
      start: e.start?.dateTime || e.start?.date || "brak",
      end: e.end?.dateTime || e.end?.date || "brak",
      location: e.location || "brak",
      attendees: (e.attendees || []).map(a => ({ email: a.email, responseStatus: a.responseStatus })),
      hangoutLink: e.hangoutLink || null,
      description: e.description || "brak"
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "❌ Błąd przy pobieraniu szczegółów wydarzenia." });
  }
});

// UTWÓRZ wydarzenie (POST JSON)
app.post("/calendar/create", async (req, res) => {
  try {
    if (!userTokens) return res.status(401).json({ error: "Brak tokenów" });
    oauth2Client.setCredentials(userTokens);
    const calendar = google.calendar({ version: "v3", auth: oauth2Client });

    const { title, start, end, location, description, reminderMinutes } = req.body || {};
    if (!title || !start || !end) {
      return res.status(400).json({ error: "Wymagane: title, start, end (ISO, np. 2025-09-01T09:00:00+02:00)" });
    }

    const event = {
      summary: title,
      location: location || undefined,
      description: description || undefined,
      start: { dateTime: start, timeZone: TZ },
      end:   { dateTime: end,   timeZone: TZ },
      reminders: reminderMinutes ? {
        useDefault: false,
        overrides: [{ method: "popup", minutes: Number(reminderMinutes) }]
      } : undefined
    };

    const created = await calendar.events.insert({ calendarId: "primary", requestBody: event });
    res.json({
      ok: true,
      id: created.data.id,
      htmlLink: created.data.htmlLink,
      when: fmtRange(start, end)
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "❌ Błąd przy tworzeniu wydarzenia." });
  }
});

// Aktualizacja tytułu/przypomnienia
app.post("/calendar/event/update", async (req, res) => {
  try {
    if (!userTokens) return res.status(401).json({ error: "Brak tokenów" });
    oauth2Client.setCredentials(userTokens);
    const calendar = google.calendar({ version: "v3", auth: oauth2Client });

    const { id, title, reminderMinutes } = req.body || {};
    if (!id) return res.status(400).json({ error: "Wymagane: id" });

    // pobierz istniejące
    const ev = await calendar.events.get({ calendarId: "primary", eventId: id });
    const e = ev.data;

    if (title) e.summary = title;
    if (reminderMinutes !== undefined) {
      e.reminders = {
        useDefault: false,
        overrides: [{ method: "popup", minutes: Number(reminderMinutes) }]
      };
    }

    const updated = await calendar.events.update({ calendarId: "primary", eventId: id, requestBody: e });
    res.json({ ok: true, id, summary: updated.data.summary });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "❌ Błąd przy aktualizacji wydarzenia." });
  }
});


// === Gmail: listowanie wiadomości ===
app.get("/gmail/messages", async (req, res) => {
  try {
    if (!userTokens) return res.send("❌ Brak tokenów. Najpierw /oauth2/start.");
    oauth2Client.setCredentials(userTokens);
    const gmail = google.gmail({ version: "v1", auth: oauth2Client });

    const query = req.query.q || "newer_than:7d";
    const list = await gmail.users.messages.list({
      userId: "me",
      q: String(query),
      maxResults: 10
    });

    const ids = (list.data.messages || []).map(m => m.id);
    if (ids.length === 0) return res.send("📬 Brak wiadomości dla: " + query);

    const results = [];
    for (const id of ids) {
      const msg = await gmail.users.messages.get({ userId: "me", id });
      const headers = msg.data.payload?.headers || [];
      const get = (name) => headers.find(h => h.name?.toLowerCase() === name.toLowerCase())?.value || "";
      const from = get("From");
      const subject = get("Subject");
      results.push(`- ${subject}  <${from}>`);
    }
    res.send("📬 Ostatnie wiadomości:\n" + results.join("\n"));
  } catch (err) {
    console.error(err);
    res.send("❌ Błąd przy pobieraniu Gmaila.");
  }
});

// === Drive: wyszukiwanie plików ===
app.get("/drive/search", async (req, res) => {
  try {
    if (!userTokens) return res.send("❌ Brak tokenów. Najpierw /oauth2/start.");
    oauth2Client.setCredentials(userTokens);
    const drive = google.drive({ version: "v3", auth: oauth2Client });

    const query = req.query.q || "";
    const result = await drive.files.list({
      q: query ? `name contains '${query}'` : undefined,
      pageSize: 10,
      fields: "files(id,name,mimeType,modifiedTime)"
    });

    const files = result.data.files || [];
    if (files.length === 0) return res.send("📂 Brak plików pasujących do zapytania.");
    const lista = files.map(f => `- ${f.name} (${f.mimeType}, ${f.modifiedTime})`);
    res.send("📂 Wyniki wyszukiwania na Google Drive:\n" + lista.join("\n"));
  } catch (err) {
    console.error(err);
    res.send("❌ Błąd przy pobieraniu plików z Drive.");
  }
});

// === Places: wyszukiwanie miejsc ===
app.get("/places/search", async (req, res) => {
  try {
    const query = req.query.q || "kawiarnia";
    const lat = req.query.lat || 52.2297; // Warszawa
    const lng = req.query.lng || 21.0122;
    const radius = req.query.radius || 3000;

    const url = "https://places.googleapis.com/v1/places:searchText";
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Goog-Api-Key": process.env.GOOGLE_MAPS_API_KEY,
        "X-Goog-FieldMask": "places.displayName,places.formattedAddress,places.rating,places.location"
      },
      body: JSON.stringify({
        textQuery: query,
        locationBias: {
          circle: {
            center: { latitude: Number(lat), longitude: Number(lng) },
            radius: Number(radius)
          }
        }
      })
    });

    const data = await response.json();
    const places = data.places || [];
    if (places.length === 0) return res.send("📍 Brak wyników dla zapytania: " + query);

    const lista = places.map(p => `- ${p.displayName?.text} (${p.formattedAddress}, ocena: ${p.rating || "brak"})`);
    res.send("📍 Wyniki wyszukiwania:\n" + lista.join("\n"));
  } catch (err) {
    console.error(err);
    res.send("❌ Błąd przy wyszukiwaniu miejsc.");
  }
});

app.listen(PORT, () => {
  console.log(`Serwer działa na http://localhost:${PORT}`);
});
