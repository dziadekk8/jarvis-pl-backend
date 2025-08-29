import express from "express";
import dotenv from "dotenv";
import { google } from "googleapis";
import fetch from "node-fetch";
import fs from "fs/promises";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 8080;
const TOKENS_PATH = "./tokens.json";

// === Narzędzia do zapisu/odczytu tokenów ===
async function loadTokens() {
  try {
    const raw = await fs.readFile(TOKENS_PATH, "utf-8");
    return JSON.parse(raw);
  } catch (_) {
    return null; // brak pliku = brak tokenów
  }
}
async function saveTokens(tokens) {
  await fs.writeFile(TOKENS_PATH, JSON.stringify(tokens, null, 2), "utf-8");
}

// === OAuth2 klient Google ===
const scopes = [
  "https://www.googleapis.com/auth/calendar.readonly",
  "https://www.googleapis.com/auth/drive.readonly"
  // tymczasowo USUŃ "https://www.googleapis.com/auth/gmail.readonly"
];

);

// Załaduj tokeny na starcie (jeśli istnieją)
let userTokens = await loadTokens();
if (userTokens) {
  oauth2Client.setCredentials(userTokens);
  console.log("🔐 Załadowano tokeny z pliku tokens.json");
}

// Zapisuj automatycznie nowe tokeny (np. po odświeżeniu)
oauth2Client.on("tokens", async (tokens) => {
  // tokens może zawierać access_token i okazjonalnie refresh_token
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
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/drive.readonly"
  ];
  const url = oauth2Client.generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    scope: scopes
  });
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
      orderBy: "startTime"
    });

    const events = response.data.items || [];
    if (events.length === 0) return res.send("📅 Brak nadchodzących wydarzeń.");

    const lista = events.map(ev => {
      const start = ev.start.dateTime || ev.start.date;
      return `- ${ev.summary} (${start})`;
    });
    res.send("📅 Nadchodzące wydarzenia:\n" + lista.join("\n"));
  } catch (err) {
    console.error(err);
    res.send("❌ Błąd przy pobieraniu wydarzeń.");
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
