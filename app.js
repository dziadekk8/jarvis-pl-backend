
// app.js — Jarvis-PL backend (ESM).
// Features: Health, OAuth2 (Google), Calendar R/W + Watch/push, Gmail send/reply/list,
// Drive search, Places (New) search/details, Redis (Upstash) for tokens/watch state.
// No express-session. Uses global fetch (Node 20+).
//
// package.json deps expected:
//  "express": "^5.1.0",
//  "cors": "^2.8.5",
//  "dotenv": "^17.2.1",
//  "googleapis": "^159.0.0",
//  //  "@upstash/redis": "^1.35.3"
//
// ENV (Render / .env):
//  BASE_URL=https://ai.aneuroasystent.pl
//  GOOGLE_CLIENT_ID=...apps.googleusercontent.com
//  GOOGLE_CLIENT_SECRET=...
//  ADMIN_TOKEN=strong_admin_secret
//  WATCH_TOKEN=dev-token
//  GOOGLE_MAPS_API_KEY=...   (Places API NEW must be enabled)
//  UPSTASH_REDIS_REST_URL=...
//  UPSTASH_REDIS_REST_TOKEN=...
//  TZ=Europe/Warsaw (optional)

import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { google } from 'googleapis';
import crypto from 'crypto';
import { Redis } from '@upstash/redis';

// App + middleware
const app = express();
app.use(cors());
app.use(express.json({ limit: '20mb' })); // handle attachments
app.use(express.urlencoded({ extended: true }));

// Config
const PORT         = process.env.PORT || 8080;
const BASE_URL     = process.env.BASE_URL || `http://localhost:${PORT}`;
const TZ           = process.env.TZ || 'Europe/Warsaw';
const ADMIN_TOKEN  = process.env.ADMIN_TOKEN || '';
const WATCH_TOKEN  = process.env.WATCH_TOKEN || '';
const MAPS_KEY     = process.env.GOOGLE_MAPS_API_KEY || '';

console.log(`✅ Serwer startuje: ${BASE_URL}`);
console.log(`DEBUG REDIRECT_URI = ${new URL('/oauth2/callback', BASE_URL).toString()}`);
console.log('MAPS KEY set?:', Boolean(MAPS_KEY));

// Redis (Upstash) — optional, but recommended
let redis = null;
try {
  if (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN) {
    redis = new Redis({
      url: process.env.UPSTASH_REDIS_REST_URL,
      token: process.env.UPSTASH_REDIS_REST_TOKEN,
    });
  }
} catch (e) {
  console.error('Redis init error:', e?.message || e);
}

const TOKENS_KEY = 'jarvis:tokens';
const PUSH_KEY   = 'jarvis:push';

async function kvGet(key) {
  if (!redis) return null;
  try { return await redis.get(key); } catch { return null; }
}
async function kvSet(key, value) {
  if (!redis) return;
  try { await redis.set(key, value); } catch {}
}
async function kvDel(key) {
  if (!redis) return;
  try { await redis.del(key); } catch {}
}

// OAuth2
const CLIENT_ID     = process.env.GOOGLE_CLIENT_ID || '';
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '';
const REDIRECT_URI  = new URL('/oauth2/callback', BASE_URL).toString();

const oAuth2Client = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);
let userTokens = null;

// Warm-load tokens from Redis on startup (if present)
(async () => {
  const t = await kvGet(TOKENS_KEY);
  if (t && (t.access_token || t.refresh_token)) {
    userTokens = t;
    oAuth2Client.setCredentials(userTokens);
    console.log('Tokens loaded from Redis.');
  } else {
    console.log('No tokens in Redis at startup.');
  }
})();

function authUrl() {
  const scopes = [
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/calendar',
    'https://www.googleapis.com/auth/gmail.send',
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/gmail.modify',
    'https://www.googleapis.com/auth/drive.readonly',
  ];
  return oAuth2Client.generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent',
    scope: scopes,
  });
}

// Health
app.get('/health', (_req, res) => {
  res.json({ ok: true });
});

// OAuth2 start
app.get('/oauth2/start', (_req, res) => {
  res.redirect(authUrl());
});

// OAuth2 callback
app.get('/oauth2/callback', async (req, res) => {
  const code = req.query.code;
  if (!code) return res.status(400).send('Brak ?code w URL');
  try {
    const { tokens } = await oAuth2Client.getToken(code);
    userTokens = tokens;
    oAuth2Client.setCredentials(tokens);
    await kvSet(TOKENS_KEY, tokens);
    res.send('✅ Autoryzacja OK. Token zapisany. Sprawdź /auth/status');
  } catch (e) {
    console.error('Błąd pobierania tokenów:', e?.response?.data || e?.message || e);
    res.status(500).send('❌ Błąd pobierania tokenów');
  }
});

// Auth status
app.get('/auth/status', async (_req, res) => {
  const t = userTokens || (await kvGet(TOKENS_KEY));
  if (!t) return res.send('🔴 Brak tokenów. Zaloguj: /oauth2/start');
  const hasRefresh = Boolean(t.refresh_token);
  res.send(`🟢 Tokeny obecne. refresh_token: ${hasRefresh ? 'TAK' : 'NIE'}`);
});

// Auth reset (admin)
app.get('/auth/reset', async (req, res) => {
  try {
    const token = req.get('x-admin-token') || '';
    if (!ADMIN_TOKEN || token !== ADMIN_TOKEN) {
      return res.status(403).json({ error: 'forbidden' });
    }
    userTokens = null;
    await kvDel(TOKENS_KEY);
    await kvDel(PUSH_KEY);
    res.json({ ok: true, cleared: [TOKENS_KEY, PUSH_KEY] });
  } catch (e) {
    res.status(500).json({ ok: false, error: e?.message || 'reset_failed' });
  }
});

// Helper: ensure Google auth
function ensureAuthOr401(res) {
  if (!userTokens) {
    res.status(401).json({ error: 'Brak autoryzacji – /oauth2/start' });
    return false;
  }
  oAuth2Client.setCredentials(userTokens);
  return true;
}

// ==== Calendar helpers ====
function makeEventTimes({ startISO, endISO, timeZone }) {
  if (!startISO || !endISO) return {};
  if (/^\d{4}-\d{2}-\d{2}$/.test(startISO) && /^\d{4}-\d{2}-\d{2}$/.test(endISO)) {
    // all-day event
    return { start: { date: startISO }, end: { date: endISO } };
  }
  return {
    start: { dateTime: startISO, timeZone: timeZone || TZ },
    end:   { dateTime: endISO,   timeZone: timeZone || TZ },
  };
}
function makeConference(createMeet) {
  if (!createMeet) return undefined;
  return {
    createRequest: {
      requestId: crypto.randomUUID(),
      conferenceSolutionKey: { type: 'hangoutsMeet' },
    }
  };
}
function mapAttendees(emails) {
  if (!Array.isArray(emails) || !emails.length) return undefined;
  return emails.map(e => ({ email: e }));
}

// List upcoming (compact)
app.get('/calendar/events/json', async (_req, res) => {
  try {
    if (!ensureAuthOr401(res)) return;
    const calendar = google.calendar({ version: 'v3', auth: oAuth2Client });
    const now = new Date().toISOString();
    const resp = await calendar.events.list({
      calendarId: 'primary',
      timeMin: now,
      singleEvents: true,
      orderBy: 'startTime',
      maxResults: 50,
    });
    const events = (resp.data.items || []).map(ev => ({
      id: ev.id,
      summary: ev.summary || '',
      start: ev.start?.dateTime || ev.start?.date || null,
    }));
    res.json({ events });
  } catch (e) {
    const status = e?.response?.status || 500;
    res.status(status).json({ error: 'calendar_list_failed', status });
  }
});

// Single event
app.get('/calendar/event', async (req, res) => {
  try {
    if (!ensureAuthOr401(res)) return;
    const id = req.query.id;
    if (!id) return res.status(400).json({ error: 'missing_id' });
    const calendar = google.calendar({ version: 'v3', auth: oAuth2Client });
    const resp = await calendar.events.get({ calendarId: 'primary', eventId: id });
    res.json(resp.data || {});
  } catch (e) {
    const status = e?.response?.status || 500;
    res.status(status).json({ error: 'calendar_get_failed', status, details: e?.response?.data });
  }
});

// Create event
app.post('/calendar/create', async (req, res) => {
  try {
    if (!ensureAuthOr401(res)) return;
    const {
      summary, description, location,
      startISO, endISO, timeZone,
      attendeesEmails, remindersMinutes,
      recurrence, createMeet, sendUpdates,
    } = req.body || {};

    const calendar = google.calendar({ version: 'v3', auth: oAuth2Client });
    const requestBody = {
      summary,
      description,
      location,
      ...makeEventTimes({ startISO, endISO, timeZone }),
      attendees: mapAttendees(attendeesEmails),
      recurrence,
      reminders: typeof remindersMinutes === 'number'
        ? { useDefault: false, overrides: [{ method: 'popup', minutes: remindersMinutes }] }
        : undefined,
      conferenceData: makeConference(createMeet),
    };

    const resp = await calendar.events.insert({
      calendarId: 'primary',
      requestBody,
      conferenceDataVersion: requestBody.conferenceData ? 1 : 0,
      sendUpdates: sendUpdates || 'none',
    });
    res.json(resp.data || {});
  } catch (e) {
    const status = e?.response?.status || 500;
    res.status(status).json({ error: 'calendar_create_failed', status, details: e?.response?.data });
  }
});

// Update (patch)
app.post('/calendar/update', async (req, res) => {
  try {
    if (!ensureAuthOr401(res)) return;
    const {
      id, summary, description, location,
      startISO, endISO, timeZone,
      attendeesEmails, remindersMinutes,
      recurrence, createMeet, sendUpdates,
    } = req.body || {};

    if (!id) return res.status(400).json({ error: 'missing_id' });
    const calendar = google.calendar({ version: 'v3', auth: oAuth2Client });

    const requestBody = {};
    if (summary !== undefined) requestBody.summary = summary;
    if (description !== undefined) requestBody.description = description;
    if (location !== undefined) requestBody.location = location;
    if (startISO || endISO) Object.assign(requestBody, makeEventTimes({ startISO, endISO, timeZone }));
    if (attendeesEmails !== undefined) requestBody.attendees = mapAttendees(attendeesEmails);
    if (recurrence !== undefined) requestBody.recurrence = recurrence;
    if (typeof remindersMinutes === 'number') {
      requestBody.reminders = { useDefault: false, overrides: [{ method: 'popup', minutes: remindersMinutes }] };
    }
    if (typeof createMeet === 'boolean') {
      requestBody.conferenceData = makeConference(createMeet);
    }

    const resp = await calendar.events.patch({
      calendarId: 'primary',
      eventId: id,
      requestBody,
      conferenceDataVersion: requestBody.conferenceData ? 1 : 0,
      sendUpdates: sendUpdates || 'none',
    });
    res.json(resp.data || {});
  } catch (e) {
    const status = e?.response?.status || 500;
    res.status(status).json({ error: 'calendar_update_failed', status, details: e?.response?.data });
  }
});

// Delete
app.post('/calendar/delete', async (req, res) => {
  try {
    if (!ensureAuthOr401(res)) return;
    const { id, sendUpdates } = req.body || {};
    if (!id) return res.status(400).json({ error: 'missing_id' });
    const calendar = google.calendar({ version: 'v3', auth: oAuth2Client });
    await calendar.events.delete({
      calendarId: 'primary',
      eventId: id,
      sendUpdates: sendUpdates || 'none',
    });
    res.json({ ok: true, deletedId: id });
  } catch (e) {
    const status = e?.response?.status || 500;
    res.status(status).json({ error: 'calendar_delete_failed', status, details: e?.response?.data });
  }
});

// QuickAdd
app.post('/calendar/quickadd', async (req, res) => {
  try {
    if (!ensureAuthOr401(res)) return;
    const { text, sendUpdates } = req.body || {};
    if (!text) return res.status(400).json({ error: 'missing_text' });
    const calendar = google.calendar({ version: 'v3', auth: oAuth2Client });
    const resp = await calendar.events.quickAdd({
      calendarId: 'primary',
      text,
      sendUpdates: sendUpdates || 'none',
    });
    res.json(resp.data || {});
  } catch (e) {
    const status = e?.response?.status || 500;
    res.status(status).json({ error: 'calendar_quickadd_failed', status, details: e?.response?.data });
  }
});

// Instances (recurring occurrences)
app.get('/calendar/instances', async (req, res) => {
  try {
    if (!ensureAuthOr401(res)) return;
    const { id, timeMin, timeMax } = req.query;
    if (!id) return res.status(400).json({ error: 'missing_id' });
    const calendar = google.calendar({ version: 'v3', auth: oAuth2Client });
    const resp = await calendar.events.instances({
      calendarId: 'primary',
      eventId: id,
      timeMin,
      timeMax,
      singleEvents: true,
    });
    res.json({
      seriesId: id,
      timeMin: timeMin || null,
      timeMax: timeMax || null,
      instances: resp.data.items || [],
    });
  } catch (e) {
    const status = e?.response?.status || 500;
    res.status(status).json({ error: 'calendar_instances_failed', status, details: e?.response?.data });
  }
});

// Freebusy
app.post('/calendar/freebusy', async (req, res) => {
  try {
    if (!ensureAuthOr401(res)) return;
    const { timeMin, timeMax, attendeesCalendars } = req.body || {};
    if (!timeMin || !timeMax) return res.status(400).json({ error: 'missing_time_range' });
    const calendar = google.calendar({ version: 'v3', auth: oAuth2Client });
    const items = (attendeesCalendars && attendeesCalendars.length)
      ? attendeesCalendars.map(id => ({ id }))
      : [{ id: 'primary' }];
    const fb = await calendar.freebusy.query({ requestBody: { timeMin, timeMax, items } });
    const calendars = fb.data.calendars || {};
    const allBusy = Object.values(calendars).flatMap(c => c.busy || []);
    res.json({ timeMin: fb.data.timeMin, timeMax: fb.data.timeMax, calendars, busyCombined: allBusy });
  } catch (e) {
    const status = e?.response?.status || 500;
    res.status(status).json({ error: 'calendar_freebusy_failed', status, details: e?.response?.data });
  }
});

// Suggest slots
function parseHHMM(s) {
  const m = /^(\d{2}):(\d{2})$/.exec(s || '');
  if (!m) return null;
  return { h: Number(m[1]), m: Number(m[2]) };
}
app.post('/calendar/suggest', async (req, res) => {
  try {
    if (!ensureAuthOr401(res)) return;
    const {
      timeMin, timeMax, durationMinutes,
      attendeesCalendars,
      workHours = { start: '08:00', end: '18:00', timeZone: TZ },
      includeWeekends = false,
      bufferMinutesBefore = 0,
      bufferMinutesAfter = 0,
      stepMinutes = 30,
      limit = 20,
    } = req.body || {};
    if (!durationMinutes) return res.status(400).json({ error: 'missing_duration' });

    // reuse our freebusy endpoint
    const fbResp = await (await fetch(new URL('/calendar/freebusy', BASE_URL).toString(), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ timeMin, timeMax, attendeesCalendars }),
    })).json();
    const busy = fbResp.busyCombined || [];

    const startBound = timeMin ? new Date(timeMin) : new Date();
    const endBound   = timeMax ? new Date(timeMax) : new Date(Date.now() + 7 * 86400000);

    const workStart = parseHHMM(workHours.start) || { h: 8, m: 0 };
    const workEnd   = parseHHMM(workHours.end)   || { h: 18, m: 0 };

    const slots = [];
    for (let day = new Date(startBound); day < endBound; day = new Date(day.getTime() + 86400000)) {
      const dow = day.getDay();
      if (!includeWeekends && (dow === 0 || dow === 6)) continue;

      const dayStart = new Date(day); dayStart.setHours(workStart.h, workStart.m, 0, 0);
      const dayEnd   = new Date(day); dayEnd.setHours(workEnd.h,   workEnd.m,   0, 0);

      for (let t = new Date(dayStart); t < dayEnd; t = new Date(t.getTime() + stepMinutes * 60000)) {
        const s = new Date(t.getTime() + bufferMinutesBefore * 60000);
        const e = new Date(s.getTime() + durationMinutes * 60000 + bufferMinutesAfter * 60000);
        if (e > dayEnd) break;
        const overlaps = busy.some(b => (new Date(s) < new Date(b.end)) && (new Date(e) > new Date(b.start)));
        if (!overlaps) {
          slots.push({ startISO: s.toISOString(), endISO: e.toISOString() });
          if (slots.length >= limit) break;
        }
      }
      if (slots.length >= limit) break;
    }

    res.json({
      timeMin: startBound.toISOString(),
      timeMax: endBound.toISOString(),
      durationMinutes,
      workHours,
      includeWeekends,
      stepMinutes,
      limitRequested: limit,
      slots,
    });
  } catch (e) {
    const status = e?.response?.status || 500;
    res.status(status).json({ error: 'calendar_suggest_failed', status, details: e?.response?.data || e?.message });
  }
});

// Watch helpers
async function getFreshSyncToken(calendar) {
  const resp = await calendar.events.list({
    calendarId: 'primary',
    singleEvents: true,
    showDeleted: true,
    maxResults: 1,
  });
  return resp.data.nextSyncToken || null;
}

// Watch start
app.post('/calendar/watch', async (_req, res) => {
  try {
    if (!ensureAuthOr401(res)) return;
    const calendar = google.calendar({ version: 'v3', auth: oAuth2Client });
    const channelId = crypto.randomUUID();
    const address   = new URL('/calendar/notifications', BASE_URL).toString();

    const watchResp = await calendar.events.watch({
      calendarId: 'primary',
      requestBody: {
        id: channelId,
        type: 'web_hook',
        address,
        token: WATCH_TOKEN || undefined,
      },
    });

    const state = {
      channelId,
      resourceId: watchResp.data.resourceId || null,
      expiration: watchResp.data.expiration || null,
      syncToken: await getFreshSyncToken(calendar),
      history: [{
        ts: new Date().toISOString(),
        state: 'sync',
        resId: watchResp.data.resourceId,
        chanId: channelId,
        token: WATCH_TOKEN,
        msgNo: 1,
        exp: watchResp.data.expiration ? new Date(Number(watchResp.data.expiration)).toUTCString() : null,
        uri: 'events.list'
      }],
      lastChanges: [],
    };
    await kvSet(PUSH_KEY, state);
    res.json({ ok: true, ...state, callback: address });
  } catch (e) {
    const status = e?.response?.status || 500;
    res.status(status).json({ error: 'calendar_watch_failed', status, details: e?.response?.data || e?.message });
  }
});

// Watch stop
app.post('/calendar/watch/stop', async (_req, res) => {
  try {
    if (!ensureAuthOr401(res)) return;
    const calendar = google.calendar({ version: 'v3', auth: oAuth2Client });
    const state = (await kvGet(PUSH_KEY)) || {};
    if (!state.channelId || !state.resourceId) {
      return res.json({ ok: true, alreadyStopped: true });
    }
    await calendar.channels.stop({ requestBody: { id: state.channelId, resourceId: state.resourceId } });
    await kvSet(PUSH_KEY, { channelId: null, resourceId: null, expiration: null, syncToken: state.syncToken || null, history: state.history || [], lastChanges: [] });
    res.json({ ok: true });
  } catch (e) {
    const status = e?.response?.status || 500;
    res.status(status).json({ error: 'calendar_watch_stop_failed', status, details: e?.response?.data || e?.message });
  }
});

// Watch state
app.get('/calendar/watch/state', async (_req, res) => {
  const state = (await kvGet(PUSH_KEY)) || { channelId: null, resourceId: null, expiration: null, syncToken: null, lastChanges: [], history: [] };
  res.json({
    channelId: state.channelId,
    resourceId: state.resourceId,
    expiration: state.expiration,
    hasSyncToken: Boolean(state.syncToken),
    lastChangesCount: Array.isArray(state.lastChanges) ? state.lastChanges.length : 0,
    history: state.history || [],
  });
});

// Webhook receiver (does not require auth headers; we load tokens ourselves)
app.post('/calendar/notifications', async (req, res) => {
  try {
    const hdr = {
      state: req.get('X-Goog-Resource-State'),
      resId: req.get('X-Goog-Resource-Id'),
      chanId: req.get('X-Goog-Channel-Id'),
      token: req.get('X-Goog-Channel-Token'),
      msgNo: req.get('X-Goog-Message-Number'),
      exp: req.get('X-Goog-Channel-Expiration'),
      uri: req.get('X-Goog-Resource-URI'),
    };
    // Always reply 200 quickly
    res.status(200).send('OK');

    // Load current state & tokens
    const state = (await kvGet(PUSH_KEY)) || {};
    state.history = state.history || [];
    state.lastChanges = [];
    state.history.push({ ts: new Date().toISOString(), ...hdr });
    await kvSet(PUSH_KEY, state);

    const storedTokens = userTokens || (await kvGet(TOKENS_KEY));
    if (!storedTokens) return;
    oAuth2Client.setCredentials(storedTokens);

    if (WATCH_TOKEN && hdr.token && hdr.token !== WATCH_TOKEN) return;

    const calendar = google.calendar({ version: 'v3', auth: oAuth2Client });
    if (!state.syncToken) {
      state.syncToken = await getFreshSyncToken(calendar);
      await kvSet(PUSH_KEY, state);
      return;
    }

    let pageToken;
    const changes = [];
    while (true) {
      try {
        const resp = await calendar.events.list({
          calendarId: 'primary',
          syncToken: state.syncToken,
          singleEvents: true,
          showDeleted: true,
          pageToken,
        });
        (resp.data.items || []).forEach(ev => {
          changes.push({
            id: ev.id,
            status: ev.status,
            summary: ev.summary,
            start: ev.start,
            end: ev.end,
            updated: ev.updated,
          });
        });
        if (resp.data.nextPageToken) {
          pageToken = resp.data.nextPageToken;
        } else {
          state.syncToken = resp.data.nextSyncToken || state.syncToken;
          break;
        }
      } catch (err) {
        if (err?.code === 410 || err?.response?.status === 410) {
          state.syncToken = await getFreshSyncToken(calendar);
          break;
        }
        break;
      }
    }
    state.lastChanges = changes;
    await kvSet(PUSH_KEY, state);
  } catch (e) {
    // swallow errors: webhook must succeed
  }
});

// ==== Gmail ====
function base64url(input) {
  return Buffer.from(input).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
function buildMime({ to, from, subject, text, html, attachments }) {
  const boundary = 'jarvis_boundary_' + crypto.randomBytes(8).toString('hex');
  const headers = [];
  if (from) headers.push(`From: ${from}`);
  if (to) headers.push(`To: ${to}`);
  if (subject) headers.push(`Subject: ${subject}`);
  headers.push('MIME-Version: 1.0');
  let body = '';

  if (attachments && attachments.length) {
    headers.push(`Content-Type: multipart/mixed; boundary="${boundary}"`);
    const altBoundary = boundary + '_alt';

    body += `--${boundary}\r\n`;
    body += `Content-Type: multipart/alternative; boundary="${altBoundary}"\r\n\r\n`;
    if (text) {
      body += `--${altBoundary}\r\n`;
      body += `Content-Type: text/plain; charset="UTF-8"\r\n\r\n${text}\r\n`;
    }
    if (html) {
      body += `--${altBoundary}\r\n`;
      body += `Content-Type: text/html; charset="UTF-8"\r\n\r\n${html}\r\n`;
    }
    body += `--${altBoundary}--\r\n`;

    for (const a of attachments) {
      if (!a?.filename || !a?.mimeType || !a?.data) continue;
      body += `--${boundary}\r\n`;
      body += `Content-Type: ${a.mimeType}; name="${a.filename}"\r\n`;
      body += `Content-Disposition: attachment; filename="${a.filename}"\r\n`;
      body += 'Content-Transfer-Encoding: base64\r\n\r\n';
      body += `${a.data}\r\n`;
    }
    body += `--${boundary}--`;
  } else if (html) {
    headers.push('Content-Type: text/html; charset="UTF-8"');
    body = html;
  } else {
    headers.push('Content-Type: text/plain; charset="UTF-8"');
    body = text || '';
  }
  return headers.join('\r\n') + '\r\n\r\n' + body;
}

// List messages (simple)
// =============== GMAIL: szczegóły pojedynczej wiadomości ===============
app.get('/gmail/message', async (req, res) => {
  try {
    if (!ensureAuthOr401(res)) return;
    const gmail = google.gmail({ version: 'v1', auth: oAuth2Client });

    const id = (req.query.id || '').toString().trim();
    const raw = ['1','true','yes','y'].includes((req.query.raw || '').toString().toLowerCase());
    if (!id) {
      return res.status(400).json({ error: 'missing_id', status: 400, details: 'Parametr ?id= jest wymagany.' });
    }

    // ⬇⬇⬇ KLUCZOWA ZMIANA: poprawna maska pól (headers(name,value), zagnieżdżone parts(...)) ⬇⬇⬇
    const msg = await gmail.users.messages.get({
      userId: 'me',
      id,
      format: 'full',
      fields: 'id,threadId,labelIds,internalDate,sizeEstimate,snippet,payload(partId,filename,mimeType,headers(name,value),body(size,data,attachmentId),parts(partId,filename,mimeType,headers(name,value),body(size,data,attachmentId),parts))'
    });

    const payload = msg.data.payload || {};
    const headers = Array.isArray(payload.headers) ? payload.headers : [];

    const h = (name) => {
      const x = headers.find(h => (h.name || '').toLowerCase() === name.toLowerCase());
      return x ? (x.value || '') : '';
    };

    let dateISO = '';
    try { const rawDate = h('Date'); if (rawDate) dateISO = new Date(rawDate).toISOString(); } catch {}

    const attachments = [];
    let htmlParts = [];
    let textParts = [];

    const decodeB64 = (b64url) => {
      try { return Buffer.from((b64url||'').replace(/-/g,'+').replace(/_/g,'/'),'base64').toString('utf8'); }
      catch { return ''; }
    };

    const walk = (part) => {
      if (!part) return;
      const mime = part.mimeType || '';
      const body = part.body || {};
      const data = body.data || '';
      const filename = part.filename || '';

      if (mime.toLowerCase() === 'text/html' && data) htmlParts.push(decodeB64(data));
      else if (mime.toLowerCase() === 'text/plain' && data) textParts.push(decodeB64(data));

      if (filename && body.attachmentId) {
        attachments.push({
          filename,
          mimeType: mime || 'application/octet-stream',
          size: body.size || 0,
          attachmentId: body.attachmentId,
          partId: part.partId || ''
        });
      }
      if (Array.isArray(part.parts)) part.parts.forEach(walk);
    };

    walk(payload);

    const result = {
      id: msg.data.id,
      threadId: msg.data.threadId,
      subject: h('Subject'),
      from: h('From'),
      to: h('To'),
      date: dateISO,
      snippet: msg.data.snippet || '',
      headers: headers.reduce((acc, it) => { if (it && it.name) acc[it.name] = it.value || ''; return acc; }, {}),
      body: { html: htmlParts.join('\n'), text: textParts.join('\n') },
      attachments
    };

    if (raw) result.rawMessage = msg.data;

    return res.json(result);
  } catch (e) {
    const status = e?.response?.status || 500;
    res.status(status).json({
      error: 'gmail_message_failed',
      status,
      details: e?.response?.data || e?.message
    });
  }
});

// == HELPER: mapuj nazwy/ID etykiet na ID (Gmail API modify wymaga ID) ==
async function mapLabelNamesToIds(gmail, labels) {
  if (!labels || !Array.isArray(labels) || labels.length === 0) return [];
  const { data } = await gmail.users.labels.list({ userId: 'me' });
  const all = data.labels || [];
  const byId = new Map(all.map(l => [l.id, l.id]));
  const byName = new Map(all.map(l => [l.name, l.id]));
  return labels
    .map(x => byId.get(x) || byName.get(x) || null)
    .filter(Boolean);
}


// Send email
app.post('/gmail/send', async (req, res) => {
  try {
    if (!ensureAuthOr401(res)) return;
    const { to, from, subject, text, html, attachments } = req.body || {};
    if (!to || !subject) return res.status(400).json({ error: 'missing_to_or_subject' });
    const gmail = google.gmail({ version: 'v1', auth: oAuth2Client });
    const mime = buildMime({ to, from, subject, text, html, attachments });
    const raw = base64url(mime);
    const send = await gmail.users.messages.send({ userId: 'me', requestBody: { raw } });
    res.json({ id: send.data.id, labelIds: send.data.labelIds });
  } catch (e) {
    const status = e?.response?.status || 500;
    res.status(status).json({ error: 'gmail_send_failed', status, details: e?.response?.data || e?.message });
  }
});



// =============== GMAIL: odpowiedź w wątku ===============
app.post('/gmail/reply', async (req, res) => {
  try {
    if (!ensureAuthOr401(res)) return;
    const gmail = google.gmail({ version: 'v1', auth: oAuth2Client });

    // Wejście: albo replyToMessageId, albo threadId (oneOf)
    const {
      replyToMessageId,
      threadId: threadIdInput,
      to: toInput,
      subject: subjectInput,
      text, html,
      inReplyTo: inReplyToInput,
      references: referencesInput,
      attachments
    } = req.body || {};

    if (!replyToMessageId && !threadIdInput) {
      return res.status(400).json({
        error: 'invalid_input',
        status: 400,
        details: 'Wymagane: replyToMessageId lub threadId.'
      });
    }
    if (!text && !html) {
      return res.status(400).json({ error: 'invalid_input', status: 400, details: 'Wymagane: text lub html.' });
    }

    let threadId = threadIdInput || '';
    let inReplyTo = inReplyToInput || '';
    let references = referencesInput || '';
    let to = toInput || '';
    let subject = subjectInput || '';

    // Jeśli mamy replyToMessageId — pobierz oryginał, by dopiąć threadId i nagłówki
    if (replyToMessageId) {
      const orig = await gmail.users.messages.get({
        userId: 'me',
        id: replyToMessageId,
        format: 'metadata',
        metadataHeaders: ['Subject', 'From', 'Reply-To', 'Message-ID', 'References']
      });

      threadId = threadId || orig.data.threadId || '';
      const hdrs = {};
      for (const h of (orig.data.payload?.headers || [])) {
        hdrs[(h.name || '').toLowerCase()] = h.value || '';
      }

      const messageId = hdrs['message-id'] || hdrs['message-id'] || '';
      const replyToHdr = hdrs['reply-to'] || '';
      const fromHdr = hdrs['from'] || '';
      const subjectHdr = hdrs['subject'] || '';
      const referencesHdr = hdrs['references'] || '';

      if (!to) to = replyToHdr || fromHdr || to;
      if (!subject) {
        subject = subjectHdr || '';
        if (!/^re:/i.test(subject)) subject = `Re: ${subject}`;
      }
      if (!inReplyTo && messageId) inReplyTo = messageId;
      if (!references) {
        references = referencesHdr ? `${referencesHdr} ${messageId}`.trim() : (messageId || '');
      }
    }

    // Zbuduj MIME
    const mime = buildMimeMessage({
      to, subject, text, html,
      attachments: Array.isArray(attachments) ? attachments : [],
      inReplyTo, references
    });
    const raw = base64Url(mime);

    const sendResp = await gmail.users.messages.send({
      userId: 'me',
      requestBody: { raw, threadId: threadId || undefined }
    });

    return res.json({
      id: sendResp.data.id,
      threadId: sendResp.data.threadId,
      labelIds: sendResp.data.labelIds
    });
  } catch (e) {
    const status = e?.response?.status || 500;
    res.status(status).json({ error: 'gmail_reply_failed', status, details: e?.response?.data || e?.message });
  }
});
// GET /gmail/labels — lista etykiet
app.get('/gmail/labels', async (req, res) => {
  try {
    if (!ensureAuthOr401(res)) return;
    const gmail = google.gmail({ version: 'v1', auth: oAuth2Client });

    const r = await gmail.users.labels.list({ userId: 'me' });
    const value = (r.data.labels || []).map(l => ({
      id: l.id,
      name: l.name,
      type: l.type,
      messageListVisibility: l.messageListVisibility,
      labelListVisibility: l.labelListVisibility
    }));

    return res.json({ value, Count: value.length });
  } catch (err) {
    const status = err?.response?.status || 400;
    console.error('GET /gmail/labels error', err?.message || err);
    return res.status(status).json({
      error: 'gmail_labels_failed',
      status,
      details: err?.response?.data || { message: err?.message || 'Unknown error' }
    });
  }
});
// POST /gmail/modify — dodaj/usuń etykiety (nazwy LUB ID)
app.post('/gmail/modify', async (req, res) => {
  try {
    if (!ensureAuthOr401(res)) return;
    const gmail = google.gmail({ version: 'v1', auth: oAuth2Client });

    const id = (req.body?.id || req.query?.id || '').toString().trim();
    if (!id) {
      return res.status(400).json({ error: 'missing_id', status: 400, details: 'Podaj id wiadomości w body lub query.' });
    }

    const addLabelsRaw = Array.isArray(req.body?.addLabels) ? req.body.addLabels : [];
    const removeLabelsRaw = Array.isArray(req.body?.removeLabels) ? req.body.removeLabels : [];

    const [addLabelIds, removeLabelIds] = await Promise.all([
      mapLabelNamesToIds(gmail, addLabelsRaw),
      mapLabelNamesToIds(gmail, removeLabelsRaw)
    ]);

    const r = await gmail.users.messages.modify({
      userId: 'me',
      id,
      requestBody: { addLabelIds, removeLabelIds }
    });

    return res.json({
      id: r.data.id,
      threadId: r.data.threadId,
      labelIds: r.data.labelIds || []
    });
  } catch (err) {
    const status = err?.response?.status || 400;
    console.error('POST /gmail/modify error', err?.message || err);
    return res.status(status).json({
      error: 'gmail_modify_failed',
      status,
      details: err?.response?.data || { message: err?.message || 'Unknown error' }
    });
  }
});

// POST /gmail/markAsRead — usuń UNREAD
app.post('/gmail/markAsRead', async (req, res) => {
  try {
    if (!ensureAuthOr401(res)) return;
    const gmail = google.gmail({ version: 'v1', auth: oAuth2Client });

    const id = (req.body?.id || req.query?.id || '').toString().trim();
    if (!id) {
      return res.status(400).json({ error: 'missing_id', status: 400, details: 'Podaj id wiadomości w body lub query.' });
    }

    const r = await gmail.users.messages.modify({
      userId: 'me',
      id,
      requestBody: { removeLabelIds: ['UNREAD'] }
    });

    return res.json({ id: r.data.id, threadId: r.data.threadId, labelIds: r.data.labelIds || [] });
  } catch (err) {
    const status = err?.response?.status || 400;
    console.error('POST /gmail/markAsRead error', err?.message || err);
    return res.status(status).json({
      error: 'gmail_mark_read_failed',
      status,
      details: err?.response?.data || { message: err?.message || 'Unknown error' }
    });
  }
});

// POST /gmail/markAsUnread — dodaj UNREAD
app.post('/gmail/markAsUnread', async (req, res) => {
  try {
    if (!ensureAuthOr401(res)) return;
    const gmail = google.gmail({ version: 'v1', auth: oAuth2Client });

    const id = (req.body?.id || req.query?.id || '').toString().trim();
    if (!id) {
      return res.status(400).json({ error: 'missing_id', status: 400, details: 'Podaj id wiadomości w body lub query.' });
    }

    const r = await gmail.users.messages.modify({
      userId: 'me',
      id,
      requestBody: { addLabelIds: ['UNREAD'] }
    });

    return res.json({ id: r.data.id, threadId: r.data.threadId, labelIds: r.data.labelIds || [] });
  } catch (err) {
    const status = err?.response?.status || 400;
    console.error('POST /gmail/markAsUnread error', err?.message || err);
    return res.status(status).json({
      error: 'gmail_mark_unread_failed',
      status,
      details: err?.response?.data || { message: err?.message || 'Unknown error' }
    });
  }
});


// Reply in thread
app.post('/gmail/reply', async (req, res) => {
  try {
    if (!ensureAuthOr401(res)) return;
    const { replyToMessageId, threadId, to, subject, text, html, attachments, inReplyTo, references } = req.body || {};
    const gmail = google.gmail({ version: 'v1', auth: oAuth2Client });

    let useThreadId = threadId;
    let headers = [];
    if (replyToMessageId) {
      const orig = await gmail.users.messages.get({ userId: 'me', id: replyToMessageId, format: 'metadata', metadataHeaders: ['Message-ID', 'In-Reply-To', 'References', 'From', 'To', 'Subject'] });
      useThreadId = useThreadId || orig.data.threadId;
      const hs = orig.data.payload?.headers || [];
      const getH = (n) => hs.find(h => h.name?.toLowerCase() === n.toLowerCase())?.value || '';
      if (!subject) headers.push(`Subject: Re: ${getH('Subject')}`);
      headers.push(`In-Reply-To: ${inReplyTo || getH('Message-ID')}`);
      const refs = [getH('References'), getH('Message-ID')].filter(Boolean).join(' ').trim();
      if (refs) headers.push(`References: ${references || refs}`);
      if (!to) headers.push(`To: ${getH('From')}`);
    } else {
      if (to) headers.push(`To: ${to}`);
      if (subject) headers.push(`Subject: ${subject}`);
    }

    const boundary = 'jarvis_reply_' + crypto.randomBytes(8).toString('hex');
    headers.push('MIME-Version: 1.0');
    let body = '';

    if (attachments && attachments.length) {
      headers.push(`Content-Type: multipart/mixed; boundary="${boundary}"`);
      const altBoundary = boundary + '_alt';

      body += `--${boundary}\r\n`;
      body += `Content-Type: multipart/alternative; boundary="${altBoundary}"\r\n\r\n`;
      if (text) {
        body += `--${altBoundary}\r\n`;
        body += `Content-Type: text/plain; charset="UTF-8"\r\n\r\n${text}\r\n`;
      }
      if (html) {
        body += `--${altBoundary}\r\n`;
        body += `Content-Type: text/html; charset="UTF-8"\r\n\r\n${html}\r\n`;
      }
      body += `--${altBoundary}--\r\n`;

      for (const a of attachments) {
        if (!a?.filename || !a?.mimeType || !a?.data) continue;
        body += `--${boundary}\r\n`;
        body += `Content-Type: ${a.mimeType}; name="${a.filename}"\r\n`;
        body += `Content-Disposition: attachment; filename="${a.filename}"\r\n`;
        body += 'Content-Transfer-Encoding: base64\r\n\r\n';
        body += `${a.data}\r\n`;
      }
      body += `--${boundary}--`;
    } else if (html) {
      headers.push('Content-Type: text/html; charset="UTF-8"');
      body = html;
    } else {
      headers.push('Content-Type: text/plain; charset="UTF-8"');
      body = text || '';
    }

    const raw = base64url(headers.join('\r\n') + '\r\n\r\n' + body);
    const send = await gmail.users.messages.send({
      userId: 'me',
      requestBody: { raw, threadId: useThreadId },
    });
    res.json({ id: send.data.id, threadId: send.data.threadId, labelIds: send.data.labelIds });
  } catch (e) {
    const status = e?.response?.status || 500;
    res.status(status).json({ error: 'gmail_reply_failed', status, details: e?.response?.data || e?.message });
  }
});

// ==== Drive ====
app.get('/drive/search', async (req, res) => {
  try {
    if (!ensureAuthOr401(res)) return;
    const drive = google.drive({ version: 'v3', auth: oAuth2Client });

    // ── Query params ──────────────────────────────────────────────────────────
    const nameQ         = (req.query.q || '').toString().trim();
    const fullTextQ     = (req.query.fulltext || '').toString().trim();
    const type          = (req.query.type || '').toString().trim().toLowerCase();
    const owner         = (req.query.owner || '').toString().trim();
    const modifiedAfter = (req.query.modifiedAfter || '').toString().trim();
    const modifiedBefore= (req.query.modifiedBefore || '').toString().trim();
    const pageSize      = Math.max(1, Math.min(100, parseInt(req.query.pageSize) || 20));

    const minSize = Number.isFinite(parseInt(req.query.minSize)) ? parseInt(req.query.minSize) : null;
    const maxSize = Number.isFinite(parseInt(req.query.maxSize)) ? parseInt(req.query.maxSize) : null;

    const exportFmt = (req.query.export || '').toString().toLowerCase(); // 'csv' | 'json' | ''
    const raw = ['1','true','yes','y'].includes((req.query.raw || '').toString().toLowerCase());
    const pageTokenParam = (req.query.pageToken || '').toString().trim() || undefined;

    // CSV: pobierz wszystkie strony?
    const allPages = ['1','true','yes','y'].includes((req.query.allPages || '').toString().toLowerCase());
    const maxTotal = Math.max(1, Math.min(10000, parseInt(req.query.maxTotal) || 2000)); // twarde ograniczenie

    // NOWE: prefiks nazwy + sort
    const namePrefix = (req.query.namePrefix || '').toString().trim();
    const sort = (req.query.sort || 'modified').toString().toLowerCase();           // 'modified' | 'name'
    const sortDir = (req.query.sortDir || (sort === 'modified' ? 'desc' : 'asc')).toString().toLowerCase(); // 'asc' | 'desc'
    const dirSuffix = (sortDir === 'desc') ? ' desc' : '';
    let orderBy = `modifiedTime${sort === 'modified' ? dirSuffix : ' desc'}`;
    if (sort === 'name') orderBy = `name${dirSuffix}`;

    // NOWE: includeShared + ext
    const includeShared = !['0','false','no','n'].includes((req.query.includeShared || 'true').toString().toLowerCase());
    const extParam = (req.query.ext || '').toString().trim();
    const extList = extParam ? extParam.split(',').map(s => s.trim().toLowerCase()).filter(Boolean) : [];

    // ── Mapowanie typów na MIME (parametr "type") ────────────────────────────
    const mimeMap = {
      pdf:        'application/pdf',
      doc:        'application/msword',
      docx:       'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      document:   'application/vnd.google-apps.document',
      sheet:      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      xlsx:       'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      spreadsheet:'application/vnd.google-apps.spreadsheet',
      slides:     'application/vnd.google-apps.presentation',
      ppt:        'application/vnd.ms-powerpoint',
      pptx:       'application/vnd.openxmlformats-officedocument.presentationml.presentation',
      folder:     'application/vnd.google-apps.folder',
      image:      'image/',   // prefix
      video:      'video/',   // prefix
      csv:        'text/csv',
      txt:        'text/plain',
      zip:        'application/zip',
    };

    // ── Budowa zapytania q ────────────────────────────────────────────────────
    const filters = ["trashed = false"];

    if (nameQ)      filters.push(`name contains '${nameQ.replace(/'/g, "\\'")}'`);
    if (fullTextQ)  filters.push(`fullText contains '${fullTextQ.replace(/'/g, "\\'")}'`);

    if (type) {
      const mime = mimeMap[type];
      if (mime) {
        if (mime.endsWith('/')) filters.push(`mimeType contains '${mime}'`);
        else filters.push(`mimeType = '${mime}'`);
      } else if (type.startsWith('mime:')) {
        filters.push(`mimeType = '${type.slice(5)}'`);
      }
    }

    // includeShared=false → tylko pliki, których jesteś właścicielem (chyba że owner=…)
    if (!includeShared && !owner) {
      filters.push(`'me' in owners`);
    }

    if (owner) {
      const val = owner === 'me' ? 'me' : owner;
      filters.push(`'${val.replace(/'/g, "\\'")}' in owners`);
    }

    if (modifiedAfter)  filters.push(`modifiedTime >= '${modifiedAfter}'`);
    if (modifiedBefore) filters.push(`modifiedTime <= '${modifiedBefore}'`);

    // Seed dla namePrefix (zawężenie po stronie Google)
    if (namePrefix) {
      const npEsc = namePrefix.replace(/'/g, "\\'");
      filters.push(`name contains '${npEsc}'`);
    }

    // Seed dla ext (zawężenie po stronie Google)
    if (extList.length) {
      const orParts = extList.slice(0, 20).map(e => `name contains '.${e.replace(/'/g, "\\'")}'`);
      filters.push(`(${orParts.join(' or ')})`);
    }

    const q = filters.join(' and ');

    // ── Pobranie 1 strony + filtry po stronie serwera ────────────────────────
    const fetchPage = async (pageToken) => {
      const resp = await drive.files.list({
        q,
        fields: 'nextPageToken, files(id,name,mimeType,modifiedTime,owners(displayName,emailAddress),webViewLink,iconLink,size)',
        pageSize,
        pageToken,
        orderBy,
        includeItemsFromAllDrives: true,
        supportsAllDrives: true,
      });

      let files = resp.data.files || [];

      // Filtry po stronie serwera
      if (minSize !== null) files = files.filter(f => f.size && Number(f.size) >= minSize);
      if (maxSize !== null) files = files.filter(f => f.size && Number(f.size) <= maxSize);

      // Precyzyjny filtr po rozszerzeniu (case-insensitive, endsWith)
      if (extList.length) {
        files = files.filter(f => {
          const n = (f.name || '').toLowerCase();
          return extList.some(e => n.endsWith(`.${e}`));
        });
      }

      // Prefiks nazwy (case-insensitive)
      if (namePrefix) {
        const pref = namePrefix.toLowerCase();
        files = files.filter(f => (f.name || '').toLowerCase().startsWith(pref));
      }

      return { files, nextPageToken: resp.data.nextPageToken };
    };

    // ── CSV ───────────────────────────────────────────────────────────────────
    if (exportFmt === 'csv') {
      let all = [];
      let pageToken = pageTokenParam || undefined;
      const SCAN_LIMIT = allPages ? 1000 : 1; // CSV allPages może skanować dużo stron
      let scans = 0;

      do {
        const { files, nextPageToken } = await fetchPage(pageToken);
        all.push(...files);
        pageToken = allPages ? nextPageToken : undefined;
        scans++;
        if (!pageToken) break;
        if (all.length >= maxTotal) break;
        if (scans >= SCAN_LIMIT) break;
      } while (true);

      const header = ['id','name','mimeType','modifiedTime','ownerName','ownerEmail','webViewLink','size'];
      const esc = (v) => {
        if (v === null || v === undefined) return '';
        const s = String(v).replace(/"/g, '""');
        return `"${s}"`;
      };
      const rows = all.slice(0, maxTotal).map(f => {
        const o = Array.isArray(f.owners) && f.owners[0] ? f.owners[0] : {};
        return [
          esc(f.id),
          esc(f.name),
          esc(f.mimeType),
          esc(f.modifiedTime),
          esc(o.displayName || ''),
          esc(o.emailAddress || ''),
          esc(f.webViewLink || ''),
          esc(f.size || ''),
        ].join(',');
      });
      const csv = [header.join(','), ...rows].join('\r\n');
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', 'attachment; filename="drive-search.csv"');
      return res.send(csv);
    }

    // ── JSON ──────────────────────────────────────────────────────────────────
    // Prefix-aware paging: jeśli jest namePrefix, skanuj strony aż zbierzesz pageSize pasujących
    if (namePrefix) {
      let collected = [];
      let token = pageTokenParam || undefined;
      let lastToken = undefined;

      const SCAN_LIMIT = 20;
      let scans = 0;

      while (collected.length < pageSize && scans < SCAN_LIMIT) {
        const { files, nextPageToken } = await fetchPage(token);
        collected.push(...files);
        if (!nextPageToken) {
          lastToken = undefined;
          break;
        }
        token = nextPageToken;
        lastToken = nextPageToken;
        scans++;
      }

      const slice = collected.slice(0, pageSize);
      if (raw) {
        return res.json({
          files: slice,
          nextPageToken: lastToken,
          pageSize,
          q,
          orderBy,
          namePrefix,
          sort,
          sortDir,
          includeShared,
          ext: extList,
          scans
        });
      }
      return res.json(slice);
    } else {
      const { files, nextPageToken } = await fetchPage(pageTokenParam);
      if (raw) {
        return res.json({ files, nextPageToken, pageSize, q, orderBy, namePrefix, sort, sortDir, includeShared, ext: extList });
      }
      return res.json(files); // kontrakt jak wcześniej
    }

  } catch (e) {
    const status = e?.response?.status || 500;
    res.status(status).json({
      error: 'drive_search_failed',
      status,
      details: e?.response?.data || e?.message
    });
  }
});





// ==== Places (New) ====
app.get('/places/search', async (req, res) => {
  try {
    const q = req.query.q || '';
    const lat = parseFloat(req.query.lat || '52.2297');
    const lng = parseFloat(req.query.lng || '21.0122');
    const radius = parseInt(req.query.radius || '3000', 10);

    if (!MAPS_KEY) return res.status(500).json({ error: 'missing_GOOGLE_MAPS_API_KEY' });

    const url = 'https://places.googleapis.com/v1/places:searchText';
    const body = {
      textQuery: q || 'kawiarnia',
      locationBias: { circle: { center: { latitude: lat, longitude: lng }, radius } },
      maxResultCount: 10,
      languageCode: 'pl',
    };

    const r = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Goog-Api-Key': MAPS_KEY,
        'X-Goog-FieldMask': '*',
      },
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
    res.status(status).json({ error: 'places_search_failed', status, details: e?.response?.data || e?.message });
  }
});

app.get('/places/details', async (req, res) => {
  try {
    const place_id = req.query.place_id;
    if (!MAPS_KEY) return res.status(500).json({ error: 'missing_GOOGLE_MAPS_API_KEY' });
    if (!place_id) return res.status(400).json({ error: 'missing_place_id' });
    const url = `https://places.googleapis.com/v1/${encodeURIComponent(place_id)}`;
    const r = await fetch(url, {
      headers: {
        'X-Goog-Api-Key': MAPS_KEY,
        'X-Goog-FieldMask': '*',
      },
    });
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
    res.status(status).json({ error: 'places_details_failed', status, details: e?.response?.data || e?.message });
  }
});
  // =============== GMAIL: listowanie wiadomości =================
app.get('/gmail/messages', async (req, res) => {
  try {
    if (!ensureAuthOr401(res)) return;
    const gmail = google.gmail({ version: 'v1', auth: oAuth2Client });

    // ── Parametry ──────────────────────────────────────────────
    const q         = (req.query.q || '').toString().trim();              // np. newer_than:7d subject:"faktura"
    const pageSize  = Math.max(1, Math.min(100, parseInt(req.query.pageSize) || 25));
    const pageToken = (req.query.pageToken || '').toString().trim() || undefined;
    const raw       = ['1','true','yes','y'].includes((req.query.raw || '').toString().toLowerCase());
    const expand    = ['1','true','yes','y'].includes((req.query.expand || '').toString().toLowerCase()); // lekkie metadane

    // ── Listowanie ID-ów ──────────────────────────────────────
    const listResp = await gmail.users.messages.list({
      userId: 'me',
      q: q || undefined,
      maxResults: pageSize,
      pageToken,
      includeSpamTrash: false,
      fields: 'nextPageToken,resultSizeEstimate,messages/id,messages/threadId'
    });

    const ids = (listResp.data.messages || []).map(m => m.id);

    // Bez expand => zwracamy tylko ID i threadId (lekko)
    if (!expand) {
      const minimal = (listResp.data.messages || []).map(m => ({ id: m.id, threadId: m.threadId }));
      if (raw) {
        return res.json({
          messages: minimal,
          nextPageToken: listResp.data.nextPageToken,
          pageSize,
          q
        });
      }
      return res.json(minimal);
    }

    // Expand=1 => lekkie metadane (headers + snippet) z limitem współbieżności
    const CONCURRENCY = 10;
    let cursor = 0;
    const results = new Array(ids.length);
    const worker = async () => {
      while (cursor < ids.length) {
        const i = cursor++;
        const id = ids[i];
        try {
          const msg = await gmail.users.messages.get({
            userId: 'me',
            id,
            format: 'metadata',
            metadataHeaders: ['Subject','From','To','Date'],
            fields: 'id,threadId,labelIds,internalDate,sizeEstimate,snippet,payload/headers'
          });

          const headers = (msg.data.payload && msg.data.payload.headers) || [];
          const h = (name) => {
            const x = headers.find(h => (h.name || '').toLowerCase() === name.toLowerCase());
            return x ? x.value || '' : '';
          };

          let dateISO = '';
          try {
            const rawDate = h('Date');
            if (rawDate) dateISO = new Date(rawDate).toISOString();
          } catch (_) { /* ignore parse issues */ }

          results[i] = {
            id: msg.data.id,
            threadId: msg.data.threadId,
            subject: h('Subject'),
            from: h('From'),
            to: h('To'),
            date: dateISO,
            snippet: msg.data.snippet || ''
          };
        } catch (e) {
          // awaria pojedynczego maila nie psuje całej strony
          results[i] = { id, threadId: (listResp.data.messages || [])[i]?.threadId || '', error: 'fetch_failed' };
        }
      }
    };

    await Promise.all(new Array(Math.min(CONCURRENCY, ids.length)).fill(0).map(() => worker()));

    if (raw) {
      return res.json({
        messages: results,
        nextPageToken: listResp.data.nextPageToken,
        pageSize,
        q
      });
    }
    return res.json(results);

  } catch (e) {
    const status = e?.response?.status || 500;
    res.status(status).json({
      error: 'gmail_list_failed',
      status,
      details: e?.response?.data || e?.message
    });
  }
});
// =============== GMAIL: szczegóły pojedynczej wiadomości ===============
app.get('/gmail/message', async (req, res) => {
  try {
    if (!ensureAuthOr401(res)) return;
    const gmail = google.gmail({ version: 'v1', auth: oAuth2Client });

    const id = (req.query.id || '').toString().trim();
    const raw = ['1','true','yes','y'].includes((req.query.raw || '').toString().toLowerCase());
    if (!id) {
      return res.status(400).json({ error: 'missing_id', status: 400, details: 'Parametr ?id= jest wymagany.' });
    }

    // ✅ poprawna maska pól (headers(name,value), zagnieżdżone parts(...))
    const msg = await gmail.users.messages.get({
      userId: 'me',
      id,
      format: 'full',
      fields: 'id,threadId,labelIds,internalDate,sizeEstimate,snippet,payload(partId,filename,mimeType,headers(name,value),body(size,data,attachmentId),parts(partId,filename,mimeType,headers(name,value),body(size,data,attachmentId),parts))'
    });

    const payload = msg.data.payload || {};
    const headers = Array.isArray(payload.headers) ? payload.headers : [];
    const h = (name) => {
      const x = headers.find(h => (h.name || '').toLowerCase() === name.toLowerCase());
      return x ? (x.value || '') : '';
    };

    let dateISO = '';
    try { const rawDate = h('Date'); if (rawDate) dateISO = new Date(rawDate).toISOString(); } catch {}

    const attachments = [];
    let htmlParts = [];
    let textParts = [];
    const decodeB64 = (b64url) => {
      try { return Buffer.from((b64url||'').replace(/-/g,'+').replace(/_/g,'/'),'base64').toString('utf8'); }
      catch { return ''; }
    };
    const walk = (part) => {
      if (!part) return;
      const mime = part.mimeType || '';
      const body = part.body || {};
      const data = body.data || '';
      const filename = part.filename || '';

      if (mime.toLowerCase() === 'text/html' && data) htmlParts.push(decodeB64(data));
      else if (mime.toLowerCase() === 'text/plain' && data) textParts.push(decodeB64(data));

      if (filename && body.attachmentId) {
        attachments.push({
          filename,
          mimeType: mime || 'application/octet-stream',
          size: body.size || 0,
          attachmentId: body.attachmentId,
          partId: part.partId || ''
        });
      }
      if (Array.isArray(part.parts)) part.parts.forEach(walk);
    };
    walk(payload);

    const result = {
      id: msg.data.id,
      threadId: msg.data.threadId,
      subject: h('Subject'),
      from: h('From'),
      to: h('To'),
      date: dateISO,
      snippet: msg.data.snippet || '',
      headers: headers.reduce((acc, it) => { if (it && it.name) acc[it.name] = it.value || ''; return acc; }, {}),
      body: { html: htmlParts.join('\n'), text: textParts.join('\n') },
      attachments
    };
    if (raw) result.rawMessage = msg.data;

    return res.json(result);
  } catch (e) {
    const status = e?.response?.status || 500;
    res.status(status).json({ error: 'gmail_message_failed', status, details: e?.response?.data || e?.message });
  }
});

// =============== GMAIL: szczegóły pojedynczej wiadomości ===============
app.get('/gmail/message', async (req, res) => {
  try {
    if (!ensureAuthOr401(res)) return;
    const gmail = google.gmail({ version: 'v1', auth: oAuth2Client });

    const id = (req.query.id || '').toString().trim();
    const raw = ['1','true','yes','y'].includes((req.query.raw || '').toString().toLowerCase());
    if (!id) {
      return res.status(400).json({ error: 'missing_id', status: 400, details: 'Parametr ?id= jest wymagany.' });
    }

    const msg = await gmail.users.messages.get({
      userId: 'me',
      id,
      format: 'full',
      fields: 'id,threadId,labelIds,internalDate,sizeEstimate,snippet,payload(partId,mimeType,filename,headers,name,value,body(size,data,attachmentId),parts)'
    });

    const payload = msg.data.payload || {};
    const headers = Array.isArray(payload.headers) ? payload.headers : [];
    const h = (name) => {
      const x = headers.find(h => (h.name || '').toLowerCase() === name.toLowerCase());
      return x ? (x.value || '') : '';
    };

    let dateISO = '';
    try { const rawDate = h('Date'); if (rawDate) dateISO = new Date(rawDate).toISOString(); } catch {}

    const attachments = [];
    let htmlParts = [];
    let textParts = [];
    const decodeB64 = (b64url) => {
      try { return Buffer.from((b64url||'').replace(/-/g,'+').replace(/_/g,'/'),'base64').toString('utf8'); }
      catch { return ''; }
    };
    const walk = (part) => {
      if (!part) return;
      const mime = part.mimeType || '';
      const body = part.body || {};
      const data = body.data || '';
      const filename = part.filename || '';

      if (mime.toLowerCase() === 'text/html' && data) htmlParts.push(decodeB64(data));
      else if (mime.toLowerCase() === 'text/plain' && data) textParts.push(decodeB64(data));

      if (filename && body.attachmentId) {
        attachments.push({
          filename,
          mimeType: mime || 'application/octet-stream',
          size: body.size || 0,
          attachmentId: body.attachmentId,
          partId: part.partId || ''
        });
      }
      if (Array.isArray(part.parts)) part.parts.forEach(walk);
    };
    walk(payload);

    const result = {
      id: msg.data.id,
      threadId: msg.data.threadId,
      subject: h('Subject'),
      from: h('From'),
      to: h('To'),
      date: dateISO,
      snippet: msg.data.snippet || '',
      headers: headers.reduce((acc, it) => { if (it && it.name) acc[it.name] = it.value || ''; return acc; }, {}),
      body: { html: htmlParts.join('\n'), text: textParts.join('\n') },
      attachments
    };
    if (raw) result.rawMessage = msg.data;

    return res.json(result);
  } catch (e) {
    const status = e?.response?.status || 500;
    res.status(status).json({ error: 'gmail_message_failed', status, details: e?.response?.data || e?.message });
  }
});

// =============== GMAIL: pobieranie załącznika po attachmentId ===============
app.get('/gmail/attachment', async (req, res) => {
  try {
    if (!ensureAuthOr401(res)) return;
    const gmail = google.gmail({ version: 'v1', auth: oAuth2Client });

    const messageId = (req.query.messageId || '').toString().trim();
    const attachmentId = (req.query.attachmentId || '').toString().trim();
    const filename = (req.query.filename || 'attachment.bin').toString().trim();
    const disposition = ((req.query.disposition || 'attachment').toString().toLowerCase() === 'inline') ? 'inline' : 'attachment';
    const contentType = (req.query.contentType || 'application/octet-stream').toString().trim();

    if (!messageId || !attachmentId) {
      return res.status(400).json({ error: 'missing_params', status: 400, details: 'Wymagane: messageId i attachmentId.' });
    }

    const att = await gmail.users.messages.attachments.get({
      userId: 'me',
      messageId,
      id: attachmentId,
      fields: 'data,size'
    });

    const b64url = att.data?.data || '';
    if (!b64url) {
      return res.status(404).json({ error: 'not_found', status: 404, details: 'Załącznik nie zawiera danych.' });
    }

    const buffer = Buffer.from(b64url.replace(/-/g,'+').replace(/_/g,'/'), 'base64');

    // --- SANITYZACJA NAZWY PLIKU (Windows/Mac/Linux) + RFC5987 ---
    function sanitizeFilename(name) {
      const fallback = 'attachment.bin';
      if (!name || typeof name !== 'string') return fallback;
      const cleaned = name
        .replace(/[\\/:*?"<>|]/g, '-')    // niedozwolone w Windows
        .replace(/[\u0000-\u001F]/g, '')  // kontrolne
        .replace(/\s+/g, ' ')
        .trim();
      return cleaned || fallback;
    }
    function encodeRFC5987(value) {
      return encodeURIComponent(value)
        .replace(/'/g, '%27')
        .replace(/\*/g, '%2A')
        .replace(/%20/g, '%20');
    }

    const fnSafe = sanitizeFilename(filename);
    res.setHeader('Content-Type', contentType);
    res.setHeader('Content-Length', buffer.length);
    res.setHeader(
      'Content-Disposition',
      `${disposition}; filename="${fnSafe}"; filename*=UTF-8''${encodeRFC5987(fnSafe)}`
    );
    return res.send(buffer);
  } catch (e) {
    const status = e?.response?.status || 500;
    res.status(status).json({ error: 'gmail_attachment_failed', status, details: e?.response?.data || e?.message });
  }
});

// =============== GMAIL: helpery MIME ===============
function base64Url(bufferOrString) {
  const b = Buffer.isBuffer(bufferOrString) ? bufferOrString : Buffer.from(bufferOrString, 'utf8');
  return b.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
function needsHeaderEncoding(str) {
  return /[^\x20-\x7E]/.test(str); // poza ASCII
}
function encodeHeaderUTF8(str) {
  // Bezpieczniej zawsze kodować, ale minimalnie: tylko gdy trzeba
  const s = String(str || '');
  if (!s) return '';
  const b64 = Buffer.from(s, 'utf8').toString('base64');
  return `=?UTF-8?B?${b64}?=`;
}
function formatHeader(name, value) {
  if (!value) return '';
  const v = needsHeaderEncoding(value) ? encodeHeaderUTF8(value) : value;
  return `${name}: ${v}`;
}
function makeBoundary(prefix='mix') {
  return `${prefix}__${Math.random().toString(16).slice(2)}_${Date.now()}`;
}
function chunkBase64(b64, lineLen=76) {
  return (b64.match(new RegExp(`.{1,${lineLen}}`, 'g')) || []).join('\r\n');
}
function sanitizeFilename(name) {
  const fallback = 'attachment.bin';
  if (!name || typeof name !== 'string') return fallback;
  const cleaned = name.replace(/[\\/:*?"<>|]/g, '-').replace(/[\u0000-\u001F]/g, '').replace(/\s+/g, ' ').trim();
  return cleaned || fallback;
}

// Top-level builder: mixed( alternative(text,html), attachments... )
function buildMimeMessage({ from, to, subject, text, html, attachments = [], inReplyTo, references }) {
  const headers = [];
  headers.push('MIME-Version: 1.0');
  if (from) headers.push(formatHeader('From', from));
  if (to) headers.push(formatHeader('To', to));
  if (subject) headers.push(formatHeader('Subject', subject));
  headers.push(`Date: ${new Date().toUTCString()}`);
  if (inReplyTo) headers.push(`In-Reply-To: ${inReplyTo}`);
  if (references) headers.push(`References: ${references}`);

  const hasText = !!text;
  const hasHtml = !!html;
  const hasAtch = Array.isArray(attachments) && attachments.length > 0;

  // 1) Bez załączników
  if (!hasAtch) {
    // 1a) Tylko HTML albo tylko TEXT
    if (hasHtml && !hasText) {
      const body = Buffer.from(html, 'utf8').toString('base64');
      headers.push('Content-Type: text/html; charset="UTF-8"');
      headers.push('Content-Transfer-Encoding: base64');
      return headers.join('\r\n') + '\r\n\r\n' + chunkBase64(body);
    }
    if (hasText && !hasHtml) {
      const body = Buffer.from(text, 'utf8').toString('base64');
      headers.push('Content-Type: text/plain; charset="UTF-8"');
      headers.push('Content-Transfer-Encoding: base64');
      return headers.join('\r\n') + '\r\n\r\n' + chunkBase64(body);
    }
    // 1b) TXT + HTML => multipart/alternative
    const bAlt = makeBoundary('alt');
    headers.push(`Content-Type: multipart/alternative; boundary="${bAlt}"`);
    const parts = [];
    // text
    parts.push(`--${bAlt}`);
    parts.push('Content-Type: text/plain; charset="UTF-8"');
    parts.push('Content-Transfer-Encoding: base64');
    parts.push('');
    parts.push(chunkBase64(Buffer.from(text || '', 'utf8').toString('base64')));
    // html
    parts.push(`--${bAlt}`);
    parts.push('Content-Type: text/html; charset="UTF-8"');
    parts.push('Content-Transfer-Encoding: base64');
    parts.push('');
    parts.push(chunkBase64(Buffer.from(html || '', 'utf8').toString('base64')));
    // end
    parts.push(`--${bAlt}--`);
    return headers.join('\r\n') + '\r\n\r\n' + parts.join('\r\n');
  }

  // 2) Z załącznikami => multipart/mixed
  const bMixed = makeBoundary('mixed');
  headers.push(`Content-Type: multipart/mixed; boundary="${bMixed}"`);
  const out = [];

  // (a) część treści — single lub alternative
  if (hasText && hasHtml) {
    const bAlt = makeBoundary('alt');
    out.push(`--${bMixed}`);
    out.push(`Content-Type: multipart/alternative; boundary="${bAlt}"`);
    out.push('');
    // text
    out.push(`--${bAlt}`);
    out.push('Content-Type: text/plain; charset="UTF-8"');
    out.push('Content-Transfer-Encoding: base64');
    out.push('');
    out.push(chunkBase64(Buffer.from(text, 'utf8').toString('base64')));
    // html
    out.push(`--${bAlt}`);
    out.push('Content-Type: text/html; charset="UTF-8"');
    out.push('Content-Transfer-Encoding: base64');
    out.push('');
    out.push(chunkBase64(Buffer.from(html, 'utf8').toString('base64')));
    out.push(`--${bAlt}--`);
  } else if (hasHtml) {
    out.push(`--${bMixed}`);
    out.push('Content-Type: text/html; charset="UTF-8"');
    out.push('Content-Transfer-Encoding: base64');
    out.push('');
    out.push(chunkBase64(Buffer.from(html, 'utf8').toString('base64')));
  } else {
    out.push(`--${bMixed}`);
    out.push('Content-Type: text/plain; charset="UTF-8"');
    out.push('Content-Transfer-Encoding: base64');
    out.push('');
    out.push(chunkBase64(Buffer.from(text || '', 'utf8').toString('base64')));
  }

  // (b) załączniki
  for (const a of attachments) {
    if (!a || !a.contentBase64) continue;
    const name = sanitizeFilename(a.filename || 'attachment.bin');
    const ctype = a.contentType || 'application/octet-stream';
    const b64 = a.contentBase64.replace(/\r?\n/g, '');
    out.push(`--${bMixed}`);
    out.push(`Content-Type: ${ctype}; name="${name}"`);
    out.push('Content-Transfer-Encoding: base64');
    out.push(`Content-Disposition: attachment; filename="${name}"`);
    out.push('');
    out.push(chunkBase64(b64));
  }
  out.push(`--${bMixed}--`);

  return headers.join('\r\n') + '\r\n\r\n' + out.join('\r\n');
}

// =============== GMAIL: wysyłka nowej wiadomości ===============
app.post('/gmail/send', async (req, res) => {
  try {
    if (!ensureAuthOr401(res)) return;
    const gmail = google.gmail({ version: 'v1', auth: oAuth2Client });

    const { to, subject, text, html, from, attachments } = req.body || {};
    if (!to || !subject || (!text && !html)) {
      return res.status(400).json({
        error: 'invalid_input',
        status: 400,
        details: 'Wymagane: to, subject oraz (text lub html).'
      });
    }

    const mime = buildMimeMessage({
      from,
      to,
      subject,
      text,
      html,
      attachments: Array.isArray(attachments) ? attachments : []
    });
    const raw = base64Url(mime);

    const sendResp = await gmail.users.messages.send({
      userId: 'me',
      requestBody: { raw }
    });

    return res.json({
      id: sendResp.data.id,
      threadId: sendResp.data.threadId,
      labelIds: sendResp.data.labelIds
    });
  } catch (e) {
    const status = e?.response?.status || 500;
    res.status(status).json({ error: 'gmail_send_failed', status, details: e?.response?.data || e?.message });
  }
});


// =============== GMAIL: pobieranie załącznika po attachmentId ===============
app.get('/gmail/attachment', async (req, res) => {
  try {
    if (!ensureAuthOr401(res)) return;
    const gmail = google.gmail({ version: 'v1', auth: oAuth2Client });

    const messageId = (req.query.messageId || '').toString().trim();
    const attachmentId = (req.query.attachmentId || '').toString().trim();
    const filename = (req.query.filename || 'attachment.bin').toString().trim();
    const disposition = ((req.query.disposition || 'attachment').toString().toLowerCase() === 'inline') ? 'inline' : 'attachment';
    const contentType = (req.query.contentType || 'application/octet-stream').toString().trim();

    if (!messageId || !attachmentId) {
      return res.status(400).json({ error: 'missing_params', status: 400, details: 'Wymagane: messageId i attachmentId.' });
    }

    const att = await gmail.users.messages.attachments.get({
      userId: 'me',
      messageId,
      id: attachmentId,
      fields: 'data,size'
    });

    const b64url = att.data?.data || '';
    if (!b64url) {
      return res.status(404).json({ error: 'not_found', status: 404, details: 'Załącznik nie zawiera danych.' });
    }

    const buffer = Buffer.from(b64url.replace(/-/g,'+').replace(/_/g,'/'), 'base64');
    res.setHeader('Content-Type', contentType);
    res.setHeader('Content-Length', buffer.length);
    res.setHeader('Content-Disposition', `${disposition}; filename="${filename.replace(/"/g, '')}"`);
    return res.send(buffer);
  } catch (e) {
    const status = e?.response?.status || 500;
    res.status(status).json({ error: 'gmail_attachment_failed', status, details: e?.response?.data || e?.message });
  }
});


// Start server
app.listen(PORT, () => {
  if (BASE_URL.includes('localhost')) {
    console.log(`Serwer działa na http://localhost:${PORT}`);
  }
});
