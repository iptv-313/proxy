require("dotenv").config();
const express = require("express");
const fetch   = require("node-fetch");
const cors    = require("cors");
const crypto  = require("crypto");

const app  = express();
const PORT = process.env.PORT || 3001;
const HOST = process.env.HOST || "0.0.0.0";
const dbAuth = require("./db");

app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || "*",
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
  allowedHeaders: ["Content-Type", "Authorization", "X-User-Agent", "X-Guest-Id", "X-Auth-Code", "Cookie", "Range"],
  exposedHeaders: ["Content-Length", "Content-Range", "Accept-Ranges"],
}));
app.use(express.json({ limit: "10mb" }));

// ── Cache: path resolution cached long-term, tokens are never cached (portals invalidate on re-handshake)
const pathCache = new Map();
const streamTickets = new Map();
const STREAM_TICKET_TTL_MS = 6 * 60 * 60 * 1000;

function issueStreamTicket(url) {
  const now = Date.now();
  if (streamTickets.size >= 10000) {
    for (const [ticket, entry] of streamTickets) {
      if (entry.expiresAt <= now) streamTickets.delete(ticket);
    }
    if (streamTickets.size >= 10000) {
      streamTickets.delete(streamTickets.keys().next().value);
    }
  }
  const ticket = crypto.randomBytes(32).toString("base64url");
  streamTickets.set(ticket, { url, expiresAt: now + STREAM_TICKET_TTL_MS });
  let isHls = false;
  try { isHls = new URL(url).pathname.toLowerCase().endsWith(".m3u8"); } catch {}
  return `${isHls ? "/stream.m3u8" : "/stream"}?ticket=${ticket}`;
}

function streamTarget(ticket) {
  const entry = streamTickets.get(String(ticket || ""));
  if (!entry) return null;
  if (entry.expiresAt <= Date.now()) {
    streamTickets.delete(String(ticket));
    return null;
  }
  return entry.url;
}

// ─────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────

function cacheKey(portal, mac) {
  return `${portal.replace(/\/+$/, "")}|${mac}`;
}

// Fallback API paths to try (from extractstb PortalValidator)
const API_PATHS = [
  "server/load.php",
  "portal.php",
  "stalker_portal/server/load.php",
];

// Build Stalker-style headers (improved from extractstb)
function stalkerHeaders(mac, token = "", portalUrl = "", opts = {}) {
  const referer = portalUrl
    ? portalUrl.replace(/\/+$/, "").replace(/\/c$/, "") + "/c/"
    : "http://localhost/";
  const headers = {
    "User-Agent":    "Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG200 stbapp ver: 2 rev: 250 Safari/533.3",
    "Accept":        "*/*",
    "Content-Type":  "application/x-www-form-urlencoded; charset=UTF-8",
    "X-User-Agent":  "Model: MAG250; Link: WiFi",
    "Authorization": token ? `Bearer ${token}` : "Bearer ",
    "Cookie":        `mac=${encodeURIComponent(mac)}; stb_lang=en; timezone=Europe%2FParis`,
    "Referer":       referer,
  };
  if (opts.serial) headers["Cookie"] += `; sn=${opts.serial}`;
  return headers;
}

// Try to extract the real API path from the portal's xpcom.common.js
// (extractstb PortalValidator step 1)
async function extractApiPath(portalUrl, mac) {
  const base = portalUrl.replace(/\/+$/, "");
  const clientUrl = base.endsWith("/c") ? base : base + "/c";
  const url = `${clientUrl}/xpcom.common.js`;
  try {
    const res = await fetch(url, {
      headers: stalkerHeaders(mac, "", portalUrl),
      timeout: 8000,
    });
    if (!res.ok) return null;
    const js = await res.text();

    // Pattern 1: dynamic portal path
    let m = js.match(/this\.ajax_loader\s*=\s*this\.portal_protocol\s*\+\s*"[^"]*"\s*\+\s*this\.portal_ip\s*\+\s*"\/"\s*\+\s*this\.portal_path\s*\+\s*"\/([^"]+)"/);
    if (m) return m[1];

    // Pattern 2: simplified dynamic
    m = js.match(/this\.ajax_loader\s*=\s*[^"]*"[^"]*\/([^"]+\.php)"/);
    if (m) return m[1];

    // Pattern 3: static path
    m = js.match(/this\.ajax_loader\s*=\s*"\/([^"]+\.php)"/);
    if (m) return m[1];
  } catch { /* ignore */ }
  return null;
}

// Try a handshake with a specific base + apiPath combo, using both GET and POST
async function tryHandshake(base, apiPath, mac, portalUrl) {
  const qs = `type=stb&action=handshake&prehash=0&token=&JsHttpRequest=1-xml`;
  const url = `${base}${apiPath}?${qs}`;
  const headers = stalkerHeaders(mac, "", portalUrl);

  try {
    const res = await fetch(url, { headers, timeout: 8000 });
    if (res.status === 429) { console.log(`  ${base}${apiPath} → 429 rate limited`); throw Object.assign(new Error("rate limited"), {code:"RATE_LIMITED"}); }
    if (res.status === 404) return null;
    if (res.ok) {
      const data = await res.json();
      const token = data?.js?.token;
      if (token) return { token, base, apiPath };
    }
  } catch(e) { if (e.code === "RATE_LIMITED") throw e; /* other errors: skip */ }
  return null;
}

// Get a session with a valid token — does exactly ONE handshake
// Path resolution is cached; token is always fresh
async function getSession(portal, mac, opts = {}) {
  const key = cacheKey(portal, mac);
  const cached = pathCache.get(key);

  // If path is known, do a single handshake on the known path
  if (cached) {
    const result = await tryHandshake(cached.base, cached.apiPath, mac, portal);
    if (result) {
      return {
        token: result.token, base: cached.base, apiPath: cached.apiPath, portal, mac, opts,
        headers: stalkerHeaders(mac, result.token, portal, opts),
        async refresh() { return getSession(portal, mac, opts); },
      };
    }
    // Path may have changed — clear cache and re-discover
    pathCache.delete(key);
  }

  // Discover path: try each base+path combo (each attempt is a handshake)
  const stripped = portal.replace(/\/+$/, "");
  const bases = [stripped + "/"];
  if (stripped.endsWith("/c")) {
    bases.push(stripped.replace(/\/c$/, "") + "/");
    const root = stripped.replace(/\/[^/]+\/c$/, "");
    if (root !== stripped) bases.push(root + "/");
  } else {
    bases.push(stripped + "/c/");
  }

  for (const base of bases) {
    for (const path of API_PATHS) {
      try {
        const result = await tryHandshake(base, path, mac, portal);
        if (result) {
          pathCache.set(key, { base, apiPath: path });
          console.log(`✓ Path resolved: ${base}${path}`);
          return {
            token: result.token, base, apiPath: path, portal, mac, opts,
            headers: stalkerHeaders(mac, result.token, portal, opts),
            async refresh() { return getSession(portal, mac, opts); },
          };
        }
      } catch(e) {
        if (e.code === "RATE_LIMITED") throw new Error("Portal rate limited (429). Try again in a minute.");
        throw e;
      }
    }
  }
  throw new Error("Handshake failed: could not obtain token from portal");
}

// portalFetch with automatic token refresh on auth failure
async function portalFetchRetry(session, params, timeout) {
  let result = await portalFetch(session, params, timeout);
  if (result === null) {
    const fresh = await session.refresh();
    Object.assign(session, fresh);
    result = await portalFetch(session, params, timeout);
  }
  if (result === null) throw new Error(`Authorization failed for ${params.action || "unknown"}`);
  return result;
}

// Make an API call using the resolved session
async function portalFetch(session, params, timeout = 12000) {
  const qs = new URLSearchParams({ ...params, JsHttpRequest: "1-xml" }).toString();
  const url = `${session.base}${session.apiPath}?${qs}`;

  try {
    const res = await fetch(url, { headers: session.headers, timeout });
    if (res.ok) {
      const text = await res.text();
      if (text.includes("Authorization failed")) return null; // token expired, signal retry
      return JSON.parse(text);
    }
  } catch { /* network error */ }

  // Try POST as fallback
  try {
    const res = await fetch(url, { method: "POST", headers: session.headers, body: qs, timeout });
    if (res.ok) {
      const text = await res.text();
      if (text.includes("Authorization failed")) return null;
      return JSON.parse(text);
    }
  } catch { /* network error */ }

  throw new Error(`Portal request failed: ${params.action || "unknown"}`);
}

// ─────────────────────────────────────────────────────────────────
// ROUTES
// ─────────────────────────────────────────────────────────────────

app.get("/health", (req, res) => res.json({ status: "ok", uptime: process.uptime() }));

// ── POST /auth/verify
app.post("/auth/verify", async (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ error: "code required" });
  try {
    const user = await dbAuth.verifyCode(code);
    if (user) {
      res.json({ success: true, isAdmin: !!user.is_admin });
    } else {
      res.json({ success: false });
    }
  } catch (e) {
    res.status(500).json({ error: "Database error" });
  }
});

// ── Admin Middleware (Simple)
async function adminOnly(req, res, next) {
  const authCode = req.headers["x-auth-code"];
  if (!authCode) return res.status(401).json({ error: "Unauthorized" });
  try {
    const user = await dbAuth.verifyCode(authCode);
    if (user && user.is_admin) {
      next();
    } else {
      res.status(403).json({ error: "Forbidden" });
    }
  } catch (e) {
    res.status(500).json({ error: "Server error" });
  }
}

// ── Admin Routes
app.get("/admin/users", adminOnly, async (req, res) => {
  try {
    const users = await dbAuth.getAccessCodes();
    res.json(users);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post("/admin/users", adminOnly, async (req, res) => {
  const { code, label, isAdmin } = req.body;
  try {
    const result = await dbAuth.addAccessCode(code, label, isAdmin ? 1 : 0);
    res.json(result);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete("/admin/users/:id", adminOnly, async (req, res) => {
  try {
    await dbAuth.deleteAccessCode(req.params.id);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get("/admin/portals", adminOnly, async (req, res) => {
  try {
    const portals = await dbAuth.getPortals();
    res.json(portals);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post("/admin/portals", adminOnly, async (req, res) => {
  const { name, url, mac, type } = req.body;
  try {
    const result = await dbAuth.addPortal(name, url, mac, type);
    res.json(result);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete("/admin/portals/:id", adminOnly, async (req, res) => {
  try {
    await dbAuth.deletePortal(req.params.id);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Public Portals Route (for users to see what's available)
app.get("/portals", async (req, res) => {
  try {
    const code = req.headers["x-auth-code"];
    if (!code) return res.status(401).json({ error: "Access code required" });
    const user = await dbAuth.verifyCode(code);
    if (!user) return res.status(403).json({ error: "Invalid access code" });
    const portals = await dbAuth.getPortals();
    res.json(portals);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Every Stalker catalog/handshake/resolution endpoint is gated by a valid
// access code from the same SQLite database used by /portals and Admin.
async function requireAccessCode(req, res, next) {
  const code = req.headers["x-auth-code"];
  if (!code) return res.status(401).json({ error: "Access code required" });
  try {
    const user = await dbAuth.verifyCode(code);
    if (!user) return res.status(403).json({ error: "Invalid access code" });
    req.proxyUser = { id: user.id, isAdmin: !!user.is_admin };
    next();
  } catch (e) {
    res.status(500).json({ error: "Authentication database error" });
  }
}

// Web players may request an opaque relay ticket for their configured stream.
// A valid SQLite access code is required; anonymous arbitrary-URL relaying is disabled.
app.post("/stream-ticket", requireAccessCode, (req, res) => {
  const rawUrl = typeof req.body?.url === "string" ? req.body.url.trim() : "";
  if (!rawUrl || rawUrl.length > 8192) return res.status(400).json({ error: "A valid stream URL is required" });
  try {
    const target = new URL(rawUrl);
    if (!["http:", "https:"].includes(target.protocol)) throw new Error("Unsupported protocol");
    res.json({ url: issueStreamTicket(target.toString()) });
  } catch {
    res.status(400).json({ error: "Only valid HTTP(S) stream URLs are supported" });
  }
});

app.use("/stalker", requireAccessCode);

// ── POST /stalker/handshake
app.post("/stalker/handshake", async (req, res) => {
  const { portal, mac, serial, deviceId, deviceId2 } = req.body;
  if (!portal || !mac) return res.status(400).json({ error: "portal and mac required" });

  try {
    const session = await getSession(portal, mac, { serial });
    res.json({ token: session.token });
  } catch (e) {
    console.error("Handshake error:", e.message);
    res.status(502).json({ error: e.message });
  }
});

// ── GET /stalker/channels (نسخة معدلة ومحسنة لتفادي الحظر)
app.get("/stalker/channels", async (req, res) => {
  const { portal, mac } = req.query;
  if (!portal || !mac) return res.status(400).json({ error: "portal and mac required" });

  try {
    const session = await getSession(portal, mac);

    // 1. جلب الفئات أولاً
    const genreData = await portalFetchRetry(session, { type: "itv", action: "get_genres" }, 10000);
    const genres = genreData?.js || [];
    const genreMap = Object.fromEntries(genres.map(g => [g.id, g.title]));

    // 2. محاولة جلب القنوات عبر get_short_channels كخيار أول وأسرع
    let chData;
    try {
      chData = await portalFetchRetry(session, { type: "itv", action: "get_short_channels" }, 15000);
    } catch (e) {
      console.log("get_short_channels failed, trying get_all_channels as fallback...");
      // خيار احتياطي في حال عدم دعم السيرفر للدالة المختصرة
      chData = await portalFetchRetry(session, { type: "itv", action: "get_all_channels" }, 20000);
    }

    const channels = chData?.js?.data || chData?.js || [];

    // إذا رجعت القنوات مصفوفة فارغة، نقوم بجلبها مقسمة حسب الفئات لتفادي حظر السيرفر
    if (!channels || channels.length === 0) {
      console.log("All channels returned empty. Fetching by genre categories sequentially...");
      for (const genre of genres) {
        try {
          const genreChannels = await portalFetchRetry(session, { 
            type: "itv", 
            action: "get_ordered_list", 
            genre: genre.id, 
            fav: 0, 
            sortby: "number" 
          }, 10000);
          
          if (genreChannels?.js?.data) {
            channels.push(...genreChannels.js.data);
          }
        } catch (err) {
          console.warn(`Failed to fetch channels for genre: ${genre.title}`);
        }
      }
    }

    // 3. ترتيب البيانات وعرضها للـ Frontend
    const result = channels.map(ch => ({
      id:    ch.id,
      name:  ch.name,
      num:   ch.number || ch.num,
      logo:  ch.logo || ch.icon || null,
      group: genreMap[ch.tv_genre_id] || genreMap[ch.category_id] || "Other",
      url:   ch.cmd || null,
      epgId: ch.xmltv_id || null,
      type:  "live",
    }));

    console.log(`✅ Successfully loaded ${result.length} live channels!`);
    res.json({ channels: result, total: result.length });
  } catch (e) {
    console.error("Channels error:", e.message);
    res.status(502).json({ error: e.message });
  }
});
// ── Fetch paginated items for one Stalker category, stopping at the declared end.
async function fetchAllPages(session, type, category, maxItems = 500) {
  const all = [];
  for (let page = 1; all.length < maxItems; page++) {
    let data;
    try {
      data = await portalFetchRetry(session,
        { type, action: "get_ordered_list", category, page, p: page }, 20000);
    } catch (e) {
      console.warn(`fetchAllPages ${type} cat=${category} page=${page}: ${e.message}`);
      break;
    }
    const items = data?.js?.data;
    if (!items || !items.length) break;
    all.push(...items);
    const declaredTotal = parseInt(data.js.total_items || data.js.results_num || 0, 10);
    if (declaredTotal > 0 && all.length >= declaredTotal) break;
    const declaredPages = parseInt(data.js.total_pages || data.js.pages_count || 0, 10);
    if (declaredPages > 0 && page >= declaredPages) break;
  }
  return all;
}

// ── GET /stalker/vod/categories — movie categories only
app.get("/stalker/vod/categories", async (req, res) => {
  const { portal, mac } = req.query;
  if (!portal || !mac) return res.status(400).json({ error: "portal and mac required" });
  try {
    const session = await getSession(portal, mac);
    const catData = await portalFetchRetry(session, { type: "vod", action: "get_categories" }, 10000);
    const categories = (catData?.js || []).map(c => ({
      id: String(c.id),
      title: c.title,
      count: parseInt(c.count || c.videos_count || c.censored_count || 0, 10),
    }));
    res.json({ categories });
  } catch (e) {
    console.error("Movie categories error:", e.message);
    res.status(502).json({ error: e.message });
  }
});

// ── GET /stalker/vod?cat=ID — movies for a single category
app.get("/stalker/vod", async (req, res) => {
  const { portal, mac, cat } = req.query;
  if (!portal || !mac) return res.status(400).json({ error: "portal and mac required" });
  if (!cat) return res.status(400).json({ error: "cat (category id) required" });
  try {
    const session = await getSession(portal, mac);
    const rawItems = await fetchAllPages(session, "vod", cat);
    const items = rawItems.map(v => ({
      id: v.id,
      name: v.name,
      logo: v.screenshot_uri || v.cover || null,
      year: v.year,
      rating: v.rating_imdb || v.rating || null,
      url: v.cmd || null,
      type: "vod",
    }));
    console.log(`Movies cat=${cat} loaded: ${items.length} items`);
    res.json({ items, total: items.length });
  } catch (e) {
    console.error("Movies error:", e.message);
    res.status(502).json({ error: e.message });
  }
});

// ── GET /stalker/series/categories — series categories
app.get("/stalker/series/categories", async (req, res) => {
  const { portal, mac } = req.query;
  if (!portal || !mac) return res.status(400).json({ error: "portal and mac required" });
  try {
    const session = await getSession(portal, mac);
    const catData = await portalFetchRetry(session, { type: "series", action: "get_categories" }, 10000);
    const categories = (catData?.js || []).map(c => ({
      id: String(c.id),
      title: c.title,
      count: parseInt(c.count || c.videos_count || c.censored_count || 0, 10),
    }));
    res.json({ categories });
  } catch (e) {
    console.error("Series categories error:", e.message);
    res.status(502).json({ error: e.message });
  }
});

// ── GET /stalker/series?cat=ID — series in a single category
app.get("/stalker/series", async (req, res) => {
  const { portal, mac, cat } = req.query;
  if (!portal || !mac) return res.status(400).json({ error: "portal and mac required" });
  if (!cat) return res.status(400).json({ error: "cat (category id) required" });
  try {
    const session = await getSession(portal, mac);
    const rawItems = await fetchAllPages(session, "series", cat);
    const items = rawItems.map(item => ({
      id: item.id,
      name: item.name,
      logo: item.screenshot_uri || item.cover || null,
      year: item.year,
      rating: item.rating_imdb || item.rating || null,
      type: "series",
    }));
    console.log(`Series cat=${cat} loaded: ${items.length} items`);
    res.json({ items, total: items.length });
  } catch (e) {
    console.error("Series error:", e.message);
    res.status(502).json({ error: e.message });
  }
});

// ── GET /stalker/series/episode/stream — resolve one series episode
app.get("/stalker/series/episode/stream", async (req, res) => {
  const { portal, mac, cmd, episode } = req.query;
  if (!portal || !mac || !cmd || !episode) {
    return res.status(400).json({ error: "portal, mac, cmd and episode required" });
  }
  try {
    const session = await getSession(portal, mac);
    const data = await portalFetchRetry(session, {
      type: "vod", action: "create_link",
      cmd, series: episode, forced_storage: 0,
      disable_ad: 0, download: 0, force_ch_link_check: 0,
    });
    const streamUrl = data?.js?.cmd;
    if (!streamUrl) throw new Error("No stream URL returned for episode");
    let cleanUrl = streamUrl.replace(/^ffmpeg\s+/, "").trim();
    if (cleanUrl.includes("localhost") || cleanUrl.includes("127.0.0.1")) {
      try {
        const portalHost = new URL(portal).host;
        cleanUrl = cleanUrl.replace(/localhost(:\d+)?/g, portalHost).replace(/127\.0\.0\.1(:\d+)?/g, portalHost);
      } catch {}
    }
    res.json({ url: issueStreamTicket(cleanUrl) });
  } catch (e) {
    console.error("Series episode stream error:", e.message);
    res.status(502).json({ error: e.message });
  }
});

// ── GET /stalker/series/:seriesId/seasons — seasons and episode lists
app.get("/stalker/series/:seriesId/seasons", async (req, res) => {
  const { portal, mac } = req.query;
  const { seriesId } = req.params;
  if (!portal || !mac) return res.status(400).json({ error: "portal and mac required" });
  if (!seriesId) return res.status(400).json({ error: "seriesId required" });
  try {
    const session = await getSession(portal, mac);
    const movieId = seriesId.split(":")[0];
    const data = await portalFetchRetry(session, {
      type: "series", action: "get_ordered_list",
      movie_id: movieId, page: 1, p: 1,
    }, 20000);
    const rawSeasons = data?.js?.data || [];
    const seasons = rawSeasons.map(season => ({
      id: season.id,
      name: season.name,
      cmd: season.cmd || "",
      episodes: Array.isArray(season.series) ? season.series : [],
      logo: season.screenshot_uri || season.cover || null,
    }));
    console.log(`Series ${seriesId} seasons: ${seasons.length}`);
    res.json({ seasons });
  } catch (e) {
    console.error("Series seasons error:", e.message);
    res.status(502).json({ error: e.message });
  }
});

// ── GET /stalker/stream
// content_type: "live" (default) uses type=itv; "vod" resolves movies.
app.get("/stalker/stream", async (req, res) => {
  const { portal, mac, cmd, content_type } = req.query;
  if (!portal || !mac || !cmd) return res.status(400).json({ error: "portal, mac and cmd required" });
  const requestedType = content_type || "live";
  if (!["live", "vod"].includes(requestedType)) {
    return res.status(400).json({ error: "content_type must be live or vod" });
  }

  // Map content_type to the correct Stalker API type parameter
  const stalkerType = requestedType === "vod" ? "vod" : "itv";

  try {
    const session = await getSession(portal, mac);
    const data = await portalFetchRetry(session, {
      type: stalkerType, action: "create_link",
      cmd, series: 0, forced_storage: 0,
      disable_ad: 0, download: 0, force_ch_link_check: 0,
    });

    const streamUrl = data?.js?.cmd;
    if (!streamUrl) throw new Error("No stream URL returned");

    let cleanUrl = streamUrl.replace(/^ffmpeg\s+/, "").trim();
    // Some portals return localhost URLs — replace with portal hostname
    if (cleanUrl.includes("localhost") || cleanUrl.includes("127.0.0.1")) {
      try {
        const portalHost = new URL(portal).host;
        cleanUrl = cleanUrl.replace(/localhost(:\d+)?/g, portalHost).replace(/127\.0\.0\.1(:\d+)?/g, portalHost);
      } catch {}
    }
    res.json({ url: issueStreamTicket(cleanUrl) });
  } catch (e) {
    console.error("Stream resolve error:", e.message);
    res.status(502).json({ error: e.message });
  }
});

// Series categories, items, seasons and episode playback are registered above.

// Stream URLs are opaque, short-lived tickets created only by authenticated
// Stalker resolution routes; arbitrary destination URLs are never accepted.
app.options(["/stream", "/stream.m3u8"], (req, res) => {
  res.set("Access-Control-Allow-Origin", "*");
  res.set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS");
  res.set("Access-Control-Allow-Headers", "Range, Content-Type");
  res.set("Access-Control-Max-Age", "86400");
  res.status(204).end();
});

app.head(["/stream", "/stream.m3u8"], async (req, res) => {
  const target = streamTarget(req.query.ticket);
  if (!target) return res.status(401).end();
  try {
    const headers = { "User-Agent": "TeroDev-TV/1.0" };
    if (req.headers.range) headers.Range = req.headers.range;
    const upstream = await fetch(target, { method: "HEAD", headers, redirect: "follow" });
    res.set("Cache-Control", "no-store");
    for (const name of ["content-type", "content-length", "content-range", "accept-ranges"]) {
      const value = upstream.headers.get(name);
      if (value) res.set(name, value);
    }
    res.status(upstream.status).end();
  } catch (e) {
    console.error("Stream HEAD error:", e.message);
    if (!res.headersSent) res.status(502).end();
  }
});

app.get(["/stream", "/stream.m3u8"], async (req, res) => {
  const target = streamTarget(req.query.ticket);
  if (!target) return res.status(401).json({ error: "Invalid or expired stream ticket" });
  try {
    const headers = { "User-Agent": "TeroDev-TV/1.0" };
    if (req.headers.range) headers.Range = req.headers.range;
    const upstream = await fetch(target, { headers, redirect: "follow" });
    res.set("Access-Control-Expose-Headers", "Content-Length, Content-Range, Accept-Ranges");
    res.set("Cache-Control", "no-store");
    for (const name of ["content-range", "accept-ranges", "content-length"]) {
      const value = upstream.headers.get(name);
      if (value) res.set(name, value);
    }
    if (!upstream.ok) return res.status(upstream.status).end();
    const ct = upstream.headers.get("content-type") || "";

    if (ct.includes("mpegurl") || ct.includes("m3u") || target.split("?")[0].endsWith(".m3u8")) {
      const text = await upstream.text();
      const selfBase = `${req.get("x-forwarded-proto") || req.protocol}://${req.get("host")}`;
      const makeRelayUrl = (ref) => {
        try {
          const absolute = new URL(ref, target).toString();
          return `${selfBase}${issueStreamTicket(absolute)}`;
        } catch { return ref; }
      };
      const rewritten = text.split(/\r?\n/).map(line => {
        const trimmed = line.trim();
        if (!trimmed) return line;
        if (trimmed.startsWith("#")) {
          return line.replace(/URI="([^"]+)"/g, (_match, uri) => `URI="${makeRelayUrl(uri)}"`);
        }
        return makeRelayUrl(trimmed);
      }).join("\n");
      res.set("Content-Type", ct);
      return res.status(upstream.status).send(rewritten);
    }
    if (ct) res.set("Content-Type", ct);
    res.status(upstream.status);
    upstream.body.pipe(res);
  } catch (e) {
    console.error("Stream proxy error:", e.message);
    if (!res.headersSent) res.status(502).json({ error: e.message });
  }
});

// ─────────────────────────────────────────────────────────────────
app.listen(PORT, HOST, () => {
  console.log(`✅ TeroDev TV+Movies+Series proxy running on http://${HOST}:${PORT}`);
  console.log(`   Health: http://${HOST}:${PORT}/health`);
});
