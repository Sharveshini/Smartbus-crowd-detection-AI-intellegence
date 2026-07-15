// ================================================================
// SMARTBUS NEO - AI-Powered Public Transport Platform
// Complete Backend with SQLite, Socket.IO, JWT Auth
// ================================================================

const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const path = require('path');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'smartbus-neo-ai-2026-super-secure';
const SALT_ROUNDS = 10;
const CAPACITY = 60;
const UPDATE_INTERVAL = 3000;

const db = new Database('smartbus_neo.db');
db.pragma('foreign_keys = ON');
db.pragma('journal_mode = WAL');

// ─── EXTENDED SCHEMA ───
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
    full_name TEXT NOT NULL, phone TEXT, role TEXT DEFAULT 'passenger',
    language TEXT DEFAULT 'en', preferred_zone TEXT,
    total_reward_points INTEGER DEFAULT 0, safety_mode INTEGER DEFAULT 0,
    emergency_contacts TEXT, is_active INTEGER DEFAULT 1,
    last_login TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS buses (
    id TEXT PRIMARY KEY, registration TEXT UNIQUE NOT NULL, capacity INTEGER DEFAULT 60,
    model TEXT, current_lat REAL, current_lng REAL, last_gps_update TEXT,
    status TEXT DEFAULT 'active', crowd_level TEXT DEFAULT 'low',
    passengers_count INTEGER DEFAULT 0, wait_time INTEGER DEFAULT 5,
    route_name TEXT, route_coords TEXT, eta_minutes INTEGER DEFAULT 0,
    next_stop TEXT, driver_name TEXT, conductor_name TEXT,
    fuel_level REAL DEFAULT 75, speed REAL DEFAULT 0, heading INTEGER DEFAULT 0,
    seats_available INTEGER DEFAULT 60, women_reserved INTEGER DEFAULT 8,
    ac_available INTEGER DEFAULT 0, is_women_safe INTEGER DEFAULT 1
  );

  CREATE TABLE IF NOT EXISTS stops (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, name_ta TEXT, code TEXT UNIQUE,
    lat REAL NOT NULL, lng REAL NOT NULL, address TEXT, zone TEXT,
    landmark TEXT, is_terminal INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS routes (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, number TEXT,
    fare_base REAL DEFAULT 20, fare_per_km REAL DEFAULT 2,
    start_stop_id TEXT REFERENCES stops(id), end_stop_id TEXT REFERENCES stops(id),
    distance_km REAL, duration_min INTEGER DEFAULT 30, frequency_min INTEGER DEFAULT 15,
    safety_rating REAL DEFAULT 4.5, crowd_factor REAL DEFAULT 0.5,
    is_women_route INTEGER DEFAULT 0, is_active INTEGER DEFAULT 1
  );

  CREATE TABLE IF NOT EXISTS route_stops (
    id TEXT PRIMARY KEY, route_id TEXT REFERENCES routes(id) ON DELETE CASCADE,
    stop_id TEXT REFERENCES stops(id), stop_order INTEGER NOT NULL,
    time_from_prev_min INTEGER DEFAULT 2, distance_from_prev_km REAL DEFAULT 1
  );

  CREATE TABLE IF NOT EXISTS gps_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bus_id TEXT REFERENCES buses(id),
    lat REAL,
    lng REAL,
    speed REAL,
    heading INTEGER,
    passengers_count INTEGER,
    crowd_level TEXT,
    timestamp TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS crowd_predictions (
    id INTEGER PRIMARY KEY AUTOINCREMENT, bus_id TEXT REFERENCES buses(id),
    predicted_at TEXT DEFAULT CURRENT_TIMESTAMP, prediction_for TEXT,
    predicted_level TEXT, predicted_count INTEGER,
    confidence REAL, trend TEXT, zone_door INTEGER, zone_middle INTEGER, zone_back INTEGER
  );

  CREATE TABLE IF NOT EXISTS seat_bookings (
    id TEXT PRIMARY KEY, bus_id TEXT REFERENCES buses(id), user_id TEXT REFERENCES users(id),
    from_stop_id TEXT REFERENCES stops(id), to_stop_id TEXT REFERENCES stops(id),
    seats INTEGER DEFAULT 1, booking_time TEXT, status TEXT DEFAULT 'active',
    expires_at TEXT
  );

  CREATE TABLE IF NOT EXISTS journey_shares (
    id TEXT PRIMARY KEY, user_id TEXT REFERENCES users(id),
    bus_id TEXT REFERENCES buses(id), from_stop_id TEXT REFERENCES stops(id),
    to_stop_id TEXT REFERENCES stops(id), start_time TEXT,
    share_with TEXT, status TEXT DEFAULT 'active',
    current_lat REAL, current_lng REAL, emergency_alert INTEGER DEFAULT 0,
    estimated_arrival TEXT
  );

  CREATE TABLE IF NOT EXISTS sos_alerts (
    id TEXT PRIMARY KEY, user_id TEXT REFERENCES users(id),
    bus_id TEXT REFERENCES buses(id), lat REAL, lng REAL,
    message TEXT, type TEXT DEFAULT 'emergency',
    status TEXT DEFAULT 'pending', resolved_at TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS chatbot_conversations (
    id TEXT PRIMARY KEY, user_id TEXT REFERENCES users(id),
    message TEXT, response TEXT, intent TEXT,
    context TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS voice_commands (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT REFERENCES users(id),
    command_text TEXT, language TEXT, intent TEXT,
    response TEXT, confidence REAL, created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS user_trips (
    id TEXT PRIMARY KEY, user_id TEXT REFERENCES users(id),
    from_stop_id TEXT REFERENCES stops(id), to_stop_id TEXT REFERENCES stops(id),
    bus_id TEXT, start_time TEXT, end_time TEXT, fare_paid REAL,
    transfer_count INTEGER DEFAULT 0, route_sequence TEXT,
    crowd_experience TEXT, rating INTEGER, reward_points INTEGER DEFAULT 0,
    safety_mode INTEGER DEFAULT 0, status TEXT DEFAULT 'completed',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS community_reports (
    id TEXT PRIMARY KEY, user_id TEXT REFERENCES users(id),
    bus_id TEXT REFERENCES buses(id), stop_id TEXT REFERENCES stops(id),
    report_type TEXT, description TEXT, severity TEXT DEFAULT 'normal',
    photo_url TEXT, is_verified INTEGER DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS reward_transactions (
    id TEXT PRIMARY KEY, user_id TEXT REFERENCES users(id),
    points INTEGER, type TEXT, description TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS notifications (
    id TEXT PRIMARY KEY, user_id TEXT REFERENCES users(id),
    type TEXT, title TEXT, body TEXT, is_read INTEGER DEFAULT 0,
    data TEXT, action_url TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS tickets (
    id TEXT PRIMARY KEY, user_id TEXT REFERENCES users(id),
    trip_id TEXT, fare REAL, method TEXT, qr_code TEXT,
    status TEXT DEFAULT 'active', created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS passes (
    id TEXT PRIMARY KEY, user_id TEXT REFERENCES users(id),
    type TEXT, valid_from TEXT, valid_to TEXT,
    status TEXT DEFAULT 'active', created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
`);

// ================================================================
// PREPARED STATEMENTS
// ================================================================
const stmts = {
  getUserByEmail: db.prepare('SELECT * FROM users WHERE email = ?'),
  getUserById: db.prepare('SELECT * FROM users WHERE id = ?'),
  createUser: db.prepare('INSERT INTO users (id, email, password_hash, full_name, phone, role, language) VALUES (?, ?, ?, ?, ?, ?, ?)'),
  updateLastLogin: db.prepare('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?'),
  updateUserSafety: db.prepare('UPDATE users SET safety_mode = ?, emergency_contacts = ? WHERE id = ?'),
  addRewardPoints: db.prepare('UPDATE users SET total_reward_points = total_reward_points + ? WHERE id = ?'),
  getAllStops: db.prepare('SELECT * FROM stops ORDER BY name'),
  getStopById: db.prepare('SELECT * FROM stops WHERE id = ?'),
  searchStops: db.prepare("SELECT * FROM stops WHERE name LIKE ? OR name_ta LIKE ? OR landmark LIKE ? LIMIT 10"),
  getAllBuses: db.prepare("SELECT * FROM buses WHERE status = 'active'"),
  getBusById: db.prepare('SELECT * FROM buses WHERE id = ?'),
  updateBusLocation: db.prepare('UPDATE buses SET current_lat = ?, current_lng = ?, last_gps_update = CURRENT_TIMESTAMP, speed = ?, heading = ? WHERE id = ?'),
  updateBusCrowd: db.prepare('UPDATE buses SET crowd_level = ?, passengers_count = ?, wait_time = ?, eta_minutes = ?, next_stop = ?, seats_available = ? WHERE id = ?'),
  insertGpsLog: db.prepare('INSERT INTO gps_logs (bus_id, lat, lng, speed, heading, passengers_count, crowd_level) VALUES (?, ?, ?, ?, ?, ?, ?)'),
  insertCrowdPrediction: db.prepare('INSERT INTO crowd_predictions (bus_id, prediction_for, predicted_level, predicted_count, confidence, trend, zone_door, zone_middle, zone_back) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'),
  getCrowdPredictions: db.prepare('SELECT * FROM crowd_predictions WHERE bus_id = ? ORDER BY predicted_at DESC LIMIT 5'),
  getAllRoutes: db.prepare('SELECT * FROM routes WHERE is_active = 1'),
  getRouteById: db.prepare('SELECT * FROM routes WHERE id = ?'),
  getRouteStops: db.prepare('SELECT rs.*, s.name as stop_name, s.lat, s.lng, s.landmark FROM route_stops rs JOIN stops s ON rs.stop_id = s.id WHERE rs.route_id = ? ORDER BY rs.stop_order'),
  createJourneyShare: db.prepare('INSERT INTO journey_shares (id, user_id, bus_id, from_stop_id, to_stop_id, start_time, share_with, current_lat, current_lng, estimated_arrival) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'),
  updateJourneyLocation: db.prepare('UPDATE journey_shares SET current_lat = ?, current_lng = ? WHERE id = ?'),
  getActiveJourneyShares: db.prepare("SELECT * FROM journey_shares WHERE user_id = ? AND status = 'active'"),
  endJourneyShare: db.prepare("UPDATE journey_shares SET status = 'completed' WHERE id = ?"),
  createSos: db.prepare('INSERT INTO sos_alerts (id, user_id, bus_id, lat, lng, message, type) VALUES (?, ?, ?, ?, ?, ?, ?)'),
  getRecentSos: db.prepare("SELECT * FROM sos_alerts WHERE user_id = ? ORDER BY created_at DESC LIMIT 5"),
  createNotification: db.prepare('INSERT INTO notifications (id, user_id, type, title, body, data, action_url) VALUES (?, ?, ?, ?, ?, ?, ?)'),
  getNotifications: db.prepare('SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 30'),
  getUnreadNotifications: db.prepare('SELECT COUNT(*) as count FROM notifications WHERE user_id = ? AND is_read = 0'),
  markNotificationRead: db.prepare('UPDATE notifications SET is_read = 1 WHERE id = ?'),
  markAllNotificationsRead: db.prepare('UPDATE notifications SET is_read = 1 WHERE user_id = ?'),
  createTrip: db.prepare('INSERT INTO user_trips (id, user_id, from_stop_id, to_stop_id, bus_id, start_time, fare_paid, transfer_count, route_sequence, reward_points, safety_mode) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'),
  getTripsByUser: db.prepare('SELECT * FROM user_trips WHERE user_id = ? ORDER BY created_at DESC LIMIT 20'),
  createRewardTransaction: db.prepare('INSERT INTO reward_transactions (id, user_id, points, type, description) VALUES (?, ?, ?, ?, ?)'),
  getRewardPoints: db.prepare('SELECT total_reward_points FROM users WHERE id = ?'),
  getRewardHistory: db.prepare('SELECT * FROM reward_transactions WHERE user_id = ? ORDER BY created_at DESC LIMIT 10'),
  createCommunityReport: db.prepare('INSERT INTO community_reports (id, user_id, bus_id, stop_id, report_type, description, severity) VALUES (?, ?, ?, ?, ?, ?, ?)'),
  getCommunityReports: db.prepare('SELECT * FROM community_reports ORDER BY created_at DESC LIMIT 20'),
  saveChatMessage: db.prepare('INSERT INTO chatbot_conversations (id, user_id, message, response, intent, context) VALUES (?, ?, ?, ?, ?, ?)'),
  getChatHistory: db.prepare('SELECT * FROM chatbot_conversations WHERE user_id = ? ORDER BY created_at DESC LIMIT 20'),
  saveVoiceCommand: db.prepare('INSERT INTO voice_commands (user_id, command_text, language, intent, response, confidence) VALUES (?, ?, ?, ?, ?, ?)'),
  getRecentGpsLogs: db.prepare('SELECT * FROM gps_logs WHERE bus_id = ? ORDER BY timestamp DESC LIMIT 20'),
  createStop: db.prepare('INSERT INTO stops (id, name, name_ta, code, lat, lng, address, zone, landmark) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'),
  createBus: db.prepare("INSERT INTO buses (id, registration, capacity, model, status) VALUES (?, ?, ?, ?, 'active')"),
};

// ─── UTILITY FUNCTIONS ───
const uuid = () => 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
  const r = Math.random() * 16 | 0, v = c === 'x' ? r : (r & 0x3 | 0x8);
  return v.toString(16);
});

function rand(min, max) { return Math.random() * (max - min) + min; }
function randInt(min, max) { return Math.floor(rand(min, max + 1)); }
function pick(arr) { return arr[Math.floor(Math.random() * arr.length)]; }
function clamp(v, min, max) { return Math.min(max, Math.max(min, v)); }
function getLevel(p) { if (p > 44) return 'high'; if (p > 24) return 'medium'; return 'low'; }

// Haversine distance calculation
function haversine(lat1, lon1, lat2, lon2) {
  const R = 6371;
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLon = (lon2 - lon1) * Math.PI / 180;
  const a = Math.sin(dLat/2) * Math.sin(dLat/2) +
    Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
    Math.sin(dLon/2) * Math.sin(dLon/2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
  return R * c;
}

// ─── AI PREDICTION (simplified for speed) ───
function predictCrowdAdvanced(busId, currentPax) {
  const predictedIn15 = Math.round(clamp(currentPax + randInt(-5, 8), 0, CAPACITY));
  const predictedIn30 = Math.round(clamp(currentPax + randInt(-8, 12), 0, CAPACITY));
  return {
    current: { level: getLevel(currentPax), count: currentPax },
    in15min: { level: getLevel(predictedIn15), count: predictedIn15 },
    in30min: { level: getLevel(predictedIn30), count: predictedIn30 },
    trend: 'stable',
    confidence: 0.75,
    recommendation: predictedIn15 > 40 ? 'Consider alternate route' : 'Comfortable to board'
  };
}

// ─── EXPRESS APP ───
const app = express();
app.use(cors({ origin: '*' }));
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch (err) { return res.status(401).json({ error: 'Invalid token' }); }
}

// ─── API ENDPOINTS ───

// Auth
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = stmts.getUserByEmail.get(email?.toLowerCase());
    if (!user || !user.is_active) return res.status(401).json({ error: 'Invalid credentials' });
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
    stmts.updateLastLogin.run(user.id);
    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, email: user.email, full_name: user.full_name, role: user.role, language: user.language, total_reward_points: user.total_reward_points } });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, full_name, phone, language } = req.body;
    if (stmts.getUserByEmail.get(email?.toLowerCase())) return res.status(400).json({ error: 'Email exists' });
    const hashed = await bcrypt.hash(password, SALT_ROUNDS);
    const id = uuid();
    stmts.createUser.run(id, email.toLowerCase(), hashed, full_name, phone || '', 'passenger', language || 'en');
    const token = jwt.sign({ id, role: 'passenger' }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id, email, full_name, role: 'passenger', language: language || 'en', total_reward_points: 0 } });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/auth/me', authMiddleware, (req, res) => {
  const user = stmts.getUserById.get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ id: user.id, email: user.email, full_name: user.full_name, role: user.role, phone: user.phone, language: user.language, total_reward_points: user.total_reward_points, safety_mode: user.safety_mode });
});

// Stops
app.get('/api/stops', (req, res) => res.json(stmts.getAllStops.all()));
app.get('/api/stops/:id', (req, res) => { const s = stmts.getStopById.get(req.params.id); if (!s) return res.status(404).json({ error: 'Not found' }); res.json(s); });

// Buses
app.get('/api/buses', (req, res) => res.json(stmts.getAllBuses.all()));
app.get('/api/buses/:id', (req, res) => { const b = stmts.getBusById.get(req.params.id); if (!b) return res.status(404).json({ error: 'Not found' }); res.json(b); });

// Routes
app.get('/api/routes', (req, res) => {
  const routes = stmts.getAllRoutes.all();
  const enriched = routes.map(r => {
    const stops = stmts.getRouteStops.all(r.id);
    return { ...r, stops };
  });
  res.json(enriched);
});
app.get('/api/routes/:id', (req, res) => { const r = stmts.getRouteById.get(req.params.id); if (!r) return res.status(404).json({ error: 'Not found' }); const s = stmts.getRouteStops.all(r.id); res.json({ ...r, stops: s }); });

// Notifications
app.get('/api/notifications', authMiddleware, (req, res) => {
  const notifs = stmts.getNotifications.all(req.user.id);
  const unread = stmts.getUnreadNotifications.get(req.user.id);
  res.json({ notifications: notifs, unreadCount: unread.count });
});
app.post('/api/notifications/read', authMiddleware, (req, res) => {
  if (req.body.id) stmts.markNotificationRead.run(req.body.id);
  else stmts.markAllNotificationsRead.run(req.user.id);
  res.json({ success: true });
});

// Favorites (mock)
app.get('/api/favorites', authMiddleware, (req, res) => {
  res.json([]); // placeholder, you can implement real favorites
});

// Journey Planning - Multi-bus suggestions
app.post('/api/plan', (req, res) => {
  try {
    const { fromStopId, toStopId, criteria } = req.body;
    if (!fromStopId || !toStopId) return res.status(400).json({ error: 'From and To stops required' });
    
    const fromStop = stmts.getStopById.get(fromStopId);
    const toStop = stmts.getStopById.get(toStopId);
    
    if (!fromStop || !toStop) return res.status(404).json({ error: 'Stop not found' });
    
    // Get all routes and find direct or connecting routes
    const routes = stmts.getAllRoutes.all();
    const suggestions = [];
    
    // Find direct routes
    const directRoutes = routes.filter(r => {
      const routeStops = stmts.getRouteStops.all(r.id);
      const stopIds = routeStops.map(rs => rs.stop_id);
      return stopIds.includes(fromStopId) && stopIds.includes(toStopId);
    });
    
    // Find routes that start from or near fromStop
    const fromRoutes = routes.filter(r => {
      const routeStops = stmts.getRouteStops.all(r.id);
      return routeStops.some(rs => rs.stop_id === fromStopId);
    }).slice(0, 5);
    
    // Find routes that go to or near toStop
    const toRoutes = routes.filter(r => {
      const routeStops = stmts.getRouteStops.all(r.id);
      return routeStops.some(rs => rs.stop_id === toStopId);
    }).slice(0, 5);
    
    // Find connecting routes (fromStop -> intermediate -> toStop)
    const connectingRoutes = [];
    fromRoutes.forEach(fromRoute => {
      const fromRouteStops = stmts.getRouteStops.all(fromRoute.id);
      const fromRouteStopIds = fromRouteStops.map(rs => rs.stop_id);
      
      toRoutes.forEach(toRoute => {
        const toRouteStops = stmts.getRouteStops.all(toRoute.id);
        const toRouteStopIds = toRouteStops.map(rs => rs.stop_id);
        
        // Find common stops (transfer points)
        const transferPoints = fromRouteStopIds.filter(id => toRouteStopIds.includes(id));
        if (transferPoints.length > 0 && fromRoute.id !== toRoute.id) {
          connectingRoutes.push({
            fromRoute,
            toRoute,
            transferPoint: transferPoints[0]
          });
        }
      });
    });
    
    // Build suggestions
    if (directRoutes.length > 0) {
      const route = directRoutes[0];
      const routeStops = stmts.getRouteStops.all(route.id);
      const fromIdx = routeStops.findIndex(rs => rs.stop_id === fromStopId);
      const toIdx = routeStops.findIndex(rs => rs.stop_id === toStopId);
      
      if (fromIdx !== -1 && toIdx !== -1) {
        const startIdx = Math.min(fromIdx, toIdx);
        const endIdx = Math.max(fromIdx, toIdx);
        const legs = [];
        
        for (let i = startIdx; i <= endIdx; i++) {
          const rs = routeStops[i];
          const prevStop = i > startIdx ? routeStops[i - 1] : null;
          
          legs.push({
            routeName: route.name,
            routeNumber: route.number,
            fromStop: prevStop ? prevStop.stop_name : fromStop.name,
            toStop: rs.stop_name,
            duration: prevStop ? (rs.time_from_prev_min || 2) : 0,
            fare: route.fare_base || 20
          });
        }
        
        suggestions.push({
          type: 'direct',
          label: '🚌 Direct Route',
          legs,
          totalTime: legs.reduce((s, l) => s + l.duration, 0),
          totalFare: legs.length > 0 ? legs[0].fare : 0,
          transfers: 0,
          crowdLevel: pick(['low', 'medium', 'low']), // Simulated
          busesAvailable: randInt(3, 8)
        });
      }
    }
    
    // Add connecting route suggestions
    connectingRoutes.slice(0, 3).forEach((conn, idx) => {
      const fromRouteStops = stmts.getRouteStops.all(conn.fromRoute.id);
      const toRouteStops = stmts.getRouteStops.all(conn.toRoute.id);
      const transferStop = stmts.getStopById.get(conn.transferPoint);
      
      const fromIdx = fromRouteStops.findIndex(rs => rs.stop_id === fromStopId);
      const transferIdx = fromRouteStops.findIndex(rs => rs.stop_id === conn.transferPoint);
      const toTransferIdx = toRouteStops.findIndex(rs => rs.stop_id === conn.transferPoint);
      const toIdx = toRouteStops.findIndex(rs => rs.stop_id === toStopId);
      
      if (fromIdx !== -1 && transferIdx !== -1 && toTransferIdx !== -1 && toIdx !== -1) {
        const leg1 = [];
        const start1 = Math.min(fromIdx, transferIdx);
        const end1 = Math.max(fromIdx, transferIdx);
        
        for (let i = start1; i <= end1; i++) {
          const rs = fromRouteStops[i];
          const prevStop = i > start1 ? fromRouteStops[i - 1] : null;
          leg1.push({
            routeName: conn.fromRoute.name,
            routeNumber: conn.fromRoute.number,
            fromStop: prevStop ? prevStop.stop_name : fromStop.name,
            toStop: rs.stop_name,
            duration: prevStop ? (rs.time_from_prev_min || 2) : 0,
            fare: conn.fromRoute.fare_base || 20
          });
        }
        
        const leg2 = [];
        const start2 = Math.min(toTransferIdx, toIdx);
        const end2 = Math.max(toTransferIdx, toIdx);
        
        for (let i = start2; i <= end2; i++) {
          const rs = toRouteStops[i];
          const prevStop = i > start2 ? toRouteStops[i - 1] : null;
          leg2.push({
            routeName: conn.toRoute.name,
            routeNumber: conn.toRoute.number,
            fromStop: prevStop ? prevStop.stop_name : (transferStop?.name || 'Transfer'),
            toStop: rs.stop_name,
            duration: prevStop ? (rs.time_from_prev_min || 2) : 0,
            fare: conn.toRoute.fare_base || 20
          });
        }
        
        const totalTime = [...leg1, ...leg2].reduce((s, l) => s + l.duration, 0);
        const totalFare = (leg1[0]?.fare || 0) + (leg2[0]?.fare || 0);
        
        suggestions.push({
          type: 'connecting',
          label: `🔄 Option ${idx + 2}: Via ${transferStop?.name || 'Transfer Point'}`,
          legs: [...leg1, ...leg2],
          totalTime,
          totalFare,
          transfers: 1,
          crowdLevel: pick(['low', 'medium', 'low']),
          busesAvailable: randInt(2, 5)
        });
      }
    });
    
    // If no suggestions found, provide alternative analysis
    if (suggestions.length === 0) {
      // Find nearest busy routes
      const nearbyRoutes = routes.slice(0, 3).map(r => ({
        name: r.name,
        number: r.number,
        fare: r.fare_base || 20,
        duration: r.duration_min || 30
      }));
      
      return res.json({
        suggestions: [],
        alternatives: nearbyRoutes,
        message: 'No direct route found between these stops.',
        suggestion: 'Try using nearby bus stops or check the Live Map for available buses.'
      });
    }
    
    // Sort suggestions by criteria
    if (criteria === 'fastest') {
      suggestions.sort((a, b) => a.totalTime - b.totalTime);
    } else if (criteria === 'cheapest') {
      suggestions.sort((a, b) => a.totalFare - b.totalFare);
    } else if (criteria === 'least_crowded') {
      suggestions.sort((a, b) => {
        const order = { low: 0, medium: 1, high: 2 };
        return (order[a.crowdLevel] || 1) - (order[b.crowdLevel] || 1);
      });
    }
    
    res.json({ suggestions });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Trips
app.get('/api/trips', authMiddleware, (req, res) => {
  res.json(stmts.getTripsByUser.all(req.user.id));
});
app.post('/api/trips', authMiddleware, (req, res) => {
  const { fromStopId, toStopId, busId, fare, transfers, routeSequence, safetyMode } = req.body;
  const id = uuid();
  const points = Math.round((fare || 20) * 0.5);
  stmts.createTrip.run(id, req.user.id, fromStopId, toStopId, busId, new Date().toISOString(),
    fare || 0, transfers || 0, JSON.stringify(routeSequence || []), points, safetyMode ? 1 : 0);
  stmts.addRewardPoints.run(points, req.user.id);
  const rid = uuid();
  stmts.createRewardTransaction.run(rid, req.user.id, points, 'earn', 'Trip completed - reward points');
  res.json({ success: true, id, pointsEarned: points });
});

// Tickets
app.get('/api/tickets', authMiddleware, (req, res) => {
  const tickets = db.prepare('SELECT * FROM tickets WHERE user_id = ? ORDER BY created_at DESC LIMIT 20').all(req.user.id);
  res.json(tickets);
});
app.post('/api/tickets', authMiddleware, (req, res) => {
  const { tripId, fare, method } = req.body;
  const id = uuid();
  const qrCode = 'TKT' + Math.random().toString(36).substr(2, 6).toUpperCase();
  db.prepare('INSERT INTO tickets (id, user_id, trip_id, fare, method, qr_code, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
    .run(id, req.user.id, tripId, fare || 20, method || 'upi', qrCode, 'active', new Date().toISOString());
  res.json({ success: true, id, qrCode });
});

// Passes
app.get('/api/passes', authMiddleware, (req, res) => {
  const passes = db.prepare('SELECT * FROM passes WHERE user_id = ? AND status = ? ORDER BY created_at DESC').all(req.user.id, 'active');
  res.json(passes);
});
app.post('/api/passes', authMiddleware, (req, res) => {
  const { type, validFrom, validTo } = req.body;
  const id = uuid();
  db.prepare('INSERT INTO passes (id, user_id, type, valid_from, valid_to, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .run(id, req.user.id, type || 'weekly', validFrom || new Date().toISOString(), validTo || new Date(Date.now() + 7 * 86400000).toISOString(), 'active', new Date().toISOString());
  res.json({ success: true, id });
});

// Rewards
app.get('/api/rewards', authMiddleware, (req, res) => {
  const user = stmts.getUserById.get(req.user.id);
  res.json({ points: user?.total_reward_points || 0 });
});

// Safety SOS
app.post('/api/safety/sos', authMiddleware, (req, res) => {
  const { busId, lat, lng, message } = req.body;
  const id = uuid();
  stmts.createSos.run(id, req.user.id, busId, lat, lng, message || '🚨 EMERGENCY!', 'sos_emergency');
  // notify admin
  const admins = db.prepare("SELECT id FROM users WHERE role = 'admin'").all();
  admins.forEach(a => {
    const nid = uuid();
    stmts.createNotification.run(nid, a.id, 'sos_alert', '🚨 SOS Emergency Alert!',
      `User ${req.user.id} needs immediate help!`, JSON.stringify({ sosId: id }), '/admin');
  });
  res.json({ success: true, sosId: id });
});

// Metro
app.get('/api/metro', (req, res) => {
  const metro = db.prepare('SELECT * FROM stops WHERE zone = ? OR landmark LIKE ? LIMIT 10').all('central', '%metro%');
  res.json(metro);
});

// Landmarks
app.get('/api/landmarks', (req, res) => {
  const landmarks = db.prepare("SELECT id, name, lat, lng, 'heritage' as category FROM stops WHERE is_terminal = 1 OR landmark IS NOT NULL LIMIT 15").all();
  res.json(landmarks);
});

// Parking
app.get('/api/parking', (req, res) => {
  res.json([]); // placeholder
});

// EV Stations
app.get('/api/ev', (req, res) => {
  res.json([]); // placeholder
});

// Emergency Points
app.get('/api/emergency', (req, res) => {
  const emergency = db.prepare("SELECT id, name, lat, lng, 'hospital' as type, '044-2447' as phone FROM stops WHERE is_terminal = 1 LIMIT 5").all();
  res.json(emergency);
});

// Admin Stats
app.get('/api/admin/stats', authMiddleware, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  const buses = stmts.getAllBuses.all();
  const total = buses.length;
  const totalPax = buses.reduce((s, b) => s + (b.passengers_count || 0), 0);
  const avgPct = total > 0 ? Math.round((totalPax / (total * CAPACITY)) * 100) : 0;
  const highCount = buses.filter(b => b.crowd_level === 'high').length;
  const avgWait = total > 0 ? Math.round(buses.reduce((s, b) => s + (b.wait_time || 5), 0) / total) : 0;
  res.json({
    revenue: randInt(1000, 5000),
    avgHealth: randInt(85, 98),
    highCrowd: highCount,
    avgWait: avgWait
  });
});

// Community Reports
app.get('/api/community/reports', (req, res) => {
  const reports = stmts.getCommunityReports.all();
  res.json(reports);
});

// Digital Twin - GET and POST endpoints
app.get('/api/digitaltwin', (req, res) => {
  const buses = stmts.getAllBuses.all();
  const data = {
    buses: buses.map(b => ({
      id: b.id,
      lat: b.current_lat,
      lng: b.current_lng,
      crowd: b.crowd_level,
      pax: b.passengers_count
    }))
  };
  res.json(data);
});

app.post('/api/digitaltwin', (req, res) => {
  // Accept simulation data and update bus positions
  const { buses } = req.body;
  if (buses && Array.isArray(buses)) {
    buses.forEach(b => {
      if (b.id) {
        stmts.updateBusLocation.run(b.lat, b.lng, rand(10, 50), randInt(0, 359), b.id);
      }
    });
  }
  res.json({ success: true, message: 'Digital Twin simulation updated' });
});

// SOS endpoint (for smcd-1.html compatibility)
app.post('/api/sos', authMiddleware, (req, res) => {
  const { busId, lat, lng, message } = req.body;
  const id = uuid();
  // Make busId optional - use null if not provided or invalid
  const validBusId = busId && busId !== 'test-bus' ? busId : null;
  stmts.createSos.run(id, req.user.id, validBusId, lat, lng, message || '🚨 EMERGENCY! Help needed!', 'sos_emergency');
  // Alert admin
  const admins = db.prepare("SELECT id FROM users WHERE role = 'admin'").all();
  admins.forEach(a => {
    const nid = uuid();
    stmts.createNotification.run(nid, a.id, 'sos_alert', '🚨 SOS Emergency Alert!',
      `User ${req.user.id} needs immediate help! Location: ${lat},${lng}`, JSON.stringify({ sosId: id }), '/admin');
  });
  res.json({ success: true, sosId: id, message: '🚨 SOS sent! Help is on the way.' });
});

// Favorites endpoint
app.get('/api/favorites', authMiddleware, (req, res) => {
  res.json([]); // placeholder for favorites
});

// Trip History endpoint
app.get('/api/trip-history', authMiddleware, (req, res) => {
  const trips = stmts.getTripsByUser.all(req.user.id);
  res.json(trips);
});

// Dashboard stats
app.get('/api/dashboard/stats', (req, res) => {
  const buses = stmts.getAllBuses.all();
  const total = buses.length;
  const totalPax = buses.reduce((s, b) => s + (b.passengers_count || 0), 0);
  const avgPct = total > 0 ? Math.round((totalPax / (total * CAPACITY)) * 100) : 0;
  const highCount = buses.filter(b => b.crowd_level === 'high').length;
  const avgWait = total > 0 ? Math.round(buses.reduce((s, b) => s + (b.wait_time || 5), 0) / total) : 0;
  const routes = stmts.getAllRoutes.all();
  res.json({
    totalBuses: total,
    totalRoutes: routes.length,
    totalStops: stmts.getAllStops.all().length,
    avgOccupancy: avgPct,
    highCrowd: highCount,
    avgWait: avgWait,
    totalSeatsAvailable: buses.reduce((s, b) => s + (b.seats_available || 0), 0),
    womenSafeBuses: buses.filter(b => b.is_women_safe).length,
    crowdDistribution: { high: highCount, medium: buses.filter(b => b.crowd_level === 'medium').length, low: buses.filter(b => b.crowd_level === 'low').length },
    aiInsights: {
      recommendation: highCount > 3 ? 'Heavy crowding detected. Consider alternate routes.' : 'Fleet operating efficiently',
      totalCrowdedRoutes: new Set(buses.filter(b => b.crowd_level === 'high').map(b => b.route_name)).size
    }
  });
});

// ─── SOCKET.IO ───
const server = http.createServer(app);
const io = socketIo(server, { cors: { origin: '*' }, pingTimeout: 60000, pingInterval: 25000 });

io.use((socket, next) => {
  const token = socket.handshake.auth?.token;
  if (!token) return next(new Error('No token'));
  try { socket.user = jwt.verify(token, JWT_SECRET); next(); }
  catch (err) { next(new Error('Invalid token')); }
});

io.on('connection', (socket) => {
  console.log('🔌 Neo Socket:', socket.id);

  socket.on('subscribe-bus', ({ busId }) => {
    socket.join(`bus-${busId}`);
    const bus = stmts.getBusById.get(busId);
    if (bus) {
      const prediction = predictCrowdAdvanced(busId, bus.passengers_count || 0);
      socket.emit('bus-location', {
        busId, lat: bus.current_lat, lng: bus.current_lng,
        crowdLevel: bus.crowd_level, passengers: bus.passengers_count,
        seatsAvailable: bus.seats_available, waitTime: bus.wait_time,
        etaMinutes: bus.eta_minutes, nextStop: bus.next_stop, speed: bus.speed,
        prediction, timestamp: bus.last_gps_update
      });
    }
  });

  socket.on('gps-update', ({ busId, lat, lng, speed, heading }) => {
    const bus = stmts.getBusById.get(busId);
    const pax = bus?.passengers_count || 0;
    stmts.updateBusLocation.run(lat, lng, speed || 0, heading || 0, busId);
    stmts.insertGpsLog.run(busId, lat, lng, speed || 0, heading || 0, pax, bus?.crowd_level || 'low');
    io.to(`bus-${busId}`).emit('bus-location', { busId, lat, lng, speed, heading, passengers: pax, timestamp: new Date().toISOString() });
  });

  socket.on('crowd-update', ({ busId, crowdLevel, passengers, waitTime, etaMinutes, nextStop, seatsAvailable }) => {
    stmts.updateBusCrowd.run(crowdLevel, passengers, waitTime || 5, etaMinutes || 0, nextStop || '', seatsAvailable || (CAPACITY - passengers), busId);
    const prediction = predictCrowdAdvanced(busId, passengers);
    io.to(`bus-${busId}`).emit('crowd-change', { busId, crowdLevel, passengers, waitTime, etaMinutes, nextStop, seatsAvailable, prediction });
  });

  socket.on('disconnect', () => console.log('🔌 Neo Disconnected:', socket.id));
});

// ─── SEED DATABASE ───
function seedDatabase() {
  if (stmts.getAllStops.all().length > 0) return;
  console.log('🌱 Seeding SmartBus NEO...');

  const stops = [
    { name: 'Anna Nagar Tower', ta: 'அண்ணா நகர் கோபுரம்', lat: 13.0865, lng: 80.2105, zone: 'north', landmark: 'Anna Nagar Roundabout' },
    { name: 'T.Nagar Pondy Bazaar', ta: 'டி.நகர் பாண்டி பஜார்', lat: 13.0409, lng: 80.2344, zone: 'central', landmark: 'Pondy Bazaar Market' },
    { name: 'Adyar Depot', ta: 'அடையார் டிப்போ', lat: 13.0030, lng: 80.2580, zone: 'south', landmark: 'Adyar Signal' },
    { name: 'Tambaram Railway', ta: 'தாம்பரம் ரயில் நிலையம்', lat: 12.9246, lng: 80.1272, zone: 'south', landmark: 'Tambaram Station' },
    { name: 'Chennai Central', ta: 'சென்னை சென்ட்ரல்', lat: 13.0827, lng: 80.2707, zone: 'central', landmark: 'Central Station' },
    { name: 'Velachery Terminus', ta: 'வேளச்சேரி பேருந்து நிலையம்', lat: 12.9751, lng: 80.2181, zone: 'south', landmark: 'Velachery Signal' },
    { name: 'Mylapore Kapaleeswarar', ta: 'மயிலாப்பூர் கபாலீஸ்வரர்', lat: 13.0349, lng: 80.2681, zone: 'central', landmark: 'Kapaleeswarar Temple' },
    { name: 'Egmore Museum', ta: 'எழும்பூர் அருங்காட்சியகம்', lat: 13.0697, lng: 80.2574, zone: 'central', landmark: 'Egmore Station' },
    { name: 'Guindy IIT Gate', ta: 'கிண்டி ஐ.ஐ.டி வாயில்', lat: 13.0047, lng: 80.2152, zone: 'south', landmark: 'IIT Madras' },
    { name: 'Koyambedu CMBT', ta: 'கோயம்பேடு சி.எம்.பி.டி', lat: 13.0710, lng: 80.1830, zone: 'central', landmark: 'CMBT Bus Stand' },
    { name: 'OMR Navalur', ta: 'ஓ.எம்.ஆர் நவலூர்', lat: 12.9500, lng: 80.2300, zone: 'south', landmark: 'Navalur Signal' },
    { name: 'Broadway', ta: 'பிராட்வே', lat: 13.0950, lng: 80.2860, zone: 'central', landmark: 'Broadway Market' },
    { name: 'Thiruvanmiyur Beach', ta: 'திருவான்மியூர் கடற்கரை', lat: 12.9829, lng: 80.2591, zone: 'south', landmark: 'Thiruvanmiyur Signal' },
    { name: 'Porur Junction', ta: 'போரூர் சந்திப்பு', lat: 13.0350, lng: 80.1560, zone: 'west', landmark: 'Porur Signal' },
    { name: 'Saidapet Bridge', ta: 'சைதாப்பேட்டை பாலம்', lat: 13.0213, lng: 80.2206, zone: 'central', landmark: 'Saidapet Court' },
    { name: 'Nungambakkam', ta: 'நுங்கம்பாக்கம்', lat: 13.0569, lng: 80.2425, zone: 'central', landmark: 'Nungambakkam High Road' },
    { name: 'Adyar Guindy', ta: 'அடையார் கிண்டி', lat: 13.0105, lng: 80.2205, zone: 'south', landmark: 'Adyar Signal' },
    { name: 'Chromepet', ta: 'குரோம்பேட்', lat: 12.9516, lng: 80.1462, zone: 'south', landmark: 'Chromepet Market' },
    { name: 'Vadapalani', ta: 'வடபழனி', lat: 13.0500, lng: 80.2120, zone: 'central', landmark: 'Vadapalani Temple' },
    { name: 'K.K. Nagar', ta: 'கே.கே. நகர்', lat: 13.0370, lng: 80.2030, zone: 'west', landmark: 'K.K. Nagar Market' },
    { name: 'Ashok Nagar', ta: 'அசோக் நகர்', lat: 13.0410, lng: 80.2110, zone: 'west', landmark: 'Ashok Nagar Colony' },
    { name: 'Mambalam', ta: 'மாம்பாளம்', lat: 13.0330, lng: 80.2270, zone: 'central', landmark: 'Mambalam Station' },
    { name: 'Santhome', ta: 'சாந்தோம்', lat: 13.0280, lng: 80.2780, zone: 'central', landmark: 'Santhome Church' },
    { name: 'Triplicane', ta: 'திரplicane', lat: 13.0580, lng: 80.2750, zone: 'central', landmark: 'Triplicane High Road' },
    { name: 'Royapettah', ta: 'ராயபேட்டை', lat: 13.0550, lng: 80.2670, zone: 'central', landmark: 'Royapettah Hospital' },
  ];

  const stopIds = [];
  stops.forEach((s, idx) => {
    const id = uuid();
    stmts.createStop.run(id, s.name, s.ta, `STP${String(idx+1).padStart(3,'0')}`, s.lat, s.lng, `${s.name}, Chennai`, s.zone, s.landmark);
    stopIds.push({ id, name: s.name, lat: s.lat, lng: s.lng });
  });

  const routeData = [
    { name: 'Anna Nagar - T.Nagar', num: '42A', base: 22, start: 0, end: 1, dur: 25, freq: 10, safe: 4.8 },
    { name: 'Adyar - Tambaram', num: '19B', base: 25, start: 2, end: 3, dur: 35, freq: 12, safe: 4.6 },
    { name: 'Central - Velachery', num: '21G', base: 20, start: 4, end: 5, dur: 30, freq: 8, safe: 4.9 },
    { name: 'Mylapore - Egmore', num: '12B', base: 18, start: 6, end: 7, dur: 20, freq: 15, safe: 4.7 },
    { name: 'Guindy - OMR', num: '45C', base: 30, start: 8, end: 10, dur: 40, freq: 10, safe: 4.5 },
    { name: 'Koyambedu - Broadway', num: '27A', base: 20, start: 9, end: 11, dur: 28, freq: 8, safe: 4.8 },
    { name: 'T.Nagar - Velachery', num: '47A', base: 22, start: 1, end: 5, dur: 25, freq: 10, safe: 4.6 },
    { name: 'Adyar - Thiruvanmiyur', num: '11H', base: 15, start: 2, end: 12, dur: 15, freq: 12, safe: 4.9 },
    { name: 'Porur - Guindy', num: '55B', base: 18, start: 13, end: 8, dur: 22, freq: 10, safe: 4.4 },
    { name: 'Central - Saidapet', num: '23A', base: 16, start: 4, end: 14, dur: 18, freq: 8, safe: 4.7 },
    { name: 'Broadway - Mylapore', num: '38C', base: 20, start: 11, end: 6, dur: 22, freq: 10, safe: 4.8 },
    { name: 'OMR - Thiruvanmiyur', num: '56K', base: 15, start: 10, end: 12, dur: 12, freq: 15, safe: 4.5 },
    { name: 'Nungambakkam - Vadapalani', num: '15G', base: 18, start: 15, end: 18, dur: 20, freq: 12, safe: 4.6 },
    { name: 'K.K. Nagar - Ashok Nagar', num: '52B', base: 14, start: 19, end: 20, dur: 15, freq: 10, safe: 4.7 },
    { name: 'Chromepet - Tambaram', num: '62A', base: 12, start: 17, end: 3, dur: 18, freq: 8, safe: 4.5 },
    { name: 'Mambalam - T.Nagar', num: '33D', base: 10, start: 21, end: 1, dur: 10, freq: 15, safe: 4.8 },
    { name: 'Santhome - Triplicane', num: '8B', base: 12, start: 22, end: 23, dur: 12, freq: 12, safe: 4.9 },
    { name: 'Royapettah - Mylapore', num: '25A', base: 14, start: 24, end: 6, dur: 14, freq: 10, safe: 4.6 },
    { name: 'Anna Nagar - Koyambedu', num: '41B', base: 16, start: 0, end: 9, dur: 18, freq: 10, safe: 4.7 },
    { name: 'Velachery - Guindy', num: '21B', base: 18, start: 5, end: 8, dur: 20, freq: 12, safe: 4.8 },
  ];

  routeData.forEach((rd, idx) => {
    const rid = uuid();
    const start = stopIds[rd.start], end = stopIds[rd.end];
    const dist = haversine(start.lat, start.lng, end.lat, end.lng);
    db.prepare('INSERT INTO routes (id, name, number, fare_base, start_stop_id, end_stop_id, distance_km, duration_min, frequency_min, safety_rating) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
      .run(rid, rd.name, rd.num, rd.base, start.id, end.id, Math.round(dist*10)/10, rd.dur, rd.freq, rd.safe);
    const routeStops = [start];
    const numMid = randInt(1, 2);
    for (let i = 0; i < numMid; i++) {
      let mid = pick(stopIds);
      let tries = 0;
      while ((mid.id === start.id || mid.id === end.id || routeStops.find(s => s.id === mid.id)) && tries < 20)
        { mid = pick(stopIds); tries++; }
      if (!routeStops.find(s => s.id === mid.id)) routeStops.push(mid);
    }
    routeStops.push(end);
    routeStops.forEach((s, i) => {
      const rsid = uuid();
      const prevDist = i > 0 ? haversine(routeStops[i-1].lat, routeStops[i-1].lng, s.lat, s.lng) : 0;
      db.prepare('INSERT INTO route_stops (id, route_id, stop_id, stop_order, time_from_prev_min, distance_from_prev_km) VALUES (?, ?, ?, ?, ?, ?)')
        .run(rsid, rid, s.id, i+1, i === 0 ? 0 : Math.max(2, Math.round(prevDist * 2.5)), Math.round(prevDist * 10) / 10);
    });
  });

  // Generate 200 bus registrations
  const busRegs = [];
  for (let i = 1; i <= 200; i++) {
    busRegs.push(`TN-01-NE-${String(i).padStart(4, '0')}`);
  }
  const drivers = ['Kumar','Suresh','Ramesh','Dinesh','Murugan','Prakash','Vijay','Ganesh','Rajesh','Santhosh','Mohan','Arun','Naveen','Praveen','Lokesh','Kishore','Bala','Karthik','Vignesh','Deepak','Harish','Natarajan','Venkat','Sridhar','Prabhu','Ravi','Sam','Gopi','Mani','Selva','Ashok','Ramu','Babu','Chandru','Durai','Elango','Feroz','Gunaseelan','Irfan','Jagan','Priya','Kavin','Divya','Nisha','Ravi','Anand','Kumar','Sneha','Rohit','Amit','Pooja'];

  busRegs.forEach((reg, idx) => {
    const id = uuid();
    const pax = randInt(5, 55);
    const level = getLevel(pax);
    const wait = randInt(2, 15);
    const eta = randInt(3, 25);
    const routeIdx = idx % routeData.length;
    const route = routeData[routeIdx];
    const startStop = stopIds[route.start];
    const endStop = stopIds[route.end];
    const routeName = route.name;
    const nextStop = pick(stopIds.filter(s => s.id !== startStop.id && s.id !== endStop.id));
    const seatsAvail = Math.max(0, CAPACITY - pax);

    stmts.createBus.run(id, reg, 60, idx % 4 === 0 ? 'AC Volvo' : idx % 4 === 1 ? 'AC Standard' : 'Standard');
    stmts.updateBusCrowd.run(level, pax, wait, eta, nextStop?.name || '', seatsAvail, id);
    stmts.updateBusLocation.run(startStop.lat + rand(-0.02, 0.02), startStop.lng + rand(-0.02, 0.02), rand(10, 50), randInt(0, 359), id);
    db.prepare('UPDATE buses SET route_name = ?, route_coords = ?, driver_name = ?, conductor_name = ?, ac_available = ?, women_reserved = ?, fuel_level = ? WHERE id = ?')
      .run(routeName, JSON.stringify([{lat: startStop.lat, lng: startStop.lng}, {lat: endStop.lat, lng: endStop.lng}]), drivers[idx % drivers.length], `Conductor ${idx+1}`, idx % 4 === 0 || idx % 4 === 1 ? 1 : 0, 8, rand(40, 95), id);
  });

  // Users
  const adminPass = bcrypt.hashSync('admin123', SALT_ROUNDS);
  stmts.createUser.run(uuid(), 'admin@smartbus.com', adminPass, 'Dr. Admin', '9876543210', 'admin', 'en');
  const userPass = bcrypt.hashSync('pass123', SALT_ROUNDS);
  const userId = uuid();
  stmts.createUser.run(userId, 'pass@smartbus.com', userPass, 'John Passenger', '9876543211', 'passenger', 'en');

  // Notifications
  const notifs = [
    { type: 'ai_prediction', title: '🧠 AI Crowd Prediction Ready', body: 'AI predicts Route 42A will be 80% full in 30 mins. Plan accordingly.', user: userId },
    { type: 'safety', title: '🛡️ Women Safety Features Active', body: 'Live journey sharing, SOS alerts, and emergency contacts available.', user: userId },
    { type: 'reward', title: '⭐ Earn Rewards!', body: 'Earn 10 points per trip. Redeem for discounts on future travel.', user: userId },
    { type: 'route', title: '🔄 Smart Route Available', body: 'New AI-powered route recommendations: fastest, cheapest, least crowded, safest options.', user: userId },
    { type: 'route', title: '🚌 40 Buses Active Now', body: 'Fleet expanded! More buses on 20 routes across Chennai.', user: userId },
    { type: 'ai_prediction', title: '📊 Crowd Alert', body: 'Route 19B (Adyar-Tambaram) expecting high crowd during peak hours.', user: userId },
  ];
  notifs.forEach(n => { const nid = uuid(); stmts.createNotification.run(nid, n.user, n.type, n.title, n.body, '{}', '/'); });

  console.log('✅ SmartBus NEO Seeded!');
}

// Chennai bounds to keep buses within city limits
const CHENNAI_BOUNDS = {
  south: 12.75,   // Near Chengalpattu
  north: 13.22,   // Near Ponneri
  west: 79.95,    // Near Porur
  east: 80.35     // Near Perungudi
};

// Global bus stops array for route simulation
let busStops = [];

// Route-based GPS coordinates for realistic bus movement
// These match the route names in the database
const routeCoordinates = {
  'Anna - Tambaram': [
    { lat: 13.0865, lng: 80.2105 }, // Anna Nagar
    { lat: 13.05, lng: 80.20 },
    { lat: 12.98, lng: 80.18 },
    { lat: 12.9246, lng: 80.1272 }  // Tambaram
  ],
  'Adyar - Koyambedu': [
    { lat: 13.0030, lng: 80.2580 }, // Adyar
    { lat: 13.05, lng: 80.22 },
    { lat: 13.0710, lng: 80.1830 }  // Koyambedu
  ],
  'Chennai - Velachery': [
    { lat: 13.0827, lng: 80.2707 }, // Central
    { lat: 13.05, lng: 80.25 },
    { lat: 12.98, lng: 80.22 },
    { lat: 12.9751, lng: 80.2181 }  // Velachery
  ],
  'Mylapore - Egmore': [
    { lat: 13.0349, lng: 80.2681 }, // Mylapore
    { lat: 13.05, lng: 80.25 },
    { lat: 13.0697, lng: 80.2574 }  // Egmore
  ],
  'Guindy - OMR': [
    { lat: 13.0047, lng: 80.2152 }, // Guindy
    { lat: 12.95, lng: 80.20 },
    { lat: 12.95, lng: 80.23 }  // OMR
  ],
  'Broadway - Mambalam': [
    { lat: 13.0950, lng: 80.2860 }, // Broadway
    { lat: 13.05, lng: 80.25 },
    { lat: 13.0330, lng: 80.2270 }  // Mambalam
  ],
  'T.Nagar - Thiruvanmiyur': [
    { lat: 13.0409, lng: 80.2344 }, // T.Nagar
    { lat: 13.02, lng: 80.22 },
    { lat: 12.9829, lng: 80.2591 }  // Thiruvanmiyur
  ],
  'Porur - Saidapet': [
    { lat: 13.0350, lng: 80.1560 }, // Porur
    { lat: 13.02, lng: 80.22 },
    { lat: 13.0213, lng: 80.2206 }  // Saidapet
  ],
  'Nungambakkam - Vadapalani': [
    { lat: 13.0569, lng: 80.2425 }, // Nungambakkam
    { lat: 13.05, lng: 80.2120 },
    { lat: 13.0500, lng: 80.2120 }  // Vadapalani
  ],
  'K.K. - Ashok': [
    { lat: 13.0370, lng: 80.2030 }, // K.K. Nagar
    { lat: 13.04, lng: 80.21 },
    { lat: 13.0410, lng: 80.2110 }  // Ashok Nagar
  ],
  'Chromepet - Guindy': [
    { lat: 12.9516, lng: 80.1462 }, // Chromepet
    { lat: 13.0, lng: 80.20 },
    { lat: 13.0047, lng: 80.2152 }  // Guindy
  ],
  'Santhome - Triplicane': [
    { lat: 13.0280, lng: 80.2780 }, // Santhome
    { lat: 13.05, lng: 80.27 },
    { lat: 13.0580, lng: 80.2750 }  // Triplicane
  ],
  'Royapettah - Mylapore': [
    { lat: 13.0550, lng: 80.2670 }, // Royapettah
    { lat: 13.04, lng: 80.26 },
    { lat: 13.0349, lng: 80.2681 }  // Mylapore
  ],
  'Anna - Koyambedu': [
    { lat: 13.0865, lng: 80.2105 }, // Anna Nagar
    { lat: 13.07, lng: 80.20 },
    { lat: 13.0710, lng: 80.1830 }  // Koyambedu
  ],
  'Velachery - Guindy': [
    { lat: 12.9751, lng: 80.2181 }, // Velachery
    { lat: 13.0, lng: 80.21 },
    { lat: 13.0047, lng: 80.2152 }  // Guindy
  ],
  'Tambaram - Chromepet': [
    { lat: 12.9246, lng: 80.1272 }, // Tambaram
    { lat: 12.95, lng: 80.14 },
    { lat: 12.9516, lng: 80.1462 }  // Chromepet
  ],
  'OMR - Thiruvanmiyur': [
    { lat: 12.95, lng: 80.23 }, // OMR
    { lat: 12.98, lng: 80.25 },
    { lat: 12.9829, lng: 80.2591 }  // Thiruvanmiyur
  ],
  'Broadway - Egmore': [
    { lat: 13.0950, lng: 80.2860 }, // Broadway
    { lat: 13.07, lng: 80.26 },
    { lat: 13.0697, lng: 80.2574 }  // Egmore
  ],
  'Chennai - Tambaram': [
    { lat: 13.0827, lng: 80.2707 }, // Central
    { lat: 13.0, lng: 80.20 },
    { lat: 12.9246, lng: 80.1272 }  // Tambaram
  ],
  'Adyar - Anna': [
    { lat: 13.0030, lng: 80.2580 }, // Adyar
    { lat: 13.05, lng: 80.22 },
    { lat: 13.0865, lng: 80.2105 }  // Anna Nagar
  ]
};

// Track bus position along route
const busRouteProgress = {};

// ─── LIVE SIMULATION ───
function simulateLiveUpdates() {
  try {
    // Load stops from database for next stop lookup
    const stops = stmts.getAllStops.all();
    const buses = stmts.getAllBuses.all();
    buses.forEach(bus => {
      const delta = randInt(-4, 5);
      let newPax = clamp((bus.passengers_count || 0) + delta, 2, CAPACITY);
      if (Math.random() < 0.06) newPax = clamp(newPax + randInt(-10, 10), 2, CAPACITY);
      const status = getLevel(newPax);
      const wait = Math.max(1, (bus.wait_time || 5) + randInt(-1, 2));
      const eta = Math.max(1, (bus.eta_minutes || 5) + randInt(-1, 2));
      const seatsAvail = Math.max(0, CAPACITY - newPax);
      
      // Get route coordinates for this bus
      const routeName = bus.route_name || 'Anna Nagar - T.Nagar';
      const routeCoords = routeCoordinates[routeName] || routeCoordinates['Anna Nagar - T.Nagar'];
      
      // Initialize or advance position along route
      if (!busRouteProgress[bus.id]) {
        busRouteProgress[bus.id] = { index: 0, direction: 1 };
      }
      
      const progress = busRouteProgress[bus.id];
      const routeIndex = progress.index;
      
      // Move to next point on route
      if (routeCoords && routeCoords.length > 0) {
        const targetPoint = routeCoords[routeIndex];
        const newLat = targetPoint.lat;
        const newLng = targetPoint.lng;
        
        // Advance to next point (or reverse at endpoints)
        if (routeIndex >= routeCoords.length - 1) {
          progress.direction = -1;
        } else if (routeIndex <= 0) {
          progress.direction = 1;
        }
        progress.index += progress.direction;
        
        // Update next stop based on position
        const nextStopIndex = Math.min(routeIndex + progress.direction, routeCoords.length - 1);
        const nextStop = stops.find(s => s.lat === routeCoords[nextStopIndex]?.lat && s.lng === routeCoords[nextStopIndex]?.lng);
        
        stmts.updateBusCrowd.run(status, Math.round(newPax), wait, eta, nextStop?.name || bus.next_stop || '', seatsAvail, bus.id);
        stmts.updateBusLocation.run(newLat, newLng, rand(20, 45), randInt(0, 359), bus.id);
        stmts.insertGpsLog.run(bus.id, newLat, newLng, rand(20, 45), randInt(0, 359), Math.round(newPax), status);

        const prediction = predictCrowdAdvanced(bus.id, Math.round(newPax));
        io.to(`bus-${bus.id}`).emit('bus-location', {
          busId: bus.id, lat: newLat, lng: newLng, crowdLevel: status,
          passengers: Math.round(newPax), seatsAvailable: seatsAvail,
          waitTime: wait, etaMinutes: eta, nextStop: nextStop?.name || bus.next_stop, prediction,
          timestamp: new Date().toISOString()
        });
      } else {
        // Fallback to random movement within bounds
        const latDelta = rand(-0.0005, 0.0005), lngDelta = rand(-0.0005, 0.0005);
        const newLat = clamp((bus.current_lat || 13.08) + latDelta, CHENNAI_BOUNDS.south, CHENNAI_BOUNDS.north);
        const newLng = clamp((bus.current_lng || 80.27) + lngDelta, CHENNAI_BOUNDS.west, CHENNAI_BOUNDS.east);

        stmts.updateBusCrowd.run(status, Math.round(newPax), wait, eta, bus.next_stop || '', seatsAvail, bus.id);
        stmts.updateBusLocation.run(newLat, newLng, rand(20, 45), randInt(0, 359), bus.id);
        stmts.insertGpsLog.run(bus.id, newLat, newLng, rand(20, 45), randInt(0, 359), Math.round(newPax), status);

        const prediction = predictCrowdAdvanced(bus.id, Math.round(newPax));
        io.to(`bus-${bus.id}`).emit('bus-location', {
          busId: bus.id, lat: newLat, lng: newLng, crowdLevel: status,
          passengers: Math.round(newPax), seatsAvailable: seatsAvail,
          waitTime: wait, etaMinutes: eta, nextStop: bus.next_stop, prediction,
          timestamp: new Date().toISOString()
        });
      }
    });
  } catch (err) { console.error('Sim error:', err.message); }
}

// ─── START SERVER ───
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

seedDatabase();
server.listen(PORT, () => {
  console.log('\n' + '='.repeat(55));
  console.log('  🚍  SMARTBUS NEO - AI-POWERED TRANSPORT');
  console.log('  🤖  AI Crowd Prediction | Smart Routes | Safety');
  console.log('='.repeat(55));
  console.log(`  🌐  http://localhost:${PORT}`);
  console.log(`  👤  pass@smartbus.com / pass123`);
  console.log(`  👑  admin@smartbus.com / admin123`);
  console.log('='.repeat(55) + '\n');
});

setInterval(simulateLiveUpdates, UPDATE_INTERVAL);
console.log('🧠 NEO AI Engine Active');