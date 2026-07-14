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

  const busRegs = [
    'TN-01-NE-0001', 'TN-01-NE-0002', 'TN-01-NE-0003', 'TN-01-NE-0004',
    'TN-01-NE-0005', 'TN-01-NE-0006', 'TN-01-NE-0007', 'TN-01-NE-0008',
    'TN-01-NE-0009', 'TN-01-NE-0010', 'TN-01-NE-0011', 'TN-01-NE-0012',
    'TN-01-NE-0013', 'TN-01-NE-0014', 'TN-01-NE-0015', 'TN-01-NE-0016'
  ];
  const drivers = ['Kumar','Suresh','Ramesh','Dinesh','Murugan','Prakash','Vijay','Ganesh','Rajesh','Santhosh','Mohan','Arun','Naveen','Praveen','Lokesh','Kishore'];

  busRegs.forEach((reg, idx) => {
    const id = uuid();
    const pax = randInt(5, 55);
    const level = getLevel(pax);
    const wait = randInt(2, 15);
    const eta = randInt(3, 25);
    const startStop = pick(stopIds);
    const endStop = pick(stopIds.filter(s => s.id !== startStop.id));
    const routeName = `${startStop.name} → ${endStop.name}`;
    const nextStop = pick(stopIds.filter(s => s.id !== startStop.id));
    const seatsAvail = Math.max(0, CAPACITY - pax);

    stmts.createBus.run(id, reg, 60, idx % 3 === 0 ? 'AC Volvo' : 'Standard');
    stmts.updateBusCrowd.run(level, pax, wait, eta, nextStop.name, seatsAvail, id);
    stmts.updateBusLocation.run(startStop.lat + rand(-0.03, 0.03), startStop.lng + rand(-0.03, 0.03), rand(10, 50), randInt(0, 359), id);
    db.prepare('UPDATE buses SET route_name = ?, driver_name = ?, conductor_name = ?, ac_available = ?, women_reserved = ?, fuel_level = ? WHERE id = ?')
      .run(routeName, drivers[idx], `Conductor ${idx+1}`, idx % 3 === 0 ? 1 : 0, 8, rand(40, 95), id);
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
  ];
  notifs.forEach(n => { const nid = uuid(); stmts.createNotification.run(nid, n.user, n.type, n.title, n.body, '{}', '/'); });

  console.log('✅ SmartBus NEO Seeded!');
}

// ─── LIVE SIMULATION ───
function simulateLiveUpdates() {
  try {
    const buses = stmts.getAllBuses.all();
    buses.forEach(bus => {
      const delta = randInt(-4, 5);
      let newPax = clamp((bus.passengers_count || 0) + delta, 2, CAPACITY);
      if (Math.random() < 0.06) newPax = clamp(newPax + randInt(-10, 10), 2, CAPACITY);
      const status = getLevel(newPax);
      const wait = Math.max(1, (bus.wait_time || 5) + randInt(-1, 2));
      const eta = Math.max(1, (bus.eta_minutes || 5) + randInt(-1, 2));
      const seatsAvail = Math.max(0, CAPACITY - newPax);
      const latDelta = rand(-0.006, 0.006), lngDelta = rand(-0.006, 0.006);
      const newLat = (bus.current_lat || 13.08) + latDelta, newLng = (bus.current_lng || 80.27) + lngDelta;

      stmts.updateBusCrowd.run(status, Math.round(newPax), wait, eta, bus.next_stop || '', seatsAvail, bus.id);
      stmts.updateBusLocation.run(newLat, newLng, rand(5, 50), randInt(0, 359), bus.id);
      stmts.insertGpsLog.run(bus.id, newLat, newLng, rand(5, 50), randInt(0, 359), Math.round(newPax), status);

      const prediction = predictCrowdAdvanced(bus.id, Math.round(newPax));
      io.to(`bus-${bus.id}`).emit('bus-location', {
        busId: bus.id, lat: newLat, lng: newLng, crowdLevel: status,
        passengers: Math.round(newPax), seatsAvailable: seatsAvail,
        waitTime: wait, etaMinutes: eta, nextStop: bus.next_stop, prediction,
        timestamp: new Date().toISOString()
      });
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