/**
 * ============================================================================
 * NARMC NETWORK OFFICIAL STORE - STRICT MONGODB ATLAS SERVER (server.js)
 * لا يعمل المتجر ولا يقبل تسجيل الدخول إلا إذا كان رابط MongoDB Atlas صحيحاً ومتصلاً!
 * يتضمن حلاً تلقائياً لمشكلة Windows DNS (querySrv ECONNREFUSED) عبر Google/Cloudflare DNS + DoH
 * ============================================================================
 */
require('dotenv').config();
const dns = require('dns');
const https = require('https');

// 1) حل مشكلة querySrv ECONNREFUSED في ويندوز والراوترات عبر تحويل DNS لـ Google & Cloudflare
try {
  if (typeof dns.setDefaultResultOrder === 'function') {
    dns.setDefaultResultOrder('ipv4first');
  }
  dns.setServers(['8.8.8.8', '1.1.1.1', '8.8.4.4', '1.0.0.1']);
  if (dns.promises && typeof dns.promises.setServers === 'function') {
    dns.promises.setServers(['8.8.8.8', '1.1.1.1', '8.8.4.4', '1.0.0.1']);
  }
} catch (_) {}

// 2) نظام احتياطي ذكي عبر HTTPS (DNS-over-HTTPS) في حال قام الراوتر أو المزود بحظر منفذ DNS 53
function fetchJsonOverHttps(url) {
  return new Promise((resolve, reject) => {
    const req = https.get(
      url,
      { headers: { Accept: 'application/dns-json' }, timeout: 6000 },
      (res) => {
        let body = '';
        res.on('data', (chunk) => (body += chunk));
        res.on('end', () => {
          try {
            resolve(JSON.parse(body));
          } catch (e) {
            reject(e);
          }
        });
      }
    );
    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy(new Error('DoH request timeout'));
    });
  });
}

const origResolveSrv = dns.promises.resolveSrv.bind(dns.promises);
const origResolveTxt = dns.promises.resolveTxt.bind(dns.promises);

dns.promises.resolveSrv = async function (hostname) {
  try {
    return await origResolveSrv(hostname);
  } catch (err) {
    console.log(`🔄 جاري تجاوز حظر DNS للراوتر (SRV) عبر HTTPS لـ: ${hostname}`);
    const urls = [
      `https://dns.google/resolve?name=${encodeURIComponent(hostname)}&type=SRV`,
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=SRV`
    ];
    for (const url of urls) {
      try {
        const data = await fetchJsonOverHttps(url);
        if (data && Array.isArray(data.Answer) && data.Answer.length > 0) {
          const records = data.Answer.filter((a) => a.type === 33 && a.data).map((a) => {
            const parts = String(a.data).trim().split(/\s+/);
            return {
              priority: Number(parts[0]) || 0,
              weight: Number(parts[1]) || 0,
              port: Number(parts[2]) || 27017,
              name: String(parts[3] || '').replace(/\.$/, '')
            };
          });
          if (records.length > 0) return records;
        }
      } catch (_) {}
    }
    throw err;
  }
};

dns.promises.resolveTxt = async function (hostname) {
  try {
    return await origResolveTxt(hostname);
  } catch (err) {
    const urls = [
      `https://dns.google/resolve?name=${encodeURIComponent(hostname)}&type=TXT`,
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=TXT`
    ];
    for (const url of urls) {
      try {
        const data = await fetchJsonOverHttps(url);
        if (data && Array.isArray(data.Answer) && data.Answer.length > 0) {
          const records = data.Answer.filter((a) => a.type === 16 && a.data).map((a) => [
            String(a.data).replace(/^"|"$|\\"/g, '')
          ]);
          if (records.length > 0) return records;
        }
      } catch (_) {}
    }
    throw err;
  }
};

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'narmc2026';
const VAULT_MASTER_PASSWORD = process.env.VAULT_MASTER_PASSWORD || 'X9#vK7!qP2@mR8$zL4';

/**
 * دالة ذكية لمعالجة رابط MongoDB وتشفير الرموز الخاصة في كلمة المرور تلقائياً
 * (مثل @ و " و £ و $ و !) حتى لا يفشل الاتصال بسبب الرموز الخاصة
 */
function normalizeMongoUri(rawUri) {
  if (!rawUri) return '';
  let uri = rawUri.trim();
  const match = uri.match(/^(mongodb(?:\+srv)?:\/\/)([^:/?#]+):(.+)@([^@/?#]+(?:\.[^@/?#]+)+)(\/.*)?$/);
  if (match) {
    const [, scheme, rawUser, rawPass, host, rest] = match;
    let decodedUser = rawUser;
    let decodedPass = rawPass;
    try { decodedUser = decodeURIComponent(rawUser); } catch (_) {}
    try { decodedPass = decodeURIComponent(rawPass); } catch (_) {}
    const encodedUser = encodeURIComponent(decodedUser);
    const encodedPass = encodeURIComponent(decodedPass);
    const cleanRest = (!rest || rest === '/') ? '/narmc_store?retryWrites=true&w=majority' : rest;
    return `${scheme}${encodedUser}:${encodedPass}@${host}${cleanRest}`;
  }
  return uri;
}

const RAW_MONGODB_URI = (process.env.MONGODB_URI || '').trim();
const MONGODB_URI = normalizeMongoUri(RAW_MONGODB_URI);

app.use(cors());
app.use(express.json({ limit: '15mb' }));
app.use(express.static(path.join(__dirname, 'public')));

let isMongoConnected = false;
let lastMongoError = 'جاري الاتصال بقاعدة بيانات MongoDB Atlas...';

function isMongoReady() {
  return isMongoConnected && mongoose.connection.readyState === 1;
}

// ============================================================================
// 1. مخطط قاعدة بيانات MongoDB Atlas (Mongoose Schema)
// ============================================================================
const StoreStateSchema = new mongoose.Schema(
  {
    singletonId: { type: String, default: 'NARMC_MAIN_STATE', unique: true },
    playerCredits: { type: Object, default: {} },
    activeSessions: { type: Object, default: {} },
    playerGifts: { type: Object, default: {} },
    discordInviteUrl: { type: String, default: 'https://discord.gg/narmc' },
    paymentAccounts: {
      type: Object,
      default: {
        asiacell: '0770 123 4567',
        zaincash: '0780 987 6543',
        mastercard: '5214 8890 3412 7765',
        visa: '4532 7109 6543 2109'
      }
    },
    bannerConfig: {
      type: Object,
      default: {
        enabled: true,
        tagAr: '⚜️ عرض ملكي خاص',
        tagEn: '⚜️ ROYAL SPECIAL OFFER',
        prefixAr: 'استخدم كود الخصم',
        prefixEn: 'Use promo code',
        promoCode: 'NAR20',
        textAr: 'للحصول على خصم 20% على جميع الرتب والمفاتيح والكتات!',
        textEn: 'to get 20% OFF on all Ranks, Keys & Hero Kits!'
      }
    },
    products: { type: Array, default: [] },
    promoCodes: {
      type: Object,
      default: { NAR20: 20, NARMC: 10, FIRE50: 50 }
    },
    topCustomer: { type: String, default: '' },
    goalPercent: { type: Number, default: 0 },
    monthlyGoalTarget: { type: Number, default: 100 },
    manualPaymentVerify: { type: Boolean, default: false },
    storeLocked: { type: Boolean, default: false },
    bannedPlayers: { type: Array, default: [] },
    bannedAdmins: { type: Array, default: [] },
    adminEditsRegistry: { type: Object, default: {} },
    adminAccessHistory: { type: Array, default: [] },
    adminOrdersAndTransfers: { type: Array, default: [] },
    auditLogs: { type: Array, default: [] },
    recentPayments: { type: Array, default: [] },
    customLogoGif: { type: String, default: '' }
  },
  { timestamps: true, minimize: false }
);

const StoreState = mongoose.model('StoreState', StoreStateSchema);

async function getStoreStateData() {
  if (!isMongoReady()) {
    throw new Error('DATABASE_NOT_CONNECTED');
  }
  let doc = await StoreState.findOne({ singletonId: 'NARMC_MAIN_STATE' });
  if (!doc) {
    doc = await StoreState.create({ singletonId: 'NARMC_MAIN_STATE' });
  } else {
    // تنظيف تلقائي لأي بيانات تجريبية وهمية قديمة كانت مخزونة سابقاً في القاعدة
    let dirty = false;
    const demoUsers = ['Azoz_IQ', 'MustafaPvP', 'Karrar_99', 'ZainCraft'];

    if (doc.topCustomer === 'xNarLegend_IQ') {
      doc.topCustomer = '';
      dirty = true;
    }
    if (Array.isArray(doc.adminOrdersAndTransfers)) {
      const filteredOrders = doc.adminOrdersAndTransfers.filter(
        (o) => o && o.id !== 'ORD-701' && o.id !== 'TX-9041'
      );
      if (filteredOrders.length !== doc.adminOrdersAndTransfers.length) {
        doc.adminOrdersAndTransfers = filteredOrders;
        doc.markModified('adminOrdersAndTransfers');
        dirty = true;
      }
    }
    if (Array.isArray(doc.recentPayments)) {
      const filteredRecent = doc.recentPayments.filter(
        (p) => p && !(demoUsers.includes(p.user) && !p.id)
      );
      if (filteredRecent.length !== doc.recentPayments.length) {
        doc.recentPayments = filteredRecent;
        doc.markModified('recentPayments');
        dirty = true;
      }
    }
    if (Array.isArray(doc.auditLogs)) {
      const filteredLogs = doc.auditLogs.filter(
        (l) => l && l.id !== 'LOG-101' && l.id !== 'LOG-102'
      );
      if (filteredLogs.length !== doc.auditLogs.length) {
        doc.auditLogs = filteredLogs;
        doc.markModified('auditLogs');
        dirty = true;
      }
    }
    if (Array.isArray(doc.adminAccessHistory)) {
      const filteredHist = doc.adminAccessHistory.filter(
        (h) => !(h && h.operator === 'Owner_Ali' && h.time === '2026-11-02 06:30:00')
      );
      if (filteredHist.length !== doc.adminAccessHistory.length) {
        doc.adminAccessHistory = filteredHist;
        doc.markModified('adminAccessHistory');
        dirty = true;
      }
    }
    if (doc.adminEditsRegistry && doc.adminEditsRegistry.Owner_Ali && doc.adminEditsRegistry.Owner_Ali.lastTime === '2026-11-02 06:30:00') {
      const reg = { ...doc.adminEditsRegistry };
      delete reg.Owner_Ali;
      doc.adminEditsRegistry = reg;
      doc.markModified('adminEditsRegistry');
      dirty = true;
    }

    // إعادة حساب الهدف الشهري وأكثر مشتري فعلياً من عمليات الشراء الحقيقية
    const purchases = (doc.adminOrdersAndTransfers || []).filter(
      (o) => o && o.type === 'PURCHASE' && o.status === 'COMPLETED'
    );
    if (purchases.length === 0 && doc.goalPercent === 68) {
      doc.goalPercent = 0;
      dirty = true;
    }
    if (dirty) {
      await doc.save();
    }
  }
  return doc;
}

async function saveStoreStateData(payload) {
  if (!isMongoReady()) {
    throw new Error('DATABASE_NOT_CONNECTED');
  }
  const allowedFields = [
    'playerCredits',
    'activeSessions',
    'playerGifts',
    'discordInviteUrl',
    'paymentAccounts',
    'bannerConfig',
    'products',
    'promoCodes',
    'topCustomer',
    'goalPercent',
    'monthlyGoalTarget',
    'manualPaymentVerify',
    'storeLocked',
    'bannedPlayers',
    'bannedAdmins',
    'adminEditsRegistry',
    'adminAccessHistory',
    'adminOrdersAndTransfers',
    'auditLogs',
    'recentPayments',
    'customLogoGif'
  ];

  let doc = await StoreState.findOne({ singletonId: 'NARMC_MAIN_STATE' });
  if (!doc) {
    doc = await StoreState.create({ singletonId: 'NARMC_MAIN_STATE' });
  }
  for (const key of allowedFields) {
    if (payload[key] !== undefined) {
      doc[key] = payload[key];
      doc.markModified(key);
    }
  }
  await doc.save();
  return doc;
}

function requireMongoMiddleware(req, res, next) {
  if (!isMongoReady()) {
    return res.status(503).json({
      ok: false,
      reason: 'DATABASE_NOT_CONNECTED',
      error: `قاعدة بيانات MongoDB Atlas غير متصلة حالياً! السبب: ${lastMongoError}`
    });
  }
  next();
}

// ============================================================================
// 2. مسارات الـ API (تعمل حصرياً عند اتصال MongoDB Atlas)
// ============================================================================
app.get('/api/status', (req, res) => {
  res.json({
    ok: isMongoReady(),
    connected: isMongoReady(),
    mode: isMongoReady() ? 'mongodb-atlas' : 'disconnected',
    error: isMongoReady() ? null : lastMongoError
  });
});

app.get('/api/state', requireMongoMiddleware, async (req, res) => {
  try {
    const stateData = await getStoreStateData();
    res.json({ ok: true, mode: 'mongodb', state: stateData });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post('/api/state/sync', requireMongoMiddleware, async (req, res) => {
  try {
    const updated = await saveStoreStateData(req.body || {});
    res.json({ ok: true, mode: 'mongodb', state: updated });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// مسار تسجيل دخول اللاعب (يتحقق من اتصال MongoDB Atlas ويحفظ الحساب مباشرة في القاعدة)
app.post('/api/player/login', requireMongoMiddleware, async (req, res) => {
  try {
    const rawUsername = (req.body && req.body.username) ? String(req.body.username).trim() : '';
    const previousUsername = (req.body && req.body.previousUsername) ? String(req.body.previousUsername).trim() : '';
    if (!rawUsername) {
      return res.status(400).json({ ok: false, reason: 'EMPTY_USERNAME', error: 'يرجى إدخال اسم اللاعب.' });
    }

    const key = rawUsername.toLowerCase();
    const doc = await getStoreStateData();

    if (Array.isArray(doc.bannedPlayers) && doc.bannedPlayers.map(p => String(p).toLowerCase()).includes(key)) {
      return res.status(403).json({ ok: false, reason: 'BANNED_PLAYER' });
    }

    const sessions = { ...(doc.activeSessions || {}) };
    if (previousUsername && previousUsername.toLowerCase() !== key) {
      delete sessions[previousUsername.toLowerCase()];
    }
    sessions[key] = true;
    doc.activeSessions = sessions;
    doc.markModified('activeSessions');

    const credits = { ...(doc.playerCredits || {}) };
    if (typeof credits[key] !== 'number') {
      credits[key] = 0;
      doc.playerCredits = credits;
      doc.markModified('playerCredits');
    }

    await doc.save();
    return res.json({
      ok: true,
      mode: 'mongodb',
      username: rawUsername,
      credit: credits[key],
      state: doc
    });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

app.post('/api/player/logout', requireMongoMiddleware, async (req, res) => {
  try {
    const rawUsername = (req.body && req.body.username) ? String(req.body.username).trim() : '';
    const doc = await getStoreStateData();
    if (rawUsername) {
      const key = rawUsername.toLowerCase();
      const sessions = { ...(doc.activeSessions || {}) };
      delete sessions[key];
      doc.activeSessions = sessions;
      doc.markModified('activeSessions');
      await doc.save();
    }
    return res.json({ ok: true, mode: 'mongodb', state: doc });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

app.post('/api/admin/verify', requireMongoMiddleware, async (req, res) => {
  try {
    const { operatorName, password } = req.body || {};
    const stateData = await getStoreStateData();
    const opKey = (operatorName || '').trim().toLowerCase();

    if (stateData.bannedAdmins && stateData.bannedAdmins.includes(opKey)) {
      return res.status(403).json({ ok: false, reason: 'BANNED_ADMIN' });
    }
    if (password === ADMIN_PASSWORD) {
      return res.json({ ok: true });
    }
    return res.status(401).json({ ok: false, reason: 'WRONG_PASSWORD' });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post('/api/vault/verify', requireMongoMiddleware, async (req, res) => {
  try {
    const { password } = req.body || {};
    if (password === VAULT_MASTER_PASSWORD) {
      return res.json({ ok: true });
    }
    return res.status(401).json({ ok: false, reason: 'WRONG_VAULT_KEY' });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ============================================================================
// 3. تشغيل السيرفر والاتصال الإلزامي بـ MongoDB Atlas
// ============================================================================
mongoose.connection.on('connected', () => {
  isMongoConnected = true;
  lastMongoError = null;
  console.log('✅ Connected successfully to MongoDB Atlas! (قاعدة البيانات متصلة وتعمل بنجاح)');
});

mongoose.connection.on('disconnected', () => {
  isMongoConnected = false;
  lastMongoError = 'انقطع الاتصال بقاعدة بيانات MongoDB Atlas';
  console.warn('⚠️ MongoDB Atlas Disconnected!');
});

mongoose.connection.on('error', (err) => {
  isMongoConnected = false;
  lastMongoError = err.message;
  console.error('❌ MongoDB Atlas Error:', err.message);
});

const server = app.listen(PORT, () => {
  console.log('============================================================');
  console.log(`🚀 NARMC Store Server is running on: http://localhost:${PORT}`);
  console.log('============================================================');
});

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`⚠️ المنفذ ${PORT} مشغول حالياً بسيرفر قديم بالخلفية! اكتب بالأوامر: taskkill /F /IM node.exe ثم أعد التشغيل.`);
    process.exit(1);
  }
});

if (!MONGODB_URI || MONGODB_URI.includes('<password>') || MONGODB_URI.includes('xxxxx')) {
  lastMongoError = 'رابط MONGODB_URI غير موجود أو غير مكتمل في ملف .env';
  console.error('❌ خطأ: لم يتم وضع رابط MONGODB_URI صحيح في ملف .env! لن يعمل تسجيل الدخول في الموقع حتى يتم وضع الرابط الصحيح.');
} else {
  console.log('⏳ جاري الاتصال بـ MongoDB Atlas...');
  mongoose
    .connect(MONGODB_URI, { serverSelectionTimeoutMS: 12000, family: 4 })
    .then(async () => {
      isMongoConnected = true;
      lastMongoError = null;
      await getStoreStateData();
      console.log('📦 تم تهيئة قاعدة البيانات (narmc_store -> storestates) بنجاح!');
    })
    .catch((err) => {
      isMongoConnected = false;
      lastMongoError = err.message;
      console.error('❌ فشل الاتصال بـ MongoDB Atlas:', err.message);
      console.error('💡 تأكد من: 1) صحة اسم المستخدم وكلمة المرور في .env  2) إضافة 0.0.0.0/0 في قسم Network Access داخل موقع MongoDB Atlas.');
    });
}
