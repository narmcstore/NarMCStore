/**
 * ============================================================================
 * NARMC NETWORK OFFICIAL STORE - STRICT MONGODB ATLAS SERVER (server.js)
 * لا يعمل المتجر ولا يقبل تسجيل الدخول إلا إذا كان رابط MongoDB Atlas صحيحاً ومتصلاً!
 * يتضمن حلاً تلقائياً لمشكلة Windows DNS (querySrv ECONNREFUSED) عبر Google/Cloudflare DNS + DoH
 * ============================================================================
 */
try { require('dotenv').config(); } catch (_) {}
const dns = require('dns');
const https = require('https');
const net = require('net');
const crypto = require('crypto');
const fs = require('fs');

try {
  if (typeof dns.setDefaultResultOrder === 'function') {
    dns.setDefaultResultOrder('ipv4first');
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
    try {
      dns.setServers(['8.8.8.8', '1.1.1.1', '8.8.4.4', '1.0.0.1']);
      if (dns.promises && typeof dns.promises.setServers === 'function') {
        dns.promises.setServers(['8.8.8.8', '1.1.1.1', '8.8.4.4', '1.0.0.1']);
      }
      return await origResolveSrv(hostname);
    } catch (_) {}
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

const DEFAULT_MONGODB_URI = 'mongodb+srv://narmcstore_db_user:Qq!!Ww""Ee££Rr$$ASDFGHJKL!@cluster0.7jltknf.mongodb.net/narmc_store?retryWrites=true&w=majority';
const RAW_MONGODB_URI = (process.env.MONGODB_URI || DEFAULT_MONGODB_URI).trim();
const MONGODB_URI = normalizeMongoUri(RAW_MONGODB_URI);

app.use(cors());
app.use(express.json({ limit: '15mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(__dirname));

let isMongoConnected = false;
let lastMongoError = 'جاري الاتصال بقاعدة بيانات MongoDB Atlas...';
let mongoConnectPromise = null;

function isMongoReady() {
  return mongoose.connection.readyState === 1;
}

async function connectToMongoDB() {
  if (mongoose.connection.readyState === 1) {
    isMongoConnected = true;
    lastMongoError = null;
    return true;
  }
  if (mongoConnectPromise) {
    return mongoConnectPromise;
  }
  mongoConnectPromise = mongoose
    .connect(MONGODB_URI, { serverSelectionTimeoutMS: 12000, family: 4 })
    .then(async () => {
      isMongoConnected = true;
      lastMongoError = null;
      await getStoreStateData().catch(() => {});
      console.log('📦 تم الاتصال وتهيئة قاعدة البيانات (narmc_store -> storestates) بنجاح!');
      mongoConnectPromise = null;
      return true;
    })
    .catch((err) => {
      isMongoConnected = false;
      lastMongoError = err.message;
      console.error('❌ فشل الاتصال بـ MongoDB Atlas:', err.message);
      mongoConnectPromise = null;
      return false;
    });
  return mongoConnectPromise;
}

// ============================================================================
// 1. مخطط قاعدة بيانات MongoDB Atlas (Mongoose Schema)
// ============================================================================
const StoreStateSchema = new mongoose.Schema(
  {
    singletonId: { type: String, default: 'NARMC_MAIN_STATE', unique: true },
    playerCredits: { type: Object, default: {} },
    activeSessions: { type: Object, default: {} },
    registeredAccounts: { type: Object, default: {} },
    playerGifts: { type: Object, default: {} },
    discordLinks: { type: Object, default: {} },
    discordInviteUrl: { type: String, default: 'https://discord.gg/narmc' },
    discordOAuthConfig: { type: Object, default: { clientId: '', clientSecret: '', botToken: '', guildId: '' } },
    paymentAccounts: {
      type: Object,
      default: {
        asiacell: '07728888950',
        mastercard: '4980256806'
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
  { timestamps: true, minimize: false, versionKey: false }
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

        if (doc.paymentAccounts && typeof doc.paymentAccounts === 'object') {
      const pa = { ...doc.paymentAccounts };
      let paChanged = false;
      if (pa.asiacell === '0770 123 4567' || !pa.asiacell) {
        pa.asiacell = '07728888950';
        paChanged = true;
      }
      if (pa.mastercard === '5214 8890 3412 7765' || !pa.mastercard) {
        pa.mastercard = '4980256806';
        paChanged = true;
      }
      if (paChanged) {
        doc.paymentAccounts = pa;
        doc.markModified('paymentAccounts');
        dirty = true;
      }
    }
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
    'registeredAccounts',
    'playerGifts',
    'discordLinks',
    'discordInviteUrl',
    'discordOAuthConfig',
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

  const updateFields = {};
  for (const key of allowedFields) {
    if (payload[key] !== undefined) {
      updateFields[key] = payload[key];
    }
  }

  const doc = await StoreState.findOneAndUpdate(
    { singletonId: 'NARMC_MAIN_STATE' },
    { $set: updateFields },
    { new: true, upsert: true, setDefaultsOnInsert: true }
  );
  return doc;
}

async function requireMongoMiddleware(req, res, next) {
  if (!isMongoReady()) {
    await connectToMongoDB();
  }
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
    const cfg = await getEffectiveDiscordConfig();
    const stateObj = stateData.toObject ? stateData.toObject() : { ...stateData };
    stateObj.oauthConfigured = Boolean(cfg.clientId);
    res.json({ ok: true, mode: 'mongodb', oauthConfigured: Boolean(cfg.clientId), state: stateObj });
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

// دالة إرسال رسالة خاصة (DM) للاعب عبر بوت الديسكورد NarMCStore Bot باستخدام الـ Discord ID حصراً
async function sendDiscordDMByUserId(discordUserId, embedPayload, plainContent = '') {
  const botToken = (process.env.DISCORD_BOT_TOKEN || '').trim();
  const cleanId = String(discordUserId || '').replace(/[^0-9]/g, '');
  if (!botToken || !cleanId) {
    return { ok: false, skipped: true, reason: 'MISSING_BOT_TOKEN_OR_DISCORD_ID' };
  }
  try {
    // 1. فتح قناة خاص (DM Channel) مع اللاعب عن طريق الـ Discord ID
    const dmRes = await fetch('https://discord.com/api/v10/users/@me/channels', {
      method: 'POST',
      headers: {
        Authorization: `Bot ${botToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ recipient_id: cleanId })
    });
    const dmData = await dmRes.json().catch(() => ({}));
    if (!dmRes.ok || !dmData.id) {
      return { ok: false, error: dmData.message || 'CANNOT_OPEN_DM' };
    }

    // 2. إرسال الرسالة أو كود التحقق من بوت NarMCStore Bot إلى خاص اللاعب
    const msgBody = {};
    if (plainContent) msgBody.content = plainContent;
    if (embedPayload) msgBody.embeds = [embedPayload];

    const msgRes = await fetch(`https://discord.com/api/v10/channels/${dmData.id}/messages`, {
      method: 'POST',
      headers: {
        Authorization: `Bot ${botToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(msgBody)
    });
    return { ok: msgRes.ok, status: msgRes.status };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

const pendingVerifyCodes = {}; // { [playerKey]: { code: '123456', expiresAt: number } }

// مسار تسجيل دخول اللاعب مع حماية ملكية الحساب وقفل الجلسات والتحقق عبر NarMCStore Bot أو High Staff Panel
app.post('/api/player/login', requireMongoMiddleware, async (req, res) => {
  try {
    const rawUsername = (req.body && req.body.username) ? String(req.body.username).trim() : '';
    const previousUsername = (req.body && req.body.previousUsername) ? String(req.body.previousUsername).trim() : '';
    const clientToken = (req.body && req.body.clientToken) ? String(req.body.clientToken).trim() : '';
    const forceStaffLogin = Boolean(req.body && req.body.forceStaffLogin);

    if (!rawUsername) {
      return res.status(400).json({ ok: false, reason: 'EMPTY_USERNAME', error: 'يرجى إدخال اسم اللاعب.' });
    }

    const key = rawUsername.toLowerCase();
    const doc = await getStoreStateData();

    if (Array.isArray(doc.bannedPlayers) && doc.bannedPlayers.map(p => String(p).toLowerCase()).includes(key)) {
      return res.status(403).json({ ok: false, reason: 'BANNED_PLAYER' });
    }

    const sessions = { ...(doc.activeSessions || {}) };
    const regAccounts = { ...(doc.registeredAccounts || {}) };
    const existingAcc = regAccounts[key];
    const isCurrentlyOnline = Boolean(sessions[key]);

    // إذا كان اللاعب يغير اسمه من حساب آخر مفتوح في نفس المتصفح، نغلق الجلسة السابقة أولاً
    if (previousUsername && previousUsername.toLowerCase() !== key) {
      const prevKey = previousUsername.toLowerCase();
      delete sessions[prevKey];
      if (regAccounts[prevKey]) {
        regAccounts[prevKey] = { ...regAccounts[prevKey], online: false };
      }
    }

    if (existingAcc && !forceStaffLogin) {
      // 1) إذا كان الحساب متصلاً ومفتوحاً حالياً من شخص آخر (ولا يملك توكن الجلسة الحالية)
      if (isCurrentlyOnline && (!clientToken || existingAcc.sessionToken !== clientToken)) {
        return res.status(403).json({
          ok: false,
          reason: 'ACCOUNT_ALREADY_ONLINE',
          hasDiscordLinked: Boolean(existingAcc.discordId),
          discordTag: existingAcc.discordTag || null
        });
      }

      // 2) حتى لو لم يكن أحد متصلاً حالياً، بما أن الحساب تم إنشاؤه مسبقاً، لا يمكن الدخول إليه إلا بتفويض من High Staff Panel أو التحقق عبر الديسكورد
      const isStaffUnlocked = Boolean(existingAcc.unlockedByStaff);
      if (!isStaffUnlocked) {
        return res.status(403).json({
          ok: false,
          reason: 'ACCOUNT_REGISTERED_LOCKED',
          hasDiscordLinked: Boolean(existingAcc.discordId),
          discordTag: existingAcc.discordTag || null,
          discordId: existingAcc.discordId || null
        });
      }
    }

    // إنشاء توكن جلسة جديد وتفعيل الحساب
    const newSessionToken = crypto.randomBytes(16).toString('hex');
    const discordInfo = (doc.discordLinks && doc.discordLinks[key]) || (existingAcc && existingAcc.discordId ? {
      discordId: existingAcc.discordId,
      discordTag: existingAcc.discordTag,
      avatar: existingAcc.avatar
    } : null);

    regAccounts[key] = {
      username: existingAcc ? existingAcc.username : rawUsername,
      createdAt: existingAcc ? existingAcc.createdAt : new Date().toISOString().replace('T', ' ').slice(0, 19),
      lastLoginAt: new Date().toISOString().replace('T', ' ').slice(0, 19),
      online: true,
      unlockedByStaff: false, // يُستهلك التفويض بمجرد الدخول
      sessionToken: newSessionToken,
      discordId: discordInfo ? discordInfo.discordId : null,
      discordTag: discordInfo ? discordInfo.discordTag : null,
      avatar: discordInfo ? discordInfo.avatar : null
    };

    sessions[key] = true;
    doc.activeSessions = sessions;
    doc.registeredAccounts = regAccounts;
    doc.markModified('activeSessions');
    doc.markModified('registeredAccounts');

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
      username: regAccounts[key].username,
      credit: credits[key],
      sessionToken: newSessionToken,
      isNewAccount: !existingAcc,
      discordLinked: discordInfo || null,
      oauthConfigured: Boolean((process.env.DISCORD_CLIENT_ID || '').trim()),
      state: doc
    });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

// إرسال كود تحقق 6 أرقام عبر بوت NarMCStore Bot إلى خاص اللاعب في الديسكورد (باستخدام الـ Discord ID حصراً) لأي عملية مهمة
app.post('/api/player/send-verify-code', requireMongoMiddleware, async (req, res) => {
  try {
    const rawUsername = String((req.body && req.body.username) || '').trim();
    const actionType = String((req.body && req.body.actionType) || 'LOGIN').trim();
    const actionDescAr = String((req.body && req.body.actionDescAr) || 'تأكيد العملية في المتجر').trim();
    const actionDescEn = String((req.body && req.body.actionDescEn) || 'Confirm Store Action').trim();
    const key = rawUsername.toLowerCase();
    if (!key) return res.status(400).json({ ok: false, error: 'Missing username' });

    const doc = await getStoreStateData();
    const acc = (doc.registeredAccounts && doc.registeredAccounts[key]) || null;
    const link = (doc.discordLinks && doc.discordLinks[key]) || null;
    const discordId = (acc && acc.discordId) || (link && link.discordId) || null;

    if (!discordId) {
      return res.status(400).json({
        ok: false,
        reason: 'NO_DISCORD_ID_LINKED',
        error: 'هذا الحساب غير مربوط بآيدي ديسكورد بعد. يرجى ربط الديسكورد عبر نافذة Authorize أولاً.'
      });
    }

    const code = String(Math.floor(100000 + Math.random() * 900000));
    pendingVerifyCodes[key] = {
      code,
      discordId,
      actionType,
      expiresAt: Date.now() + 10 * 60 * 1000
    };

    const dmResult = await sendDiscordDMByUserId(discordId, {
      title: '🛡️ طلب تحقق أمني (Verify) - NarMCStore Bot',
      description: `مرحباً **${rawUsername}**!
تم طلب تنفيذ عملية مهمة على حسابك في متجر **NARMC.XYZ**:

📌 **نوع العملية:** ${actionDescAr} (${actionDescEn})

🔢 **كود التحقق الخاص بك (Verify Code):**
# \`${code}\`

⚠️ أدخل هذا الكود في الموقع لإتمام العملية. إذا لم تكن أنت من طلب ذلك، فلا تشارك الكود مع أي شخص وسيبقى حسابك وربطك محمياً بالكامل.`,
      color: 0xf97316,
      footer: { text: `NarMCStore Bot • Sent to Discord ID: ${discordId}` },
      timestamp: new Date().toISOString()
    });

    if (!dmResult.ok) {
      return res.status(400).json({
        ok: false,
        reason: 'DM_SEND_FAILED',
        error: 'تعذر إرسال رسالة التحقق بالخاص عبر NarMCStore Bot (تأكد من وضع DISCORD_BOT_TOKEN في .env وأن خاصك مفتوح للبوت).'
      });
    }

    return res.json({ ok: true, discordId, actionType });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

// التحقق من كود الـ 6 أرقام لأي عملية حساسة (تسجيل خروج / فك ربط الديسكورد / شراء / إهداء / شحن كردت / تغيير حساب)
app.post('/api/player/verify-action-code', requireMongoMiddleware, async (req, res) => {
  try {
    const rawUsername = String((req.body && req.body.username) || '').trim();
    const code = String((req.body && req.body.code) || '').trim();
    const actionType = String((req.body && req.body.actionType) || '').trim();
    const key = rawUsername.toLowerCase();

    const record = pendingVerifyCodes[key];
    if (!record || record.expiresAt < Date.now() || record.code !== code) {
      return res.status(400).json({ ok: false, reason: 'INVALID_CODE' });
    }

    delete pendingVerifyCodes[key];
    const doc = await getStoreStateData();

    // إذا كانت العملية هي تسجيل الخروج وفك ربط الديسكورد من الموقع (LOGOUT_UNLINK)
    if (actionType === 'LOGOUT_UNLINK') {
      const sessions = { ...(doc.activeSessions || {}) };
      const regAccounts = { ...(doc.registeredAccounts || {}) };
      const links = { ...(doc.discordLinks || {}) };

      delete sessions[key];
      delete links[key];
      if (regAccounts[key]) {
        regAccounts[key] = {
          ...regAccounts[key],
          online: false,
          unlockedByStaff: false,
          sessionToken: '',
          discordId: null,
          discordTag: null
        };
      }
      doc.activeSessions = sessions;
      doc.registeredAccounts = regAccounts;
      doc.discordLinks = links;
      doc.markModified('activeSessions');
      doc.markModified('registeredAccounts');
      doc.markModified('discordLinks');
      await doc.save();

      if (record.discordId) {
        sendDiscordDMByUserId(record.discordId, {
          title: '🚪 تم تأكيد تسجيل الخروج وفك ربط الديسكورد - NarMCStore Bot',
          description: `تم التحقق من الكود بنجاح وتم تسجيل خروج الحساب **${rawUsername}** وفك ربط الديسكورد من المتجر بناءً على طلبك.`,
          color: 0xef4444,
          timestamp: new Date().toISOString()
        }).catch(() => {});
      }

      return res.json({ ok: true, actionType: 'LOGOUT_UNLINK', state: doc });
    }

    return res.json({ ok: true, actionType, verified: true, state: doc });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

// التحقق من الكود المرسل عبر NarMCStore Bot وفتح الحساب
app.post('/api/player/verify-code', requireMongoMiddleware, async (req, res) => {
  try {
    const rawUsername = String((req.body && req.body.username) || '').trim();
    const code = String((req.body && req.body.code) || '').trim();
    const key = rawUsername.toLowerCase();

    const record = pendingVerifyCodes[key];
    if (!record || record.expiresAt < Date.now() || record.code !== code) {
      return res.status(400).json({ ok: false, reason: 'INVALID_CODE' });
    }

    delete pendingVerifyCodes[key];
    const doc = await getStoreStateData();
    const regAccounts = { ...(doc.registeredAccounts || {}) };
    const sessions = { ...(doc.activeSessions || {}) };
    const newSessionToken = crypto.randomBytes(16).toString('hex');

    regAccounts[key] = {
      ...(regAccounts[key] || { username: rawUsername, createdAt: new Date().toISOString().replace('T', ' ').slice(0, 19) }),
      online: true,
      unlockedByStaff: false,
      sessionToken: newSessionToken,
      lastLoginAt: new Date().toISOString().replace('T', ' ').slice(0, 19)
    };
    sessions[key] = true;

    doc.registeredAccounts = regAccounts;
    doc.activeSessions = sessions;
    doc.markModified('registeredAccounts');
    doc.markModified('activeSessions');
    await doc.save();

    const credits = doc.playerCredits || {};
    return res.json({
      ok: true,
      username: regAccounts[key].username,
      credit: typeof credits[key] === 'number' ? credits[key] : 0,
      sessionToken: newSessionToken,
      state: doc
    });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

// ربط وتوثيق حساب الديسكورد (Authorize) مع الحساب وحفظ الـ Discord ID
app.post('/api/player/discord-authorize-link', requireMongoMiddleware, async (req, res) => {
  try {
    const rawUsername = String((req.body && req.body.username) || '').trim();
    const discordId = String((req.body && req.body.discordId) || '').replace(/[^0-9]/g, '');
    const discordTag = String((req.body && req.body.discordTag) || '').trim();
    const key = rawUsername.toLowerCase();

    if (!rawUsername || !discordId) {
      return res.status(400).json({ ok: false, error: 'Missing username or Discord ID' });
    }

    const doc = await getStoreStateData();
    const regAccounts = { ...(doc.registeredAccounts || {}) };
    const links = { ...(doc.discordLinks || {}) };
    const sessions = { ...(doc.activeSessions || {}) };

    // إذا كان الحساب مسجلاً مسبقاً بآيدي ديسكورد مختلف، نمنع تغييره إلا إذا كان مطابقاً لآيدي المالك
    if (regAccounts[key] && regAccounts[key].discordId && regAccounts[key].discordId !== discordId) {
      return res.status(403).json({
        ok: false,
        reason: 'DISCORD_ID_MISMATCH',
        error: 'آيدي الديسكورد هذا لا يطابق آيدي الديسكورد المربوط بهذا الحساب!'
      });
    }

    const newSessionToken = crypto.randomBytes(16).toString('hex');
    links[key] = {
      discordId,
      discordTag: discordTag || `ID:${discordId}`,
      linkedAt: new Date().toISOString()
    };

    regAccounts[key] = {
      ...(regAccounts[key] || { username: rawUsername, createdAt: new Date().toISOString().replace('T', ' ').slice(0, 19) }),
      online: true,
      unlockedByStaff: false,
      sessionToken: newSessionToken,
      discordId,
      discordTag: discordTag || `ID:${discordId}`,
      lastLoginAt: new Date().toISOString().replace('T', ' ').slice(0, 19)
    };
    sessions[key] = true;

    const credits = { ...(doc.playerCredits || {}) };
    if (typeof credits[key] !== 'number') credits[key] = 0;

    doc.discordLinks = links;
    doc.registeredAccounts = regAccounts;
    doc.activeSessions = sessions;
    doc.playerCredits = credits;
    doc.markModified('discordLinks');
    doc.markModified('registeredAccounts');
    doc.markModified('activeSessions');
    doc.markModified('playerCredits');
    await doc.save();

    // إرسال رسالة تأكيد بالخاص عبر NarMCStore Bot إلى الـ Discord ID
    sendDiscordDMByUserId(discordId, {
      title: '✅ تم ربط وتوثيق حسابك في متجر NARMC الرسمي!',
      description: `مرحباً بك **${rawUsername}**!
تم ربط حسابك في اللعبة مع حسابك في الديسكورد (\`${discordId}\`) عبر **NarMCStore Bot** بنجاح.

🛡️ حسابك الآن محمي بالكامل، وستصلك إشعارات الشراء والرتب تلقائياً على هذا الحساب.`,
      color: 0x10b981,
      footer: { text: `NarMCStore Bot • Discord ID: ${discordId}` },
      timestamp: new Date().toISOString()
    }).catch(() => {});

    return res.json({
      ok: true,
      username: regAccounts[key].username,
      credit: credits[key],
      sessionToken: newSessionToken,
      discordId,
      discordTag: links[key].discordTag,
      state: doc
    });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

// تحكم الإدارة العليا (High Staff Panel / Super Vault) بالحسابات المسجلة (منح صلاحية دخول / إخراج / حذف القفل)
app.post('/api/vault/account-control', requireMongoMiddleware, async (req, res) => {
  try {
    const { action, targetUsername } = req.body || {};
    const raw = String(targetUsername || '').trim();
    const key = raw.toLowerCase();
    if (!key) return res.status(400).json({ ok: false, error: 'Missing targetUsername' });

    const doc = await getStoreStateData();
    const regAccounts = { ...(doc.registeredAccounts || {}) };
    const sessions = { ...(doc.activeSessions || {}) };
    const links = { ...(doc.discordLinks || {}) };

    if (action === 'grant_access') {
      // السماح بالدخول للحساب في المرة القادمة وفك الجلسة الحالية
      sessions[key] = false;
      delete sessions[key];
      regAccounts[key] = {
        ...(regAccounts[key] || { username: raw, createdAt: new Date().toISOString().replace('T', ' ').slice(0, 19) }),
        online: false,
        unlockedByStaff: true
      };
    } else if (action === 'force_logout') {
      sessions[key] = false;
      delete sessions[key];
      if (regAccounts[key]) {
        regAccounts[key] = { ...regAccounts[key], online: false, sessionToken: '' };
      }
    } else if (action === 'delete_lock') {
      delete sessions[key];
      delete regAccounts[key];
      delete links[key];
    }

    doc.registeredAccounts = regAccounts;
    doc.activeSessions = sessions;
    doc.discordLinks = links;
    doc.markModified('registeredAccounts');
    doc.markModified('activeSessions');
    doc.markModified('discordLinks');
    await doc.save();

    return res.json({ ok: true, state: doc });
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
      const regAccounts = { ...(doc.registeredAccounts || {}) };
      delete sessions[key];
      if (regAccounts[key]) {
        // يبقى الحساب مسجلاً ومقفلاً بعد الخروج بحيث لا يدخل إليه غير صاحبه أو بتفويض الإدارة العليا
        regAccounts[key] = { ...regAccounts[key], online: false, unlockedByStaff: false };
        doc.registeredAccounts = regAccounts;
        doc.markModified('registeredAccounts');
      }
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


// ============================================================================
// 2.5 أنظمة الربط المباشر: Minecraft RCON + Discord Authorize + Tebex Webhook
// ============================================================================
function sendMinecraftRconCommand(command) {
  return new Promise((resolve) => {
    const host = (process.env.MC_RCON_HOST || '').trim();
    const port = parseInt(process.env.MC_RCON_PORT || '25575', 10);
    const password = (process.env.MC_RCON_PASSWORD || '').trim();

    if (!host || !password) {
      return resolve({ ok: false, skipped: true, reason: 'RCON_NOT_CONFIGURED' });
    }

    const socket = new net.Socket();
    let authenticated = false;
    let resolved = false;

    const finish = (result) => {
      if (!resolved) {
        resolved = true;
        try { socket.destroy(); } catch (_) {}
        resolve(result);
      }
    };

    socket.setTimeout(6000);
    socket.on('timeout', () => finish({ ok: false, error: 'RCON timeout' }));
    socket.on('error', (err) => finish({ ok: false, error: err.message }));

    function makePacket(reqId, type, payloadStr) {
      const payloadBuf = Buffer.from(payloadStr, 'utf8');
      const length = 4 + 4 + payloadBuf.length + 2;
      const buf = Buffer.alloc(4 + length);
      buf.writeInt32LE(length, 0);
      buf.writeInt32LE(reqId, 4);
      buf.writeInt32LE(type, 8);
      payloadBuf.copy(buf, 12);
      buf.writeInt16LE(0, 12 + payloadBuf.length);
      return buf;
    }

    socket.connect(port, host, () => {
      socket.write(makePacket(1, 3, password));
    });

    socket.on('data', (data) => {
      if (data.length < 12) return;
      const reqId = data.readInt32LE(4);
      if (!authenticated) {
        if (reqId === -1) {
          return finish({ ok: false, error: 'كلمة مرور RCON غير صحيحة' });
        }
        authenticated = true;
        socket.write(makePacket(2, 2, command));
      } else {
        const respBody = data.toString('utf8', 12, Math.max(12, data.length - 2));
        return finish({ ok: true, response: respBody });
      }
    });
  });
}

function buildMinecraftCommandsForItem(player, item) {
  const cmds = [];
  const id = String(item.id || '').toLowerCase();
  const qty = Math.max(1, parseInt(item.qty || 1, 10));

  if (id.startsWith('rank-')) {
    const rankSlug = id.replace('rank-', '');
    for (let i = 0; i < qty; i++) {
      cmds.push(`lp user ${player} parent add ${rankSlug}`);
    }
    cmds.push(`say §6[NARMC Store] §e${player} §aاشترى رتبة §6${item.name}§a من المتجر الرسمي!`);
  } else if (id.startsWith('key-')) {
    const keySlug = id.replace('key-', '');
    cmds.push(`excellentcrates key give ${player} ${keySlug} ${qty}`);
    cmds.push(`crates givekey ${player} ${keySlug} ${qty}`);
  } else if (id.startsWith('kit-')) {
    const kitSlug = id.replace('kit-', '');
    cmds.push(`lp user ${player} permission set essentials.kits.${kitSlug} true`);
    cmds.push(`kit ${kitSlug} ${player}`);
  }
  return cmds;
}

async function assignDiscordRoleForRank(discordUserId, rankId) {
  const botToken = (process.env.DISCORD_BOT_TOKEN || '').trim();
  const guildId = (process.env.DISCORD_GUILD_ID || '').trim();
  if (!botToken || !guildId || !discordUserId) {
    return { ok: false, skipped: true };
  }

  const envKey = 'DISCORD_ROLE_' + String(rankId || '').toUpperCase().replace(/[^A-Z0-9]/g, '_');
  const roleId = (process.env[envKey] || '').trim();
  if (!roleId) {
    return { ok: false, skipped: true, reason: `Missing ${envKey} in .env` };
  }

  try {
    const url = `https://discord.com/api/v10/guilds/${guildId}/members/${discordUserId}/roles/${roleId}`;
    const res = await fetch(url, {
      method: 'PUT',
      headers: {
        Authorization: `Bot ${botToken}`,
        'Content-Type': 'application/json'
      }
    });
    return { ok: res.ok, status: res.status };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}


// دالة قراءة إعدادات الديسكورد من قاعدة البيانات أو ملف .env
async function getEffectiveDiscordConfig() {
  let dbCfg = {};
  if (isMongoReady()) {
    try {
      const doc = await getStoreStateData();
      dbCfg = (doc && doc.discordOAuthConfig) || {};
    } catch (_) {}
  }
  return {
    clientId: (dbCfg.clientId || process.env.DISCORD_CLIENT_ID || '').trim(),
    clientSecret: (dbCfg.clientSecret || process.env.DISCORD_CLIENT_SECRET || '').trim(),
    botToken: (dbCfg.botToken || process.env.DISCORD_BOT_TOKEN || '').trim(),
    guildId: (dbCfg.guildId || process.env.DISCORD_GUILD_ID || '').trim(),
    redirectUri: (dbCfg.redirectUri || process.env.DISCORD_REDIRECT_URI || '').trim()
  };
}

// مسار حفظ إعدادات Discord OAuth2 وبوت الديسكورد من الخزنة السرية العليا
app.post('/api/vault/discord-config', requireMongoMiddleware, async (req, res) => {
  try {
    const { clientId, clientSecret, botToken, guildId, redirectUri } = req.body || {};
    const doc = await getStoreStateData();
    const cur = (doc && doc.discordOAuthConfig) || {};
    doc.discordOAuthConfig = {
      clientId: clientId !== undefined ? String(clientId).trim() : (cur.clientId || ''),
      clientSecret: clientSecret !== undefined && clientSecret !== '' ? String(clientSecret).trim() : (cur.clientSecret || ''),
      botToken: botToken !== undefined && botToken !== '' ? String(botToken).trim() : (cur.botToken || ''),
      guildId: guildId !== undefined ? String(guildId).trim() : (cur.guildId || ''),
      redirectUri: redirectUri !== undefined ? String(redirectUri).trim() : (cur.redirectUri || '')
    };
    if (doc.discordOAuthConfig.clientId) process.env.DISCORD_CLIENT_ID = doc.discordOAuthConfig.clientId;
    if (doc.discordOAuthConfig.clientSecret) process.env.DISCORD_CLIENT_SECRET = doc.discordOAuthConfig.clientSecret;
    if (doc.discordOAuthConfig.botToken) process.env.DISCORD_BOT_TOKEN = doc.discordOAuthConfig.botToken;
    if (doc.discordOAuthConfig.guildId) process.env.DISCORD_GUILD_ID = doc.discordOAuthConfig.guildId;
    doc.markModified('discordOAuthConfig');
    await doc.save();
    return res.json({ ok: true, oauthConfigured: Boolean(doc.discordOAuthConfig.clientId) });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

// مسار فحص عدد اللاعبين المتصلين في سيرفر ماينكرافت بشكل لحظي بدون كاش (Real-Time Uncached Ping)
app.get('/api/mc-status', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');

  const rawIp = String(req.query.ip || process.env.MC_SERVER_IP || 'narmc.net').trim();
  const ts = Date.now();

  try {
    const mcRes = await fetch(`https://api.mcstatus.io/v2/status/java/${encodeURIComponent(rawIp)}?_t=${ts}`, {
      headers: { 'Cache-Control': 'no-cache', 'Pragma': 'no-cache' }
    });
    if (mcRes.ok) {
      const mcData = await mcRes.json();
      if (mcData && mcData.online && mcData.players && typeof mcData.players.online === 'number') {
        return res.json({
          ok: true,
          online: true,
          onlinePlayers: mcData.players.online,
          maxPlayers: mcData.players.max || 1000
        });
      }
    }
  } catch (_) {}

  try {
    const fallbackRes = await fetch(`https://api.mcsrvstat.us/3/${encodeURIComponent(rawIp)}`, {
      headers: { 'Cache-Control': 'no-cache' }
    });
    if (fallbackRes.ok) {
      const fbData = await fallbackRes.json();
      if (fbData && fbData.online && fbData.players && typeof fbData.players.online === 'number') {
        return res.json({
          ok: true,
          online: true,
          onlinePlayers: fbData.players.online,
          maxPlayers: fbData.players.max || 1000
        });
      }
    }
  } catch (_) {}

  return res.json({ ok: true, online: false, onlinePlayers: 0, maxPlayers: 1000 });
});

app.get('/api/discord/login', async (req, res) => {
  const player = String(req.query.player || '').trim();
  const cfg = await getEffectiveDiscordConfig();
  const clientId = cfg.clientId;
  const hostUrl = `${req.protocol}://${req.get('host')}`;
  const redirectUri = cfg.redirectUri || `${hostUrl}/api/discord/callback`;

  if (!clientId) {
    return res.redirect(`/?open_discord_oauth_modal=1&player=${encodeURIComponent(player)}`);
  }

  const stateParam = Buffer.from(JSON.stringify({ player })).toString('base64url');
  const authUrl = `https://discord.com/oauth2/authorize?response_type=code&scope=identify&client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${stateParam}`;
  res.redirect(authUrl);
});

app.get('/api/discord/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code) return res.redirect('/?discord_error=cancelled');

    let player = '';
    try {
      const parsed = JSON.parse(Buffer.from(String(state || ''), 'base64url').toString('utf8'));
      player = String(parsed.player || '').trim();
    } catch (_) {}

    const cfg = await getEffectiveDiscordConfig();
    const clientId = cfg.clientId;
    const clientSecret = cfg.clientSecret;
    const hostUrl = `${req.protocol}://${req.get('host')}`;
    const redirectUri = cfg.redirectUri || `${hostUrl}/api/discord/callback`;

    const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: clientId,
        client_secret: clientSecret,
        grant_type: 'authorization_code',
        code: String(code),
        redirect_uri: redirectUri
      })
    });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) {
      return res.redirect('/?discord_error=token_failed');
    }

    const userRes = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });
    const userData = await userRes.json();

    const botToken = (process.env.DISCORD_BOT_TOKEN || '').trim();
    const guildId = (process.env.DISCORD_GUILD_ID || '').trim();
    if (botToken && guildId && userData.id) {
      try {
        await fetch(`https://discord.com/api/v10/guilds/${guildId}/members/${userData.id}`, {
          method: 'PUT',
          headers: {
            Authorization: `Bot ${botToken}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ access_token: tokenData.access_token })
        });
      } catch (_) {}
    }

    if (player && userData.id && isMongoReady()) {
      const doc = await getStoreStateData();
      const pKey = player.toLowerCase();
      const links = { ...(doc.discordLinks || {}) };
      const regAccounts = { ...(doc.registeredAccounts || {}) };
      const sessions = { ...(doc.activeSessions || {}) };

      if (regAccounts[pKey] && regAccounts[pKey].discordId && regAccounts[pKey].discordId !== userData.id) {
        return res.redirect('/?discord_error=id_mismatch');
      }

      const dTagClean = userData.global_name || userData.username || 'DiscordUser';
      links[pKey] = {
        discordId: userData.id,
        discordTag: dTagClean,
        avatar: userData.avatar,
        linkedAt: new Date().toISOString()
      };
      const newSessionToken = crypto.randomBytes(16).toString('hex');
      regAccounts[pKey] = {
        ...(regAccounts[pKey] || { username: player, createdAt: new Date().toISOString().replace('T', ' ').slice(0, 19) }),
        online: true,
        unlockedByStaff: true,
        sessionToken: newSessionToken,
        discordId: userData.id,
        discordTag: dTagClean,
        avatar: userData.avatar,
        lastLoginAt: new Date().toISOString().replace('T', ' ').slice(0, 19)
      };
      sessions[pKey] = true;

      await StoreState.findOneAndUpdate(
        { singletonId: 'NARMC_MAIN_STATE' },
        { $set: { discordLinks: links, registeredAccounts: regAccounts, activeSessions: sessions } },
        { new: true, upsert: true }
      );

      sendDiscordDMByUserId(userData.id, {
        title: '✅ تم التحقق وربط حسابك عبر NarMCStore Bot',
        description: `مرحباً **${player}**!
تم التحقق من هويتك عبر الديسكورد بنجاح (Discord ID: \`${userData.id}\`).
يمكنك الآن الشراء واستلام الرتب والمفاتيح والكتات بشكل فوري!`,
        color: 0x5865f2,
        timestamp: new Date().toISOString()
      }).catch(() => {});
    }

    const dTag = encodeURIComponent(userData.global_name || userData.username || 'DiscordUser');
    res.redirect(`/?discord_linked=1&discord_tag=${dTag}&discord_id=${encodeURIComponent(userData.id || '')}`);
  } catch (err) {
    res.redirect('/?discord_error=server_error');
  }
});

app.get('/api/discord/status', async (req, res) => {
  try {
    const player = String(req.query.player || '').trim().toLowerCase();
    if (!player || !isMongoReady()) return res.json({ ok: true, linked: null });
    const doc = await getStoreStateData();
    const info = (doc.discordLinks && doc.discordLinks[player]) || null;
    res.json({ ok: true, linked: info });
  } catch (err) {
    res.json({ ok: false, linked: null });
  }
});

app.post('/api/fulfill-order', requireMongoMiddleware, async (req, res) => {
  try {
    const { buyer, targetPlayer, player, items, totalPaid, total, isGift } = req.body || {};
    const receiver = String(targetPlayer || buyer || player || '').trim();
    const finalPaid = totalPaid !== undefined ? totalPaid : total;
    if (!receiver || !Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ ok: false, error: 'بيانات الطلب غير مكتملة' });
    }

    const doc = await getStoreStateData();
    const discordInfo = (doc.discordLinks && doc.discordLinks[receiver.toLowerCase()]) || null;

    const rconResults = [];
    const discordResults = [];

    for (const item of items) {
      const cmds = buildMinecraftCommandsForItem(receiver, item);
      for (const cmd of cmds) {
        const r = await sendMinecraftRconCommand(cmd);
        rconResults.push({ cmd, ...r });
      }
      if (String(item.id || '').startsWith('rank-') && discordInfo && discordInfo.discordId) {
        const dRes = await assignDiscordRoleForRank(discordInfo.discordId, item.id);
        discordResults.push({ itemId: item.id, ...dRes });
      }
    }

    const webhookUrl = (process.env.DISCORD_WEBHOOK_URL || '').trim();
    if (webhookUrl) {
      const itemsList = items.map(i => `• **${i.name}** (x${i.qty || 1})`).join('\n');
      fetch(webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          embeds: [{
            title: isGift ? '🎁 هدية جديدة من متجر NARMC' : '🛒 عملية شراء جديدة - NARMC Store',
            color: 0xe03500,
            fields: [
              { name: 'المشتري', value: String(buyer || receiver), inline: true },
              { name: 'المستلم داخل اللعبة', value: receiver, inline: true },
              { name: 'المبلغ المدفوع', value: `$${Number(finalPaid || 0).toFixed(2)}`, inline: true },
              { name: 'حساب الديسكورد المربوط', value: discordInfo ? `${discordInfo.discordTag} (<@${discordInfo.discordId}>)` : 'غير مربوط', inline: false },
              { name: 'الحزم المسلّمة', value: itemsList || '-', inline: false }
            ],
            timestamp: new Date().toISOString()
          }]
        })
      }).catch(() => {});
    }

    if (discordInfo && discordInfo.discordId) {
      const dmItemsList = items.map(i => `• **${i.name}** (x${i.qty || 1})`).join('\n');
      sendDiscordDMByUserId(discordInfo.discordId, {
        title: '🎉 إيصال شراء وتسليم فوري - NarMCStore Bot',
        description: `شكراً لتسوقك في متجر **NARMC.XYZ**!
تم تنفيذ طلبك وإرساله مباشرةً إلى حسابك داخل السيرفر (\`${receiver}\`).`,
        color: 0x10b981,
        fields: [
          { name: '👤 حساب اللاعب', value: receiver, inline: true },
          { name: '💰 الإجمالي المدفوع', value: `$${Number(finalPaid || 0).toFixed(2)}`, inline: true },
          { name: '📦 الحزم المسلّمة', value: dmItemsList || '-', inline: false }
        ],
        footer: { text: `NarMCStore Bot • Delivered to Discord ID: ${discordInfo.discordId}` },
        timestamp: new Date().toISOString()
      }).catch(() => {});
    }

    return res.json({
      ok: true,
      receiver,
      rconDelivered: rconResults.some(r => r.ok),
      discordRoleAssigned: discordResults.some(d => d.ok),
      rconResults,
      discordResults
    });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

app.post('/api/tebex/create-checkout', async (req, res) => {
  try {
    const { username, amount } = req.body || {};
    const cleanUser = String(username || '').trim();
    const numAmount = Math.max(1, parseFloat(amount) || 0);
    const webstoreToken = (process.env.TEBEX_WEBSTORE_IDENTIFIER || '').trim();
    const packageId = parseInt(process.env.TEBEX_CREDIT_PACKAGE_ID || '0', 10);

    if (!cleanUser || !numAmount) {
      return res.status(400).json({ ok: false, error: 'يرجى تسجيل الدخول وتحديد المبلغ أولاً' });
    }
    if (!webstoreToken || !packageId) {
      return res.status(400).json({
        ok: false,
        reason: 'TEBEX_NOT_CONFIGURED',
        error: 'يرجى إضافة TEBEX_WEBSTORE_IDENTIFIER و TEBEX_CREDIT_PACKAGE_ID في إعدادات البيئة (.env / Railway Variables) لتفعيل الدفع المباشر عبر Tebex.'
      });
    }

    const hostUrl = `${req.protocol}://${req.get('host')}`;
    const basketRes = await fetch(`https://headless.tebex.io/api/accounts/${encodeURIComponent(webstoreToken)}/baskets`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: cleanUser,
        complete_url: `${hostUrl}/?tebex_status=success&player=${encodeURIComponent(cleanUser)}&amount=${numAmount}`,
        cancel_url: `${hostUrl}/?tebex_status=cancelled`,
        custom: { username: cleanUser, creditAmount: numAmount }
      })
    });
    const basketData = await basketRes.json().catch(() => ({}));
    const basketIdent = basketData && basketData.data && basketData.data.ident;

    if (!basketRes.ok || !basketIdent) {
      return res.status(400).json({ ok: false, error: 'تعذر إنشاء سلة الدفع في Tebex. تأكد من صحة الكود في Variables.' });
    }

    const addPkgRes = await fetch(`https://headless.tebex.io/api/baskets/${encodeURIComponent(basketIdent)}/packages`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ package_id: packageId, quantity: Math.max(1, Math.round(numAmount)) })
    });
    const addPkgData = await addPkgRes.json().catch(() => ({}));
    const checkoutUrl = addPkgData && addPkgData.data && addPkgData.data.links && addPkgData.data.links.checkout;

    if (!checkoutUrl) {
      return res.status(400).json({ ok: false, error: 'تعذر جلب رابط الدفع من Tebex.' });
    }

    return res.json({ ok: true, checkoutUrl });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

// مسار استقبال إشعارات Tebex الرسمية (يرد تلقائياً على طلب Validate ويضيف الكردت عند الدفع)
async function handleTebexWebhookRequest(req, res) {
  try {
    const body = req.body || {};
    // 1. الرد الفوري على طلب التحقق (Validation Webhook) من موقع Tebex ليتحول للون الأخضر Validated
    if (body.type === 'validation.webhook') {
      return res.status(200).json({ id: body.id });
    }

    // 2. إضافة الكردت تلقائياً لحساب اللاعب عند اكتمال الدفع (payment.completed)
    if (body.type === 'payment.completed' && body.subject) {
      const subj = body.subject;
      const customUser = subj.custom && subj.custom.username;
      const tebexUser = subj.customer && subj.customer.username && subj.customer.username.username;
      const targetPlayer = String(customUser || tebexUser || '').trim();
      const paidAmount = parseFloat(
        (subj.custom && subj.custom.creditAmount) ||
        (subj.price_paid && subj.price_paid.amount) ||
        (subj.price && subj.price.amount) ||
        0
      );

      if (targetPlayer && paidAmount > 0 && isMongoReady()) {
        const doc = await getStoreStateData();
        const key = targetPlayer.toLowerCase();
        const credits = { ...(doc.playerCredits || {}) };
        credits[key] = +((credits[key] || 0) + paidAmount).toFixed(2);

        const orders = Array.isArray(doc.adminOrdersAndTransfers) ? [...doc.adminOrdersAndTransfers] : [];
        orders.unshift({
          id: 'TBX-' + (subj.transaction_id || Math.floor(1000 + Math.random() * 9000)),
          type: 'TOPUP',
          player: targetPlayer,
          amount: +paidAmount.toFixed(2),
          method: 'TEBEX',
          dest: 'Tebex Global Checkout',
          ref: `Tebex TX: ${subj.transaction_id || 'Verified'}`,
          status: 'APPROVED',
          time: new Date().toISOString().replace('T', ' ').slice(0, 19)
        });

        await StoreState.findOneAndUpdate(
          { singletonId: 'NARMC_MAIN_STATE' },
          { $set: { playerCredits: credits, adminOrdersAndTransfers: orders } },
          { new: true, upsert: true }
        );
      }
    }
    return res.status(200).json({ id: body.id });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
}

// يقبل رابط الدومين الصافي مباشرة (مثل https://narmcstore.up.railway.app أو https://narmc.xyz) أو مع /api/tebex/webhook
app.post('/', handleTebexWebhookRequest);
app.post('/api/tebex/webhook', handleTebexWebhookRequest);

app.use((req, res) => {
  const pubIndex = path.join(__dirname, 'public', 'index.html');
  const rootIndex = path.join(__dirname, 'index.html');
  if (fs.existsSync(pubIndex)) {
    return res.sendFile(pubIndex);
  }
  if (fs.existsSync(rootIndex)) {
    return res.sendFile(rootIndex);
  }
  res.status(404).send('index.html not found');
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

console.log('⏳ جاري الاتصال بـ MongoDB Atlas...');
connectToMongoDB();
