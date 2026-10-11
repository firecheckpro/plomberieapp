/* ==========================================================================
   PipePline V2.4 CH — Application de gestion pour plombier
   100% hors ligne / privée / chiffrée
   Fichier : app.js
   ========================================================================== */
'use strict';

/* ==========================================================================
   SERVICE WORKER
   ========================================================================== */
if ('serviceWorker' in navigator && location.protocol !== 'file:') {
  window.addEventListener('load', function() {
    navigator.serviceWorker.register('sw.js').catch(function() {
      var swCode = "self.addEventListener('fetch', function(e) { if (e.request.method !== 'GET') return; e.respondWith(fetch(e.request).catch(function() { return caches.match(e.request); })); });";
      var blob = new Blob([swCode], { type: 'application/javascript' });
      navigator.serviceWorker.register(URL.createObjectURL(blob)).catch(function() {});
    });
  });
}

/* ==========================================================================
   HAPTIC
   ========================================================================== */
function haptic(pattern) {
  if (navigator.vibrate) { try { navigator.vibrate(pattern || 10); } catch(e) {} }
}

/* ==========================================================================
   INDEXEDDB
   ========================================================================== */
var IDB_NAME = 'pipepline_ch_db';
var IDB_VERSION = 2;
var IDB_STORE = 'kv';
var IDB_CRYPTO_STORE = 'crypto';
var idbPromise = null;

function openIDB() {
  if (idbPromise) return idbPromise;
  idbPromise = new Promise(function(resolve, reject) {
    if (!('indexedDB' in window)) { reject(new Error('IndexedDB non supporté')); return; }
    var req = indexedDB.open(IDB_NAME, IDB_VERSION);
    req.onupgradeneeded = function(e) {
      var db = e.target.result;
      if (!db.objectStoreNames.contains(IDB_STORE)) db.createObjectStore(IDB_STORE);
      if (!db.objectStoreNames.contains(IDB_CRYPTO_STORE)) db.createObjectStore(IDB_CRYPTO_STORE);
    };
    req.onsuccess = function(e) { resolve(e.target.result); };
    req.onerror = function(e) { reject(e.target.error); };
  });
  return idbPromise;
}

function idbGet(key, storeName) {
  storeName = storeName || IDB_STORE;
  return openIDB().then(function(db) {
    return new Promise(function(resolve, reject) {
      var tx = db.transaction(storeName, 'readonly');
      var req = tx.objectStore(storeName).get(key);
      req.onsuccess = function() { resolve(req.result); };
      req.onerror = function() { reject(req.error); };
    });
  });
}

function idbSet(key, value, storeName) {
  storeName = storeName || IDB_STORE;
  return openIDB().then(function(db) {
    return new Promise(function(resolve, reject) {
      var tx = db.transaction(storeName, 'readwrite');
      var req = tx.objectStore(storeName).put(value, key);
      req.onsuccess = function() { resolve(); };
      req.onerror = function() { reject(req.error); };
    });
  });
}

function idbRemove(key, storeName) {
  storeName = storeName || IDB_STORE;
  return openIDB().then(function(db) {
    return new Promise(function(resolve, reject) {
      var tx = db.transaction(storeName, 'readwrite');
      var req = tx.objectStore(storeName).delete(key);
      req.onsuccess = function() { resolve(); };
      req.onerror = function() { reject(req.error); };
    });
  });
}

/* ==========================================================================
   CHIFFREMENT AES-GCM (dérivé du PIN via PBKDF2)
   ========================================================================== */
var cryptoKey = null;

function deriveKeyFromPin(pin, salt) {
  var enc = new TextEncoder();
  return crypto.subtle.importKey('raw', enc.encode(pin), { name: 'PBKDF2' }, false, ['deriveKey'])
    .then(function(baseKey) {
      return crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' },
        baseKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
      );
    });
}

function generateSalt() {
  var salt = new Uint8Array(16);
  crypto.getRandomValues(salt);
  return salt;
}

function encryptData(data, key) {
  return new Promise(function(resolve, reject) {
    try {
      var enc = new TextEncoder();
      var iv = new Uint8Array(12);
      crypto.getRandomValues(iv);
      var json = JSON.stringify(data);
      crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, enc.encode(json))
        .then(function(ciphertext) {
          resolve({ iv: Array.from(iv), ciphertext: Array.from(new Uint8Array(ciphertext)) });
        })
        .catch(reject);
    } catch(e) { reject(e); }
  });
}

function decryptData(payload, key) {
  return new Promise(function(resolve, reject) {
    try {
      var iv = new Uint8Array(payload.iv);
      var ciphertext = new Uint8Array(payload.ciphertext);
      crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, ciphertext)
        .then(function(plaintext) {
          var dec = new TextDecoder();
          resolve(JSON.parse(dec.decode(plaintext)));
        })
        .catch(reject);
    } catch(e) { reject(e); }
  });
}

/* Un storage sécurisé : si un PIN est actif, on NE DOIT JAMAIS
   retomber sur localStorage en clair (fuite). On échoue proprement. */
function isPinRequired() {
  return !!(pinMeta && pinMeta.active);
}

function storageGet(key) {
  return idbGet(key).then(function(result) {
    if (result && result.__encrypted) {
      if (!cryptoKey) {
        // Données chiffrées mais pas de clé → on ne peut pas déchiffrer.
        // Ne JAMAIS tenter un fallback localStorage (fuite possible).
        return null;
      }
      return decryptData(result, cryptoKey).catch(function(err) {
        // Déchiffrement raté (mauvais PIN ou corruption) : on propage
        // une erreur explicite au lieu de renvoyer null silencieusement.
        var e = new Error('DECRYPT_FAILED');
        e.cause = err;
        e.key = key;
        throw e;
      });
    }
    return result;
  }).catch(function(err) {
    // Si PIN actif → pas de fallback du tout.
    if (isPinRequired()) {
      if (err && err.message === 'DECRYPT_FAILED') throw err;
      return null;
    }
    // Pas de PIN : fallback localStorage autorisé (mode legacy/non chiffré).
    try {
      var raw = localStorage.getItem(key);
      return raw ? JSON.parse(raw) : null;
    } catch(e) { return null; }
  });
}

function storageSet(key, value) {
  if (cryptoKey && !(value && value.__encrypted)) {
    return encryptData(value, cryptoKey).then(function(payload) {
      payload.__encrypted = true;
      return idbSet(key, payload);
    }).catch(function() {
      // Ne PAS retomber sur idbSet en clair si on a une clé : ça
      // écraserait des données chiffrées par du clair.
      if (isPinRequired()) return false;
      return idbSet(key, value);
    });
  }
  return idbSet(key, value).catch(function() {
    if (isPinRequired()) return false; // pas de fallback clair
    try { localStorage.setItem(key, JSON.stringify(value)); return true; } catch(e) { return false; }
  });
}

function storageRemove(key) {
  return idbRemove(key).catch(function() {
    if (isPinRequired()) return;
    try { localStorage.removeItem(key); } catch(e) {}
  });
}
/* ==========================================================================
   PIN
   ========================================================================== */
var PIN_KEY = 'pipepline_pin_meta';
var SESSION_KEY = 'pipepline_session';
var pinBuffer = '';
var pinMeta = { active: false, salt: null };
var isAuthenticated = false;

function loadPinMeta() {
  return storageGet(PIN_KEY).then(function(m) {
    if (m) pinMeta = m;
    return pinMeta;
  });
}
function savePinMeta() { return storageSet(PIN_KEY, pinMeta); }

function base64ToUint8(b64) {
  var bin = atob(b64);
  var arr = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}
function uint8ToBase64(arr) {
  var bin = '';
  for (var i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
  return btoa(bin);
}

function showPinOverlay() {
  document.getElementById('pinOverlay').classList.add('show');
  pinBuffer = '';
  renderPinDots();
  document.getElementById('pinError').textContent = '';
}
function hidePinOverlay() {
  document.getElementById('pinOverlay').classList.remove('show');
  isAuthenticated = true;
  sessionStorage.setItem(SESSION_KEY, '1');
}
function renderPinDots() {
  var dots = document.querySelectorAll('#pinDisplay .pin-dot');
  dots.forEach(function(d, i) {
    if (i < pinBuffer.length) d.classList.add('filled');
    else d.classList.remove('filled');
  });
}
function handlePinKey(digit) {
  haptic(8);
  if (digit === 'clear') { pinBuffer = ''; renderPinDots(); return; }
  if (digit === 'ok') { validatePin(); return; }
  if (pinBuffer.length < 8) {
    pinBuffer += digit;
    renderPinDots();
    if (pinMeta.pinLength === 4 && pinBuffer.length === 4) {
      setTimeout(validatePin, 200);
    }
  }
}
var pinValidating = false; // anti double-tap

function validatePin() {
  if (pinValidating) return;
  if (pinBuffer.length < 4) {
    document.getElementById('pinError').textContent = 'Code trop court';
    return;
  }
  pinValidating = true;
  var errEl = document.getElementById('pinError');
  errEl.textContent = '';

  var enc = new TextEncoder();
  var pinBytes = enc.encode(pinBuffer);

  crypto.subtle.digest('SHA-256', pinBytes).then(function(hash) {
    var hashB64 = uint8ToBase64(new Uint8Array(hash));
    if (hashB64 !== pinMeta.pinHash) {
      haptic([30, 50, 30]);
      errEl.textContent = 'Code incorrect';
      pinBuffer = '';
      renderPinDots();
      pinValidating = false;
      return null;
    }
    var salt = base64ToUint8(pinMeta.salt);
    return deriveKeyFromPin(pinBuffer, salt);
  }).then(function(key) {
    if (!key) return null; // mauvais PIN déjà géré
    cryptoKey = key;
    // Attendre le chargement AVANT de cacher l'overlay → pas de course.
    return loadFromStorage().then(function(ok) {
      hidePinOverlay();
      renderAll();
      showToast('Bienvenue', 'success');
      return ok;
    });
  }).catch(function(err) {
    console.error('[PIN]', err);
    haptic([30, 50, 30]);
    if (err && err.message === 'DECRYPT_FAILED') {
      errEl.textContent = 'Données illisibles — PIN ou sauvegarde corrompue';
    } else {
      errEl.textContent = 'Erreur de déchiffrement';
    }
    pinBuffer = '';
    renderPinDots();
    cryptoKey = null;
  }).then(function() {
    pinValidating = false;
  });
}
document.getElementById('pinKeypad').addEventListener('click', function(e) {
  var btn = e.target.closest('button[data-pin]');
  if (btn) handlePinKey(btn.dataset.pin);
});
document.addEventListener('keydown', function(e) {
  if (!document.getElementById('pinOverlay').classList.contains('show')) return;
  if (e.key >= '0' && e.key <= '9') handlePinKey(e.key);
  else if (e.key === 'Backspace') handlePinKey('clear');
  else if (e.key === 'Enter') handlePinKey('ok');
});

/* ==========================================================================
   HELPERS GÉNÉRAUX
   ========================================================================== */
function getSwissHolidays(year) {
  var h = {};
  h[year + '-01-01'] = 'Nouvel An';
  h[year + '-08-01'] = 'Fête nationale suisse';
  h[year + '-12-25'] = 'Noël';
  var easter = getEasterDate(year);
  var easterMs = easter.getTime();
  var dayMs = 86400000;
  function iso(ms) { return new Date(ms).toISOString().slice(0, 10); }
  h[iso(easterMs - 2 * dayMs)] = 'Vendredi saint';
  h[iso(easterMs + 1 * dayMs)] = 'Lundi de Pâques';
  h[iso(easterMs + 39 * dayMs)] = 'Ascension';
  h[iso(easterMs + 50 * dayMs)] = 'Lundi de Pentecôte';
  h[year + '-05-01'] = 'Fête du Travail';
  h[year + '-11-01'] = 'Toussaint';
  h[year + '-12-26'] = 'Saint-Étienne';
  return h;
}
var easterCache = {};
function getEasterDate(year) {
  if (easterCache[year]) return easterCache[year];
  var a = year % 19, b = Math.floor(year / 100), c = year % 100;
  var d = Math.floor(b / 4), e = b % 4, f = Math.floor((b + 8) / 25);
  var g = Math.floor((b - f + 1) / 3);
  var hh = (19 * a + b - d - g + 15) % 30;
  var i = Math.floor(c / 4), k = c % 4;
  var l = (32 + 2 * e + 2 * i - hh - k) % 7;
  var m = Math.floor((a + 11 * hh + 22 * l) / 451);
  var month = Math.floor((hh + l - 7 * m + 114) / 31);
  var day = ((hh + l - 7 * m + 114) % 31) + 1;
  var dt = new Date(year, month - 1, day);
  easterCache[year] = dt;
  return dt;
}
var holidayCache = {};
function isHoliday(dateStr) {
  if (!dateStr) return null;
  var year = parseInt(dateStr.slice(0, 4));
  if (!holidayCache[year]) holidayCache[year] = getSwissHolidays(year);
  return holidayCache[year][dateStr] || null;
}

function updateOfflineBadge() {
  var badge = document.getElementById('offlineBadge');
  var text = document.getElementById('offlineText');
  if (navigator.onLine) {
    badge.className = 'offline-badge show';
    text.textContent = 'En ligne - Données locales sécurisées';
    setTimeout(function() { badge.classList.remove('show'); }, 2500);
  } else {
    badge.className = 'offline-badge show offline persistent';
    text.textContent = 'Hors ligne - Fonctionne normalement';
  }
}
window.addEventListener('online', updateOfflineBadge);
window.addEventListener('offline', updateOfflineBadge);
updateOfflineBadge();

/* ==========================================================================
   LIBRAIRIES PDF & QR-FACTURE (inline — plus de dossier lib/)
   ========================================================================== */
var libCache = {};

function loadScript(src) {
  return new Promise(function(resolve, reject) {
    var existing = document.querySelector('script[src="' + src + '"]');
    if (existing) { resolve(); return; }
    var s = document.createElement('script');
    s.src = src;
    s.async = true;
    s.onload = function() { resolve(); };
    s.onerror = function() { reject(new Error('Échec chargement: ' + src)); };
    document.head.appendChild(s);
  });
}

function loadJsPDF() {
  if (libCache.jspdf) return libCache.jspdf;
  libCache.jspdf = new Promise(function(resolve, reject) {
    if (window.jspdf && window.jspdf.jsPDF) { resolve(window.jspdf); return; }
    var localPath = 'lib/jspdf.umd.min.js';
    var cdnPath = 'https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js';
    loadScript(localPath).then(function() {
      if (window.jspdf && window.jspdf.jsPDF) resolve(window.jspdf);
      else throw new Error('jsPDF local indisponible');
    }).catch(function() {
      console.warn('[PipePline] jsPDF local absent, fallback CDN');
      loadScript(cdnPath).then(function() { resolve(window.jspdf); })
        .catch(function() { reject(new Error('jsPDF indisponible (local + CDN)')); });
    });
  });
  return libCache.jspdf;
}

function loadSwissQRBill() {
  if (libCache.qr) return libCache.qr;
  libCache.qr = new Promise(function(resolve, reject) {
    if (window.SwissQRBill && window.SwissQRBill.QRBill) { resolve(window.SwissQRBill); return; }
    var localPath = 'lib/swissqrbill.min.js';
    var cdnPath = 'https://cdn.jsdelivr.net/npm/swissqrbill@4/dist/swissqrbill.min.js';
    loadScript(localPath).then(function() {
      if (window.SwissQRBill && window.SwissQRBill.QRBill) resolve(window.SwissQRBill);
      else throw new Error('SwissQRBill local indisponible');
    }).catch(function() {
      console.warn('[PipePline] SwissQRBill local absent, fallback CDN');
      loadScript(cdnPath).then(function() { resolve(window.SwissQRBill); })
        .catch(function() { reject(new Error('SwissQRBill indisponible (local + CDN)')); });
    });
  });
  return libCache.qr;
}

/* ==========================================================================
   VALIDATION IBAN SUISSE + RÉFÉRENCE QR (inline)
   ========================================================================== */
function isValidSwissIBAN(iban) {
  if (!iban) return false;
  var clean = iban.replace(/\s+/g, '').toUpperCase();
  if (!/^(CH|LI)\d{2}[A-Z0-9]{17}$/.test(clean)) return false;
  var rearranged = clean.slice(4) + clean.slice(0, 4);
  var numeric = '';
  for (var i = 0; i < rearranged.length; i++) {
    var c = rearranged.charCodeAt(i);
    if (c >= 65 && c <= 90) numeric += (c - 55).toString();
    else numeric += rearranged[i];
  }
  var remainder = 0;
  for (var j = 0; j < numeric.length; j += 7) {
    var chunk = remainder + numeric.substr(j, 7);
    remainder = parseInt(chunk, 10) % 97;
  }
  return remainder === 1;
}

function generateQRReference(baseNumber) {
  var base = String(baseNumber).replace(/\D/g, '').slice(0, 26).padStart(26, '0');
  var digits = base.split('').map(Number);
  var table = [0, 9, 4, 6, 8, 2, 7, 1, 3, 5];
  var carry = 0;
  for (var i = 0; i < digits.length - 1; i++) {
    carry = table[(carry + digits[i]) % 10];
  }
  var check = (10 - carry) % 10;
  return base.slice(0, 25) + check;
}

function formatQRReference(ref) {
  var clean = String(ref).replace(/\s+/g, '');
  return clean.replace(/(.{5})/g, '$1 ').trim();
}

/* ==========================================================================
   ÉTAT DE L'APPLICATION
   ========================================================================== */
var APP_VERSION = 'V2.4 CH';
var STORAGE_KEY = 'pipepline_ch_v4';
var SETTINGS_KEY = 'pipepline_ch_settings_v4';
var BACKUP_META_KEY = 'pipepline_ch_backup_meta_v4';
var STORAGE_ALERT_KEY = 'pipepline_ch_storage_alert_v4';
var STOCK_KEY = 'pipepline_ch_stock_v3';
var THEME_KEY = 'pipepline_theme';
var TAB_NEWS_KEY = 'pipepline_tab_news';
var SAVE_DELAY = 1500;
var WORK_HOURS_PER_DAY = 7;
var TVA_SEUIL_CHF = 100000;
var TVA_BANNER_DURATION = 5000;

var TYPES_TACHES = {
  depannage: { label: 'Dépannage', color: 'depannage' },
  reparation: { label: 'Réparation fuite', color: 'reparation' },
  entretien: { label: 'Entretien chaudière', color: 'entretien' },
  installation: { label: 'Installation', color: 'installation' },
  urgence: { label: 'Urgence', color: 'urgence' },
  autre: { label: 'Autre', color: 'autre' },
  credit: { label: 'Avoir', color: 'credit' }
};

var interventions = [];
var devisList = [];
var clients = [];
var stock = {};
var factureCounter = 1;
var devisCounter = 1;
var avoirCounter = 1;
var currentFactureId = null;
var currentDevisId = null;
var currentMailType = 'facture';
var currentMailId = null;
var clientSignatureData = null;
var techSignatureData = null;
var clientSignatureHash = null;
var techSignatureHash = null;
var currentSignatureTarget = null;
var editingDevisId = null;
var editingPlanningId = null;
var convertDevisSourceId = null;
var currentQuickFilter = 'all';
var currentFactureFilter = 'all';
var currentSortInterventions = 'date_desc';
var currentSortFactures = 'date_desc';
var currentSortDevis = 'date_desc';
var dateFilterFrom = '';
var dateFilterTo = '';
var tempPieces = [];
var tempFrais = [];
var tempDevisPieces = [];
var tempPhotos = [];
var saveTimeout = null;
var broadcastChannel = null;
var storageDirty = false;
var currentWizardStep = 1;
var totalCache = new Map();
var tvaBannerTimeout = null;
var openMonths = {};
var openDays = {};
var stockSearchTerm = '';
var stockSortMode = 'name_asc';
var tabNews = {};

var settings = {
  nom: 'PipePline', adresse: '', zip: '', city: '', siret: '', iban: '', tel: '', email: '',
  taxe: 21.2, tva: 8.1, tvaActive: false, tvaIntra: '',
  tauxDefaut: 90, deplacementDefaut: 50, seuilAlerte: 30, seuilSauvegarde: 15,
  assuranceNom: '', assuranceNum: '', delaiPaiement: 30, pays: 'CH',
  kmRate: 0.70, acompteSeuil: 5000,
  pinActive: false, encryptExport: false
};
var backupMeta = { lastExportAt: null, lastReminderAt: null };
var planningDate = new Date();
var selectedPlanningDate = new Date();
var searchTerm = '';
var searchFactureTerm = '';
var searchDevisTerm = '';
var confirmCallback = null;
var recapDate = new Date();
var currentAvoirSourceFactureId = null;

/* ==========================================================================
   ESCAPE HTML
   ========================================================================== */
function escapeHtml(text) {
  if (!text && text !== 0) return '';
  var s = String(text);
  var div = document.createElement('div');
  div.textContent = s;
  return div.innerHTML;
}

/* ==========================================================================
   FORMATAGE
   ========================================================================== */
function formatDate(dateStr) {
  if (!dateStr) return '—';
  try {
    var d = new Date(dateStr + 'T00:00:00');
    var day = String(d.getDate()).padStart(2, '0');
    var month = String(d.getMonth() + 1).padStart(2, '0');
    var year = d.getFullYear();
    return day + '.' + month + '.' + year;
  } catch(e) { return dateStr; }
}
function formatMois(date) {
  var s = date.toLocaleDateString('fr-CH', { month: 'long', year: 'numeric' });
  return s.charAt(0).toUpperCase() + s.slice(1);
}
function formatCHF(n) {
  if (isNaN(n) || n === null) n = 0;
  var parts = n.toFixed(2).split('.');
  var intPart = parts[0].replace(/\B(?=(\d{3})+(?!\d))/g, "'");
  return intPart + '.' + parts[1] + ' CHF';
}
function formatDuree(minutes) {
  if (!minutes || minutes === 0) return '0 min';
  var total = parseInt(minutes) || 0;
  var j = Math.floor(total / (WORK_HOURS_PER_DAY * 60));
  var reste = total % (WORK_HOURS_PER_DAY * 60);
  var h = Math.floor(reste / 60);
  var m = reste % 60;
  var parts = [];
  if (j > 0) parts.push(j + 'j');
  if (h > 0) parts.push(h + 'h');
  if (m > 0) parts.push(m + 'min');
  return parts.join(' ') || '0 min';
}
function minutesVersDuree(minutes) {
  var total = parseInt(minutes) || 0;
  var jours = Math.floor(total / (WORK_HOURS_PER_DAY * 60));
  var reste = total % (WORK_HOURS_PER_DAY * 60);
  return { jours: jours, heures: Math.floor(reste / 60), minutes: reste % 60 };
}
function dureeVersMinutes(j, h, m) {
  return (parseInt(j) || 0) * WORK_HOURS_PER_DAY * 60 + (parseInt(h) || 0) * 60 + (parseInt(m) || 0);
}
function diffHeures(debut, fin) {
  if (!debut || !fin) return 0;
  var partsD = debut.split(':');
  var partsF = fin.split(':');
  var d = parseInt(partsD[0]) * 60 + parseInt(partsD[1]);
  var f = parseInt(partsF[0]) * 60 + parseInt(partsF[1]);
  var diff = f - d;
  if (diff < 0) diff += 24 * 60;
  return diff;
}
function ajouterMinutes(heure, minutes) {
  if (!heure) return '';
  var parts = heure.split(':');
  var total = parseInt(parts[0]) * 60 + parseInt(parts[1]) + minutes;
  total = ((total % (24 * 60)) + 24 * 60) % (24 * 60);
  return String(Math.floor(total / 60)).padStart(2, '0') + ':' + String(total % 60).padStart(2, '0');
}
function joursEntre(d1, d2) {
  var a = new Date(d1 + 'T00:00:00');
  var b = new Date(d2 + 'T00:00:00');
  return Math.floor((b - a) / 86400000);
}
function joursDepuis(iso) {
  if (!iso) return null;
  return Math.floor((new Date() - new Date(iso)) / 86400000);
}
function isToday(dateStr) {
  if (!dateStr) return false;
  return dateStr === new Date().toISOString().slice(0, 10);
}
function genererNumeroFacture() {
  var year = new Date().getFullYear();
  return 'FAC-' + year + '-' + String(factureCounter++).padStart(4, '0');
}
function genererNumeroDevis() {
  var year = new Date().getFullYear();
  return 'DEV-' + year + '-' + String(devisCounter++).padStart(4, '0');
}
function genererNumeroAvoir() {
  var year = new Date().getFullYear();
  return 'AVR-' + year + '-' + String(avoirCounter++).padStart(4, '0');
}
function toDateStr(d) {
  return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0');
}
function getMonthKey(dateStr) { return dateStr ? dateStr.slice(0, 7) : ''; }
function formatMonthHeader(monthKey) {
  if (!monthKey) return '—';
  try {
    var d = new Date(monthKey + '-01T00:00:00');
    var s = d.toLocaleDateString('fr-CH', { month: 'long', year: 'numeric' });
    return s.charAt(0).toUpperCase() + s.slice(1);
  } catch(e) { return monthKey; }
}
function formatDayHeader(dateStr) {
  if (!dateStr) return '—';
  try {
    var d = new Date(dateStr + 'T00:00:00');
    var dayName = d.toLocaleDateString('fr-CH', { weekday: 'long' });
    var dayNum = d.getDate();
    var monthName = d.toLocaleDateString('fr-CH', { month: 'long' });
    var year = d.getFullYear();
    return dayName.charAt(0).toUpperCase() + dayName.slice(1) + ' ' + dayNum + ' ' + monthName + ' ' + year;
  } catch(e) { return dateStr; }
}

/* ==========================================================================
   THÈME
   ========================================================================== */
function applyTheme(theme) {
  if (theme === 'dark') document.documentElement.setAttribute('data-theme', 'dark');
  else if (theme === 'light') document.documentElement.setAttribute('data-theme', 'light');
  else document.documentElement.removeAttribute('data-theme');
  try { localStorage.setItem(THEME_KEY, theme); } catch(e) {}
}
function getCurrentTheme() {
  try { return localStorage.getItem(THEME_KEY) || 'auto'; } catch(e) { return 'auto'; }
}

/* ==========================================================================
   TAB NEWS
   ========================================================================== */
function loadTabNews() {
  try {
    var raw = localStorage.getItem(TAB_NEWS_KEY);
    if (raw) tabNews = JSON.parse(raw);
  } catch(e) { tabNews = {}; }
}
function saveTabNews() {
  try { localStorage.setItem(TAB_NEWS_KEY, JSON.stringify(tabNews)); } catch(e) {}
}
function markTabAsNew(tabName) {
  tabNews[tabName] = true;
  saveTabNews();
  updateTabNewDots();
}
function clearTabNew(tabName) {
  if (tabNews[tabName]) {
    tabNews[tabName] = false;
    saveTabNews();
    updateTabNewDots();
  }
}
function updateTabNewDots() {
  document.querySelectorAll('.main-tab').forEach(function(t) {
    if (tabNews[t.dataset.tab]) t.classList.add('has-new');
    else t.classList.remove('has-new');
  });
  document.querySelectorAll('.bottom-nav-item').forEach(function(t) {
    if (tabNews[t.dataset.tab]) t.classList.add('has-new');
    else t.classList.remove('has-new');
  });
}

/* ==========================================================================
   KM / TOTAUX
   ========================================================================== */
function getKmTotal(distance, retourMultiplier, rate) {
  var d = parseFloat(distance) || 0;
  var r = parseInt(retourMultiplier) || 1;
  var t = parseFloat(rate) || 0.70;
  return d * r * t;
}
function updateKmTotal() {
  var active = document.getElementById('intKmActive').checked;
  var fields = document.getElementById('intKmFields');
  if (active) fields.classList.add('show');
  else fields.classList.remove('show');
  var distance = document.getElementById('intKmDistance').value;
  var retour = document.getElementById('intKmRetour').value;
  var rate = document.getElementById('intKmTaux').value;
  var total = getKmTotal(distance, retour, rate);
  document.getElementById('intKmTotal').textContent = formatCHF(total);
}

function invalidateTotals(id) {
  if (id) totalCache.delete(id);
  else totalCache.clear();
}
function getPiecesTotal(pieces) {
  if (!pieces || !pieces.length) return 0;
  var total = 0;
  for (var i = 0; i < pieces.length; i++) total += (parseFloat(pieces[i].prix) || 0) * (parseInt(pieces[i].qte) || 1);
  return total;
}
function getFraisTotal(frais) {
  if (!frais || !frais.length) return 0;
  var total = 0;
  for (var i = 0; i < frais.length; i++) total += parseFloat(frais[i].montant) || 0;
  return total;
}
function getKmFraisAmount(item) {
  if (!item.kmActive) return 0;
  return getKmTotal(item.kmDistance, item.kmRetour, item.kmTaux);
}
function getTotalHT(item) {
  if (item.montantForceHT !== undefined && item.montantForceHT !== null) return item.montantForceHT;
  var cacheKey = item.id + '_ht';
  if (totalCache.has(cacheKey)) return totalCache.get(cacheKey);
  var heures = (item.duree || 0) / 60;
  var total = heures * (item.taux || settings.tauxDefaut)
    + (item.deplacement || 0)
    + getPiecesTotal(item.pieces)
    + getFraisTotal(item.frais)
    + getKmFraisAmount(item);
  if (item.isAvoir) total = -Math.abs(total);
  totalCache.set(cacheKey, total);
  return total;
}
function getTauxTva(item) {
  if (!settings.tvaActive) return 0;
  if (item.paysClient && item.paysClient !== 'CH' && item.paysClient !== 'autre') return 0;
  return settings.tva;
}
function isAutoliquidation(item) {
  return settings.tvaActive && item.paysClient && item.paysClient !== 'CH' && item.paysClient !== 'autre';
}
function getTotalTTC(item) {
  var ht = getTotalHT(item);
  var cacheKey = item.id + '_ttc';
  if (totalCache.has(cacheKey)) return totalCache.get(cacheKey);
  var total = ht * (1 + getTauxTva(item) / 100);
  totalCache.set(cacheKey, total);
  return total;
}
function getTvaMontant(item) { return getTotalTTC(item) - getTotalHT(item); }
function getTotalNet(item) { return getTotalTTC(item) * (1 - settings.taxe / 100); }

function isOverdue(int) {
  if (int.paye) return false;
  if (int.isAvoir) return false;
  if (!int.date) return false;
  return joursEntre(int.date, new Date().toISOString().slice(0, 10)) > (settings.seuilAlerte || 30);
}

function getStatut(int) {
  if (int.isAvoir) return 'credit';
  if (int.paye) return 'paid';
  if (int.statut === 'en_cours') return 'in_progress';
  if (isOverdue(int)) return 'overdue';
  if (int.statut === 'termine') return 'termine';
  return 'unpaid';
}
function getStatutLabel(int) {
  if (int.isAvoir) return '↩ Avoir';
  if (int.paye) return '✓ Payée';
  if (int.statut === 'en_cours') return '⏳ En cours';
  if (isOverdue(int)) return '⏰ En retard';
  if (int.statut === 'termine') return '✓ Terminé';
  return '⚠ Impayée';
}

function findConflicts(date, heureDebut, heureFin, excludeId) {
  if (!date || !heureDebut) return [];
  var conflicts = [];
  var fin = heureFin || ajouterMinutes(heureDebut, 60);
  for (var i = 0; i < interventions.length; i++) {
    var int = interventions[i];
    if (int.id === excludeId || int.isAvoir) continue;
    if (int.date !== date || !int.heure) continue;
    var intFin = int.heureFin || ajouterMinutes(int.heure, int.duree || 60);
    if (heureDebut < intFin && fin > int.heure) conflicts.push(int);
  }
  return conflicts;
}

function adjustStock(pieces, sign) {
  if (!pieces || !pieces.length) return;
  pieces.forEach(function(p) {
    if (!p.nom) return;
    var key = p.nom.trim().toLowerCase();
    if (stock[key]) stock[key].qte = Math.max(0, stock[key].qte + sign * (parseInt(p.qte) || 1));
  });
  storageSet(STOCK_KEY, stock);
}
function decrementStock(pieces) { adjustStock(pieces, -1); }
function restoreStock(pieces) { adjustStock(pieces, +1); }
function getStockStatus(nom) {
  if (!nom) return null;
  var key = nom.trim().toLowerCase();
  if (!stock[key]) return null;
  if (stock[key].qte <= stock[key].seuil) return { qte: stock[key].qte, seuil: stock[key].seuil, low: true };
  return { qte: stock[key].qte, seuil: stock[key].seuil, low: false };
}

/* ==========================================================================
   TOASTS / SKELETON / CONFIRM
   ========================================================================== */
function showToast(message, type, options) {
  options = options || {};
  var stack = document.getElementById('toastStack');
  var el = document.createElement('div');
  el.className = 'toast-item ' + (type || 'info');
  var iconChar = 'ℹ';
  if (type === 'success') iconChar = '✓';
  else if (type === 'warning') iconChar = '⚠';
  else if (type === 'error') iconChar = '✕';
  else if (type === 'purple') iconChar = '↩';
  el.innerHTML = '<span style="font-weight:700;">' + iconChar + '</span>'
    + '<span class="toast-msg">' + escapeHtml(message) + '</span>'
    + (options.action ? '<button class="toast-action">' + escapeHtml(options.action) + '</button>' : '')
    + '<button class="toast-close" aria-label="Fermer">✕</button>';
  stack.appendChild(el);
  while (stack.children.length > 4) stack.removeChild(stack.firstChild);
  var actionBtn = el.querySelector('.toast-action');
  if (actionBtn && options.onAction) actionBtn.addEventListener('click', function() { options.onAction(); dismissToast(el); });
  el.querySelector('.toast-close').addEventListener('click', function() { dismissToast(el); });
  var timeout = options.persistent ? 0 : (options.duration || (options.action ? 5000 : 3200));
  if (timeout) setTimeout(function() { dismissToast(el); }, timeout);
}
function dismissToast(el) {
  if (!el.parentNode) return;
  el.classList.add('removing');
  setTimeout(function() { if (el.parentNode) el.parentNode.removeChild(el); }, 250);
}

function showSkeleton(container, count) {
  count = count || 3;
  var html = '';
  for (var i = 0; i < count; i++) {
    html += '<div class="skeleton-card"><div class="skeleton-line short skeleton"></div><div class="skeleton-line long skeleton"></div><div class="skeleton-line medium skeleton"></div></div>';
  }
  container.innerHTML = html;
}

function showConfirm(message, callback) {
  document.getElementById('confirmMessage').textContent = message;
  document.getElementById('confirmModal').classList.add('show');
  confirmCallback = callback;
}
document.getElementById('confirmYes').addEventListener('click', function() {
  document.getElementById('confirmModal').classList.remove('show');
  haptic(15);
  if (confirmCallback) { confirmCallback(true); confirmCallback = null; }
});
document.getElementById('confirmNo').addEventListener('click', function() {
  document.getElementById('confirmModal').classList.remove('show');
  if (confirmCallback) { confirmCallback(false); confirmCallback = null; }
});

function debounce(fn, delay) {
  var timer;
  return function() {
    var args = arguments, ctx = this;
    clearTimeout(timer);
    timer = setTimeout(function() { fn.apply(ctx, args); }, delay);
  };
}

/* ==========================================================================
   SAUVEGARDE / CHARGEMENT
   ========================================================================== */
function saveToStorage(silent) {
  if (silent && !storageDirty) return Promise.resolve(true);
  var data = {
    interventions: interventions,
    devisList: devisList,
    clients: clients,
    factureCounter: factureCounter,
    devisCounter: devisCounter,
    avoirCounter: avoirCounter,
    schemaVersion: 4,
    appVersion: APP_VERSION,
    savedAt: new Date().toISOString()
  };
  return storageSet(STORAGE_KEY, data)
    .then(function() { return storageSet(SETTINGS_KEY, settings); })
    .then(function() { return storageSet(BACKUP_META_KEY, backupMeta); })
    .then(function() {
      storageDirty = false;
      updateSaveIndicator(true);
      if (broadcastChannel) {
        try { broadcastChannel.postMessage({ type: 'data-updated', at: Date.now() }); } catch(e) {}
      }
      return true;
    }).catch(function(e) {
      console.error('Erreur sauvegarde:', e);
      return false;
    });
}

function loadFromStorage() {
  return storageGet(STORAGE_KEY).then(function(data) {
    if (data) {
      interventions = data.interventions || [];
      devisList = data.devisList || [];
      clients = data.clients || [];
      factureCounter = data.factureCounter || 1;
      devisCounter = data.devisCounter || 1;
      avoirCounter = data.avoirCounter || 1;
      interventions.forEach(function(int) {
        if (int.statut === 'termine' && int.pieces && int.pieces.length > 0) {
          int.stockDecremented = true;
        }
      });
    }
    return storageGet(SETTINGS_KEY);
  }).then(function(s) {
    if (s) {
      for (var key in s) {
        if (settings.hasOwnProperty(key)) settings[key] = s[key];
      }
    }
    return storageGet(BACKUP_META_KEY);
  }).then(function(bm) {
    if (bm) {
      backupMeta.lastExportAt = bm.lastExportAt || null;
      backupMeta.lastReminderAt = bm.lastReminderAt || null;
    }
    if (!backupMeta.lastReminderAt && !backupMeta.lastExportAt) backupMeta.lastReminderAt = new Date().toISOString();
    return storageGet(STOCK_KEY);
  }).then(function(s) {
    if (s) stock = s;
    storageDirty = false;
    invalidateTotals();
    return true;
  }).catch(function(e) {
    console.error('Erreur chargement:', e);
    return false;
  });
}

function markAsDirty() {
  storageDirty = true;
  updateSaveIndicator(false);
  if (saveTimeout) clearTimeout(saveTimeout);
  saveTimeout = setTimeout(function() { saveToStorage(); }, SAVE_DELAY);
}
function updateSaveIndicator(saved) {
  var dot = document.getElementById('saveDot');
  var text = document.getElementById('saveStatusText');
  if (saved) {
    dot.className = 'save-dot';
    text.textContent = 'Sauvegardé';
  } else {
    dot.className = 'save-dot dirty';
    text.textContent = 'Modifications...';
  }
}

function getPhoneHref(tel) {
  if (!tel) return '';
  return 'tel:' + String(tel).replace(/[^0-9+]/g, '');
}
function getMapsHref(adresse) {
  if (!adresse) return '';
  var q = encodeURIComponent(adresse);
  var isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent) && !window.MSStream;
  return isIOS ? 'https://maps.apple.com/?q=' + q : 'https://www.google.com/maps/search/?api=1&query=' + q;
}

/* ==========================================================================
   AUTOCOMPLETE
   ========================================================================== */
function setupAutocomplete(inputId, listId, onSelect) {
  var input = document.getElementById(inputId);
  var list = document.getElementById(listId);
  if (!input || !list) return;
  function getAllClients() {
    var map = {};
    clients.forEach(function(c) {
      var key = (c.nom || '').toLowerCase();
      if (key) map[key] = { nom: c.nom, email: c.email || '', tel: c.tel || '', adresse: c.adresse || '' };
    });
    interventions.forEach(function(i) {
      if (!i.client) return;
      var key = i.client.toLowerCase();
      map[key] = { nom: i.client, email: i.email || '', tel: i.tel || '', adresse: i.adresse || '' };
    });
    devisList.forEach(function(d) {
      if (!d.client) return;
      var key = d.client.toLowerCase();
      if (!map[key]) map[key] = { nom: d.client, email: d.email || '', tel: d.tel || '', adresse: d.adresse || '' };
    });
    return Object.values(map);
  }
  function renderList(term) {
    var all = getAllClients();
    if (!term) { list.classList.remove('show'); return; }
    var t = term.toLowerCase();
    var matches = all.filter(function(c) {
      return c.nom.toLowerCase().indexOf(t) !== -1
        || (c.email || '').toLowerCase().indexOf(t) !== -1
        || (c.tel || '').indexOf(t) !== -1;
    }).slice(0, 6);
    if (matches.length === 0) { list.classList.remove('show'); return; }
    list.innerHTML = matches.map(function(c) {
      return '<div class="autocomplete-item" data-nom="' + escapeHtml(c.nom) + '"><div class="ac-name">' + escapeHtml(c.nom) + '</div><div class="ac-detail">' + escapeHtml(c.email || '') + (c.tel ? ' • ' + escapeHtml(c.tel) : '') + '</div></div>';
    }).join('');
    list.classList.add('show');
    list.querySelectorAll('.autocomplete-item').forEach(function(el) {
      el.addEventListener('click', function() {
        var nom = this.dataset.nom;
        var c = all.find(function(x) { return x.nom === nom; });
        if (c && onSelect) onSelect(c);
        list.classList.remove('show');
      });
    });
  }
  input.addEventListener('input', debounce(function() { renderList(this.value); }, 150));
  input.addEventListener('focus', function() { if (this.value) renderList(this.value); });
  input.addEventListener('blur', function() { setTimeout(function() { list.classList.remove('show'); }, 200); });
}

/* ==========================================================================
   BANNIÈRE TVA / CLIENTS RÉCURRENTS
   ========================================================================== */
function showTvaBanner() {
  var banner = document.getElementById('alertTva');
  var text = document.getElementById('alertTvaText');
  if (!settings.tvaActive) text.innerHTML = '<strong>TVA non applicable</strong> — CA annuel < ' + formatCHF(TVA_SEUIL_CHF) + '. Vos factures porteront la mention « TVA non applicable (art. 10 al. 2 LTVA) ».';
  else text.innerHTML = '<strong>Assujetti à la TVA suisse</strong> — Taux : ' + settings.tva + ' %. N° TVA : ' + (settings.tvaIntra || 'à renseigner') + '. Clients UE : autoliquidation (0 %).';
  banner.classList.remove('hiding');
  banner.classList.add('show');
  if (tvaBannerTimeout) clearTimeout(tvaBannerTimeout);
  tvaBannerTimeout = setTimeout(hideTvaBanner, TVA_BANNER_DURATION);
}
function hideTvaBanner() {
  var banner = document.getElementById('alertTva');
  banner.classList.add('hiding');
  banner.classList.remove('show');
  setTimeout(function() { banner.classList.remove('hiding'); }, 500);
}
document.getElementById('alertTvaClose').addEventListener('click', function(e) {
  e.stopPropagation();
  if (tvaBannerTimeout) clearTimeout(tvaBannerTimeout);
  hideTvaBanner();
});
function updateTvaBannerContent() {
  var banner = document.getElementById('alertTva');
  if (!banner.classList.contains('show')) return;
  var text = document.getElementById('alertTvaText');
  if (!settings.tvaActive) text.innerHTML = '<strong>TVA non applicable</strong> — CA annuel < ' + formatCHF(TVA_SEUIL_CHF) + '. Vos factures porteront la mention « TVA non applicable (art. 10 al. 2 LTVA) ».';
  else text.innerHTML = '<strong>Assujetti à la TVA suisse</strong> — Taux : ' + settings.tva + ' %. N° TVA : ' + (settings.tvaIntra || 'à renseigner') + '. Clients UE : autoliquidation (0 %).';
}

function checkRecurringClients() {
  var alertEl = document.getElementById('alertRecurring');
  var alertText = document.getElementById('alertRecurringText');
  var upcoming = [];
  var now = new Date();
  interventions.forEach(function(int) {
    if (!int.recurring) return;
    if (int.isAvoir) return;
    var lastDate = new Date(int.date + 'T00:00:00');
    var nextDate = new Date(lastDate);
    nextDate.setMonth(nextDate.getMonth() + 11);
    var diffDays = Math.floor((nextDate - now) / 86400000);
    if (diffDays >= -5 && diffDays <= 30) {
      upcoming.push({ client: int.client, date: nextDate, diffDays: diffDays });
    }
  });
  if (upcoming.length > 0) {
    var first = upcoming[0];
    var msg = '🔁 <strong>' + upcoming.length + '</strong> rappel' + (upcoming.length > 1 ? 's' : '') + ' entretien : ';
    if (first.diffDays < 0) msg += '<strong>' + escapeHtml(first.client) + '</strong> (en retard de ' + Math.abs(first.diffDays) + 'j)';
    else if (first.diffDays === 0) msg += '<strong>' + escapeHtml(first.client) + '</strong> (aujourd\'hui)';
    else msg += '<strong>' + escapeHtml(first.client) + '</strong> dans ' + first.diffDays + 'j';
    alertText.innerHTML = msg;
    alertEl.classList.add('show');
  } else alertEl.classList.remove('show');
}
document.getElementById('alertRecurring').addEventListener('click', function() {
  switchTab('interventions');
  openMonths = {};
  openDays = {};
  markTabAsNew('interventions');
  showToast('Rappels entretien disponibles dans les interventions', 'purple');
});

/* ==========================================================================
   STATS / BADGES / FILTRES
   ========================================================================== */
function renderStats() {
  var total = interventions.length;
  var impayees = 0, payees = 0, overdue = 0, overdueTotal = 0;
  var caMois = 0, caNetMois = 0, caAnnuel = 0, resteEncaisser = 0;
  var now = new Date();
  var currentMonth = now.getMonth();
  var currentYear = now.getFullYear();
  for (var i = 0; i < interventions.length; i++) {
    var int = interventions[i];
    var ttc = getTotalTTC(int);
    var net = getTotalNet(int);
    if (!int.isAvoir) {
      if (int.paye) payees++;
      else {
        impayees++;
        resteEncaisser += ttc;
        if (isOverdue(int)) { overdue++; overdueTotal += ttc; }
      }
    }
    var intDate = new Date(int.date + 'T00:00:00');
    if (intDate.getMonth() === currentMonth && intDate.getFullYear() === currentYear) {
      caMois += ttc;
      caNetMois += net;
    }
    if (intDate.getFullYear() === currentYear) caAnnuel += ttc;
  }
  document.getElementById('totalInterventions').textContent = total;
  document.getElementById('totalImpayees').textContent = impayees;
  document.getElementById('caMoisMini').textContent = formatCHF(caMois);
  document.getElementById('tabInterventionsCount').textContent = total;
  document.getElementById('tabFacturesCount').textContent = total;
  document.getElementById('tabDevisCount').textContent = devisList.length;
  document.getElementById('caMois').textContent = formatCHF(caMois);
  document.getElementById('caNetMois').textContent = formatCHF(caNetMois);
  document.getElementById('caAnnuel').textContent = formatCHF(caAnnuel);
  document.getElementById('resteEncaisser').textContent = formatCHF(resteEncaisser);
  document.getElementById('caMoisLabel').textContent = formatMois(now);
  document.getElementById('caAnnuelLabel').textContent = currentYear;
  document.getElementById('caNetMoisSub').textContent = '~' + settings.taxe + '%';

  updateBottomNavBadges();
  updateQuickFilterCounts();
  updateTvaBannerContent();
  checkRecurringClients();

  var alertEl = document.getElementById('alertOverdue');
  var alertText = document.getElementById('alertOverdueText');
  if (overdue > 0) {
    alertEl.classList.add('show');
    alertText.innerHTML = '<strong>' + overdue + '</strong> facture' + (overdue > 1 ? 's' : '') + ' impayée' + (overdue > 1 ? 's' : '') + ' depuis plus de ' + settings.seuilAlerte + ' jours — Total : <strong>' + formatCHF(overdueTotal) + '</strong>';
  } else alertEl.classList.remove('show');
}

function updateBottomNavBadges() {
  var impayees = interventions.filter(function(i) { return !i.paye && !i.isAvoir; }).length;
  var bnInt = document.getElementById('bnInterventions');
  var bnFac = document.getElementById('bnFactures');
  var bnDev = document.getElementById('bnDevis');
  if (impayees > 0) { bnInt.textContent = impayees; bnInt.classList.remove('hidden'); }
  else bnInt.classList.add('hidden');
  if (interventions.length > 0) { bnFac.textContent = interventions.length; bnFac.classList.remove('hidden'); }
  else bnFac.classList.add('hidden');
  if (devisList.length > 0) { bnDev.textContent = devisList.length; bnDev.classList.remove('hidden'); }
  else bnDev.classList.add('hidden');
}

function updateQuickFilterCounts() {
  var today = new Date().toISOString().slice(0, 10);
  var qf = {
    all: interventions.length,
    unpaid: interventions.filter(function(i) { return !i.paye && !i.isAvoir; }).length,
    overdue: interventions.filter(isOverdue).length,
    today: interventions.filter(function(i) { return i.date === today; }).length,
    in_progress: interventions.filter(function(i) { return i.statut === 'en_cours' && !i.paye && !i.isAvoir; }).length,
    termine: interventions.filter(function(i) { return i.statut === 'termine' && !i.paye && !i.isAvoir; }).length,
    paid: interventions.filter(function(i) { return i.paye; }).length
  };
  var el;
  if (el = document.getElementById('qfAll')) el.textContent = qf.all;
  if (el = document.getElementById('qfUnpaid')) el.textContent = qf.unpaid;
  if (el = document.getElementById('qfOverdue')) el.textContent = qf.overdue;
  if (el = document.getElementById('qfToday')) el.textContent = qf.today;
  if (el = document.getElementById('qfInProgress')) el.textContent = qf.in_progress;
  if (el = document.getElementById('qfTermine')) el.textContent = qf.termine;
  if (el = document.getElementById('qfPaid')) el.textContent = qf.paid;
}

function filterInterventions(list, filter) {
  var today = new Date().toISOString().slice(0, 10);
  if (filter === 'unpaid') return list.filter(function(i) { return !i.paye && !i.isAvoir; });
  if (filter === 'overdue') return list.filter(isOverdue);
  if (filter === 'today') return list.filter(function(i) { return i.date === today; });
  if (filter === 'in_progress') return list.filter(function(i) { return i.statut === 'en_cours' && !i.paye && !i.isAvoir; });
  if (filter === 'termine') return list.filter(function(i) { return i.statut === 'termine' && !i.paye && !i.isAvoir; });
  if (filter === 'paid') return list.filter(function(i) { return i.paye; });
  return list;
}

function applySortAndDateFilter(list, sortMode, fromDate, toDate) {
  var result = list.slice();
  if (fromDate) result = result.filter(function(i) { return (i.date || '') >= fromDate; });
  if (toDate) result = result.filter(function(i) { return (i.date || '') <= toDate; });
  result.sort(function(a, b) {
    switch (sortMode) {
      case 'date_asc': return (a.date || '').localeCompare(b.date || '');
      case 'montant_desc': return getTotalTTC(b) - getTotalTTC(a);
      case 'montant_asc': return getTotalTTC(a) - getTotalTTC(b);
      case 'client_asc': return (a.client || '').localeCompare(b.client || '');
      case 'client_desc': return (b.client || '').localeCompare(a.client || '');
      case 'date_desc':
      default: return (b.date || '').localeCompare(a.date || '');
    }
  });
  return result;
}

/* ==========================================================================
   RENDU AUJOURD'HUI
   ========================================================================== */
function renderToday() {
  var todayStr = new Date().toISOString().slice(0, 10);
  var todayDate = new Date();
  var label = todayDate.toLocaleDateString('fr-CH', { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' });
  document.getElementById('todayDateLabel').textContent = label.charAt(0).toUpperCase() + label.slice(1);

  var todayItems = interventions.filter(function(i) { return i.date === todayStr && !i.isAvoir; });
  todayItems.sort(function(a, b) { return (a.heure || '99:99').localeCompare(b.heure || '99:99'); });

  var totalMin = todayItems.reduce(function(s, i) { return s + (i.duree || 0); }, 0);
  var workH = Math.round(totalMin / 60 * 10) / 10;
  var caJour = todayItems.reduce(function(s, i) { return s + getTotalTTC(i); }, 0);
  var unpaidCount = todayItems.filter(function(i) { return !i.paye; }).length;

  var summary = document.getElementById('todaySummary');
  summary.innerHTML =
    '<span class="today-pill">' + todayItems.length + ' RDV</span>'
    + '<span class="today-pill">' + workH + 'h / ' + WORK_HOURS_PER_DAY + 'h</span>'
    + '<span class="today-pill">' + formatCHF(caJour) + '</span>'
    + (unpaidCount > 0 ? '<span class="today-pill warn">⚠ ' + unpaidCount + ' à encaisser</span>' : '<span class="today-pill ok">✓ tout payé</span>');

  var timeline = document.getElementById('todayTimeline');
  if (todayItems.length === 0) {
    timeline.innerHTML = '<div class="today-empty">Aucun rendez-vous aujourd\'hui.<br>Profitez-en pour faire vos devis ou relancer les impayés !</div>';
    return;
  }
  timeline.innerHTML = todayItems.map(function(int) {
    var statut = getStatut(int);
    var heure = int.heure || '--:--';
    var heureFin = int.heureFin || '';
    var typeInfo = TYPES_TACHES[int.type] || TYPES_TACHES.autre;
    var actionsHtml = '';
    if (int.tel) actionsHtml += '<a class="ts-call" href="' + getPhoneHref(int.tel) + '" onclick="event.stopPropagation();" title="Appeler">☎</a>';
    if (int.adresse) actionsHtml += '<a class="ts-route" href="' + getMapsHref(int.adresse) + '" target="_blank" rel="noopener" onclick="event.stopPropagation();" title="Itinéraire">📍</a>';
    if (!int.paye && int.statut !== 'termine') {
      if (int.statut === 'en_cours') actionsHtml += '<button class="ts-finish" data-action="finish" data-id="' + int.id + '" title="Terminer">✓</button>';
      else actionsHtml += '<button class="ts-start" data-action="start" data-id="' + int.id + '" title="Démarrer">▶</button>';
    }
    return '<div class="today-slot ' + statut + '" data-id="' + int.id + '">'
      + '<div class="today-slot-time"><span class="tst-hour">' + heure + '</span>' + (heureFin ? '<span class="tst-end">' + heureFin + '</span>' : '') + '</div>'
      + '<div class="today-slot-body">'
      + '<div class="today-slot-client">' + escapeHtml(int.client || 'Client') + '</div>'
      + '<div class="today-slot-desc">' + escapeHtml(int.description || '—') + '</div>'
      + '<div class="today-slot-meta"><span>' + typeInfo.label + '</span><span>⏱ ' + formatDuree(int.duree) + '</span><span>' + formatCHF(getTotalTTC(int)) + '</span></div>'
      + '</div>'
      + '<div class="today-slot-actions">' + actionsHtml + '</div>'
      + '</div>';
  }).join('');

  timeline.querySelectorAll('.today-slot').forEach(function(slot) {
    slot.addEventListener('click', function(e) {
      if (e.target.closest('button') || e.target.closest('a')) return;
      haptic(8);
      openFacture(slot.dataset.id);
    });
  });
  timeline.querySelectorAll('[data-action="start"]').forEach(function(btn) {
    btn.addEventListener('click', function(e) { e.stopPropagation(); haptic(15); setInterventionStatus(btn.dataset.id, 'en_cours'); });
  });
  timeline.querySelectorAll('[data-action="finish"]').forEach(function(btn) {
    btn.addEventListener('click', function(e) { e.stopPropagation(); haptic(15); setInterventionStatus(btn.dataset.id, 'termine'); });
  });
}

/* ==========================================================================
   RENDU INTERVENTIONS
   ========================================================================== */
function renderInterventions() {
  var container = document.getElementById('interventionsGroups');
  var term = searchTerm.trim().toLowerCase();
  var filtered = interventions.slice();
  if (term) {
    filtered = filtered.filter(function(int) {
      return (int.client || '').toLowerCase().indexOf(term) !== -1
        || (int.description || '').toLowerCase().indexOf(term) !== -1
        || (int.numeroFacture || '').toLowerCase().indexOf(term) !== -1
        || (int.email || '').toLowerCase().indexOf(term) !== -1;
    });
  }
  filtered = filterInterventions(filtered, currentQuickFilter);
  filtered = applySortAndDateFilter(filtered, currentSortInterventions, dateFilterFrom, dateFilterTo);

  if (filtered.length === 0) {
    container.innerHTML = '<div class="empty-state">'
      + (term || currentQuickFilter !== 'all' || dateFilterFrom || dateFilterTo ? 'Aucun résultat' : 'Aucune intervention pour le moment')
      + '<button class="empty-action" id="emptyCreateBtn">+ Créer ma première intervention</button></div>';
    var emptyBtn = document.getElementById('emptyCreateBtn');
    if (emptyBtn) emptyBtn.addEventListener('click', function() { haptic(10); openInterventionModal(); });
    return;
  }

  if (currentSortInterventions === 'date_desc' || currentSortInterventions === 'date_asc') {
    renderInterventionsGrouped(container, filtered);
  } else {
    var frag = document.createDocumentFragment();
    filtered.forEach(function(int) { frag.appendChild(buildInterventionCard(int)); });
    container.innerHTML = '';
    container.appendChild(frag);
    attachInterventionHandlers(container);
  }
}

function renderInterventionsGrouped(container, filtered) {
  var todayStr = new Date().toISOString().slice(0, 10);
  var groupedByMonth = {};
  filtered.forEach(function(int) {
    var mKey = getMonthKey(int.date); if (!mKey) mKey = 'inconnu';
    if (!groupedByMonth[mKey]) groupedByMonth[mKey] = {};
    var dKey = int.date || 'inconnu';
    if (!groupedByMonth[mKey][dKey]) groupedByMonth[mKey][dKey] = [];
    groupedByMonth[mKey][dKey].push(int);
  });
  var months = Object.keys(groupedByMonth).sort(function(a, b) { return b.localeCompare(a); });
  var todayMonthKey = todayStr.slice(0, 7);
  if (typeof openMonths[todayMonthKey] === 'undefined') openMonths[todayMonthKey] = true;
  var todayDayKey = todayMonthKey + '_' + todayStr;
  if (typeof openDays[todayDayKey] === 'undefined') openDays[todayDayKey] = true;

  var html = '';
  months.forEach(function(mKey) {
    var days = groupedByMonth[mKey];
    var dayKeys = Object.keys(days).sort(function(a, b) { return b.localeCompare(a); });
    var monthCount = 0, monthTotal = 0, monthImpayees = 0;
    dayKeys.forEach(function(dk) {
      days[dk].forEach(function(it) {
        monthCount++;
        monthTotal += getTotalTTC(it);
        if (!it.paye && !it.isAvoir) monthImpayees++;
      });
    });
    var isMonthOpen = openMonths[mKey] === true;
    html += '<div class="group-month' + (isMonthOpen ? ' open' : '') + '" data-month="' + escapeHtml(mKey) + '">';
    html += '<div class="group-month-header" data-month-toggle="' + escapeHtml(mKey) + '"><div class="gm-left"><span class="gm-chevron">▶</span><span class="gm-title">' + formatMonthHeader(mKey) + '</span></div><div class="gm-stats"><span class="gm-stat">' + monthCount + ' interv.</span><span class="gm-stat">' + formatCHF(monthTotal) + '</span>' + (monthImpayees > 0 ? '<span class="gm-stat danger">⚠ ' + monthImpayees + '</span>' : '') + '</div></div>';
    html += '<div class="group-month-content">';
    dayKeys.forEach(function(dKey) {
      var dayItems = days[dKey];
      var dayTotal = 0;
      dayItems.forEach(function(it) { dayTotal += getTotalTTC(it); });
      var dayKeyFull = mKey + '_' + dKey;
      var isDayOpen = openDays[dayKeyFull] === true;
      var isToday = dKey === todayStr;
      html += '<div class="group-day' + (isDayOpen ? ' open' : '') + '" data-day="' + escapeHtml(dayKeyFull) + '">';
      html += '<div class="group-day-header" data-day-toggle="' + escapeHtml(dayKeyFull) + '"><div class="gd-left"><span class="gd-chevron">▶</span><span class="gd-date' + (isToday ? ' today' : '') + '">' + formatDayHeader(dKey) + '</span></div><span class="gd-count">' + dayItems.length + '</span><span class="gd-total">' + formatCHF(dayTotal) + '</span></div>';
      html += '<div class="group-day-content" data-day-content="' + escapeHtml(dayKeyFull) + '"></div>';
      html += '</div>';
    });
    html += '</div></div>';
  });
  container.innerHTML = html;

  months.forEach(function(mKey) {
    var days = groupedByMonth[mKey];
    Object.keys(days).forEach(function(dKey) {
      var dayKeyFull = mKey + '_' + dKey;
      var content = container.querySelector('[data-day-content="' + CSS.escape(dayKeyFull) + '"]');
      if (content) {
        var frag = document.createDocumentFragment();
        days[dKey].forEach(function(int) { frag.appendChild(buildInterventionCard(int)); });
        content.appendChild(frag);
      }
    });
  });
  attachInterventionHandlers(container);
  attachAccordionHandlers(container);
}

function attachAccordionHandlers(container) {
  container.querySelectorAll('[data-month-toggle]').forEach(function(header) {
    header.addEventListener('click', function(e) {
      e.stopPropagation();
      var mKey = this.dataset.monthToggle;
      openMonths[mKey] = !openMonths[mKey];
      haptic(8);
      var parent = this.closest('.group-month');
      if (parent) parent.classList.toggle('open', openMonths[mKey]);
    });
  });
  container.querySelectorAll('[data-day-toggle]').forEach(function(header) {
    header.addEventListener('click', function(e) {
      e.stopPropagation();
      var dKey = this.dataset.dayToggle;
      openDays[dKey] = !openDays[dKey];
      haptic(8);
      var parent = this.closest('.group-day');
      if (parent) parent.classList.toggle('open', openDays[dKey]);
    });
  });
}

function buildInterventionCard(int) {
  var typeInfo = TYPES_TACHES[int.type] || TYPES_TACHES.autre;
  var total = getTotalTTC(int);
  var today = isToday(int.date) && !int.isAvoir;
  var statut = getStatut(int);
  var cardClass = statut;
  if (today) cardClass += ' today';
  var card = document.createElement('div');
  card.className = 'intervention-card ' + cardClass;
  card.dataset.id = int.id;
  var statusLabel = getStatutLabel(int);
  var photosHtml = '';
  if (int.photos && int.photos.length > 0) {
    photosHtml = '<div class="photos-label">Photos (' + int.photos.length + ')</div><div class="photos-strip">'
      + int.photos.slice(0, 6).map(function(p, i) {
        return '<img src="' + p + '" class="photo-thumb" loading="lazy" data-idx="' + i + '" alt="Photo ' + (i + 1) + '" />';
      }).join('')
      + (int.photos.length > 6 ? '<div class="photo-thumb" style="display:flex; align-items:center; justify-content:center; background:var(--accent-light); color:var(--accent); font-weight:700; font-size:0.75rem;">+' + (int.photos.length - 6) + '</div>' : '')
      + '</div>';
  }
  var actionsHtml = '<div class="int-actions">';
  if (int.tel) actionsHtml += '<a class="int-btn-primary call" href="' + getPhoneHref(int.tel) + '" title="Appeler" onclick="event.stopPropagation();" aria-label="Appeler">☎</a>';
  if (int.adresse && !int.isAvoir) actionsHtml += '<a class="int-btn-primary route" href="' + getMapsHref(int.adresse) + '" target="_blank" rel="noopener" title="Itinéraire" onclick="event.stopPropagation();" aria-label="Itinéraire">📍</a>';
  if (!int.paye && !int.isAvoir) {
    if (int.statut === 'en_cours') actionsHtml += '<button class="int-btn-primary finish" data-action="finish" data-id="' + int.id + '" title="Marquer terminé" aria-label="Terminer">✓</button>';
    else if (int.statut !== 'termine') actionsHtml += '<button class="int-btn-primary progress" data-action="progress" data-id="' + int.id + '" title="Démarrer" aria-label="Démarrer">▶</button>';
  }
  actionsHtml += '<button class="int-btn-more" data-action="more" data-id="' + int.id + '" title="Plus d\'actions" aria-label="Plus">⋯</button>';
  actionsHtml += '</div>';

  card.innerHTML = '<div style="padding-top:' + (today ? '10px' : '0') + ';">'
    + '<div class="int-header">'
    + '<div class="int-title">'
    + '<span class="int-type-badge ' + typeInfo.color + '">' + typeInfo.label + '</span>'
    + '<span class="int-client">' + escapeHtml(int.client || 'Client') + '</span>'
    + (int.numeroFacture ? '<span style="font-size:0.65rem; font-family:var(--mono-stack); background:var(--accent-light); padding:2px 8px; border-radius:var(--r-full); color:var(--accent);">' + int.numeroFacture + '</span>' : '')
    + (int.signatureClient ? '<span style="font-size:0.6rem; color:var(--success);" title="Signée">✍</span>' : '')
    + (int.recurring ? '<span class="recurring-badge">🔁 Récurrent</span>' : '')
    + '</div>'
    + '<span class="int-status ' + statut + '">' + statusLabel + '</span>'
    + '</div>'
    + '<div class="int-description">' + escapeHtml(int.description || '—') + '</div>'
    + photosHtml
    + '<div class="int-footer">'
    + '<div class="int-meta">'
    + (int.heure ? '<span class="int-meta-item">🕐 ' + int.heure + (int.heureFin ? ' → ' + int.heureFin : '') + '</span>' : '<span class="int-meta-item">📅 ' + formatDate(int.date) + '</span>')
    + '<span class="int-meta-item">⏱ ' + formatDuree(int.duree) + '</span>'
    + '<span class="int-meta-item total">' + formatCHF(total) + '</span>'
    + '</div>'
    + actionsHtml
    + '</div></div>';
  return card;
}

function attachInterventionHandlers(container) {
  container.querySelectorAll('.intervention-card').forEach(function(card) {
    card.addEventListener('click', function(e) {
      if (e.target.closest('.int-btn-primary') || e.target.closest('.int-btn-more') || e.target.closest('a') || e.target.closest('.photo-thumb')) return;
      haptic(8);
      openFacture(card.dataset.id);
    });
  });
  container.querySelectorAll('.photo-thumb[data-idx]').forEach(function(thumb) {
    thumb.addEventListener('click', function(e) {
      e.stopPropagation();
      var card = this.closest('.intervention-card');
      var int = interventions.find(function(i) { return i.id === card.dataset.id; });
      if (int && int.photos) openPhotoViewer(int.photos, parseInt(this.dataset.idx));
    });
  });
  container.querySelectorAll('.int-btn-primary.progress').forEach(function(btn) {
    btn.addEventListener('click', function(e) { e.stopPropagation(); haptic(15); setInterventionStatus(btn.dataset.id, 'en_cours'); });
  });
  container.querySelectorAll('.int-btn-primary.finish').forEach(function(btn) {
    btn.addEventListener('click', function(e) { e.stopPropagation(); haptic(15); setInterventionStatus(btn.dataset.id, 'termine'); });
  });
  container.querySelectorAll('.int-btn-more').forEach(function(btn) {
    btn.addEventListener('click', function(e) { e.stopPropagation(); openActionSheet(btn.dataset.id); });
  });
}

function setInterventionStatus(id, statut) {
  var int = interventions.find(function(i) { return i.id === id; });
  if (!int) return;
  var oldStatut = int.statut;
  if (oldStatut === statut) return;
  int.statut = statut;
  if (statut === 'termine' && oldStatut !== 'termine') {
    if (int.pieces && int.pieces.length > 0 && !int.stockDecremented) {
      decrementStock(int.pieces);
      int.stockDecremented = true;
    }
  }
  if (oldStatut === 'termine' && statut !== 'termine' && int.stockDecremented) {
    restoreStock(int.pieces || []);
    int.stockDecremented = false;
  }
  invalidateTotals(id);
  markAsDirty();
  renderAll();
  if (statut === 'termine') showToast('Marquée terminée', 'success');
  else if (statut === 'en_cours') showToast('Marquée en cours', 'info');
}

function openActionSheet(id) {
  var int = interventions.find(function(i) { return i.id === id; });
  if (!int) return;
  haptic(10);
  document.getElementById('actionSheetTitle').textContent = int.client || 'Client';
  document.getElementById('actionSheetSub').textContent = (int.numeroFacture || '') + ' • ' + formatCHF(getTotalTTC(int));
  var sheet = document.getElementById('actionSheet');
  sheet.dataset.id = id;
  var progressBtn = sheet.querySelector('[data-action="progress"]');
  if (int.paye || int.statut === 'termine' || int.isAvoir) progressBtn.classList.add('hidden');
  else if (int.statut === 'en_cours') {
    progressBtn.classList.remove('hidden');
    progressBtn.innerHTML = '<span class="as-icon">✓</span><span>Terminer</span>';
  } else {
    progressBtn.classList.remove('hidden');
    progressBtn.innerHTML = '<span class="as-icon">▶</span><span>En cours</span>';
  }
  var signBtn = sheet.querySelector('[data-action="sign"]');
  if (int.signatureClient && int.signatureTech) signBtn.classList.add('hidden');
  else signBtn.classList.remove('hidden');
  var creditBtn = sheet.querySelector('[data-action="credit"]');
  if (int.isAvoir) creditBtn.classList.add('hidden');
  else creditBtn.classList.remove('hidden');
  var certBtn = sheet.querySelector('[data-action="certificate"]');
  if (int.type === 'entretien') certBtn.classList.remove('hidden');
  else certBtn.classList.add('hidden');
  sheet.classList.add('show');
}

document.getElementById('actionSheet').addEventListener('click', function(e) {
  if (e.target === this) { this.classList.remove('show'); return; }
  var btn = e.target.closest('[data-action]');
  if (btn) {
    var id = this.dataset.id;
    var action = btn.dataset.action;
    this.classList.remove('show');
    handleAction(action, id);
  }
  if (e.target.classList.contains('action-sheet-cancel')) this.classList.remove('show');
});

function handleAction(action, id) {
  haptic(10);
  switch(action) {
    case 'view': openFacture(id); break;
    case 'edit': editIntervention(id); break;
    case 'sign': openSignatureModal(id, 'facture'); break;
    case 'progress':
      var int = interventions.find(function(i) { return i.id === id; });
      if (int) {
        if (int.statut === 'en_cours') setInterventionStatus(id, 'termine');
        else setInterventionStatus(id, 'en_cours');
      }
      break;
    case 'certificate': openCertificateModal(id); break;
    case 'duplicate': duplicateIntervention(id); break;
    case 'followup': addFollowUp(id); break;
    case 'credit': openAvoirModal(id); break;
    case 'pdf': generateFacturePDF(id); break;
    case 'mail': openMailModal(id, 'facture'); break;
    case 'share': shareFacture(id); break;
    case 'delete': showConfirm('Supprimer cette intervention ?', function(c) { if (c) deleteInterventionWithUndo(id); }); break;
  }
}

function deleteInterventionWithUndo(id) {
  var idx = interventions.findIndex(function(i) { return i.id === id; });
  if (idx === -1) return;
  var backup = interventions[idx];
  if (backup.stockDecremented) restoreStock(backup.pieces || []);
  interventions.splice(idx, 1);
  invalidateTotals(id);
  markAsDirty();
  renderAll();
  showToast('Intervention supprimée', 'warning', {
    action: 'Annuler',
    duration: 5000,
    onAction: function() {
      interventions.splice(idx, 0, backup);
      if (backup.stockDecremented) decrementStock(backup.pieces || []);
      invalidateTotals(backup.id);
      markAsDirty();
      renderAll();
      showToast('Intervention restaurée', 'success');
    }
  });
}

function addFollowUp(id) {
  var int = interventions.find(function(i) { return i.id === id; });
  if (!int) return;
  haptic(10);
  openInterventionModal({
    client: int.client, email: int.email, tel: int.tel, adresse: int.adresse,
    type: int.type, taux: int.taux, deplacement: int.deplacement,
    description: 'Suite : ' + (int.description || ''),
    date: new Date(Date.now() + 7 * 86400000).toISOString().slice(0, 10)
  });
}

function duplicateIntervention(id) {
  var int = interventions.find(function(i) { return i.id === id; });
  if (!int) return;
  var copy = JSON.parse(JSON.stringify(int));
  copy.id = 'int_' + Date.now();
  copy.numeroFacture = genererNumeroFacture();
  copy.date = new Date().toISOString().slice(0, 10);
  copy.paye = false;
  copy.statut = 'planifie';
  copy.datePaiement = null;
  copy.signatureClient = null;
  copy.signatureTech = null;
  copy.stockDecremented = false;
  copy.isAvoir = false;
  copy.createdAt = new Date().toISOString();
  interventions.push(copy);
  invalidateTotals();
  markAsDirty();
  renderAll();
  showToast('Intervention dupliquée : ' + copy.numeroFacture, 'success');
}

/* ==========================================================================
   PLANNING
   ========================================================================== */
function getWeekDays(date) {
  var d = new Date(date);
  var day = d.getDay();
  var diff = d.getDate() - day + (day === 0 ? -6 : 1);
  var monday = new Date(d.setDate(diff));
  monday.setHours(0, 0, 0, 0);
  var days = [];
  for (var i = 0; i < 7; i++) {
    var dd = new Date(monday);
    dd.setDate(monday.getDate() + i);
    days.push(dd);
  }
  return days;
}
function getDayWorkMinutes(dateStr) {
  var total = 0;
  interventions.forEach(function(int) {
    if (int.date === dateStr && !int.isAvoir) total += int.duree || 0;
  });
  return total;
}

function renderPlanning() {
  var grid = document.getElementById('planningGrid');
  var days = getWeekDays(planningDate);
  var today = new Date();
  today.setHours(0, 0, 0, 0);
  document.getElementById('planningMonthLabel').textContent = formatMois(days[0]);
  grid.innerHTML = '';
  var dayNames = ['Lun', 'Mar', 'Mer', 'Jeu', 'Ven', 'Sam', 'Dim'];
  days.forEach(function(day, i) {
    var dayStr = toDateStr(day);
    var events = interventions.filter(function(int) { return int.date === dayStr && !int.isAvoir; });
    var isToday = day.getTime() === today.getTime();
    var isSelected = day.toDateString() === selectedPlanningDate.toDateString();
    var workMinutes = getDayWorkMinutes(dayStr);
    var workHours = Math.round(workMinutes / 60 * 10) / 10;
    var isOver = workMinutes > WORK_HOURS_PER_DAY * 60;
    var holidayName = isHoliday(dayStr);
    var el = document.createElement('div');
    el.className = 'planning-day' + (isToday ? ' today' : '') + (isSelected ? ' selected' : '') + (events.length > 0 ? ' has-events' : '') + (holidayName ? ' holiday' : '');
    el.title = holidayName || '';
    el.innerHTML = '<div class="planning-day-name">' + dayNames[i] + '</div>'
      + '<div class="planning-day-num">' + day.getDate() + '</div>'
      + (events.length > 0 ? '<div class="planning-day-events">' + events.length + '</div>' : '')
      + (workMinutes > 0 ? '<div class="planning-day-hours' + (isOver ? ' over' : '') + '">' + workHours + 'h</div>' : '');
    el.addEventListener('click', function() { haptic(8); selectedPlanningDate = new Date(day); renderPlanning(); });
    grid.appendChild(el);
  });
  var eventsContainer = document.getElementById('planningEvents');
  var selStr = toDateStr(selectedPlanningDate);
  var selEvents = interventions.filter(function(int) { return int.date === selStr && !int.isAvoir; });
  selEvents.sort(function(a, b) { return (a.heure || '99:99').localeCompare(b.heure || '99:99'); });
  var workMin = getDayWorkMinutes(selStr);
  var workH = Math.round(workMin / 60 * 10) / 10;
  var holiday = isHoliday(selStr);
  var label = selectedPlanningDate.toLocaleDateString('fr-CH', { weekday: 'long', day: 'numeric', month: 'long' });
  if (workMin > 0) label += ' — ' + workH + 'h / ' + WORK_HOURS_PER_DAY + 'h';
  if (holiday) label += ' 🎉 ' + holiday;
  document.getElementById('planningDayLabel').textContent = label;
  eventsContainer.innerHTML = '';
  if (selEvents.length === 0) eventsContainer.innerHTML = '<div class="empty-state" style="padding:20px;">Aucune intervention ce jour</div>';
  else {
    var frag = document.createDocumentFragment();
    selEvents.forEach(function(int) {
      var typeInfo = TYPES_TACHES[int.type] || TYPES_TACHES.autre;
      var el = document.createElement('div');
      el.className = 'planning-event ' + getStatut(int);
      var heureAffichage = int.heure || '--:--';
      if (int.heure && int.heureFin) heureAffichage = int.heure + ' → ' + int.heureFin;
      el.innerHTML = '<div style="display:flex; align-items:center; gap:10px; flex-wrap:wrap; flex:1;">'
        + '<span class="pe-time">' + heureAffichage + '</span>'
        + '<span class="pe-client">' + escapeHtml(int.client) + '</span>'
        + '<span class="pe-type">' + typeInfo.label + '</span>'
        + '<span style="font-size:0.65rem; color:var(--text-faint);">⏱ ' + formatDuree(int.duree) + '</span></div>'
        + '<div class="pe-actions">'
        + (int.tel ? '<a class="call-ev" href="' + getPhoneHref(int.tel) + '" title="Appeler" onclick="event.stopPropagation();">☎</a>' : '')
        + (int.adresse ? '<a class="route-ev" href="' + getMapsHref(int.adresse) + '" target="_blank" rel="noopener" title="Itinéraire" onclick="event.stopPropagation();">📍</a>' : '')
        + '<button data-id="' + int.id + '" class="edit-ev" title="Modifier">✎</button>'
        + '<button data-id="' + int.id + '" class="view-ev" title="Voir">👁</button>'
        + '</div>';
      el.addEventListener('click', function(e) {
        if (e.target.closest('button') || e.target.closest('a')) return;
        haptic(8);
        openFacture(int.id);
      });
      frag.appendChild(el);
    });
    eventsContainer.appendChild(frag);
    eventsContainer.querySelectorAll('.view-ev').forEach(function(btn) {
      btn.addEventListener('click', function(e) { e.stopPropagation(); haptic(8); openFacture(btn.dataset.id); });
    });
    eventsContainer.querySelectorAll('.edit-ev').forEach(function(btn) {
      btn.addEventListener('click', function(e) { e.stopPropagation(); haptic(8); editIntervention(btn.dataset.id); });
    });
  }
}

/* ==========================================================================
   PARTAGE PLANNING
   ========================================================================== */
function buildPlanningText(format) {
  var days = getWeekDays(planningDate);
  var lines = [];
  var monthLabel = formatMois(days[0]);
  lines.push('📅 PLANNING SEMAINE — ' + monthLabel);
  lines.push('');
  days.forEach(function(day) {
    var dayStr = toDateStr(day);
    var events = interventions.filter(function(int) { return int.date === dayStr && !int.isAvoir; });
    if (events.length === 0) return;
    events.sort(function(a, b) { return (a.heure || '99:99').localeCompare(b.heure || '99:99'); });
    var dayLabel = day.toLocaleDateString('fr-CH', { weekday: 'long', day: 'numeric', month: 'long' });
    lines.push('▶ ' + dayLabel.charAt(0).toUpperCase() + dayLabel.slice(1));
    events.forEach(function(int) {
      var heure = int.heure || '--:--';
      var heureFin = int.heureFin ? ' → ' + int.heureFin : '';
      if (format === 'detailed') {
        var typeInfo = TYPES_TACHES[int.type] || TYPES_TACHES.autre;
        lines.push('   • ' + heure + heureFin + ' — ' + (int.client || 'Client') + ' (' + typeInfo.label + ')');
        if (int.adresse) lines.push('     📍 ' + int.adresse);
        if (int.tel) lines.push('     ☎ ' + int.tel);
        if (int.description) lines.push('     📝 ' + int.description);
      } else {
        lines.push('   • ' + heure + heureFin + ' — ' + (int.client || 'Client'));
      }
    });
    lines.push('');
  });
  var totalEvents = days.reduce(function(sum, day) {
    return sum + interventions.filter(function(int) { return int.date === toDateStr(day) && !int.isAvoir; }).length;
  }, 0);
  lines.push('Total : ' + totalEvents + ' intervention(s)');
  lines.push('');
  lines.push('— ' + settings.nom);
  return lines.join('\n');
}
function openSharePlanningModal() {
  haptic(10);
  var days = getWeekDays(planningDate);
  document.getElementById('shareWeekLabel').value = formatMois(days[0]) + ' (semaine du ' + formatDate(toDateStr(days[0])) + ')';
  updateSharePreview();
  document.getElementById('sharePlanningModal').classList.add('show');
}
function updateSharePreview() {
  var format = document.getElementById('shareFormat').value;
  document.getElementById('sharePreview').value = buildPlanningText(format);
}
document.getElementById('shareFormat').addEventListener('change', updateSharePreview);
document.getElementById('shareWeekBtn').addEventListener('click', openSharePlanningModal);
document.getElementById('closeSharePlanning').addEventListener('click', function() { document.getElementById('sharePlanningModal').classList.remove('show'); });
document.getElementById('shareSmsBtn').addEventListener('click', function() {
  var text = document.getElementById('sharePreview').value;
  window.location.href = 'sms:?body=' + encodeURIComponent(text);
});
document.getElementById('shareMailBtn').addEventListener('click', function() {
  var text = document.getElementById('sharePreview').value;
  var days = getWeekDays(planningDate);
  var subject = 'Planning semaine ' + formatMois(days[0]);
  window.location.href = 'mailto:?subject=' + encodeURIComponent(subject) + '&body=' + encodeURIComponent(text);
});
document.getElementById('shareNativeBtn').addEventListener('click', function() {
  var text = document.getElementById('sharePreview').value;
  if (navigator.share) navigator.share({ title: 'Planning PipePline', text: text }).catch(function() {});
  else showToast('Partage natif non supporté', 'warning');
});
document.getElementById('shareCopyBtn').addEventListener('click', function() {
  var text = document.getElementById('sharePreview').value;
  if (navigator.clipboard) navigator.clipboard.writeText(text).then(function() { showToast('Planning copié', 'success'); });
  else {
    var ta = document.getElementById('sharePreview');
    ta.select();
    document.execCommand('copy');
    showToast('Planning copié', 'success');
  }
});

/* ==========================================================================
   PLANNING MODALE (ajout RDV)
   ========================================================================== */
function updatePlanDureeCalc() {
  var debut = document.getElementById('planHeureDebut').value;
  var fin = document.getElementById('planHeureFin').value;
  var el = document.getElementById('planDureeCalc');
  if (debut && fin) {
    var diff = diffHeures(debut, fin);
    el.value = diff > 0 ? formatDuree(diff) : '—';
  } else el.value = '—';
  checkPlanConflict();
}
function checkPlanConflict() {
  var date = document.getElementById('planDate').value;
  var heureDebut = document.getElementById('planHeureDebut').value;
  var heureFin = document.getElementById('planHeureFin').value;
  var warn = document.getElementById('planConflictWarning');
  var warnText = document.getElementById('planConflictWarningText');
  if (!date || !heureDebut) { warn.classList.remove('show'); return; }
  var conflicts = findConflicts(date, heureDebut, heureFin, editingPlanningId);
  if (conflicts.length > 0) {
    warnText.textContent = '⚠ Conflit : ' + conflicts.length + ' RDV déjà prévu(s) sur ce créneau (' + conflicts.map(function(c) { return c.client; }).join(', ') + ')';
    warn.classList.add('show');
  } else warn.classList.remove('show');
}
function setPlanningHeures(debut, minutes) {
  document.getElementById('planHeureDebut').value = debut;
  document.getElementById('planHeureFin').value = ajouterMinutes(debut, minutes);
  updatePlanDureeCalc();
}
function openPlanningModal(editId) {
  editingPlanningId = editId || null;
  var int = null;
  if (editId) int = interventions.find(function(i) { return i.id === editId; });
  var selStr = toDateStr(selectedPlanningDate);
  document.getElementById('planDate').value = int ? int.date : selStr;
  document.getElementById('planHeureDebut').value = int ? (int.heure || '') : '';
  document.getElementById('planHeureFin').value = int ? (int.heureFin || '') : '';
  document.getElementById('planClient').value = int ? (int.client || '') : '';
  document.getElementById('planTel').value = int ? (int.tel || '') : '';
  document.getElementById('planAdresse').value = int ? (int.adresse || '') : '';
  document.getElementById('planDescription').value = int ? (int.description || '') : '';
  document.getElementById('planTypeSelect').value = int ? (int.type || 'depannage') : 'depannage';
  updatePlanDureeCalc();
  if (editId) {
    document.getElementById('planningModalTitle').textContent = 'Modifier le RDV';
    document.getElementById('confirmPlanning').textContent = '✓ Mettre à jour';
  } else {
    document.getElementById('planningModalTitle').textContent = 'Ajouter au planning';
    document.getElementById('confirmPlanning').textContent = '✓ Ajouter';
  }
  document.getElementById('planningModal').classList.add('show');
  setTimeout(function() { document.getElementById('planClient').focus(); }, 100);
}
document.getElementById('addFromPlanningBtn').addEventListener('click', function() { haptic(10); openPlanningModal(); });
document.getElementById('cancelPlanning').addEventListener('click', function() {
  document.getElementById('planningModal').classList.remove('show');
  editingPlanningId = null;
});
['planHeureDebut', 'planHeureFin', 'planDate'].forEach(function(id) {
  var el = document.getElementById(id);
  if (el) { el.addEventListener('change', updatePlanDureeCalc); el.addEventListener('input', updatePlanDureeCalc); }
});
document.getElementById('planPreset7h').addEventListener('click', function() { setPlanningHeures('08:00', Math.round(8.4 * 60)); });
document.getElementById('planPresetDemi').addEventListener('click', function() { setPlanningHeures('08:00', Math.round(4.2 * 60)); });
document.getElementById('planPreset1h').addEventListener('click', function() { setPlanningHeures('08:00', 60); });
document.getElementById('planPreset2h').addEventListener('click', function() { setPlanningHeures('08:00', 120); });
document.getElementById('planPresetClear').addEventListener('click', function() {
  document.getElementById('planHeureDebut').value = '';
  document.getElementById('planHeureFin').value = '';
  updatePlanDureeCalc();
});
document.getElementById('confirmPlanning').addEventListener('click', function() {
  var type = document.getElementById('planTypeSelect').value;
  var date = document.getElementById('planDate').value;
  var heureDebut = document.getElementById('planHeureDebut').value;
  var heureFin = document.getElementById('planHeureFin').value;
  var client = document.getElementById('planClient').value.trim();
  var tel = document.getElementById('planTel').value.trim();
  var adresse = document.getElementById('planAdresse').value.trim();
  var description = document.getElementById('planDescription').value.trim();
  if (!client) { showToast('Client / Adresse requis', 'warning'); return; }
  if (!description) { showToast('Description requise', 'warning'); return; }
  if (!date) { showToast('Date requise', 'warning'); return; }
  if (!heureDebut) { showToast('Heure de début requise', 'warning'); return; }
  var duree = 0;
  if (heureFin) {
    duree = diffHeures(heureDebut, heureFin);
    if (duree <= 0) { showToast('L\'heure de fin doit être après l\'heure de début', 'warning'); return; }
  }
  haptic(15);
  if (editingPlanningId) {
    var int = interventions.find(function(i) { return i.id === editingPlanningId; });
    if (int) {
      int.type = type; int.date = date; int.heure = heureDebut; int.heureFin = heureFin;
      int.client = client; int.tel = tel; int.adresse = adresse; int.description = description;
      if (duree > 0) int.duree = duree;
      invalidateTotals(int.id);
    }
    editingPlanningId = null;
    showToast('RDV mis à jour', 'success');
  } else {
    var newInt = {
      id: 'int_' + Date.now(),
      numeroFacture: genererNumeroFacture(),
      client: client, email: '', tel: tel, adresse: adresse,
      description: description, type: type,
      date: date, heure: heureDebut, heureFin: heureFin, duree: duree,
      taux: settings.tauxDefaut, deplacement: settings.deplacementDefaut,
      pieces: [], frais: [], photos: [], notes: '', paye: false, statut: 'planifie',
      paysClient: 'CH',
      datePaiement: null, signatureClient: null, signatureTech: null,
      createdAt: new Date().toISOString()
    };
    interventions.push(newInt);
    showToast('Ajouté au planning', 'success');
  }
  document.getElementById('planningModal').classList.remove('show');
  markAsDirty();
  renderAll();
});

/* ==========================================================================
   INTERVENTION MODALE (wizard)
   ========================================================================== */
var interventionModal = document.getElementById('interventionModal');

function editIntervention(id) {
  var int = interventions.find(function(i) { return i.id === id; });
  if (!int) return;
  openInterventionModal({
    editId: int.id, client: int.client, email: int.email,
    tel: int.tel, adresse: int.adresse,
    description: int.description, type: int.type, date: int.date,
    heure: int.heure, heureFin: int.heureFin, duree: int.duree, taux: int.taux,
    deplacement: int.deplacement, notes: int.notes, paye: int.paye,
    statut: int.statut, pieces: int.pieces, frais: int.frais, photos: int.photos,
    paysClient: int.paysClient, noTvaClient: int.noTvaClient,
    kmActive: int.kmActive, kmDistance: int.kmDistance, kmRetour: int.kmRetour, kmTaux: int.kmTaux,
    recurring: int.recurring
  });
}

function setWizardStep(step) {
  currentWizardStep = step;
  interventionModal.querySelectorAll('.wizard-pane').forEach(function(p) {
    p.classList.toggle('active', parseInt(p.dataset.pane) === step);
  });
  interventionModal.querySelectorAll('.wizard-step').forEach(function(s) {
    var n = parseInt(s.dataset.step);
    s.classList.toggle('active', n === step);
    s.classList.toggle('done', n < step);
  });
  document.getElementById('wizardPrev').style.display = step > 1 ? 'inline-flex' : 'none';
  document.getElementById('wizardNext').style.display = step < 3 ? 'inline-flex' : 'none';
  document.getElementById('confirmIntervention').style.display = step === 3 ? 'inline-flex' : 'none';
  setTimeout(function() {
    var pane = interventionModal.querySelector('.wizard-pane[data-pane="' + step + '"]');
    if (pane) {
      var firstInput = pane.querySelector('input, select, textarea');
      if (firstInput && window.innerWidth > 768) firstInput.focus();
    }
  }, 100);
}

function updatePaysClientUI() {
  var pays = document.getElementById('intPays').value;
  var group = document.getElementById('intNoTvaClientGroup');
  if (settings.tvaActive && pays !== 'CH' && pays !== 'autre') group.style.display = 'block';
  else group.style.display = 'none';
}
document.getElementById('intPays').addEventListener('change', updatePaysClientUI);

function openInterventionModal(prefill) {
  prefill = prefill || {};
  tempPieces = (prefill.pieces || []).map(function(p) { return { nom: p.nom, prix: p.prix, qte: p.qte || 1 }; });
  tempFrais = (prefill.frais || []).map(function(f) { return { libelle: f.libelle, montant: f.montant }; });
  tempPhotos = (prefill.photos || []).slice();
  renderPieces();
  renderFrais();
  renderPhotos();
  document.getElementById('interventionModalTitle').textContent = prefill.editId ? 'Modifier l\'intervention' : 'Nouvelle intervention';
  document.getElementById('intTypeSelect').value = prefill.type || 'depannage';
  document.getElementById('intClient').value = prefill.client || '';
  document.getElementById('intEmail').value = prefill.email || '';
  document.getElementById('intTel').value = prefill.tel || '';
  document.getElementById('intAdresse').value = prefill.adresse || '';
  document.getElementById('intPays').value = prefill.paysClient || 'CH';
  document.getElementById('intNoTvaClient').value = prefill.noTvaClient || '';
  updatePaysClientUI();
  document.getElementById('intDescription').value = prefill.description || '';
  document.getElementById('intDate').value = prefill.date || new Date().toISOString().slice(0, 10);
  document.getElementById('intHeure').value = prefill.heure || '';
  document.getElementById('intHeureFin').value = prefill.heureFin || '';
  document.getElementById('intStatutSelect').value = prefill.statut || 'planifie';
  var obj = minutesVersDuree(prefill.duree || 0);
  document.getElementById('intDureeJours').value = obj.jours;
  document.getElementById('intDureeHeures').value = obj.heures;
  document.getElementById('intDureeMinutes').value = obj.minutes;
  updateDureeTotal('int');
  document.getElementById('intTaux').value = prefill.taux || settings.tauxDefaut;
  document.getElementById('intDeplacement').value = prefill.deplacement || settings.deplacementDefaut;
  document.getElementById('intNotes').value = prefill.notes || '';
  document.getElementById('intPaye').checked = prefill.paye || false;
  document.getElementById('intRecurring').checked = prefill.recurring || false;
  document.getElementById('intKmActive').checked = prefill.kmActive || false;
  document.getElementById('intKmDistance').value = prefill.kmDistance || 0;
  document.getElementById('intKmRetour').value = prefill.kmRetour || 2;
  document.getElementById('intKmTaux').value = prefill.kmTaux || settings.kmRate;
  updateKmTotal();
  interventionModal.dataset.editId = prefill.editId || '';
  var isStockDecremented = prefill.editId && interventions.find(function(i) { return i.id === prefill.editId; })?.stockDecremented;
  document.getElementById('addPieceBtn').disabled = !!isStockDecremented;
  if (isStockDecremented) document.getElementById('addPieceBtn').title = 'Stock déjà décrémenté';
  checkIntConflict();
  setWizardStep(1);
  interventionModal.classList.add('show');
}

function checkIntConflict() {
  var date = document.getElementById('intDate').value;
  var heure = document.getElementById('intHeure').value;
  var heureFin = document.getElementById('intHeureFin').value;
  var editId = interventionModal.dataset.editId;
  var warn = document.getElementById('conflictWarning');
  var warnText = document.getElementById('conflictWarningText');
  if (!date || !heure) { warn.classList.remove('show'); return; }
  var conflicts = findConflicts(date, heure, heureFin, editId);
  if (conflicts.length > 0) {
    warnText.textContent = '⚠ Conflit : ' + conflicts.length + ' RDV déjà prévu(s) sur ce créneau (' + conflicts.map(function(c) { return c.client; }).join(', ') + ')';
    warn.classList.add('show');
  } else warn.classList.remove('show');
}
['intDate', 'intHeure', 'intHeureFin'].forEach(function(id) {
  document.getElementById(id).addEventListener('change', checkIntConflict);
  document.getElementById(id).addEventListener('input', checkIntConflict);
});

document.getElementById('intKmActive').addEventListener('change', updateKmTotal);
document.getElementById('intKmDistance').addEventListener('input', updateKmTotal);
document.getElementById('intKmRetour').addEventListener('change', updateKmTotal);
document.getElementById('intKmTaux').addEventListener('input', updateKmTotal);

document.getElementById('addInterventionBtn').addEventListener('click', function() { haptic(10); openInterventionModal(); });
document.getElementById('todayAddBtn').addEventListener('click', function() { haptic(10); openInterventionModal(); });
document.getElementById('addFactureBtn').addEventListener('click', function() { haptic(10); switchTab('interventions'); openInterventionModal(); });
document.getElementById('cancelIntervention').addEventListener('click', function() {
  interventionModal.classList.remove('show');
  interventionModal.dataset.editId = '';
});
document.getElementById('wizardNext').addEventListener('click', function() {
  if (currentWizardStep === 1) {
    var client = document.getElementById('intClient').value.trim();
    if (!client) { showToast('Nom du client requis', 'warning'); return; }
  }
  if (currentWizardStep === 2) {
    var desc = document.getElementById('intDescription').value.trim();
    if (!desc) { showToast('Description requise', 'warning'); return; }
    var duree = dureeVersMinutes(document.getElementById('intDureeJours').value, document.getElementById('intDureeHeures').value, document.getElementById('intDureeMinutes').value);
    if (duree <= 0) { showToast('Durée requise', 'warning'); return; }
  }
  setWizardStep(Math.min(3, currentWizardStep + 1));
});
document.getElementById('wizardPrev').addEventListener('click', function() { setWizardStep(Math.max(1, currentWizardStep - 1)); });

document.getElementById('confirmIntervention').addEventListener('click', function() {
  var editId = interventionModal.dataset.editId;
  var client = document.getElementById('intClient').value.trim();
  var email = document.getElementById('intEmail').value.trim();
  var tel = document.getElementById('intTel').value.trim();
  var adresse = document.getElementById('intAdresse').value.trim();
  var paysClient = document.getElementById('intPays').value;
  var noTvaClient = document.getElementById('intNoTvaClient').value.trim();
  var description = document.getElementById('intDescription').value.trim();
  var type = document.getElementById('intTypeSelect').value;
  var date = document.getElementById('intDate').value;
  var heure = document.getElementById('intHeure').value;
  var heureFin = document.getElementById('intHeureFin').value;
  var statut = document.getElementById('intStatutSelect').value;
  var duree = dureeVersMinutes(document.getElementById('intDureeJours').value, document.getElementById('intDureeHeures').value, document.getElementById('intDureeMinutes').value);
  var taux = parseFloat(document.getElementById('intTaux').value) || settings.tauxDefaut;
  var deplacement = parseFloat(document.getElementById('intDeplacement').value) || 0;
  var notes = document.getElementById('intNotes').value.trim();
  var paye = document.getElementById('intPaye').checked;
  var recurring = document.getElementById('intRecurring').checked;
  var kmActive = document.getElementById('intKmActive').checked;
  var kmDistance = parseFloat(document.getElementById('intKmDistance').value) || 0;
  var kmRetour = parseInt(document.getElementById('intKmRetour').value) || 1;
  var kmTaux = parseFloat(document.getElementById('intKmTaux').value) || settings.kmRate;
  if (!client) { showToast('Nom du client requis', 'warning'); setWizardStep(1); return; }
  if (!description) { showToast('Description requise', 'warning'); setWizardStep(2); return; }
  if (!date) { showToast('Date requise', 'warning'); setWizardStep(2); return; }
  if (duree <= 0) { showToast('Durée requise', 'warning'); setWizardStep(2); return; }
  var pieces = tempPieces.filter(function(p) { return p.nom && p.nom.trim() && parseFloat(p.prix) > 0; });
  var frais = tempFrais.filter(function(f) { return f.libelle && f.libelle.trim() && parseFloat(f.montant) > 0; });
  var photos = tempPhotos.slice();
  haptic(15);
  if (editId) {
    var int = interventions.find(function(i) { return i.id === editId; });
    if (int) {
      var oldPieces = int.pieces || [];
      int.client = client; int.email = email; int.tel = tel; int.adresse = adresse;
      int.paysClient = paysClient; int.noTvaClient = noTvaClient;
      int.description = description;
      int.type = type; int.date = date; int.heure = heure; int.heureFin = heureFin;
      int.duree = duree; int.taux = taux; int.deplacement = deplacement;
      int.notes = notes; int.pieces = pieces; int.frais = frais; int.photos = photos; int.statut = statut;
      int.recurring = recurring;
      int.kmActive = kmActive; int.kmDistance = kmDistance; int.kmRetour = kmRetour; int.kmTaux = kmTaux;
      if (int.stockDecremented) {
        restoreStock(oldPieces);
        decrementStock(pieces);
      }
      if (paye && !int.paye) {
        int.paye = true;
        int.datePaiement = new Date().toISOString().slice(0, 10);
      } else if (!paye && int.paye) {
        int.paye = false;
        int.datePaiement = null;
      }
      invalidateTotals(int.id);
    }
    showToast('Intervention modifiée', 'success');
  } else {
    var newInt = {
      id: 'int_' + Date.now(),
      numeroFacture: genererNumeroFacture(),
      client: client, email: email, tel: tel, adresse: adresse,
      paysClient: paysClient, noTvaClient: noTvaClient,
      description: description, type: type,
      date: date, heure: heure, heureFin: heureFin, duree: duree,
      taux: taux, deplacement: deplacement,
      pieces: pieces, frais: frais, photos: photos, notes: notes, paye: paye, statut: statut,
      recurring: recurring,
      kmActive: kmActive, kmDistance: kmDistance, kmRetour: kmRetour, kmTaux: kmTaux,
      datePaiement: paye ? new Date().toISOString().slice(0, 10) : null,
      signatureClient: null, signatureTech: null, createdAt: new Date().toISOString()
    };
    interventions.push(newInt);
    if (email && !clients.find(function(c) { return c.email === email; })) {
      clients.push({ nom: client, email: email, tel: tel, adresse: adresse });
    }
    showToast('Facture ' + newInt.numeroFacture + ' créée', 'success');
    markTabAsNew('interventions');
  }
  interventionModal.classList.remove('show');
  interventionModal.dataset.editId = '';
  markAsDirty();
  renderAll();
});

/* ==========================================================================
   PIÈCES / FRAIS / PHOTOS
   ========================================================================== */
function renderPieces() {
  var container = document.getElementById('piecesContainer');
  if (!container) return;
  container.innerHTML = '';
  tempPieces.forEach(function(p, i) {
    var stockInfo = getStockStatus(p.nom);
    var row = document.createElement('div');
    row.className = 'piece-row';
    row.innerHTML = '<input type="text" class="piece-nom" placeholder="Nom" value="' + escapeHtml(p.nom || '') + '" data-idx="' + i + '" data-field="nom" />'
      + '<input type="number" class="piece-qte" placeholder="Qté" value="' + (p.qte || 1) + '" min="1" step="1" data-idx="' + i + '" data-field="qte" />'
      + '<input type="number" class="piece-prix" placeholder="Prix CHF" value="' + (p.prix || '') + '" step="0.01" min="0" data-idx="' + i + '" data-field="prix" />'
      + '<button data-idx="' + i + '" class="del-piece" aria-label="Supprimer">✕</button>';
    container.appendChild(row);
    if (stockInfo && stockInfo.low) {
      var warn = document.createElement('div');
      warn.style.cssText = 'font-size:0.65rem; color:var(--danger); margin-top:-4px; margin-bottom:4px; padding-left:4px;';
      warn.textContent = '⚠ Stock bas (' + stockInfo.qte + ')';
      container.appendChild(warn);
    }
  });
  container.querySelectorAll('input').forEach(function(inp) {
    inp.addEventListener('input', function() {
      var idx = parseInt(this.dataset.idx);
      tempPieces[idx][this.dataset.field] = this.value;
      updatePiecesTotal();
    });
    inp.addEventListener('blur', function() {
      if (this.dataset.field === 'nom') renderPieces();
    });
  });
  container.querySelectorAll('.del-piece').forEach(function(btn) {
    btn.addEventListener('click', function() { haptic(8); tempPieces.splice(parseInt(this.dataset.idx), 1); renderPieces(); });
  });
  updatePiecesTotal();
}
function updatePiecesTotal() {
  document.getElementById('piecesTotal').textContent = formatCHF(getPiecesTotal(tempPieces));
}
document.getElementById('addPieceBtn').addEventListener('click', function() {
  haptic(8);
  tempPieces.push({ nom: '', prix: '', qte: 1 });
  renderPieces();
});

function renderFrais() {
  var container = document.getElementById('fraisContainer');
  if (!container) return;
  container.innerHTML = '';
  tempFrais.forEach(function(f, i) {
    var row = document.createElement('div');
    row.className = 'frais-row';
    row.innerHTML = '<input type="text" class="frais-libelle" placeholder="Ex: Carburant" value="' + escapeHtml(f.libelle || '') + '" data-idx="' + i + '" data-field="libelle" />'
      + '<input type="number" class="frais-montant" placeholder="CHF" value="' + (f.montant || '') + '" step="0.01" min="0" data-idx="' + i + '" data-field="montant" />'
      + '<button data-idx="' + i + '" class="del-frais" aria-label="Supprimer">✕</button>';
    container.appendChild(row);
  });
  container.querySelectorAll('input').forEach(function(inp) {
    inp.addEventListener('input', function() {
      var idx = parseInt(this.dataset.idx);
      tempFrais[idx][this.dataset.field] = this.value;
      updateFraisTotal();
    });
  });
  container.querySelectorAll('.del-frais').forEach(function(btn) {
    btn.addEventListener('click', function() { haptic(8); tempFrais.splice(parseInt(this.dataset.idx), 1); renderFrais(); });
  });
  updateFraisTotal();
}
function updateFraisTotal() {
  document.getElementById('fraisTotal').textContent = formatCHF(getFraisTotal(tempFrais));
}
document.getElementById('addFraisBtn').addEventListener('click', function() {
  haptic(8);
  tempFrais.push({ libelle: '', montant: '' });
  renderFrais();
});

function renderDevisPieces() {
  var container = document.getElementById('devisPiecesContainer');
  if (!container) return;
  container.innerHTML = '';
  tempDevisPieces.forEach(function(p, i) {
    var row = document.createElement('div');
    row.className = 'piece-row';
    row.innerHTML = '<input type="text" class="piece-nom" placeholder="Nom" value="' + escapeHtml(p.nom || '') + '" data-idx="' + i + '" data-field="nom" />'
      + '<input type="number" class="piece-qte" placeholder="Qté" value="' + (p.qte || 1) + '" min="1" step="1" data-idx="' + i + '" data-field="qte" />'
      + '<input type="number" class="piece-prix" placeholder="Prix CHF" value="' + (p.prix || '') + '" step="0.01" min="0" data-idx="' + i + '" data-field="prix" />'
      + '<button data-idx="' + i + '" class="del-piece" aria-label="Supprimer">✕</button>';
    container.appendChild(row);
  });
  container.querySelectorAll('input').forEach(function(inp) {
    inp.addEventListener('input', function() {
      var idx = parseInt(this.dataset.idx);
      tempDevisPieces[idx][this.dataset.field] = this.value;
      updateDevisPiecesTotal();
    });
  });
  container.querySelectorAll('.del-piece').forEach(function(btn) {
    btn.addEventListener('click', function() { haptic(8); tempDevisPieces.splice(parseInt(this.dataset.idx), 1); renderDevisPieces(); });
  });
  updateDevisPiecesTotal();
}
function updateDevisPiecesTotal() {
  document.getElementById('devisPiecesTotal').textContent = formatCHF(getPiecesTotal(tempDevisPieces));
}
document.getElementById('addDevisPieceBtn').addEventListener('click', function() {
  haptic(8);
  tempDevisPieces.push({ nom: '', prix: '', qte: 1 });
  renderDevisPieces();
});

function updateDureeTotal(prefix) {
  var j = document.getElementById(prefix + 'DureeJours');
  var h = document.getElementById(prefix + 'DureeHeures');
  var m = document.getElementById(prefix + 'DureeMinutes');
  var badge = document.getElementById(prefix + 'DureeTotalBadge');
  if (!j || !h || !m || !badge) return;
  var total = dureeVersMinutes(j.value, h.value, m.value);
  badge.textContent = 'Total : ' + formatDuree(total) + ' (' + (total / 60).toFixed(1) + 'h)';
}
function applyDureePreset(prefix, heures) {
  var totalMinutes = Math.round(heures * 60);
  var obj = minutesVersDuree(totalMinutes);
  document.getElementById(prefix + 'DureeJours').value = obj.jours;
  document.getElementById(prefix + 'DureeHeures').value = obj.heures;
  document.getElementById(prefix + 'DureeMinutes').value = obj.minutes;
  updateDureeTotal(prefix);
}
['int', 'devis'].forEach(function(prefix) {
  ['DureeJours', 'DureeHeures', 'DureeMinutes'].forEach(function(field) {
    var el = document.getElementById(prefix + field);
    if (el) el.addEventListener('input', function() { updateDureeTotal(prefix); });
  });
});
document.querySelectorAll('.duree-presets button[data-prefix]').forEach(function(btn) {
  btn.addEventListener('click', function() { applyDureePreset(this.dataset.prefix, parseFloat(this.dataset.hours)); });
});

function compressPhotoFile(file, maxW, quality) {
  maxW = maxW || 800;
  quality = quality || 0.7;
  return new Promise(function(resolve, reject) {
    var reader = new FileReader();
    reader.onload = function(e) {
      var img = new Image();
      img.onload = function() {
        var canvas = document.createElement('canvas');
        var ratio = img.width / img.height;
        var w = Math.min(maxW, img.width);
        var h = Math.round(w / ratio);
        canvas.width = w;
        canvas.height = h;
        var ctx = canvas.getContext('2d');
        ctx.drawImage(img, 0, 0, w, h);
        resolve(canvas.toDataURL('image/jpeg', quality));
      };
      img.onerror = reject;
      img.src = e.target.result;
    };
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}
function renderPhotos() {
  var container = document.getElementById('photosPreview');
  if (!container) return;
  container.innerHTML = '';
  tempPhotos.forEach(function(p, i) {
    var item = document.createElement('div');
    item.className = 'photo-item';
    item.innerHTML = '<img src="' + p + '" data-idx="' + i + '" loading="lazy" alt="Photo ' + (i + 1) + '" /><button class="photo-remove" data-idx="' + i + '" aria-label="Supprimer">✕</button>';
    container.appendChild(item);
  });
  var addBtn = document.createElement('button');
  addBtn.type = 'button';
  addBtn.className = 'photo-add-btn';
  addBtn.innerHTML = '+ Ajouter';
  addBtn.addEventListener('click', function() { document.getElementById('photoInput').click(); });
  container.appendChild(addBtn);
  container.querySelectorAll('.photo-remove').forEach(function(btn) {
    btn.addEventListener('click', function(e) { e.stopPropagation(); haptic(8); tempPhotos.splice(parseInt(this.dataset.idx), 1); renderPhotos(); });
  });
  container.querySelectorAll('.photo-item img').forEach(function(img) {
    img.addEventListener('click', function() { openPhotoViewer(tempPhotos, parseInt(this.dataset.idx)); });
  });
}
document.getElementById('addPhotoBtn').addEventListener('click', function() { haptic(10); document.getElementById('photoInput').click(); });
document.getElementById('photoInput').addEventListener('change', function(e) {
  var files = Array.from(e.target.files || []);
  if (!files.length) return;
  if (tempPhotos.length + files.length > 20) showToast('Maximum 20 photos', 'warning');
  var promises = files.slice(0, 20 - tempPhotos.length).map(function(f) { return compressPhotoFile(f, 800, 0.7); });
  Promise.all(promises).then(function(results) {
    tempPhotos = tempPhotos.concat(results);
    renderPhotos();
    haptic(15);
    showToast(files.length + ' photo(s) ajoutée(s)', 'success');
  }).catch(function() { showToast('Erreur chargement photo', 'error'); });
  e.target.value = '';
});
function openPhotoViewer(photos, startIdx) {
  var overlay = document.createElement('div');
  overlay.style.cssText = 'position:fixed; top:0; left:0; right:0; bottom:0; background:rgba(0,0,0,0.92); z-index:100000; display:flex; align-items:center; justify-content:center; padding:20px;';
  var idx = startIdx || 0;
  function render() {
    overlay.innerHTML = '';
    var img = document.createElement('img');
    img.src = photos[idx];
    img.style.cssText = 'max-width:100%; max-height:100%; object-fit:contain; border-radius:12px;';
    overlay.appendChild(img);
    var close = document.createElement('button');
    close.textContent = '✕';
    close.style.cssText = 'position:absolute; top:20px; right:20px; background:white; color:#1a5279; border:none; width:44px; height:44px; border-radius:50%; font-size:1.2rem; cursor:pointer;';
    close.addEventListener('click', function() { document.body.removeChild(overlay); });
    overlay.appendChild(close);
    if (photos.length > 1) {
      var prev = document.createElement('button');
      prev.textContent = '◀';
      prev.style.cssText = 'position:absolute; left:20px; top:50%; transform:translateY(-50%); background:rgba(255,255,255,0.9); color:#1a5279; border:none; width:44px; height:44px; border-radius:50%; font-size:1.2rem; cursor:pointer;';
      prev.addEventListener('click', function() { idx = (idx - 1 + photos.length) % photos.length; render(); });
      overlay.appendChild(prev);
      var next = document.createElement('button');
      next.textContent = '▶';
      next.style.cssText = 'position:absolute; right:20px; top:50%; transform:translateY(-50%); background:rgba(255,255,255,0.9); color:#1a5279; border:none; width:44px; height:44px; border-radius:50%; font-size:1.2rem; cursor:pointer;';
      next.addEventListener('click', function() { idx = (idx + 1) % photos.length; render(); });
      overlay.appendChild(next);
    }
    overlay.onclick = function(e) { if (e.target === overlay) document.body.removeChild(overlay); };
  }
  render();
  document.body.appendChild(overlay);
}

/* ==========================================================================
   DEVIS
   ========================================================================== */
function openDevisModal() {
  editingDevisId = null;
  tempDevisPieces = [];
  renderDevisPieces();
  document.getElementById('devisClient').value = '';
  document.getElementById('devisEmail').value = '';
  document.getElementById('devisTel').value = '';
  document.getElementById('devisAdresse').value = '';
  document.getElementById('devisDescription').value = '';
  document.getElementById('devisDate').value = new Date().toISOString().slice(0, 10);
  document.getElementById('devisValidite').value = '30';
  document.getElementById('devisDureeJours').value = 0;
  document.getElementById('devisDureeHeures').value = 0;
  document.getElementById('devisDureeMinutes').value = 0;
  updateDureeTotal('devis');
  document.getElementById('devisTaux').value = settings.tauxDefaut;
  document.getElementById('devisDeplacement').value = settings.deplacementDefaut;
  document.getElementById('devisNotes').value = '';
  document.getElementById('devisModalTitle').textContent = 'Nouveau devis';
  document.getElementById('confirmDevis').textContent = '✓ Créer le devis';
  document.getElementById('devisModal').classList.add('show');
}
document.getElementById('addDevisBtn').addEventListener('click', function() { haptic(10); openDevisModal(); });
document.getElementById('cancelDevis').addEventListener('click', function() {
  document.getElementById('devisModal').classList.remove('show');
  editingDevisId = null;
});
document.getElementById('confirmDevis').addEventListener('click', function() {
  var client = document.getElementById('devisClient').value.trim();
  var email = document.getElementById('devisEmail').value.trim();
  var tel = document.getElementById('devisTel').value.trim();
  var adresse = document.getElementById('devisAdresse').value.trim();
  var description = document.getElementById('devisDescription').value.trim();
  var date = document.getElementById('devisDate').value;
  var validite = parseInt(document.getElementById('devisValidite').value) || 30;
  var duree = dureeVersMinutes(document.getElementById('devisDureeJours').value, document.getElementById('devisDureeHeures').value, document.getElementById('devisDureeMinutes').value);
  var taux = parseFloat(document.getElementById('devisTaux').value) || settings.tauxDefaut;
  var deplacement = parseFloat(document.getElementById('devisDeplacement').value) || 0;
  var notes = document.getElementById('devisNotes').value.trim();
  if (!client || !description || !date) { showToast('Champs obligatoires manquants', 'warning'); return; }
  var pieces = tempDevisPieces.filter(function(p) { return p.nom && p.nom.trim() && parseFloat(p.prix) > 0; });
  haptic(15);
  if (editingDevisId) {
    var d = devisList.find(function(x) { return x.id === editingDevisId; });
    if (d) {
      d.client = client; d.email = email; d.tel = tel; d.adresse = adresse;
      d.description = description; d.date = date; d.validite = validite;
      d.duree = duree; d.taux = taux; d.deplacement = deplacement;
      d.pieces = pieces; d.notes = notes;
      invalidateTotals(d.id);
    }
    editingDevisId = null;
    showToast('Devis modifié', 'success');
  } else {
    var newDevis = {
      id: 'dev_' + Date.now(),
      numeroDevis: genererNumeroDevis(),
      client: client, email: email, tel: tel, adresse: adresse,
      description: description, date: date,
      validite: validite, duree: duree, taux: taux, deplacement: deplacement,
      pieces: pieces, notes: notes, statut: 'en_attente',
      paysClient: 'CH',
      signatureClient: null, signatureTech: null, createdAt: new Date().toISOString()
    };
    devisList.push(newDevis);
    showToast('Devis ' + newDevis.numeroDevis + ' créé', 'success');
    markTabAsNew('devis');
  }
  document.getElementById('devisModal').classList.remove('show');
  markAsDirty();
  renderAll();
});

function editDevis(id) {
  var d = devisList.find(function(x) { return x.id === id; });
  if (!d) return;
  editingDevisId = id;
  tempDevisPieces = (d.pieces || []).map(function(p) { return { nom: p.nom, prix: p.prix, qte: p.qte || 1 }; });
  renderDevisPieces();
  document.getElementById('devisClient').value = d.client || '';
  document.getElementById('devisEmail').value = d.email || '';
  document.getElementById('devisTel').value = d.tel || '';
  document.getElementById('devisAdresse').value = d.adresse || '';
  document.getElementById('devisDescription').value = d.description || '';
  document.getElementById('devisDate').value = d.date || new Date().toISOString().slice(0, 10);
  document.getElementById('devisValidite').value = d.validite || 30;
  var dureeObj = minutesVersDuree(d.duree || 0);
  document.getElementById('devisDureeJours').value = dureeObj.jours;
  document.getElementById('devisDureeHeures').value = dureeObj.heures;
  document.getElementById('devisDureeMinutes').value = dureeObj.minutes;
  updateDureeTotal('devis');
  document.getElementById('devisTaux').value = d.taux || settings.tauxDefaut;
  document.getElementById('devisDeplacement').value = d.deplacement || settings.deplacementDefaut;
  document.getElementById('devisNotes').value = d.notes || '';
  document.getElementById('devisModalTitle').textContent = 'Modifier le devis';
  document.getElementById('confirmDevis').textContent = '✓ Mettre à jour';
  document.getElementById('devisModal').classList.add('show');
}

/* ==========================================================================
   DEVIS DETAIL
   ========================================================================== */
function openDevisDetail(id) {
  var d = devisList.find(function(x) { return x.id === id; });
  if (!d) return;
  currentDevisId = id;
  var heures = (d.duree || 0) / 60;
  var mainOeuvre = heures * (d.taux || settings.tauxDefaut);
  var ht = getTotalHT(d);
  var ttc = getTotalTTC(d);
  var tvaMontant = getTvaMontant(d);
  document.getElementById('devisNumeroDisplay').textContent = d.numeroDevis || '';
  var html = '';
  html += '<div class="facture-line"><span>Client</span><strong>' + escapeHtml(d.client) + '</strong></div>';
  if (d.email) html += '<div class="facture-line"><span>Email</span><span>' + escapeHtml(d.email) + '</span></div>';
  if (d.tel) html += '<div class="facture-line"><span>Téléphone</span><a href="' + getPhoneHref(d.tel) + '" style="color:var(--accent); font-weight:600;">' + escapeHtml(d.tel) + '</a></div>';
  if (d.adresse) html += '<div class="facture-line"><span>Adresse</span><a href="' + getMapsHref(d.adresse) + '" target="_blank" rel="noopener" style="color:var(--accent); font-weight:600;">' + escapeHtml(d.adresse) + '</a></div>';
  html += '<div class="facture-line"><span>Date</span><span>' + formatDate(d.date) + '</span></div>';
  html += '<div class="facture-line"><span>Validité</span><span>' + d.validite + ' jours</span></div>';
  html += '<div class="facture-line"><span>Description</span><span style="text-align:right; max-width:60%;">' + escapeHtml(d.description) + '</span></div>';
  if (d.notes) html += '<div class="facture-line"><span>Notes</span><span style="text-align:right; max-width:60%; font-style:italic; color:var(--text-faint);">' + escapeHtml(d.notes) + '</span></div>';
  html += '<div class="facture-line" style="margin-top:10px; padding-top:10px; border-top:1px solid var(--border-1);"><span>Main d\'œuvre (' + formatDuree(d.duree) + ')</span><span>' + (d.taux || settings.tauxDefaut) + ' CHF/h = ' + mainOeuvre.toFixed(2) + ' CHF</span></div>';
  html += '<div class="facture-line"><span>Déplacement</span><span>' + (d.deplacement || 0).toFixed(2) + ' CHF</span></div>';
  if (d.pieces && d.pieces.length > 0) {
    d.pieces.forEach(function(p) {
      var qte = parseInt(p.qte) || 1;
      html += '<div class="facture-line"><span>• ' + escapeHtml(p.nom) + (qte > 1 ? ' ×' + qte : '') + '</span><span>' + (parseFloat(p.prix) * qte).toFixed(2) + ' CHF</span></div>';
    });
  }
  html += '<div class="facture-line" style="font-weight:600;"><span>Total HT</span><span>' + formatCHF(ht) + '</span></div>';
  if (settings.tvaActive) {
    if (isAutoliquidation(d)) html += '<div class="facture-line"><span>Autoliquidation</span><span>0,00 CHF (TVA due par le client)</span></div>';
    else html += '<div class="facture-line"><span>TVA (' + settings.tva + '%)</span><span>' + formatCHF(tvaMontant) + '</span></div>';
  } else html += '<div class="facture-line"><span style="color:var(--text-faint); font-style:italic;">TVA non applicable</span><span></span></div>';
  html += '<div class="facture-total-highlight"><div><div class="total-label">Total TTC</div>' + (settings.tvaActive && !isAutoliquidation(d) ? '<div class="total-sub">dont TVA ' + formatCHF(tvaMontant) + '</div>' : '<div class="total-sub">HT</div>') + '</div><div class="total-value">' + formatCHF(ttc) + '</div></div>';
  var statutLabel = d.statut === 'accepte' ? 'Accepté' : (d.statut === 'refuse' ? 'Refusé' : 'En attente');
  var statutColor = d.statut === 'accepte' ? 'var(--success)' : (d.statut === 'refuse' ? 'var(--danger)' : '#b16b1a');
  html += '<div style="margin-top:12px; padding:10px; border-radius:var(--r-sm); text-align:center; font-weight:600; font-size:0.85rem; background:' + statutColor + '20; color:' + statutColor + ';">' + statutLabel + '</div>';
  document.getElementById('devisDetailContent').innerHTML = html;
  document.getElementById('acceptDevisBtn').style.display = d.statut === 'accepte' ? 'none' : 'inline-flex';
  document.getElementById('refuseDevisBtn').style.display = d.statut === 'refuse' ? 'none' : 'inline-flex';
  document.getElementById('convertDevisBtn').style.display = d.statut === 'accepte' ? 'inline-flex' : 'none';
  document.getElementById('devisDetailModal').classList.add('show');
}
document.getElementById('closeDevisDetail').addEventListener('click', function() { document.getElementById('devisDetailModal').classList.remove('show'); });
document.getElementById('acceptDevisBtn').addEventListener('click', function() {
  haptic(15);
  var d = devisList.find(function(x) { return x.id === currentDevisId; });
  if (d) { d.statut = 'accepte'; markAsDirty(); renderAll(); openDevisDetail(currentDevisId); showToast('Devis accepté', 'success'); }
});
document.getElementById('refuseDevisBtn').addEventListener('click', function() {
  haptic(15);
  var d = devisList.find(function(x) { return x.id === currentDevisId; });
  if (d) { d.statut = 'refuse'; markAsDirty(); renderAll(); openDevisDetail(currentDevisId); showToast('Devis refusé', 'warning'); }
});
document.getElementById('editDevisBtn').addEventListener('click', function() {
  if (!currentDevisId) return;
  document.getElementById('devisDetailModal').classList.remove('show');
  editDevis(currentDevisId);
});

/* ==========================================================================
   CONVERSION DEVIS → FACTURE
   ========================================================================== */
function updateConvertAcompte() {
  var d = devisList.find(function(x) { return x.id === convertDevisSourceId; });
  if (!d) return;
  var ttc = getTotalTTC(d);
  var actif = document.getElementById('convertAcompteActive').checked;
  var fields = document.getElementById('convertAcompteFields');
  if (actif) fields.classList.add('show');
  else fields.classList.remove('show');
  var pct = parseFloat(document.getElementById('convertAcomptePct').value) || 0;
  var acompte = ttc * pct / 100;
  var reste = ttc - acompte;
  document.getElementById('convertAcompteMontant').value = formatCHF(acompte);
  document.getElementById('convertResteMontant').value = formatCHF(reste);
  var info = document.getElementById('convertInfo');
  if (actif) info.innerHTML = 'Deux factures seront créées :<br>• <strong>Acompte ' + pct + '%</strong> = ' + formatCHF(acompte) + ' (impayée)<br>• <strong>Solde</strong> = ' + formatCHF(reste) + ' (sera facturé plus tard)';
  else info.textContent = 'Sans acompte, une seule facture sera créée au montant total du devis : ' + formatCHF(ttc);
}
document.getElementById('convertAcompteActive').addEventListener('change', updateConvertAcompte);
document.getElementById('convertAcomptePct').addEventListener('input', updateConvertAcompte);
document.getElementById('convertDevisBtn').addEventListener('click', function() {
  haptic(10);
  var d = devisList.find(function(x) { return x.id === currentDevisId; });
  if (!d) return;
  convertDevisSourceId = currentDevisId;
  document.getElementById('convertClientDisplay').value = d.client || '—';
  document.getElementById('convertTotalDisplay').value = formatCHF(getTotalTTC(d));
  var ttc = getTotalTTC(d);
  var autoAcompte = ttc > (settings.acompteSeuil || 5000);
  document.getElementById('convertAcompteActive').checked = autoAcompte;
  document.getElementById('convertAcomptePct').value = 30;
  var dateSolde = new Date();
  dateSolde.setDate(dateSolde.getDate() + 30);
  document.getElementById('convertEcheanceSolde').value = dateSolde.toISOString().slice(0, 10);
  updateConvertAcompte();
  if (autoAcompte) {
    setTimeout(function() {
      showToast('💡 Devis > ' + formatCHF(settings.acompteSeuil) + ' — Acompte 30% pré-sélectionné', 'warning');
    }, 400);
  }
  document.getElementById('convertDevisModal').classList.add('show');
});
document.getElementById('cancelConvertDevis').addEventListener('click', function() {
  document.getElementById('convertDevisModal').classList.remove('show');
  convertDevisSourceId = null;
});
document.getElementById('confirmConvertDevis').addEventListener('click', function() {
  var d = devisList.find(function(x) { return x.id === convertDevisSourceId; });
  if (!d) return;
  var ttc = getTotalTTC(d);
  var actif = document.getElementById('convertAcompteActive').checked;
  var pct = parseFloat(document.getElementById('convertAcomptePct').value) || 0;
  var today = new Date().toISOString().slice(0, 10);
  var echeanceSolde = document.getElementById('convertEcheanceSolde').value;
  haptic(15);
  var fraisCopy = (d.frais || []).map(function(f) { return { libelle: f.libelle, montant: f.montant }; });
  if (actif && pct > 0 && pct < 100) {
    var acompteMontant = ttc * pct / 100;
    var factureAcompte = {
      id: 'int_' + Date.now() + '_a',
      numeroFacture: genererNumeroFacture(),
      client: d.client, email: d.email, tel: d.tel, adresse: d.adresse,
      paysClient: d.paysClient || 'CH',
      description: 'Acompte ' + pct + '% — ' + (d.description || ''),
      type: 'autre', date: today, heure: '', heureFin: '',
      duree: 0, taux: 0, deplacement: 0,
      pieces: [], frais: [], photos: [], notes: 'Acompte sur devis ' + d.numeroDevis,
      paye: false, statut: 'planifie', datePaiement: null,
      signatureClient: d.signatureClient, signatureTech: d.signatureTech,
      fromDevis: d.numeroDevis, factureType: 'acompte',
      montantForceHT: settings.tvaActive ? acompteMontant / (1 + settings.tva / 100) : acompteMontant,
      createdAt: new Date().toISOString()
    };
    var resteMontant = ttc - acompteMontant;
    var factureSolde = {
      id: 'int_' + Date.now() + '_s',
      numeroFacture: genererNumeroFacture(),
      client: d.client, email: d.email, tel: d.tel, adresse: d.adresse,
      paysClient: d.paysClient || 'CH',
      description: 'Solde — ' + (d.description || ''),
      type: 'autre', date: echeanceSolde || today, heure: '', heureFin: '',
      duree: d.duree, taux: d.taux, deplacement: d.deplacement,
      pieces: (d.pieces || []).slice(), frais: fraisCopy, photos: [], notes: 'Solde devis ' + d.numeroDevis + ' (acompte ' + pct + '% déduit)',
      paye: false, statut: 'planifie', datePaiement: null,
      signatureClient: d.signatureClient, signatureTech: d.signatureTech,
      fromDevis: d.numeroDevis, factureType: 'solde',
      montantForceHT: settings.tvaActive ? resteMontant / (1 + settings.tva / 100) : resteMontant,
      createdAt: new Date().toISOString()
    };
    interventions.push(factureAcompte);
    interventions.push(factureSolde);
    d.statut = 'accepte';
    d.converti = true;
    invalidateTotals();
    markAsDirty();
    renderAll();
    document.getElementById('convertDevisModal').classList.remove('show');
    document.getElementById('devisDetailModal').classList.remove('show');
    switchTab('interventions');
    showToast('2 factures créées : acompte ' + formatCHF(acompteMontant) + ' + solde ' + formatCHF(resteMontant), 'success');
  } else {
    var newInt = {
      id: 'int_' + Date.now(),
      numeroFacture: genererNumeroFacture(),
      client: d.client, email: d.email, tel: d.tel, adresse: d.adresse,
      paysClient: d.paysClient || 'CH',
      description: d.description, type: 'autre',
      date: echeanceSolde || today,
      heure: '', heureFin: '', duree: d.duree, taux: d.taux, deplacement: d.deplacement,
      pieces: (d.pieces || []).slice(), frais: fraisCopy, photos: [], notes: d.notes, paye: false,
      statut: 'planifie', datePaiement: null,
      signatureClient: d.signatureClient, signatureTech: d.signatureTech,
      fromDevis: d.numeroDevis, createdAt: new Date().toISOString()
    };
    interventions.push(newInt);
    d.statut = 'accepte';
    d.converti = true;
    invalidateTotals();
    markAsDirty();
    renderAll();
    document.getElementById('convertDevisModal').classList.remove('show');
    document.getElementById('devisDetailModal').classList.remove('show');
    switchTab('interventions');
    openFacture(newInt.id);
    showToast('Devis converti en facture ' + newInt.numeroFacture, 'success');
  }
  markTabAsNew('factures');
  convertDevisSourceId = null;
});
document.getElementById('downloadDevisPdfBtn').addEventListener('click', function() { if (currentDevisId) generateDevisPDF(currentDevisId); });
document.getElementById('sendDevisMailBtn').addEventListener('click', function() { if (currentDevisId) openMailModal(currentDevisId, 'devis'); });
document.getElementById('shareDevisBtn').addEventListener('click', function() { if (currentDevisId) shareDevis(currentDevisId); });

/* ==========================================================================
   AVOIR
   ========================================================================== */
function openAvoirModal(sourceFactureId) {
  currentAvoirSourceFactureId = sourceFactureId || null;
  var select = document.getElementById('avoirFactureRef');
  select.innerHTML = '<option value="">— Aucune (avoir libre) —</option>';
  interventions.filter(function(i) { return !i.isAvoir; })
    .sort(function(a, b) { return (b.date || '').localeCompare(a.date || ''); })
    .slice(0, 30)
    .forEach(function(int) {
      var opt = document.createElement('option');
      opt.value = int.id;
      opt.textContent = (int.numeroFacture || '—') + ' • ' + (int.client || '—') + ' • ' + formatCHF(getTotalTTC(int));
      select.appendChild(opt);
    });
  if (sourceFactureId) {
    select.value = sourceFactureId;
    var src = interventions.find(function(i) { return i.id === sourceFactureId; });
    if (src) {
      document.getElementById('avoirClient').value = src.client || '';
      document.getElementById('avoirMontant').value = Math.abs(getTotalTTC(src)).toFixed(2);
      document.getElementById('avoirDescription').value = 'Avoir sur facture ' + (src.numeroFacture || '');
    }
  } else {
    document.getElementById('avoirClient').value = '';
    document.getElementById('avoirMontant').value = '';
    document.getElementById('avoirDescription').value = '';
  }
  document.getElementById('avoirDate').value = new Date().toISOString().slice(0, 10);
  document.getElementById('avoirModal').classList.add('show');
}
document.getElementById('avoirFactureRef').addEventListener('change', function() {
  var id = this.value;
  if (!id) return;
  var src = interventions.find(function(i) { return i.id === id; });
  if (src) {
    document.getElementById('avoirClient').value = src.client || '';
    document.getElementById('avoirMontant').value = Math.abs(getTotalTTC(src)).toFixed(2);
    document.getElementById('avoirDescription').value = 'Avoir sur facture ' + (src.numeroFacture || '');
  }
});
document.getElementById('cancelAvoir').addEventListener('click', function() {
  document.getElementById('avoirModal').classList.remove('show');
  currentAvoirSourceFactureId = null;
});
document.getElementById('addAvoirBtn').addEventListener('click', function() { haptic(10); openAvoirModal(); });
document.getElementById('confirmAvoir').addEventListener('click', function() {
  var client = document.getElementById('avoirClient').value.trim();
  var montant = parseFloat(document.getElementById('avoirMontant').value);
  var motif = document.getElementById('avoirMotif').value;
  var description = document.getElementById('avoirDescription').value.trim();
  var date = document.getElementById('avoirDate').value;
  var sourceId = document.getElementById('avoirFactureRef').value;
  if (!client) { showToast('Client requis', 'warning'); return; }
  if (!montant || montant <= 0) { showToast('Montant positif requis', 'warning'); return; }
  if (!date) { showToast('Date requise', 'warning'); return; }
  var motifLabels = {
    annulation: 'Annulation totale',
    retour_piece: 'Retour de pièce',
    correction_prix: 'Correction de prix',
    geste_commercial: 'Geste commercial',
    erreur_facturation: 'Erreur de facturation',
    autre: 'Autre'
  };
  var srcFacture = sourceId ? interventions.find(function(i) { return i.id === sourceId; }) : null;
  var newAvoir = {
    id: 'avr_' + Date.now(),
    numeroFacture: genererNumeroAvoir(),
    isAvoir: true,
    client: client,
    email: srcFacture ? srcFacture.email : '',
    tel: srcFacture ? srcFacture.tel : '',
    adresse: srcFacture ? srcFacture.adresse : '',
    description: '↩ AVOIR — ' + (motifLabels[motif] || motif) + (description ? ' — ' + description : ''),
    type: 'credit',
    date: date,
    heure: '', heureFin: '', duree: 0, taux: 0, deplacement: 0,
    pieces: [], frais: [], photos: [], notes: description,
    paye: true, statut: 'termine',
    datePaiement: date,
    signatureClient: null, signatureTech: null,
    paysClient: 'CH',
    avoirMotif: motif,
    avoirSourceFacture: srcFacture ? srcFacture.numeroFacture : null,
    montantForceHT: -Math.abs(montant),
    createdAt: new Date().toISOString()
  };
  interventions.push(newAvoir);
  invalidateTotals();
  markAsDirty();
  renderAll();
  document.getElementById('avoirModal').classList.remove('show');
  currentAvoirSourceFactureId = null;
  markTabAsNew('factures');
  haptic(15);
  showToast('Avoir ' + newAvoir.numeroFacture + ' créé (' + formatCHF(montant) + ')', 'purple');
});

/* ==========================================================================
   RENDU FACTURES
   ========================================================================== */
function renderFactures() {
  var container = document.getElementById('factureList');
  var term = searchFactureTerm.trim().toLowerCase();
  var filtered = interventions.filter(function(int) {
    if (!term) return true;
    return (int.numeroFacture || '').toLowerCase().indexOf(term) !== -1
      || (int.client || '').toLowerCase().indexOf(term) !== -1
      || (int.date || '').toLowerCase().indexOf(term) !== -1;
  });
  if (currentFactureFilter !== 'all') filtered = filterInterventions(filtered, currentFactureFilter);
  filtered = applySortAndDateFilter(filtered, currentSortFactures, '', '');
  container.innerHTML = '';
  if (filtered.length === 0) {
    container.innerHTML = '<div class="empty-state">Aucune facture</div>';
    return;
  }
  var frag = document.createDocumentFragment();
  filtered.forEach(function(int) {
    var total = getTotalTTC(int);
    var overdue = isOverdue(int);
    var statut = getStatut(int);
    var item = document.createElement('div');
    item.className = 'facture-item ' + statut;
    item.dataset.id = int.id;
    var statutHtml = '';
    if (int.isAvoir) statutHtml = '<span style="color:var(--purple); font-weight:600; font-size:0.7rem;">↩ Avoir</span>';
    else if (int.paye) statutHtml = '<span style="color:var(--success); font-weight:600; font-size:0.7rem;">✓ Payée</span>';
    else if (int.statut === 'en_cours') statutHtml = '<span style="color:var(--accent); font-weight:600; font-size:0.7rem;">⏳ En cours</span>';
    else if (overdue) statutHtml = '<span style="color:var(--warning); font-weight:600; font-size:0.7rem;">⏰ En retard</span>';
    else if (int.statut === 'termine') statutHtml = '<span style="color:#0288d1; font-weight:600; font-size:0.7rem;">✓ Terminé (à encaisser)</span>';
    else statutHtml = '<span style="color:var(--danger); font-weight:600; font-size:0.7rem;">⚠ Impayée</span>';

    item.innerHTML = '<div style="display:flex; align-items:center; gap:12px; flex-wrap:wrap; flex:1;">'
      + '<span class="fact-num" ' + (int.isAvoir ? 'style="background:#f3e5f5; color:var(--purple);"' : '') + '>' + (int.numeroFacture || '—') + '</span>'
      + '<span class="fact-client">' + escapeHtml(int.client || '—') + '</span>'
      + (int.signatureClient ? '<span style="font-size:0.6rem; color:var(--success);">✍ Signée</span>' : '')
      + '</div>'
      + '<div class="fact-info">'
      + '<span>📅 ' + formatDate(int.date) + '</span>'
      + '<span class="fact-total" ' + (int.isAvoir ? 'style="color:var(--purple);"' : '') + '>' + formatCHF(total) + '</span>'
      + statutHtml
      + '</div>'
      + '<div class="fact-actions">'
      + (int.tel ? '<a class="call" href="' + getPhoneHref(int.tel) + '" title="Appeler" onclick="event.stopPropagation();">☎</a>' : '')
      + (int.adresse && !int.isAvoir ? '<a class="route" href="' + getMapsHref(int.adresse) + '" target="_blank" rel="noopener" title="Itinéraire" onclick="event.stopPropagation();">📍</a>' : '')
      + '<button class="view" data-id="' + int.id + '" title="Voir">👁</button>'
      + (!int.paye && !int.isAvoir ? '<button class="pay" data-id="' + int.id + '" title="Payée">✓</button>' : '')
      + '<button class="more" data-id="' + int.id + '" title="Plus">⋯</button>'
      + '</div>';
    frag.appendChild(item);
  });
  container.appendChild(frag);
  container.querySelectorAll('.facture-item').forEach(function(item) {
    item.addEventListener('click', function(e) {
      if (e.target.closest('.fact-actions button') || e.target.closest('a')) return;
      haptic(8);
      openFacture(item.dataset.id);
    });
  });
  container.querySelectorAll('.fact-actions .view').forEach(function(btn) {
    btn.addEventListener('click', function(e) { e.stopPropagation(); haptic(8); openFacture(btn.dataset.id); });
  });
  container.querySelectorAll('.fact-actions .pay').forEach(function(btn) {
    btn.addEventListener('click', function(e) {
      e.stopPropagation();
      haptic(15);
      showConfirm('Marquer comme payée ?', function(c) { if (c) markAsPaid(btn.dataset.id); });
    });
  });
  container.querySelectorAll('.fact-actions .more').forEach(function(btn) {
    btn.addEventListener('click', function(e) { e.stopPropagation(); openActionSheet(btn.dataset.id); });
  });
}

/* ==========================================================================
   RENDU DEVIS
   ========================================================================== */
function renderDevis() {
  var container = document.getElementById('devisList');
  var term = searchDevisTerm.trim().toLowerCase();
  var filtered = devisList.filter(function(d) {
    if (!term) return true;
    return (d.numeroDevis || '').toLowerCase().indexOf(term) !== -1
      || (d.client || '').toLowerCase().indexOf(term) !== -1
      || (d.date || '').toLowerCase().indexOf(term) !== -1;
  });
  filtered = applySortAndDateFilter(filtered, currentSortDevis, '', '');
  container.innerHTML = '';
  if (filtered.length === 0) {
    container.innerHTML = '<div class="empty-state">Aucun devis</div>';
    return;
  }
  var frag = document.createDocumentFragment();
  filtered.forEach(function(d) {
    var total = getTotalTTC(d);
    var statusLabel, statusClass, borderClass;
    if (d.statut === 'accepte') { statusLabel = 'Accepté'; statusClass = 'accepted'; borderClass = 'devis-accepted'; }
    else if (d.statut === 'refuse') { statusLabel = 'Refusé'; statusClass = 'refused'; borderClass = 'devis-refused'; }
    else { statusLabel = 'En attente'; statusClass = 'pending'; borderClass = 'devis-pending'; }
    var item = document.createElement('div');
    item.className = 'facture-item ' + borderClass;
    item.dataset.id = d.id;
    item.innerHTML = '<div style="display:flex; align-items:center; gap:12px; flex-wrap:wrap; flex:1;">'
      + '<span class="fact-num" style="background:var(--accent-light); color:var(--info);">' + (d.numeroDevis || '—') + '</span>'
      + '<span class="fact-client">' + escapeHtml(d.client || '—') + '</span>'
      + '<span class="devis-badge ' + statusClass + '">' + statusLabel + '</span>'
      + '</div>'
      + '<div class="fact-info">'
      + '<span>📅 ' + formatDate(d.date) + '</span>'
      + '<span class="fact-total">' + formatCHF(total) + '</span>'
      + '</div>'
      + '<div class="fact-actions">'
      + (d.tel ? '<a class="call" href="' + getPhoneHref(d.tel) + '" title="Appeler" onclick="event.stopPropagation();">☎</a>' : '')
      + '<button class="view" data-id="' + d.id + '" title="Voir">👁</button>'
      + '<button class="more" data-id="' + d.id + '" title="Plus">⋯</button>'
      + '</div>';
    frag.appendChild(item);
  });
  container.appendChild(frag);
  container.querySelectorAll('.facture-item').forEach(function(item) {
    item.addEventListener('click', function(e) {
      if (e.target.closest('.fact-actions button') || e.target.closest('a')) return;
      haptic(8);
      openDevisDetail(item.dataset.id);
    });
  });
  container.querySelectorAll('.fact-actions .view').forEach(function(btn) {
    btn.addEventListener('click', function(e) { e.stopPropagation(); haptic(8); openDevisDetail(btn.dataset.id); });
  });
  container.querySelectorAll('.fact-actions .more').forEach(function(btn) {
    btn.addEventListener('click', function(e) { e.stopPropagation(); haptic(8); openDevisDetail(btn.dataset.id); });
  });
}

/* ==========================================================================
   PARTAGE
   ========================================================================== */
function shareFacture(id) {
  var int = interventions.find(function(i) { return i.id === id; });
  if (!int) return;
  showToast('Génération du PDF...', 'info');
  generateFacturePDFBlob(int).then(function(blob) {
    if (!blob) { showToast('Impossible de générer le PDF', 'error'); return; }
    var file = new File([blob], (int.isAvoir ? 'Avoir_' : 'Facture_') + (int.numeroFacture || 'Client').replace(/[^a-zA-Z0-9\-]/g, '_') + '.pdf', { type: 'application/pdf' });
    if (navigator.canShare && navigator.canShare({ files: [file] })) {
      navigator.share({
        files: [file],
        title: (int.isAvoir ? 'Avoir ' : 'Facture ') + int.numeroFacture,
        text: (int.isAvoir ? 'Avoir ' : 'Facture ') + int.numeroFacture + ' - ' + formatCHF(getTotalTTC(int))
      }).catch(function(err) {
        if (err.name !== 'AbortError') downloadBlob(blob, file.name);
      });
    } else {
      downloadBlob(blob, file.name);
      showToast('Partage non supporté → PDF téléchargé', 'info');
    }
  });
}
function shareDevis(id) {
  var d = devisList.find(function(x) { return x.id === id; });
  if (!d) return;
  showToast('Génération du PDF...', 'info');
  generateDevisPDFBlob(d).then(function(blob) {
    if (!blob) { showToast('Impossible de générer le PDF', 'error'); return; }
    var file = new File([blob], 'Devis_' + (d.numeroDevis || 'Client').replace(/[^a-zA-Z0-9\-]/g, '_') + '.pdf', { type: 'application/pdf' });
    if (navigator.canShare && navigator.canShare({ files: [file] })) {
      navigator.share({ files: [file], title: 'Devis ' + d.numeroDevis, text: 'Devis ' + d.numeroDevis + ' - ' + formatCHF(getTotalTTC(d)) })
        .catch(function(err) { if (err.name !== 'AbortError') downloadBlob(blob, file.name); });
    } else {
      downloadBlob(blob, file.name);
      showToast('Partage non supporté → PDF téléchargé', 'info');
    }
  });
}
function downloadBlob(blob, filename) {
  var url = URL.createObjectURL(blob);
  var link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.click();
  setTimeout(function() { URL.revokeObjectURL(url); }, 1000);
}

/* ==========================================================================
   OUVERTURE FACTURE
   ========================================================================== */
function openFacture(id) {
  var int = interventions.find(function(i) { return i.id === id; });
  if (!int) return;
  currentFactureId = id;
  var typeInfo = TYPES_TACHES[int.type] || TYPES_TACHES.autre;
  var heures = (int.duree || 0) / 60;
  var mainOeuvre = heures * (int.taux || settings.tauxDefaut);
  var ht = getTotalHT(int);
  var ttc = getTotalTTC(int);
  var tvaMontant = getTvaMontant(int);
  document.getElementById('factureNumeroDisplay').textContent = int.numeroFacture || '';
  var html = '';
  if (int.isAvoir) {
    html += '<div style="margin-bottom:12px; padding:10px 14px; background:#f3e5f5; border-radius:var(--r-sm); border-left:4px solid var(--purple); font-size:0.85rem; color:#6a1b9a; font-weight:600;">↩ AVOIR — ' + (int.avoirSourceFacture ? 'Réf. facture ' + escapeHtml(int.avoirSourceFacture) : 'Avoir libre') + '</div>';
  }
  html += '<div class="facture-line"><span>Client</span><strong>' + escapeHtml(int.client || '—') + '</strong></div>';
  if (int.email) html += '<div class="facture-line"><span>Email</span><span>' + escapeHtml(int.email) + '</span></div>';
  if (int.tel) html += '<div class="facture-line"><span>Téléphone</span><a href="' + getPhoneHref(int.tel) + '" style="color:var(--accent); font-weight:600;">' + escapeHtml(int.tel) + '</a></div>';
  if (int.adresse) html += '<div class="facture-line"><span>Adresse</span><a href="' + getMapsHref(int.adresse) + '" target="_blank" rel="noopener" style="color:var(--accent); font-weight:600;">' + escapeHtml(int.adresse) + '</a></div>';
  html += '<div class="facture-line"><span>Type</span><span>' + typeInfo.label + (int.factureType ? ' — ' + int.factureType : '') + '</span></div>';
  var heureStr = formatDate(int.date);
  if (int.heure) heureStr += ' de ' + int.heure;
  if (int.heureFin) heureStr += ' à ' + int.heureFin;
  html += '<div class="facture-line"><span>Date</span><span>' + heureStr + '</span></div>';
  html += '<div class="facture-line"><span>Description</span><span style="text-align:right; max-width:60%;">' + escapeHtml(int.description || '—') + '</span></div>';
  if (int.notes) html += '<div class="facture-line"><span>Notes</span><span style="text-align:right; max-width:60%; font-style:italic; color:var(--text-faint);">' + escapeHtml(int.notes) + '</span></div>';
  if (!int.isAvoir) {
    html += '<div class="facture-line" style="margin-top:10px; padding-top:10px; border-top:1px solid var(--border-1);"><span>Main d\'œuvre (' + formatDuree(int.duree) + ')</span><span>' + (int.taux || settings.tauxDefaut) + ' CHF/h = ' + mainOeuvre.toFixed(2) + ' CHF</span></div>';
    if ((int.deplacement || 0) > 0) html += '<div class="facture-line"><span>Déplacement</span><span>' + (int.deplacement || 0).toFixed(2) + ' CHF</span></div>';
    if (int.kmActive) {
      var kmTotal = getKmFraisAmount(int);
      html += '<div class="facture-line"><span>🚗 Frais km (' + (int.kmDistance || 0) + ' km × ' + (int.kmRetour || 1) + ' × ' + (int.kmTaux || 0.70) + ' CHF)</span><span>' + kmTotal.toFixed(2) + ' CHF</span></div>';
    }
    if (int.pieces && int.pieces.length > 0) {
      html += '<div class="facture-line" style="margin-top:6px; font-weight:600; color:var(--accent);"><span>Pièces & Matériels</span><span></span></div>';
      int.pieces.forEach(function(p) {
        var qte = parseInt(p.qte) || 1;
        html += '<div class="facture-line"><span>• ' + escapeHtml(p.nom) + (qte > 1 ? ' ×' + qte : '') + '</span><span>' + (parseFloat(p.prix) * qte).toFixed(2) + ' CHF</span></div>';
      });
    }
    if (int.frais && int.frais.length > 0) {
      html += '<div class="facture-line" style="margin-top:6px; font-weight:600; color:var(--accent);"><span>Notes de frais</span><span></span></div>';
      int.frais.forEach(function(f) {
        html += '<div class="facture-line"><span>• ' + escapeHtml(f.libelle) + '</span><span>' + (parseFloat(f.montant) || 0).toFixed(2) + ' CHF</span></div>';
      });
    }
  }
  html += '<div class="facture-line" style="font-weight:600;"><span>Total HT</span><span>' + formatCHF(ht) + '</span></div>';
  if (settings.tvaActive) {
    if (isAutoliquidation(int)) html += '<div class="facture-line"><span>Autoliquidation</span><span>0,00 CHF</span></div>';
    else html += '<div class="facture-line"><span>TVA (' + settings.tva + '%)</span><span>' + formatCHF(tvaMontant) + '</span></div>';
  } else html += '<div class="facture-line"><span style="color:var(--text-faint); font-style:italic;">TVA non applicable</span><span></span></div>';
  html += '<div class="facture-total-highlight' + (int.isAvoir ? ' credit' : '') + '">'
    + '<div><div class="total-label">Total ' + (int.isAvoir ? 'Avoir' : (settings.tvaActive && !isAutoliquidation(int) ? 'TTC' : '')) + '</div>'
    + (settings.tvaActive && !isAutoliquidation(int) ? '<div class="total-sub">dont TVA ' + formatCHF(tvaMontant) + '</div>' : '<div class="total-sub">' + (int.isAvoir ? 'Montant crédité' : (!settings.tvaActive ? 'TVA non applicable' : 'Autoliquidation')) + '</div>')
    + '</div><div class="total-value">' + formatCHF(ttc) + '</div></div>';
  if (int.paye) html += '<div style="margin-top:12px; padding:10px; background:#e8f5e9; border-radius:var(--r-sm); text-align:center; color:var(--success); font-weight:600; font-size:0.85rem;">✓ Payée le ' + formatDate(int.datePaiement) + '</div>';
  else if (int.statut === 'en_cours') html += '<div style="margin-top:12px; padding:10px; background:var(--accent-light); border-radius:var(--r-sm); text-align:center; color:var(--accent); font-weight:600; font-size:0.85rem;">⏳ En cours</div>';
  else if (isOverdue(int)) {
    var jrs = joursEntre(int.date, new Date().toISOString().slice(0, 10));
    html += '<div style="margin-top:12px; padding:10px; background:#fff3e0; border-radius:var(--r-sm); text-align:center; color:var(--warning); font-weight:600; font-size:0.85rem;">⏰ En retard de ' + jrs + ' jours</div>';
  }
  else if (int.statut === 'termine') html += '<div style="margin-top:12px; padding:10px; background:#e1f5fe; border-radius:var(--r-sm); text-align:center; color:#0288d1; font-weight:600; font-size:0.85rem;">✓ Terminé — En attente de paiement</div>';
  else if (!int.isAvoir) html += '<div style="margin-top:12px; padding:10px; background:#ffebee; border-radius:var(--r-sm); text-align:center; color:var(--danger); font-weight:600; font-size:0.85rem;">⚠ En attente de paiement</div>';
  document.getElementById('factureContent').innerHTML = html;
  document.getElementById('markPaidBtn').style.display = (int.paye || int.isAvoir) ? 'none' : 'inline-flex';
  document.getElementById('sendMailBtn').style.display = int.email ? 'inline-flex' : 'none';
  document.getElementById('factureModal').classList.add('show');
}
document.getElementById('closeFacture').addEventListener('click', function() { document.getElementById('factureModal').classList.remove('show'); });
document.getElementById('markPaidBtn').addEventListener('click', function() {
  if (!currentFactureId) return;
  markAsPaid(currentFactureId);
  document.getElementById('factureModal').classList.remove('show');
});
document.getElementById('downloadPdfBtn').addEventListener('click', function() { if (currentFactureId) generateFacturePDF(currentFactureId); });
document.getElementById('shareFactureBtn').addEventListener('click', function() { if (currentFactureId) shareFacture(currentFactureId); });
document.getElementById('sendMailBtn').addEventListener('click', function() { if (currentFactureId) openMailModal(currentFactureId, 'facture'); });
document.getElementById('signFactureBtn').addEventListener('click', function() {
  if (currentFactureId) {
    document.getElementById('factureModal').classList.remove('show');
    openSignatureModal(currentFactureId, 'facture');
  }
});
document.getElementById('editFactureBtn').addEventListener('click', function() {
  if (!currentFactureId) return;
  document.getElementById('factureModal').classList.remove('show');
  editIntervention(currentFactureId);
});

function markAsPaid(id) {
  var int = interventions.find(function(i) { return i.id === id; });
  if (int) {
    int.paye = true;
    int.datePaiement = new Date().toISOString().slice(0, 10);
    invalidateTotals(id);
    markAsDirty();
    renderAll();
    haptic(15);
    showToast('Marquée comme payée', 'success');
  }
}

/* ==========================================================================
   MAIL
   ========================================================================== */
function openMailModal(id, type) {
  currentMailType = type;
  currentMailId = id;
  var item = type === 'facture' ? interventions.find(function(i) { return i.id === id; }) : devisList.find(function(d) { return d.id === id; });
  if (!item) return;
  if (!item.email) { showToast('Aucun email renseigné', 'warning'); return; }
  var total = getTotalTTC(item);
  var num = type === 'facture' ? item.numeroFacture : item.numeroDevis;
  document.getElementById('mailTo').value = item.email;
  document.getElementById('mailSubject').value = (item.isAvoir ? 'Avoir ' : (type === 'facture' ? 'Facture ' : 'Devis ')) + (num || '') + ' - ' + settings.nom;
  document.getElementById('mailBody').value = 'Bonjour ' + item.client + ',\n\n'
    + 'Veuillez trouver ci-joint ' + (item.isAvoir ? 'l\'avoir ' : (type === 'facture' ? 'la facture ' : 'le devis ')) + (num || '') + ' d\'un montant de ' + formatCHF(total) + '.\n\n'
    + 'Cordialement,\n' + settings.nom + '\n' + settings.tel + '\n' + settings.email;
  document.getElementById('mailModal').classList.add('show');
}
document.getElementById('cancelMail').addEventListener('click', function() { document.getElementById('mailModal').classList.remove('show'); });
document.getElementById('confirmMail').addEventListener('click', function() {
  var to = document.getElementById('mailTo').value;
  var subject = document.getElementById('mailSubject').value;
  var body = document.getElementById('mailBody').value;
  if (currentMailType === 'facture') generateFacturePDF(currentMailId, true);
  else generateDevisPDF(currentMailId, true);
  window.location.href = 'mailto:' + encodeURIComponent(to) + '?subject=' + encodeURIComponent(subject) + '&body=' + encodeURIComponent(body);
  document.getElementById('mailModal').classList.remove('show');
  showToast('Client mail ouvert. Joignez le PDF.', 'success');
});
/* ==========================================================================
   SIGNATURES (avec hash SHA-256)
   ========================================================================== */
var clientCanvas, clientCtx, techCanvas, techCtx;
var clientDrawing = false, techDrawing = false;
var clientLastX = 0, clientLastY = 0, techLastX = 0, techLastY = 0;
var signatureInitialized = false;

function initSignatureCanvases() {
  if (signatureInitialized) return;
  signatureInitialized = true;
  clientCanvas = document.getElementById('clientSignatureCanvas');
  techCanvas = document.getElementById('techSignatureCanvas');
  [clientCanvas, techCanvas].forEach(function(canvas) {
    var rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * 2;
    canvas.height = rect.height * 2;
    var ctx = canvas.getContext('2d');
    ctx.scale(2, 2);
    ctx.lineWidth = 2;
    ctx.lineCap = 'round';
    ctx.lineJoin = 'round';
    ctx.strokeStyle = '#1a5279';
  });
  clientCtx = clientCanvas.getContext('2d');
  techCtx = techCanvas.getContext('2d');
  ['client', 'tech'].forEach(function(who) {
    var c = who === 'client' ? clientCanvas : techCanvas;
    c.addEventListener('touchstart', function(e) { e.preventDefault(); startDraw(e, who); }, { passive: false });
    c.addEventListener('touchmove', function(e) { e.preventDefault(); draw(e, who); }, { passive: false });
    c.addEventListener('touchend', function(e) { e.preventDefault(); endDraw(who); }, { passive: false });
    c.addEventListener('mousedown', function(e) { startDraw(e, who); });
    c.addEventListener('mousemove', function(e) { draw(e, who); });
    c.addEventListener('mouseup', function() { endDraw(who); });
    c.addEventListener('mouseleave', function() { endDraw(who); });
  });
}
function getPos(e, canvas) {
  var rect = canvas.getBoundingClientRect();
  var cx, cy;
  if (e.touches && e.touches.length > 0) { cx = e.touches[0].clientX; cy = e.touches[0].clientY; }
  else if (e.changedTouches && e.changedTouches.length > 0) { cx = e.changedTouches[0].clientX; cy = e.changedTouches[0].clientY; }
  else { cx = e.clientX; cy = e.clientY; }
  return { x: cx - rect.left, y: cy - rect.top };
}
function startDraw(e, who) {
  var canvas = who === 'client' ? clientCanvas : techCanvas;
  var pos = getPos(e, canvas);
  if (who === 'client') { clientDrawing = true; clientLastX = pos.x; clientLastY = pos.y; }
  else { techDrawing = true; techLastX = pos.x; techLastY = pos.y; }
}
function draw(e, who) {
  var canvas = who === 'client' ? clientCanvas : techCanvas;
  var ctx = who === 'client' ? clientCtx : techCtx;
  var drawing = who === 'client' ? clientDrawing : techDrawing;
  if (!drawing) return;
  var pos = getPos(e, canvas);
  ctx.beginPath();
  if (who === 'client') { ctx.moveTo(clientLastX, clientLastY); ctx.lineTo(pos.x, pos.y); clientLastX = pos.x; clientLastY = pos.y; }
  else { ctx.moveTo(techLastX, techLastY); ctx.lineTo(pos.x, pos.y); techLastX = pos.x; techLastY = pos.y; }
  ctx.stroke();
}
function endDraw(who) { if (who === 'client') clientDrawing = false; else techDrawing = false; }
function clearCanvas(who) {
  var canvas = who === 'client' ? clientCanvas : techCanvas;
  var ctx = who === 'client' ? clientCtx : techCtx;
  ctx.clearRect(0, 0, canvas.width, canvas.height);
}
function isCanvasEmpty(canvas) {
  var ctx = canvas.getContext('2d');
  var data = ctx.getImageData(0, 0, canvas.width, canvas.height).data;
  for (var i = 0; i < data.length; i += 4) { if (data[i + 3] !== 0) return false; }
  return true;
}
function compressImage(canvas, maxW, quality) {
  maxW = maxW || 500;
  quality = quality || 0.7;
  try {
    var tmp = document.createElement('canvas');
    var ratio = canvas.width / canvas.height;
    var w = Math.min(maxW, canvas.width);
    var h = Math.round(w / ratio);
    tmp.width = w;
    tmp.height = h;
    var ctx = tmp.getContext('2d');
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, w, h);
    ctx.drawImage(canvas, 0, 0, w, h);
    return tmp.toDataURL('image/jpeg', quality);
  } catch(e) { return canvas.toDataURL('image/png'); }
}

function hashDataURL(dataURL) {
  var enc = new TextEncoder();
  return crypto.subtle.digest('SHA-256', enc.encode(dataURL)).then(function(hash) {
    return uint8ToBase64(new Uint8Array(hash));
  });
}

function openSignatureModal(id, type) {
  currentSignatureTarget = { id: id, type: type };
  clientSignatureData = null;
  techSignatureData = null;
  clientSignatureHash = null;
  techSignatureHash = null;
  document.getElementById('signatureModal').classList.add('show');
  setTimeout(function() {
    initSignatureCanvases();
    var item = type === 'facture' ? interventions.find(function(i) { return i.id === id; }) : devisList.find(function(d) { return d.id === id; });
    clearCanvas('client');
    clearCanvas('tech');
    if (item && item.signatureClient) {
      var img = new Image();
      img.onload = function() { clientCtx.drawImage(img, 0, 0, clientCanvas.width / 2, clientCanvas.height / 2); };
      img.src = item.signatureClient;
    }
    if (item && item.signatureTech) {
      var img2 = new Image();
      img2.onload = function() { techCtx.drawImage(img2, 0, 0, techCanvas.width / 2, techCanvas.height / 2); };
      img2.src = item.signatureTech;
    }
  }, 150);
}
document.getElementById('clearClientSig').addEventListener('click', function() { haptic(8); clearCanvas('client'); });
document.getElementById('clearTechSig').addEventListener('click', function() { haptic(8); clearCanvas('tech'); });

/* Les handlers "Valider" attendent la fin du hash AVANT de dire OK.
   On stocke le hash dans un objet { data, hash } au lieu de 2 variables
   globales qui peuvent se désynchroniser. */
var clientSigBundle = null;   // { data, hash } | null
var techSigBundle = null;     // { data, hash } | null

function _buildSigBundle(who) {
  var canvas = who === 'client' ? clientCanvas : techCanvas;
  var data = compressImage(canvas, 500, 0.7);
  return hashDataURL(data).then(function(hash) {
    return { data: data, hash: hash };
  });
}

document.getElementById('saveClientSig').addEventListener('click', function() {
  if (isCanvasEmpty(clientCanvas)) { showToast('Veuillez signer avant de valider', 'warning'); return; }
  _buildSigBundle('client').then(function(bundle) {
    clientSigBundle = bundle;
    clientSignatureData = bundle.data;
    clientSignatureHash = bundle.hash;
    haptic(15);
    showToast('Signature client enregistrée', 'success');
  }).catch(function() {
    showToast('Erreur signature client', 'error');
  });
});

document.getElementById('saveTechSig').addEventListener('click', function() {
  if (isCanvasEmpty(techCanvas)) { showToast('Veuillez signer avant de valider', 'warning'); return; }
  _buildSigBundle('tech').then(function(bundle) {
    techSigBundle = bundle;
    techSignatureData = bundle.data;
    techSignatureHash = bundle.hash;
    haptic(15);
    showToast('Signature technicien enregistrée', 'success');
  }).catch(function() {
    showToast('Erreur signature technicien', 'error');
  });
});

/* saveSignatures accepte un callback optionnel (pour enchaîner sur la fermeture) */
function saveSignatures(done) {
  if (!currentSignatureTarget) { if (done) done(); return; }
  var item = currentSignatureTarget.type === 'facture'
    ? interventions.find(function(i) { return i.id === currentSignatureTarget.id; })
    : devisList.find(function(d) { return d.id === currentSignatureTarget.id; });
  if (!item) { if (done) done(); return; }

  var hasClient = !!clientSignatureData;
  var hasTech = !!techSignatureData;
  var hadHash = false;

  if (hasClient) {
    item.signatureClient = clientSignatureData;
    item.signatureClientHash = clientSignatureHash;
    item.signatureClientAt = new Date().toISOString();
    hadHash = hadHash || !!clientSignatureHash;
  }
  if (hasTech) {
    item.signatureTech = techSignatureData;
    item.signatureTechHash = techSignatureHash;
    item.signatureTechAt = new Date().toISOString();
    hadHash = hadHash || !!techSignatureHash;
  }
  if (hasClient || hasTech) {
    markAsDirty();
    renderAll();
    showToast('Signatures enregistrées' + (hadHash ? ' (horodatées + hash)' : ''), 'success');
  }
  clientSignatureData = null;
  techSignatureData = null;
  clientSignatureHash = null;
  techSignatureHash = null;
  clientSigBundle = null;
  techSigBundle = null;
  currentSignatureTarget = null;
  if (done) done();
}

document.getElementById('closeSignatureModal').addEventListener('click', function() {
  // On attend la fin de saveSignatures avant de cacher.
  saveSignatures(function() {
    document.getElementById('signatureModal').classList.remove('show');
  });
});
/* ==========================================================================
   PDF FACTURE (QR-facture)
   ========================================================================== */
function buildQRBillOptions(int) {
  var zip = settings.zip || '';
  var city = settings.city || '';
  if (!zip && settings.adresse) {
    var m = settings.adresse.match(/(\d{4})\s+(.+)$/);
    if (m) { zip = m[1]; city = m[2]; }
  }
  return {
    numero: int.numeroFacture,
    isAvoir: !!int.isAvoir,
    clientName: int.client,
    clientAddress: int.adresse,
    clientCountry: int.paysClient || 'CH',
    date: formatDate(int.date),
    description: int.description,
    totalHT: getTotalHT(int),
    totalTTC: getTotalTTC(int),
    tvaAmount: getTvaMontant(int),
    tvaActive: settings.tvaActive,
    tvaRate: settings.tva,
    autoliquidation: isAutoliquidation(int),
    sellerName: settings.nom,
    sellerAddress: settings.adresse,
    sellerZip: zip,
    sellerCity: city,
    sellerIDE: settings.siret,
    sellerTVA: settings.tvaIntra,
    assuranceNom: settings.assuranceNom,
    assuranceNum: settings.assuranceNum,
    delaiPaiement: settings.delaiPaiement,
    iban: settings.iban
  };
}

function createFactureDoc(int) {
  var jsPDF = window.jspdf.jsPDF;
  var doc = new jsPDF('p', 'mm', 'a4');
  var pageWidth = doc.internal.pageSize.getWidth();
  var pageHeight = doc.internal.pageSize.getHeight();
  var margin = 15;
  var y = margin;
  var headerColor = int.isAvoir ? '#7b1fa2' : '#1a5279';
  doc.setFillColor(headerColor);
  doc.rect(0, 0, pageWidth, 40, 'F');
  doc.setTextColor('#ffffff');
  doc.setFontSize(20);
  doc.setFont('helvetica', 'bold');
  doc.text(settings.nom.toUpperCase(), pageWidth / 2, 22, { align: 'center' });
  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  doc.text(int.isAvoir ? 'Artisan Plombier - AVOIR' : 'Artisan Plombier - Dépannage & Entretien', pageWidth / 2, 31, { align: 'center' });
  y = 50;
  doc.setTextColor(headerColor);
  doc.setFontSize(16);
  doc.setFont('helvetica', 'bold');
  doc.text(int.isAvoir ? 'AVOIR' : 'FACTURE', margin + 10, y);
  doc.setFontSize(11);
  doc.setFont('helvetica', 'normal');
  doc.text(int.numeroFacture || '', pageWidth - margin - 10, y, { align: 'right' });
  y += 10;
  doc.setDrawColor(headerColor);
  doc.line(margin + 10, y, pageWidth - margin - 10, y);
  y += 10;
  doc.setTextColor('#333333');
  doc.setFontSize(10);
  doc.setFont('helvetica', 'bold');
  doc.text('Client :', margin + 10, y);
  doc.setFont('helvetica', 'normal');
  doc.text(int.client || '—', margin + 45, y);
  if (int.email) { y += 7; doc.setFont('helvetica', 'bold'); doc.text('Email :', margin + 10, y); doc.setFont('helvetica', 'normal'); doc.text(int.email, margin + 45, y); }
  if (int.tel) { y += 7; doc.setFont('helvetica', 'bold'); doc.text('Téléphone :', margin + 10, y); doc.setFont('helvetica', 'normal'); doc.text(int.tel, margin + 45, y); }
  if (int.adresse) {
    y += 7;
    doc.setFont('helvetica', 'bold');
    doc.text('Adresse :', margin + 10, y);
    doc.setFont('helvetica', 'normal');
    var adrLines = doc.splitTextToSize(int.adresse, pageWidth - margin - 55);
    doc.text(adrLines, margin + 45, y);
    y += (adrLines.length - 1) * 5;
  }
  y += 7;
  doc.setFont('helvetica', 'bold');
  doc.text('Date :', margin + 10, y);
  doc.setFont('helvetica', 'normal');
  doc.text(formatDate(int.date), margin + 45, y);
  y += 7;
  doc.setFont('helvetica', 'bold');
  doc.text('Description :', margin + 10, y);
  doc.setFont('helvetica', 'normal');
  var descLines = doc.splitTextToSize(int.description || '—', pageWidth - margin - 55);
  doc.text(descLines, margin + 45, y);
  y += descLines.length * 5;
    y += 12;
  doc.setFillColor(int.isAvoir ? '#f3e5f5' : '#f0f7ff');
  doc.rect(margin + 10, y, pageWidth - 2 * margin - 20, 9, 'F');
  doc.setTextColor(headerColor);
  doc.setFontSize(9);
  doc.setFont('helvetica', 'bold');
  doc.text('DÉSIGNATION', margin + 15, y + 6.5);
  doc.text('MONTANT', pageWidth - margin - 15, y + 6.5, { align: 'right' });
  y += 12;
  doc.setTextColor('#333333');
  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');

  var ht = getTotalHT(int);
  var ttc = getTotalTTC(int);
  var tvaMontant = getTvaMontant(int);

  // --- Détail des lignes ---
  if (!int.isAvoir) {
    var heures = (int.duree || 0) / 60;
    var taux = int.taux || settings.tauxDefaut;
    var mainOeuvre = heures * taux;
    var deplacement = int.deplacement || 0;
    var kmMontant = getKmFraisAmount(int);
    var piecesArr = int.pieces || [];
    var fraisArr = int.frais || [];

    // Main d'œuvre
    if (mainOeuvre > 0) {
      var labelMO = 'Main d\'œuvre (' + formatDuree(int.duree) + ' à ' + taux + ' CHF/h)';
      doc.text(labelMO, margin + 15, y + 5);
      doc.text(mainOeuvre.toFixed(2) + ' CHF', pageWidth - margin - 15, y + 5, { align: 'right' });
      y += 7;
    }

    // Déplacement
    if (deplacement > 0) {
      doc.text('Déplacement', margin + 15, y + 5);
      doc.text(deplacement.toFixed(2) + ' CHF', pageWidth - margin - 15, y + 5, { align: 'right' });
      y += 7;
    }

    // Frais kilométriques
    if (int.kmActive && kmMontant > 0) {
      var labelKm = 'Frais kilométriques (' + (int.kmDistance || 0) + ' km × ' + (int.kmRetour || 1) + ' × ' + (int.kmTaux || 0.70) + ' CHF)';
      doc.text(labelKm, margin + 15, y + 5);
      doc.text(kmMontant.toFixed(2) + ' CHF', pageWidth - margin - 15, y + 5, { align: 'right' });
      y += 7;
    }

    // Pièces
    piecesArr.forEach(function(p) {
      if (!p.nom || !p.prix) return;
      var qte = parseInt(p.qte) || 1;
      var ligne = p.nom + (qte > 1 ? ' × ' + qte : '');
      var totalPiece = (parseFloat(p.prix) || 0) * qte;
      var lines = doc.splitTextToSize('• ' + ligne, pageWidth - margin - 55);
      doc.text(lines, margin + 15, y + 5);
      doc.text(totalPiece.toFixed(2) + ' CHF', pageWidth - margin - 15, y + 5, { align: 'right' });
      y += (lines.length * 4) + 3;
    });

    // Notes de frais
    fraisArr.forEach(function(f) {
      if (!f.libelle || !f.montant) return;
      var lines = doc.splitTextToSize('• ' + f.libelle, pageWidth - margin - 55);
      doc.text(lines, margin + 15, y + 5);
      doc.text((parseFloat(f.montant) || 0).toFixed(2) + ' CHF', pageWidth - margin - 15, y + 5, { align: 'right' });
      y += (lines.length * 4) + 3;
    });
  } else {
    // Avoir libre : juste le montant forcé
    doc.text('Avoir', margin + 15, y + 5);
    doc.text(ht.toFixed(2) + ' CHF', pageWidth - margin - 15, y + 5, { align: 'right' });
    y += 7;
  }

  // --- Sous-total HT ---
  doc.setDrawColor('#cccccc');
  doc.line(margin + 10, y, pageWidth - margin - 10, y);
  y += 6;
  doc.setFont('helvetica', 'bold');
  doc.text('Total HT', margin + 15, y + 4);
  doc.text(ht.toFixed(2) + ' CHF', pageWidth - margin - 15, y + 4, { align: 'right' });
  doc.setFont('helvetica', 'normal');
  y += 7;

  if (settings.tvaActive && !isAutoliquidation(int)) {
    doc.text('TVA (' + settings.tva + '%)', margin + 15, y + 4);
    doc.text(tvaMontant.toFixed(2) + ' CHF', pageWidth - margin - 15, y + 4, { align: 'right' });
    y += 7;
  } else if (isAutoliquidation(int)) {
    doc.setFontSize(8);
    doc.text('Autoliquidation — TVA due par le client (art. 8 al. 1 LTVA)', margin + 15, y + 4);
    y += 7;
    doc.setFontSize(9);
  } else {
    doc.setFontSize(8);
    doc.text('TVA non applicable (art. 10 al. 2 LTVA)', margin + 15, y + 4);
    y += 7;
    doc.setFontSize(9);
  }

  doc.setDrawColor(headerColor);
  doc.line(margin + 10, y, pageWidth - margin - 10, y);
  y += 8;
  doc.setTextColor(headerColor);
  doc.setFontSize(13);
  doc.setFont('helvetica', 'bold');
  doc.text('TOTAL', margin + 15, y + 5);
  doc.text(ttc.toFixed(2) + ' CHF', pageWidth - margin - 15, y + 5, { align: 'right' });
  y += 20;
  doc.setTextColor('#666666');
  doc.setFontSize(7);
  doc.setFont('helvetica', 'normal');
  var legal = [];
  if (settings.siret) legal.push('IDE : ' + settings.siret);
  if (settings.tvaActive && settings.tvaIntra) legal.push('N° TVA : ' + settings.tvaIntra);
  if (settings.assuranceNom) legal.push('RC pro : ' + settings.assuranceNom + (settings.assuranceNum ? ' (' + settings.assuranceNum + ')' : ''));
  if (settings.delaiPaiement) legal.push('Délai de paiement : ' + settings.delaiPaiement + ' jours');
  if (settings.iban) legal.push('IBAN : ' + settings.iban);
  legal.forEach(function(line) { doc.text(line, margin + 10, y); y += 3.5; });

  // --- Signatures ---
  if (int.signatureClient || int.signatureTech) {
    var sigY = y + 5;
    var sigW = 50;
    var sigH = 22;
    var halfPage = pageWidth / 2;

    if (int.signatureTech) {
      try {
        doc.addImage(int.signatureTech, 'PNG', margin + 10, sigY, sigW, sigH);
      } catch(e) { console.warn('Erreur sig tech', e); }
      doc.setFontSize(7);
      doc.setTextColor('#666666');
      doc.text('Signature technicien', margin + 10, sigY + sigH + 4);
    }

    if (int.signatureClient) {
      try {
        doc.addImage(int.signatureClient, 'PNG', halfPage + 10, sigY, sigW, sigH);
      } catch(e) { console.warn('Erreur sig client', e); }
      doc.setFontSize(7);
      doc.setTextColor('#666666');
      doc.text('Signature client', halfPage + 10, sigY + sigH + 4);
      if (int.signatureClientAt) {
        doc.setFontSize(6);
        doc.setTextColor('#999999');
        var d = new Date(int.signatureClientAt);
        var dateStr = String(d.getDate()).padStart(2, '0') + '.' + String(d.getMonth() + 1).padStart(2, '0') + '.' + d.getFullYear()
          + ' ' + String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0');
        doc.text('Signé le ' + dateStr, halfPage + 10, sigY + sigH + 8);
      }
    }
  }

  y = pageHeight - 15;
  doc.setTextColor('#999999');
  doc.setFontSize(6.5);
  doc.text(settings.nom + ' - ' + settings.adresse + ' - ' + settings.tel + ' - ' + settings.email, pageWidth / 2, y, { align: 'center' });
  return doc;
}  

function generateFacturePDFBlob(int) {
  var qrAvailable = !!(window.SwissQRBill && window.SwissQRBill.QRBill) && typeof isValidSwissIBAN === 'function';
  var ibanOk = qrAvailable && settings.iban && isValidSwissIBAN(settings.iban);
  var promise;
  if (ibanOk) {
    promise = loadJsPDF()
      .then(function() { return loadSwissQRBill(); })
      .then(function() { return generateQRBillPDF(int); });
  } else {
    if (!qrAvailable && settings.iban) {
      console.warn('[PipePline] QR-bill indisponible — PDF sans QR');
    }
    promise = loadJsPDF().then(function() { return createFactureDoc(int).output('blob'); });
  }
  return promise.catch(function(e) { console.error(e); return null; });
}

function generateFacturePDF(id, silent) {
  var int = interventions.find(function(i) { return i.id === id; });
  if (!int) return;
  showToast('Génération du PDF...', 'info');
  var qrAvailable = !!(window.SwissQRBill && window.SwissQRBill.QRBill) && typeof isValidSwissIBAN === 'function';
  var ibanOk = qrAvailable && settings.iban && isValidSwissIBAN(settings.iban);
  var promise;
  if (ibanOk) {
    promise = loadJsPDF()
      .then(function() { return loadSwissQRBill(); })
      .then(function() { return generateQRBillPDF(int); });
  } else {
    promise = loadJsPDF().then(function() { return createFactureDoc(int).output('blob'); });
  }
  promise.then(function(blob) {
    downloadBlob(blob, (int.isAvoir ? 'Avoir_' : 'Facture_') + (int.numeroFacture || 'Client').replace(/[^a-zA-Z0-9\-]/g, '_') + '.pdf');
    if (!silent) showToast((int.isAvoir ? 'Avoir' : 'Facture') + ' PDF ' + (ibanOk ? 'QR ' : '') + 'téléchargé', 'success');
  }).catch(function(e) {
    console.error(e);
    showToast('Erreur PDF : ' + (e.message || e), 'error');
  });
}

/* Génère le PDF avec QR-facture suisse */
function generateQRBillPDF(int) {
  var jsPDF = window.jspdf.jsPDF;
  var SwissQRBill = window.SwissQRBill;
  var doc = new jsPDF({ unit: 'mm', format: 'a4' });

  var pageWidth = doc.internal.pageSize.getWidth();
  var pageHeight = doc.internal.pageSize.getHeight();
  var margin = 15;
  var y = margin;

  var headerColor = int.isAvoir ? '#7b1fa2' : '#1a5279';
  doc.setFillColor(headerColor);
  doc.rect(0, 0, pageWidth, 40, 'F');
  doc.setTextColor('#ffffff');
  doc.setFontSize(20);
  doc.setFont('helvetica', 'bold');
  doc.text((settings.nom || 'ENTREPRISE').toUpperCase(), pageWidth / 2, 22, { align: 'center' });
  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  doc.text('Artisan Plombier - Dépannage & Entretien', pageWidth / 2, 31, { align: 'center' });

  y = 50;
  doc.setTextColor(headerColor);
  doc.setFontSize(16);
  doc.setFont('helvetica', 'bold');
  doc.text(int.isAvoir ? 'AVOIR' : 'FACTURE', margin + 10, y);
  doc.setFontSize(11);
  doc.setFont('helvetica', 'normal');
  doc.text(int.numeroFacture || '', pageWidth - margin - 10, y, { align: 'right' });
  y += 10;
  doc.setDrawColor(headerColor);
  doc.line(margin + 10, y, pageWidth - margin - 10, y);
  y += 10;

  doc.setTextColor('#333333');
  doc.setFontSize(10);
  doc.setFont('helvetica', 'bold');
  doc.text('Client :', margin + 10, y);
  doc.setFont('helvetica', 'normal');
  doc.text(int.client || '—', margin + 45, y);

  if (int.adresse) {
    y += 7;
    doc.setFont('helvetica', 'bold');
    doc.text('Adresse :', margin + 10, y);
    doc.setFont('helvetica', 'normal');
    var addrLines = doc.splitTextToSize(int.adresse, pageWidth - margin - 55);
    doc.text(addrLines, margin + 45, y);
    y += (addrLines.length - 1) * 5;
  }
  y += 7;
  doc.setFont('helvetica', 'bold');
  doc.text('Date :', margin + 10, y);
  doc.setFont('helvetica', 'normal');
  doc.text(formatDate(int.date), margin + 45, y);

  y += 7;
  doc.setFont('helvetica', 'bold');
  doc.text('Description :', margin + 10, y);
  doc.setFont('helvetica', 'normal');
  var descLines = doc.splitTextToSize(int.description || '—', pageWidth - margin - 55);
  doc.text(descLines, margin + 45, y);
  y += descLines.length * 5 + 8;

  doc.setFillColor(int.isAvoir ? '#f3e5f5' : '#f0f7ff');
  doc.rect(margin + 10, y, pageWidth - 2 * margin - 20, 9, 'F');
  doc.setTextColor(headerColor);
  doc.setFontSize(9);
  doc.setFont('helvetica', 'bold');
  doc.text('DÉSIGNATION', margin + 15, y + 6.5);
  doc.text('MONTANT', pageWidth - margin - 15, y + 6.5, { align: 'right' });
  y += 10;
  doc.setTextColor('#333333');
  doc.setFont('helvetica', 'normal');

  var ht = getTotalHT(int);
  var ttc = getTotalTTC(int);
  var tvaMontant = getTvaMontant(int);

  doc.text('Total HT', margin + 15, y + 5);
  doc.text(ht.toFixed(2) + ' CHF', pageWidth - margin - 15, y + 5, { align: 'right' });
  y += 7;

  if (settings.tvaActive && !isAutoliquidation(int)) {
    doc.text('TVA (' + settings.tva + '%)', margin + 15, y + 5);
    doc.text(tvaMontant.toFixed(2) + ' CHF', pageWidth - margin - 15, y + 5, { align: 'right' });
    y += 7;
  } else if (isAutoliquidation(int)) {
    doc.setFontSize(8);
    doc.text('Autoliquidation — TVA due par le client (art. 8 al. 1 LTVA)', margin + 15, y + 5);
    y += 7;
  } else {
    doc.setFontSize(8);
    doc.text('TVA non applicable (art. 10 al. 2 LTVA)', margin + 15, y + 5);
    y += 7;
  }

  doc.setDrawColor(headerColor);
  doc.line(margin + 10, y, pageWidth - margin - 10, y);
  y += 8;
  doc.setTextColor(headerColor);
  doc.setFontSize(13);
  doc.setFont('helvetica', 'bold');
  doc.text('TOTAL', margin + 15, y + 5);
  doc.text(ttc.toFixed(2) + ' CHF', pageWidth - margin - 15, y + 5, { align: 'right' });

  y += 15;
  doc.setTextColor('#666666');
  doc.setFontSize(7);
  doc.setFont('helvetica', 'normal');
  var legal = [];
  if (settings.siret) legal.push('IDE : ' + settings.siret);
  if (settings.tvaActive && settings.tvaIntra) legal.push('N° TVA : ' + settings.tvaIntra);
  if (settings.assuranceNom) legal.push('RC pro : ' + settings.assuranceNom + (settings.assuranceNum ? ' (' + settings.assuranceNum + ')' : ''));
  if (settings.delaiPaiement) legal.push('Délai de paiement : ' + settings.delaiPaiement + ' jours');
  legal.forEach(function(line) { doc.text(line, margin + 10, y); y += 3.5; });

    var qrBillHeight = 105;
  var qrY = pageHeight - qrBillHeight;

  // --- Signatures (au-dessus de la QR-facture) ---
  if (int.signatureClient || int.signatureTech) {
    var sigY = qrY - 35;
    var sigW = 50;
    var sigH = 22;
    var halfPage = pageWidth / 2;

    if (int.signatureTech) {
      try {
        doc.addImage(int.signatureTech, 'PNG', margin + 10, sigY, sigW, sigH);
      } catch(e) { console.warn('Erreur sig tech', e); }
      doc.setFontSize(7);
      doc.setTextColor('#666666');
      doc.text('Signature technicien', margin + 10, sigY + sigH + 4);
    }

    if (int.signatureClient) {
      try {
        doc.addImage(int.signatureClient, 'PNG', halfPage + 10, sigY, sigW, sigH);
      } catch(e) { console.warn('Erreur sig client', e); }
      doc.setFontSize(7);
      doc.setTextColor('#666666');
      doc.text('Signature client', halfPage + 10, sigY + sigH + 4);
      if (int.signatureClientAt) {
        doc.setFontSize(6);
        doc.setTextColor('#999999');
        var dSig = new Date(int.signatureClientAt);
        var dateStr = String(dSig.getDate()).padStart(2, '0') + '.' + String(dSig.getMonth() + 1).padStart(2, '0') + '.' + dSig.getFullYear()
          + ' ' + String(dSig.getHours()).padStart(2, '0') + ':' + String(dSig.getMinutes()).padStart(2, '0');
        doc.text('Signé le ' + dateStr, halfPage + 10, sigY + sigH + 8);
      }
    }
    doc.setTextColor('#333333');
  }

  var iban = (settings.iban || '').replace(/\s+/g, '');
  /* Toujours retourner une Promise<Blob> — jamais un Blob direct. */
  if (!isValidSwissIBAN(iban)) {
    doc.setTextColor('#c62828');
    doc.setFontSize(8);
    doc.text('⚠ IBAN suisse invalide ou absent — QR-facture non générée.', margin, qrY + 10);
    return Promise.resolve(doc.output('blob'));
  }

  // ... (inchangé jusqu'au try)

  try {
    var qrBill = new SwissQRBill.QRBill(qrData, { language: 'fr' });
    var svg = qrBill.toString();
    return svgToDataURL(svg).then(function(dataUrl) {
      doc.addImage(dataUrl, 'PNG', 0, qrY, pageWidth, qrBillHeight, undefined, 'FAST');
      return doc.output('blob');
    });
  } catch (e) {
    console.error('[QRBill]', e);
    doc.setTextColor('#c62828');
    doc.setFontSize(8);
    doc.text('⚠ Erreur génération QR-facture : ' + e.message, margin, qrY + 10);
    return Promise.resolve(doc.output('blob'));
  }
}

function svgToDataURL(svgString) {
  return new Promise(function(resolve, reject) {
    var img = new Image();
    var svg64 = btoa(unescape(encodeURIComponent(svgString)));
    img.onload = function() {
      var canvas = document.createElement('canvas');
      canvas.width = 2480;
      canvas.height = 1240;
      var ctx = canvas.getContext('2d');
      ctx.fillStyle = '#ffffff';
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
      resolve(canvas.toDataURL('image/png'));
    };
    img.onerror = function() { reject(new Error('SVG → PNG échoué')); };
    img.src = 'data:image/svg+xml;base64,' + svg64;
  });
}

/* ==========================================================================
   PDF DEVIS
   ========================================================================== */
function createDevisDoc(d) {
  var jsPDF = window.jspdf.jsPDF;
  var doc = new jsPDF('p', 'mm', 'a4');
  var pageWidth = doc.internal.pageSize.getWidth();
  var pageHeight = doc.internal.pageSize.getHeight();
  var margin = 15;
  var y = margin;
  doc.setFillColor('#4338ca');
  doc.rect(0, 0, pageWidth, 40, 'F');
  doc.setTextColor('#ffffff');
  doc.setFontSize(20);
  doc.setFont('helvetica', 'bold');
  doc.text(settings.nom.toUpperCase(), pageWidth / 2, 22, { align: 'center' });
  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  doc.text('Artisan Plombier - Devis', pageWidth / 2, 31, { align: 'center' });
  y = 50;
  doc.setTextColor('#4338ca');
  doc.setFontSize(16);
  doc.setFont('helvetica', 'bold');
  doc.text('DEVIS', margin + 10, y);
  doc.setFontSize(11);
  doc.setFont('helvetica', 'normal');
  doc.text(d.numeroDevis || '', pageWidth - margin - 10, y, { align: 'right' });
  y += 10;
  doc.setDrawColor('#4338ca');
  doc.line(margin + 10, y, pageWidth - margin - 10, y);
  y += 10;
  doc.setTextColor('#333333');
  doc.setFontSize(10);
  doc.setFont('helvetica', 'bold');
  doc.text('Client :', margin + 10, y);
  doc.setFont('helvetica', 'normal');
  doc.text(d.client || '—', margin + 45, y);
  if (d.email) { y += 7; doc.setFont('helvetica', 'bold'); doc.text('Email :', margin + 10, y); doc.setFont('helvetica', 'normal'); doc.text(d.email, margin + 45, y); }
  if (d.tel) { y += 7; doc.setFont('helvetica', 'bold'); doc.text('Téléphone :', margin + 10, y); doc.setFont('helvetica', 'normal'); doc.text(d.tel, margin + 45, y); }
  if (d.adresse) {
    y += 7;
    doc.setFont('helvetica', 'bold');
    doc.text('Adresse :', margin + 10, y);
    doc.setFont('helvetica', 'normal');
    var adrLines = doc.splitTextToSize(d.adresse, pageWidth - margin - 55);
    doc.text(adrLines, margin + 45, y);
    y += (adrLines.length - 1) * 5;
  }
  y += 7;
  doc.setFont('helvetica', 'bold');
  doc.text('Date :', margin + 10, y);
  doc.setFont('helvetica', 'normal');
  doc.text(formatDate(d.date), margin + 45, y);
  y += 7;
  doc.setFont('helvetica', 'bold');
  doc.text('Validité :', margin + 10, y);
  doc.setFont('helvetica', 'normal');
  doc.text(d.validite + ' jours', margin + 45, y);
  y += 7;
  doc.setFont('helvetica', 'bold');
  doc.text('Durée :', margin + 10, y);
  doc.setFont('helvetica', 'normal');
  doc.text(formatDuree(d.duree), margin + 45, y);
  y += 7;
  doc.setFont('helvetica', 'bold');
  doc.text('Description :', margin + 10, y);
  doc.setFont('helvetica', 'normal');
  var descLines = doc.splitTextToSize(d.description || '—', pageWidth - margin - 55);
  doc.text(descLines, margin + 45, y);
  y += descLines.length * 5;
  y += 12;
  doc.setFillColor('#eef2ff');
  doc.rect(margin + 10, y, pageWidth - 2 * margin - 20, 9, 'F');
  doc.setTextColor('#4338ca');
  doc.setFontSize(9);
  doc.setFont('helvetica', 'bold');
  doc.text('DÉSIGNATION', margin + 15, y + 6.5);
  doc.text('MONTANT', pageWidth - margin - 15, y + 6.5, { align: 'right' });
  y += 10;
  doc.setTextColor('#333333');
  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  var heures = (d.duree || 0) / 60;
  var mainOeuvre = heures * (d.taux || settings.tauxDefaut);
  doc.text('Main d\'œuvre (' + formatDuree(d.duree) + ')', margin + 15, y + 5);
  doc.text(mainOeuvre.toFixed(2) + ' CHF', pageWidth - margin - 15, y + 5, { align: 'right' });
  y += 7;
  if ((d.deplacement || 0) > 0) {
    doc.text('Frais de déplacement', margin + 15, y + 5);
    doc.text((d.deplacement || 0).toFixed(2) + ' CHF', pageWidth - margin - 15, y + 5, { align: 'right' });
    y += 7;
  }
  if (d.pieces && d.pieces.length > 0) {
    d.pieces.forEach(function(p) {
      var qte = parseInt(p.qte) || 1;
      var label = p.nom + (qte > 1 ? ' ×' + qte : '');
      doc.text('• ' + label, margin + 15, y + 5);
      doc.text((parseFloat(p.prix) * qte).toFixed(2) + ' CHF', pageWidth - margin - 15, y + 5, { align: 'right' });
      y += 7;
    });
  }
  var ht = getTotalHT(d);
  var ttc = getTotalTTC(d);
  var tvaMontant = getTvaMontant(d);
  doc.setDrawColor('#cccccc');
  doc.line(margin + 10, y, pageWidth - margin - 10, y);
  y += 6;
  doc.text('Total HT', margin + 15, y + 4);
  doc.text(ht.toFixed(2) + ' CHF', pageWidth - margin - 15, y + 4, { align: 'right' });
  y += 6;
  if (settings.tvaActive) {
    doc.text('TVA (' + settings.tva + '%)', margin + 15, y + 4);
    doc.text(tvaMontant.toFixed(2) + ' CHF', pageWidth - margin - 15, y + 4, { align: 'right' });
    y += 6;
  }
  doc.setDrawColor('#4338ca');
  doc.line(margin + 10, y, pageWidth - margin - 10, y);
  y += 8;
  doc.setTextColor('#4338ca');
  doc.setFontSize(13);
  doc.setFont('helvetica', 'bold');
  doc.text('TOTAL', margin + 15, y + 5);
  doc.text(ttc.toFixed(2) + ' CHF', pageWidth - margin - 15, y + 5, { align: 'right' });
  y = pageHeight - 15;
  doc.setTextColor('#999999');
  doc.setFontSize(6.5);
  doc.setFont('helvetica', 'normal');
  doc.text(settings.nom + ' - ' + settings.adresse + ' - ' + settings.tel + ' - ' + settings.email, pageWidth / 2, y, { align: 'center' });
  return doc;
}

function generateDevisPDFBlob(d) {
  return loadJsPDF().then(function() { return createDevisDoc(d).output('blob'); }).catch(function(e) { console.error(e); return null; });
}

function generateDevisPDF(id, silent) {
  var d = devisList.find(function(x) { return x.id === id; });
  if (!d) return;
  loadJsPDF().then(function() {
    try {
      var doc = createDevisDoc(d);
      doc.save('Devis_' + (d.numeroDevis || 'Client').replace(/[^a-zA-Z0-9\-]/g, '_') + '.pdf');
      if (!silent) showToast('Devis PDF téléchargé', 'success');
    } catch (e) { showToast('Erreur PDF : ' + e.message, 'error'); }
  }).catch(function() { showToast('Impossible de charger le générateur PDF', 'error'); });
}

document.getElementById('printFactureBtn').addEventListener('click', function() {
  if (!currentFactureId) return;
  var int = interventions.find(function(i) { return i.id === currentFactureId; });
  if (!int) return;
  var printSection = document.getElementById('printSection');
  var ttc = getTotalTTC(int);
  printSection.innerHTML = '<div style="font-family:Arial, sans-serif; max-width:800px; margin:0 auto; padding:20px;"><h1>' + escapeHtml(int.isAvoir ? 'AVOIR' : 'FACTURE') + ' ' + escapeHtml(int.numeroFacture || '') + '</h1><p><strong>Client :</strong> ' + escapeHtml(int.client) + '</p><p><strong>Total :</strong> ' + ttc.toFixed(2) + ' CHF</p></div>';
  printSection.style.display = 'block';
  window.print();
  setTimeout(function() { printSection.style.display = 'none'; }, 1000);
});

/* ==========================================================================
   RECHERCHE / FILTRES
   ========================================================================== */
document.getElementById('searchInput').addEventListener('input', debounce(function() { searchTerm = this.value; renderInterventions(); }, 250));
document.getElementById('searchBtn').addEventListener('click', function() { searchTerm = document.getElementById('searchInput').value; renderInterventions(); });
document.getElementById('searchFactureInput').addEventListener('input', debounce(function() { searchFactureTerm = this.value; renderFactures(); }, 250));
document.getElementById('searchFactureBtn').addEventListener('click', function() { searchFactureTerm = document.getElementById('searchFactureInput').value; renderFactures(); });
document.getElementById('searchDevisInput').addEventListener('input', debounce(function() { searchDevisTerm = this.value; renderDevis(); }, 250));
document.getElementById('searchDevisBtn').addEventListener('click', function() { searchDevisTerm = document.getElementById('searchDevisInput').value; renderDevis(); });

document.querySelectorAll('#quickFiltersInterventions .quick-filter').forEach(function(btn) {
  btn.addEventListener('click', function() {
    haptic(8);
    document.querySelectorAll('#quickFiltersInterventions .quick-filter').forEach(function(b) { b.classList.remove('active'); });
    this.classList.add('active');
    currentQuickFilter = this.dataset.filter;
    openMonths = {};
    openDays = {};
    renderInterventions();
  });
});
document.querySelectorAll('#quickFiltersFactures .quick-filter').forEach(function(btn) {
  btn.addEventListener('click', function() {
    haptic(8);
    document.querySelectorAll('#quickFiltersFactures .quick-filter').forEach(function(b) { b.classList.remove('active'); });
    this.classList.add('active');
    currentFactureFilter = this.dataset.filter;
    renderFactures();
  });
});

document.getElementById('sortInterventionsSelect').addEventListener('change', function() {
  currentSortInterventions = this.value;
  renderInterventions();
});
document.getElementById('sortFacturesSelect').addEventListener('change', function() {
  currentSortFactures = this.value;
  renderFactures();
});
document.getElementById('sortDevisSelect').addEventListener('change', function() {
  currentSortDevis = this.value;
  renderDevis();
});
document.getElementById('dateFilterFrom').addEventListener('change', function() { dateFilterFrom = this.value; renderInterventions(); });
document.getElementById('dateFilterTo').addEventListener('change', function() { dateFilterTo = this.value; renderInterventions(); });
document.getElementById('clearDateFilter').addEventListener('click', function() {
  dateFilterFrom = '';
  dateFilterTo = '';
  document.getElementById('dateFilterFrom').value = '';
  document.getElementById('dateFilterTo').value = '';
  renderInterventions();
});

/* ==========================================================================
   EXPORT / IMPORT
   ========================================================================== */
function exportData(encrypt) {
  var data = {
    interventions: interventions,
    devisList: devisList,
    clients: clients,
    stock: stock,
    factureCounter: factureCounter,
    devisCounter: devisCounter,
    avoirCounter: avoirCounter,
    settings: settings,
    exportedAt: new Date().toISOString(),
    schemaVersion: 4,
    appVersion: APP_VERSION,
    pays: 'CH'
  };
  var filename = 'pipepline_ch_sauvegarde_' + new Date().toISOString().slice(0, 10) + '.json';
  if (encrypt && window.crypto && window.crypto.subtle) {
    var pwd = prompt('Mot de passe pour chiffrer la sauvegarde (min. 8 caractères) :');
    if (!pwd || pwd.length < 8) { showToast('Mot de passe trop court, sauvegarde annulée', 'warning'); return; }
    var salt = generateSalt();
    var iterations = 100000;
    var enc = new TextEncoder();
    crypto.subtle.importKey('raw', enc.encode(pwd), { name: 'PBKDF2' }, false, ['deriveKey'])
      .then(function(baseKey) {
        return crypto.subtle.deriveKey(
          { name: 'PBKDF2', salt: salt, iterations: iterations, hash: 'SHA-256' },
          baseKey,
          { name: 'AES-GCM', length: 256 },
          false,
          ['encrypt']
        );
      })
      .then(function(key) {
        var iv = new Uint8Array(12);
        crypto.getRandomValues(iv);
        return crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, enc.encode(JSON.stringify(data)))
          .then(function(ciphertext) {
            return {
              v: 1,
              encrypted: true,
              algo: 'AES-GCM-256',
              kdf: 'PBKDF2-SHA256',
              iterations: iterations,
              salt: uint8ToBase64(salt),
              iv: uint8ToBase64(iv),
              ciphertext: uint8ToBase64(new Uint8Array(ciphertext))
            };
          });
      })
      .then(function(payload) {
        var blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
        var link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = filename.replace('.json', '_chiffre.json');
        link.click();
        backupMeta.lastExportAt = new Date().toISOString();
        backupMeta.lastReminderAt = null;
        saveToStorage(true);
        checkBackupReminder();
        haptic(15);
        showToast('Sauvegarde chiffrée téléchargée', 'success');
      })
      .catch(function(e) { showToast('Erreur chiffrement : ' + e.message, 'error'); });
    return;
  }
  var blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  var link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = filename;
  link.click();
  backupMeta.lastExportAt = new Date().toISOString();
  backupMeta.lastReminderAt = null;
  saveToStorage(true);
  checkBackupReminder();
  haptic(15);
  showToast('Sauvegarde téléchargée', 'success');
}

document.getElementById('exportDataBtn').addEventListener('click', function() {
  exportData(settings.encryptExport);
});

document.getElementById('exportCsvBtn').addEventListener('click', function() {
  haptic(15);
  var lines = [];
  lines.push(['Type', 'Numero', 'Date', 'Client', 'Email', 'Telephone', 'Description', 'Total HT', 'TVA', 'Total TTC', 'Paye', 'Statut'].join(';'));
  interventions.forEach(function(int) {
    var ht = getTotalHT(int);
    var tva = settings.tvaActive ? getTvaMontant(int) : 0;
    var ttc = getTotalTTC(int);
    lines.push([
      int.isAvoir ? 'Avoir' : 'Facture',
      int.numeroFacture || '',
      int.date || '',
      (int.client || '').replace(/[;\n]/g, ' '),
      int.email || '',
      int.tel || '',
      (int.description || '').replace(/[;\n]/g, ' '),
      ht.toFixed(2).replace('.', ','),
      tva.toFixed(2).replace('.', ','),
      ttc.toFixed(2).replace('.', ','),
      int.paye ? 'Oui' : 'Non',
      int.statut || ''
    ].join(';'));
  });
  devisList.forEach(function(d) {
    var ht = getTotalHT(d);
    var tva = settings.tvaActive ? getTvaMontant(d) : 0;
    var ttc = getTotalTTC(d);
    lines.push([
      'Devis',
      d.numeroDevis || '',
      d.date || '',
      (d.client || '').replace(/[;\n]/g, ' '),
      d.email || '',
      d.tel || '',
      (d.description || '').replace(/[;\n]/g, ' '),
      ht.toFixed(2).replace('.', ','),
      tva.toFixed(2).replace('.', ','),
      ttc.toFixed(2).replace('.', ','),
      '',
      d.statut || ''
    ].join(';'));
  });
  var csv = '\uFEFF' + lines.join('\r\n');
  var blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  var link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = 'pipepline_ch_export_' + new Date().toISOString().slice(0, 10) + '.csv';
  link.click();
  showToast('Export CSV téléchargé', 'success');
});

document.getElementById('importDataBtn').addEventListener('click', function() {
  document.getElementById('importDataInput').click();
});

document.getElementById('importDataInput').addEventListener('change', function(e) {
  var file = e.target.files && e.target.files[0];
  if (!file) return;
  var reader = new FileReader();
  reader.onload = function(evt) {
    try {
      var data = JSON.parse(evt.target.result);
      if (data && data.encrypted === true) {
        var pwd = prompt('Ce fichier est chiffré. Entrez le mot de passe :');
        if (!pwd) { document.getElementById('importDataInput').value = ''; return; }
        var salt = base64ToUint8(data.salt);
        var iv = base64ToUint8(data.iv);
        var ciphertext = base64ToUint8(data.ciphertext);
        var enc = new TextEncoder();
        crypto.subtle.importKey('raw', enc.encode(pwd), { name: 'PBKDF2' }, false, ['deriveKey'])
          .then(function(baseKey) {
            return crypto.subtle.deriveKey(
              { name: 'PBKDF2', salt: salt, iterations: data.iterations || 100000, hash: 'SHA-256' },
              baseKey,
              { name: 'AES-GCM', length: 256 },
              false,
              ['decrypt']
            );
          })
          .then(function(key) {
            return crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, ciphertext);
          })
          .then(function(plaintext) {
            var dec = new TextDecoder();
            var realData = JSON.parse(dec.decode(plaintext));
            doImport(realData);
          })
          .catch(function() {
            showToast('Mot de passe incorrect ou fichier corrompu', 'error');
            document.getElementById('importDataInput').value = '';
          });
        return;
      }
      doImport(data);
    } catch (err) {
      showToast('Fichier invalide : ' + err.message, 'error');
      document.getElementById('importDataInput').value = '';
    }
  };
  reader.readAsText(file);
});

function doImport(data) {
  if (!data || typeof data !== 'object') throw new Error('Format invalide');
  if (!data.interventions && !data.devisList) throw new Error('Aucune donnée trouvée');
  var nbInt = (data.interventions || []).length;
  var nbDevis = (data.devisList || []).length;
  var msg = '⚠ ATTENTION : Cette opération va REMPLACER toutes vos données.\n\n'
    + 'Fichier : ' + nbInt + ' interventions, ' + nbDevis + ' devis.\n\nContinuer ?';
  showConfirm(msg, function(confirm) {
    if (!confirm) { document.getElementById('importDataInput').value = ''; return; }
    try {
      storageSet('pipepline_ch_backup_before_import', {
        interventions: interventions,
        devisList: devisList,
        clients: clients,
        factureCounter: factureCounter,
        devisCounter: devisCounter,
        settings: settings,
        backupAt: new Date().toISOString()
      });
      interventions = data.interventions || [];
      devisList = data.devisList || [];
      clients = data.clients || [];
      stock = data.stock || {};
      factureCounter = data.factureCounter || 1;
      devisCounter = data.devisCounter || 1;
      avoirCounter = data.avoirCounter || 1;
      if (data.settings) {
        for (var key in data.settings) {
          if (settings.hasOwnProperty(key)) settings[key] = data.settings[key];
        }
      }
      interventions.forEach(function(int) {
        if (int.statut === 'termine' && int.pieces && int.pieces.length > 0) {
          int.stockDecremented = true;
        }
      });
      invalidateTotals();
      storageDirty = true;
      saveToStorage().then(function() {
        renderAll();
        haptic(15);
        showToast('Restauration réussie : ' + nbInt + ' interventions, ' + nbDevis + ' devis', 'success');
      });
    } catch (err) {
      showToast('Erreur restauration : ' + err.message, 'error');
    }
    document.getElementById('importDataInput').value = '';
  });
}

document.getElementById('alertOverdue').addEventListener('click', function() { switchTab('factures'); });

/* ==========================================================================
   STOCK
   ========================================================================== */
document.getElementById('openStockBtn').addEventListener('click', function() {
  haptic(10);
  stockSearchTerm = '';
  var searchInput = document.getElementById('stockSearchInput');
  if (searchInput) searchInput.value = '';
  renderStockList();
  document.getElementById('stockModal').classList.add('show');
});
document.getElementById('closeStock').addEventListener('click', function() {
  document.getElementById('stockModal').classList.remove('show');
});
document.getElementById('stockSearchInput').addEventListener('input', debounce(function() { stockSearchTerm = this.value; renderStockList(); }, 150));
document.getElementById('stockSortSelect').addEventListener('change', function() { stockSortMode = this.value; renderStockList(); });

function renderStockStats() {
  var total = Object.keys(stock).length;
  var low = 0, out = 0;
  Object.keys(stock).forEach(function(k) {
    var item = stock[k];
    if (item.qte <= 0) out++;
    else if (item.qte <= item.seuil) low++;
  });
  var elTotal = document.getElementById('stockStatTotal');
  var elLow = document.getElementById('stockStatLow');
  var elOut = document.getElementById('stockStatOut');
  if (elTotal) elTotal.textContent = total;
  if (elLow) elLow.textContent = low;
  if (elOut) elOut.textContent = out;
}
function getFilteredSortedStock() {
  var term = (stockSearchTerm || '').toLowerCase().trim();
  var keys = Object.keys(stock);
  var items = keys.map(function(k) { return { key: k, nom: k, qte: stock[k].qte, seuil: stock[k].seuil }; });
  if (term) items = items.filter(function(it) { return it.nom.toLowerCase().indexOf(term) !== -1; });
  items.sort(function(a, b) {
    switch (stockSortMode) {
      case 'name_desc': return b.nom.localeCompare(a.nom);
      case 'qty_asc': return a.qte - b.qte;
      case 'qty_desc': return b.qte - a.qte;
      case 'low_first':
        var aLow = a.qte <= a.seuil ? 0 : 1;
        var bLow = b.qte <= b.seuil ? 0 : 1;
        if (aLow !== bLow) return aLow - bLow;
        return a.nom.localeCompare(b.nom);
      case 'name_asc':
      default: return a.nom.localeCompare(b.nom);
    }
  });
  return items;
}
function renderStockList() {
  renderStockStats();
  var container = document.getElementById('stockList');
  if (!container) return;
  var items = getFilteredSortedStock();
  if (items.length === 0) {
    container.innerHTML = '<div class="stock-empty">' + (stockSearchTerm ? 'Aucun article pour « ' + escapeHtml(stockSearchTerm) + ' »' : 'Aucun article en stock.<br>Ajoutez votre premier article ci-dessous.') + '</div>';
    return;
  }
  container.innerHTML = items.map(function(it) {
    var qte = it.qte;
    var seuil = it.seuil;
    var state = 'ok';
    var stateLabel = '';
    if (qte <= 0) { state = 'out'; stateLabel = '<span class="si-badge out">Rupture</span>'; }
    else if (qte <= seuil) { state = 'low'; stateLabel = '<span class="si-badge low">Stock bas</span>'; }
    return '<div class="stock-item ' + (state === 'ok' ? '' : state) + '" data-key="' + escapeHtml(it.key) + '">'
      + '<div class="si-info">'
      + '<div class="si-name">' + escapeHtml(it.key) + stateLabel + '</div>'
      + '<div class="si-cat">Seuil : ' + seuil + ' • ' + (state === 'ok' ? 'OK' : (state === 'low' ? 'à réapprovisionner' : 'rupture')) + '</div>'
      + '</div>'
      + '<div class="stock-qty-control">'
      + '<button type="button" class="sq-minus" data-key="' + escapeHtml(it.key) + '">−</button>'
      + '<span class="sq-value ' + (state === 'ok' ? '' : state) + '">' + qte + '</span>'
      + '<button type="button" class="sq-plus" data-key="' + escapeHtml(it.key) + '">+</button>'
      + '</div>'
      + '<div class="si-actions">'
      + '<button type="button" class="si-btn edit-stock" data-key="' + escapeHtml(it.key) + '" title="Modifier">✎</button>'
      + '<button type="button" class="si-btn del del-stock" data-key="' + escapeHtml(it.key) + '" title="Supprimer">🗑</button>'
      + '</div>'
      + '</div>';
  }).join('');
  container.querySelectorAll('.sq-plus').forEach(function(btn) {
    btn.addEventListener('click', function(e) {
      e.stopPropagation();
      var key = this.dataset.key;
      if (!stock[key]) return;
      stock[key].qte = (parseInt(stock[key].qte) || 0) + 1;
      storageSet(STOCK_KEY, stock);
      haptic(8);
      renderStockList();
    });
  });
  container.querySelectorAll('.sq-minus').forEach(function(btn) {
    btn.addEventListener('click', function(e) {
      e.stopPropagation();
      var key = this.dataset.key;
      if (!stock[key]) return;
      stock[key].qte = Math.max(0, (parseInt(stock[key].qte) || 0) - 1);
      storageSet(STOCK_KEY, stock);
      haptic(8);
      renderStockList();
    });
  });
  container.querySelectorAll('.edit-stock').forEach(function(btn) {
    btn.addEventListener('click', function(e) {
      e.stopPropagation();
      var key = this.dataset.key;
      if (!stock[key]) return;
      document.getElementById('stockName').value = key;
      document.getElementById('stockQte').value = stock[key].qte;
      document.getElementById('stockSeuil').value = stock[key].seuil;
      document.getElementById('stockName').focus();
      haptic(8);
    });
  });
  container.querySelectorAll('.del-stock').forEach(function(btn) {
    btn.addEventListener('click', function(e) {
      e.stopPropagation();
      var key = this.dataset.key;
      showConfirm('Supprimer "' + key + '" du stock ?', function(c) {
        if (c) {
          delete stock[key];
          storageSet(STOCK_KEY, stock);
          renderStockList();
          renderPieces();
          showToast('Article supprimé', 'success');
        }
      });
    });
  });
}
document.getElementById('addStockBtn').addEventListener('click', function() {
  var name = document.getElementById('stockName').value.trim();
  var qte = parseInt(document.getElementById('stockQte').value) || 0;
  var seuil = parseInt(document.getElementById('stockSeuil').value) || 0;
  if (!name) { showToast('Nom requis', 'warning'); return; }
  var key = name.toLowerCase();
  var existing = !!stock[key];
  stock[key] = { qte: qte, seuil: seuil };
  storageSet(STOCK_KEY, stock);
  document.getElementById('stockName').value = '';
  document.getElementById('stockQte').value = 0;
  document.getElementById('stockSeuil').value = 1;
  renderStockList();
  showToast(existing ? 'Article mis à jour' : 'Article ajouté', 'success');
  haptic(15);
});

/* ==========================================================================
   RÉCAP MENSUEL
   ========================================================================== */
function renderRecap() {
  var month = recapDate.getMonth();
  var year = recapDate.getFullYear();
  document.getElementById('recapMonthLabel').textContent = formatMois(recapDate);
  var filtered = interventions.filter(function(int) {
    var d = new Date(int.date + 'T00:00:00');
    return d.getMonth() === month && d.getFullYear() === year;
  });
  var totalHT = 0, totalTTC = 0, totalNet = 0, totalHeures = 0, payees = 0, impayees = 0;
  filtered.forEach(function(int) {
    totalHT += getTotalHT(int);
    totalTTC += getTotalTTC(int);
    totalNet += getTotalNet(int);
    totalHeures += int.duree || 0;
    if (int.paye || int.isAvoir) payees++;
    else impayees++;
  });
  document.getElementById('recapGrid').innerHTML =
    '<div class="recap-card"><div class="recap-label">CA TTC</div><div class="recap-value">' + formatCHF(totalTTC) + '</div></div>'
    + '<div class="recap-card"><div class="recap-label">CA Net</div><div class="recap-value green">' + formatCHF(totalNet) + '</div></div>'
    + '<div class="recap-card"><div class="recap-label">Interventions</div><div class="recap-value">' + filtered.length + '</div></div>'
    + '<div class="recap-card"><div class="recap-label">Temps total</div><div class="recap-value">' + formatDuree(totalHeures) + '</div></div>'
    + '<div class="recap-card"><div class="recap-label">Payées</div><div class="recap-value green">' + payees + '</div></div>'
    + '<div class="recap-card"><div class="recap-label">Impayées</div><div class="recap-value red">' + impayees + '</div></div>';
  var detail = document.getElementById('recapDetail');
  if (filtered.length === 0) detail.innerHTML = '<div class="empty-state">Aucune intervention ce mois</div>';
  else {
    var html = '<h3 style="font-size:0.9rem; color:var(--accent); margin-bottom:10px;">Détail</h3><div style="display:flex; flex-direction:column; gap:6px;">';
    filtered.sort(function(a, b) { return (b.date || '').localeCompare(a.date || ''); }).forEach(function(int) {
      var typeInfo = TYPES_TACHES[int.type] || TYPES_TACHES.autre;
      html += '<div style="display:flex; justify-content:space-between; align-items:center; padding:8px 12px; background:var(--bg-surface); border-radius:var(--r-sm); font-size:0.8rem; flex-wrap:wrap; gap:6px;">'
        + '<div><span class="int-type-badge ' + typeInfo.color + '" style="font-size:0.55rem; margin-right:6px;">' + typeInfo.label + '</span><strong>' + escapeHtml(int.client) + '</strong></div>'
        + '<div style="display:flex; gap:12px; align-items:center;">'
        + '<span style="color:var(--text-muted);">' + formatDate(int.date) + '</span>'
        + '<span style="font-weight:600; color:' + (int.isAvoir ? 'var(--purple)' : 'var(--accent)') + ';">' + formatCHF(getTotalTTC(int)) + '</span>'
        + ((int.paye || int.isAvoir) ? '<span style="color:var(--success);">✓</span>' : '<span style="color:var(--danger);">⚠</span>')
        + '</div>'
        + '</div>';
    });
    html += '</div>';
    detail.innerHTML = html;
  }
}
document.getElementById('prevMonthBtn').addEventListener('click', function() { haptic(8); recapDate.setMonth(recapDate.getMonth() - 1); renderRecap(); });
document.getElementById('nextMonthBtn').addEventListener('click', function() { haptic(8); recapDate.setMonth(recapDate.getMonth() + 1); renderRecap(); });
document.getElementById('dashToggle').addEventListener('click', function(e) {
  e.stopPropagation();
  haptic(8);
  var panel = document.getElementById('caPanel');
  panel.classList.toggle('open');
  this.classList.toggle('open');
});

/* ==========================================================================
   DÉCOMPTE TVA
   ========================================================================== */
function openTvaModal() {
  haptic(10);
  var yearSelect = document.getElementById('tvaYearSelect');
  var currentYear = new Date().getFullYear();
  yearSelect.innerHTML = '';
  for (var y = currentYear; y >= currentYear - 5; y--) {
    var opt = document.createElement('option');
    opt.value = y;
    opt.textContent = y;
    yearSelect.appendChild(opt);
  }
  yearSelect.value = currentYear;
  renderTvaResult();
  document.getElementById('tvaModal').classList.add('show');
}
function getTvaPeriodRange(year, period) {
  switch (period) {
    case 'q1': return { start: new Date(year, 0, 1), end: new Date(year, 2, 31) };
    case 'q2': return { start: new Date(year, 3, 1), end: new Date(year, 5, 30) };
    case 'q3': return { start: new Date(year, 6, 1), end: new Date(year, 8, 30) };
    case 'q4': return { start: new Date(year, 9, 1), end: new Date(year, 11, 31) };
    case 's1': return { start: new Date(year, 0, 1), end: new Date(year, 5, 30) };
    case 's2': return { start: new Date(year, 6, 1), end: new Date(year, 11, 31) };
    case 'year': return { start: new Date(year, 0, 1), end: new Date(year, 11, 31) };
  }
}
function renderTvaResult() {
  var year = parseInt(document.getElementById('tvaYearSelect').value);
  var period = document.getElementById('tvaPeriodSelect').value;
  var range = getTvaPeriodRange(year, period);
  var filtered = interventions.filter(function(int) {
    if (!int.date) return false;
    var d = new Date(int.date + 'T00:00:00');
    return d >= range.start && d <= range.end;
  });
  var caHT = 0, tvaCollectee = 0, caTTC = 0, avoirsHT = 0;
  var parTaux = {};
  filtered.forEach(function(int) {
    if (int.isAvoir) {
      avoirsHT += Math.abs(getTotalHT(int));
      return;
    }
    var ht = getTotalHT(int);
    var taux = getTauxTva(int);
    caHT += ht;
    caTTC += getTotalTTC(int);
    tvaCollectee += getTvaMontant(int);
    if (!parTaux[taux]) parTaux[taux] = { base: 0, tva: 0 };
    parTaux[taux].base += ht;
    parTaux[taux].tva += getTvaMontant(int);
  });
  caHT -= avoirsHT;
  var html = '';
  html += '<div style="display:grid; grid-template-columns: 1fr 1fr; gap:10px; margin:14px 0;">';
  html += '<div class="ca-card"><span class="ca-lbl">CA HT facturé</span><span class="ca-val">' + formatCHF(caHT) + '</span></div>';
  html += '<div class="ca-card"><span class="ca-lbl">CA TTC facturé</span><span class="ca-val">' + formatCHF(caTTC) + '</span></div>';
  html += '<div class="ca-card"><span class="ca-lbl">TVA collectée</span><span class="ca-val net">' + formatCHF(tvaCollectee) + '</span></div>';
  html += '<div class="ca-card"><span class="ca-lbl">Avoirs HT</span><span class="ca-val red">-' + formatCHF(avoirsHT) + '</span></div>';
  html += '</div>';
  if (Object.keys(parTaux).length > 1) {
    html += '<h4 style="font-size:0.75rem; color:var(--accent); margin:14px 0 8px;">Répartition par taux</h4>';
    html += '<div style="display:flex; flex-direction:column; gap:6px;">';
    Object.keys(parTaux).sort().forEach(function(t) {
      var p = parTaux[t];
      html += '<div style="display:flex; justify-content:space-between; padding:6px 10px; background:var(--bg-surface); border-radius:var(--r-xs); font-size:0.75rem;">'
        + '<span><strong>' + t + '%</strong> — base ' + formatCHF(p.base) + '</span>'
        + '<span style="font-weight:700; color:var(--success);">TVA ' + formatCHF(p.tva) + '</span>'
        + '</div>';
    });
    html += '</div>';
  }
  html += '<div style="margin-top:16px; padding:12px; background:var(--accent-light); border-radius:var(--r-sm); font-size:0.75rem; color:var(--text-secondary); line-height:1.6;">';
  html += '<strong>Rappel AFC :</strong> ce décompte concerne la <strong>TVA collectée</strong> sur vos ventes. ';
  html += 'Pour la déclaration, vous devez y soustraire la <strong>TVA déductible</strong> (achats, frais généraux) que vous trouverez sur vos factures fournisseurs. ';
  html += 'Seuil d\'assujettissement : ' + formatCHF(TVA_SEUIL_CHF) + ' de CA annuel.';
  html += '</div>';
  document.getElementById('tvaResult').innerHTML = html;
}
document.getElementById('tvaYearSelect').addEventListener('change', renderTvaResult);
document.getElementById('tvaPeriodSelect').addEventListener('change', renderTvaResult);
document.getElementById('closeTva').addEventListener('click', function() { document.getElementById('tvaModal').classList.remove('show'); });
document.getElementById('openTvaBtn').addEventListener('click', openTvaModal);
document.getElementById('openTvaRecapBtn').addEventListener('click', openTvaModal);
document.getElementById('tvaExportBtn').addEventListener('click', function() {
  var year = parseInt(document.getElementById('tvaYearSelect').value);
  var period = document.getElementById('tvaPeriodSelect').value;
  var range = getTvaPeriodRange(year, period);
  var filtered = interventions.filter(function(int) {
    if (!int.date) return false;
    var d = new Date(int.date + 'T00:00:00');
    return d >= range.start && d <= range.end && !int.isAvoir;
  });
  var lines = [];
  lines.push(['N° facture', 'Date', 'Client', 'Pays', 'Base HT', 'Taux TVA', 'TVA', 'TTC'].join(';'));
  filtered.forEach(function(int) {
    lines.push([
      int.numeroFacture || '',
      int.date || '',
      (int.client || '').replace(/[;\n]/g, ' '),
      int.paysClient || 'CH',
      getTotalHT(int).toFixed(2).replace('.', ','),
      getTauxTva(int),
      getTvaMontant(int).toFixed(2).replace('.', ','),
      getTotalTTC(int).toFixed(2).replace('.', ',')
    ].join(';'));
  });
  var csv = '\uFEFF' + lines.join('\r\n');
  var blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  var link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = 'tva_' + year + '_' + period + '.csv';
  link.click();
  showToast('Décompte TVA exporté', 'success');
});

/* ==========================================================================
   CERTIFICAT CHAUDIÈRE
   ========================================================================== */
function openCertificateModal(id) {
  haptic(10);
  var int = interventions.find(function(i) { return i.id === id; });
  if (!int) return;
  document.getElementById('certificateModal').dataset.intId = id;
  document.getElementById('certMarque').value = int.certMarque || '';
  document.getElementById('certSerie').value = int.certSerie || '';
  document.getElementById('certAnnee').value = int.certAnnee || '';
  document.getElementById('certCombustible').value = int.certCombustible || 'gaz';
  document.getElementById('certPuissance').value = int.certPuissance || '';
  document.getElementById('certCO').value = int.certCO || '';
  document.getElementById('certCO2').value = int.certCO2 || '';
  document.getElementById('certTempFumees').value = int.certTempFumees || '';
  document.getElementById('certRendement').value = int.certRendement || '';
  document.getElementById('certTravaux').value = int.certTravaux || '';
  document.getElementById('certObservations').value = int.certObservations || '';
  document.getElementById('certDate').value = int.date || new Date().toISOString().slice(0, 10);
  var nextYear = new Date(int.date || Date.now());
  nextYear.setFullYear(nextYear.getFullYear() + 1);
  document.getElementById('certProchain').value = nextYear.toISOString().slice(0, 10);
  document.getElementById('certificateModal').classList.add('show');
}
document.getElementById('cancelCertificate').addEventListener('click', function() {
  document.getElementById('certificateModal').classList.remove('show');
});
document.getElementById('generateCertificateBtn').addEventListener('click', function() {
  var intId = document.getElementById('certificateModal').dataset.intId;
  var int = interventions.find(function(i) { return i.id === intId; });
  if (!int) return;
  var certData = {
    marque: document.getElementById('certMarque').value.trim(),
    serie: document.getElementById('certSerie').value.trim(),
    annee: document.getElementById('certAnnee').value,
    combustible: document.getElementById('certCombustible').value,
    puissance: document.getElementById('certPuissance').value,
    CO: document.getElementById('certCO').value,
    CO2: document.getElementById('certCO2').value,
    tempFumees: document.getElementById('certTempFumees').value,
    rendement: document.getElementById('certRendement').value,
    travaux: document.getElementById('certTravaux').value.trim(),
    observations: document.getElementById('certObservations').value.trim(),
    date: document.getElementById('certDate').value,
    prochain: document.getElementById('certProchain').value
  };
  if (!certData.marque) { showToast('Marque / modèle requis', 'warning'); return; }
  int.certificat = certData;
  markAsDirty();
  renderAll();
  document.getElementById('certificateModal').classList.remove('show');
  haptic(15);
  showToast('Certificat enregistré — génération PDF...', 'success');
  generateCertificatePDF(int);
});

function generateCertificatePDF(int) {
  loadJsPDF().then(function() {
    var jsPDF = window.jspdf.jsPDF;
    var doc = new jsPDF('p', 'mm', 'a4');
    var pw = doc.internal.pageSize.getWidth();
    var ph = doc.internal.pageSize.getHeight();
    var margin = 15;
    var y = margin;
    doc.setFillColor('#ed6c02');
    doc.rect(0, 0, pw, 38, 'F');
    doc.setTextColor('#ffffff');
    doc.setFontSize(18);
    doc.setFont('helvetica', 'bold');
    doc.text('CERTIFICAT D\'ENTRETIEN', pw / 2, 20, { align: 'center' });
    doc.setFontSize(10);
    doc.setFont('helvetica', 'normal');
    doc.text('Chaudière — Conforme aux exigences cantonales', pw / 2, 30, { align: 'center' });
    y = 50;
    doc.setTextColor('#333333');
    doc.setFontSize(10);
    var cert = int.certificat || {};
    var lines = [
      ['Entreprise', settings.nom],
      ['IDE', settings.siret || '—'],
      ['Date d\'intervention', formatDate(cert.date || int.date)],
      ['Client', int.client || '—'],
      ['Adresse', int.adresse || '—']
    ];
    lines.forEach(function(l) {
      doc.setFont('helvetica', 'bold');
      doc.text(l[0] + ' :', margin + 5, y);
      doc.setFont('helvetica', 'normal');
      doc.text(String(l[1]), margin + 55, y);
      y += 7;
    });
    y += 5;
    doc.setDrawColor('#ed6c02');
    doc.line(margin, y, pw - margin, y);
    y += 8;
    doc.setFontSize(12);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor('#ed6c02');
    doc.text('CHAUDIÈRE', margin + 5, y);
    y += 8;
    doc.setFontSize(10);
    doc.setTextColor('#333333');
    var chaudiere = [
      ['Marque / Modèle', cert.marque || '—'],
      ['N° de série', cert.serie || '—'],
      ['Année d\'installation', cert.annee || '—'],
      ['Combustible', ({gaz: 'Gaz naturel', mazout: 'Mazout', propane: 'Propane', pellet: 'Pellets', bois: 'Bois', pac: 'Pompe à chaleur'}[cert.combustible]) || cert.combustible],
      ['Puissance (kW)', cert.puissance || '—']
    ];
    chaudiere.forEach(function(l) {
      doc.setFont('helvetica', 'bold');
      doc.text(l[0] + ' :', margin + 5, y);
      doc.setFont('helvetica', 'normal');
      doc.text(String(l[1]), margin + 70, y);
      y += 7;
    });
    y += 5;
    doc.setDrawColor('#cccccc');
    doc.line(margin, y, pw - margin, y);
    y += 8;
    doc.setFontSize(12);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor('#ed6c02');
    doc.text('MESURES & CONTRÔLES', margin + 5, y);
    y += 8;
    doc.setFontSize(10);
    doc.setTextColor('#333333');
    var mesures = [
      ['Taux de CO (ppm)', cert.CO || '—'],
      ['CO₂ (%)', cert.CO2 || '—'],
      ['Température fumées (°C)', cert.tempFumees || '—'],
      ['Rendement (%)', cert.rendement || '—']
    ];
    mesures.forEach(function(l) {
      doc.setFont('helvetica', 'bold');
      doc.text(l[0] + ' :', margin + 5, y);
      doc.setFont('helvetica', 'normal');
      doc.text(String(l[1]), margin + 70, y);
      y += 7;
    });
    y += 5;
    doc.setFont('helvetica', 'bold');
    doc.text('Interventions effectuées :', margin + 5, y);
    y += 6;
    doc.setFont('helvetica', 'normal');
    var travauxLines = doc.splitTextToSize(cert.travaux || '—', pw - 2 * margin - 10);
    doc.text(travauxLines, margin + 5, y);
    y += travauxLines.length * 5 + 5;
    doc.setFont('helvetica', 'bold');
    doc.text('Observations / recommandations :', margin + 5, y);
    y += 6;
    doc.setFont('helvetica', 'normal');
    var obsLines = doc.splitTextToSize(cert.observations || '—', pw - 2 * margin - 10);
    doc.text(obsLines, margin + 5, y);
    y += obsLines.length * 5 + 10;
    doc.setDrawColor('#cccccc');
    doc.line(margin, y, pw - margin, y);
    y += 8;
    doc.setFontSize(10);
    doc.setFont('helvetica', 'bold');
    doc.text('Prochain entretien recommandé :', margin + 5, y);
    doc.setFont('helvetica', 'normal');
    doc.text(formatDate(cert.prochain || ''), margin + 75, y);
        y += 20;

    // --- Signature du technicien uniquement ---
    if (int.signatureTech) {
      try { doc.addImage(int.signatureTech, 'PNG', margin + 5, y, 60, 25); } catch(e) { console.warn('Erreur sig tech', e); }
      doc.setFontSize(8);
      doc.setTextColor('#666666');
      doc.text('Signature du technicien', margin + 5, y + 30);
      if (int.signatureTechAt) {
        doc.setFontSize(7);
        doc.setTextColor('#999999');
        var dTech = new Date(int.signatureTechAt);
        var dateTech = String(dTech.getDate()).padStart(2, '0') + '.' + String(dTech.getMonth() + 1).padStart(2, '0') + '.' + dTech.getFullYear()
          + ' ' + String(dTech.getHours()).padStart(2, '0') + ':' + String(dTech.getMinutes()).padStart(2, '0');
        doc.text('Signé le ' + dateTech, margin + 5, y + 34);
      }
    } else {
      doc.setFontSize(8);
      doc.setTextColor('#999999');
      doc.setFont('helvetica', 'italic');
      doc.text('(Aucune signature enregistrée — signez depuis la fiche intervention)', margin + 5, y + 10);
    }

    // --- Nom de l'entreprise pour renforcer la valeur du certificat ---
    doc.setFontSize(9);
    doc.setTextColor('#333333');
    doc.setFont('helvetica', 'bold');
    doc.text(settings.nom + (settings.siret ? ' (' + settings.siret + ')' : ''), margin + 5, y + 42);
    doc.setFontSize(7);
    doc.setTextColor('#999999');
    doc.text(settings.nom + ' - ' + settings.adresse + ' - ' + settings.tel, pw / 2, ph - 10, { align: 'center' });
    doc.save('Certificat_' + (int.numeroFacture || 'chaudiere') + '.pdf');
    showToast('Certificat PDF téléchargé', 'success');
  }).catch(function() { showToast('Impossible de générer le PDF', 'error'); });
}
/* ==========================================================================
   BACKUP REMINDER / STORAGE
   ========================================================================== */
function checkBackupReminder() {
  var alertEl = document.getElementById('alertBackup');
  var alertText = document.getElementById('alertBackupText');
  var seuil = settings.seuilSauvegarde || 15;
  if (!backupMeta.lastExportAt) {
    var derniereAlerte = backupMeta.lastReminderAt ? new Date(backupMeta.lastReminderAt) : null;
    if (derniereAlerte) {
      var joursDepuisAlerte = Math.floor((new Date() - derniereAlerte) / 86400000);
      if (joursDepuisAlerte < 7) { alertEl.classList.remove('show'); return; }
    }
    alertText.innerHTML = 'Pensez à <strong>sauvegarder</strong> vos données pour les protéger';
    alertEl.classList.add('show');
    return;
  }
  var jours = joursDepuis(backupMeta.lastExportAt);
  if (jours === null || jours < seuil) { alertEl.classList.remove('show'); return; }
  if (backupMeta.lastReminderAt) {
    var joursDepuisRappel = joursDepuis(backupMeta.lastReminderAt);
    if (joursDepuisRappel !== null && joursDepuisRappel < 7) { alertEl.classList.remove('show'); return; }
  }
  alertText.innerHTML = 'Cela fait <strong>' + jours + ' jours</strong> depuis votre dernière sauvegarde';
  alertEl.classList.add('show');
}
function dismissBackupReminder() {
  backupMeta.lastReminderAt = new Date().toISOString();
  storageDirty = true;
  saveToStorage();
  document.getElementById('alertBackup').classList.remove('show');
}
document.getElementById('alertBackup').addEventListener('click', function(e) {
  if (e.target.closest('.alert-close')) return;
  document.getElementById('exportDataBtn').click();
});
document.getElementById('alertBackupClose').addEventListener('click', function(e) {
  e.stopPropagation();
  dismissBackupReminder();
});
function checkStorageUsage() {
  if (!navigator.storage || !navigator.storage.estimate) return;
  var lastCheck = localStorage.getItem(STORAGE_ALERT_KEY);
  if (lastCheck && (new Date() - new Date(lastCheck)) / 3600000 < 24) return;
  navigator.storage.estimate().then(function(est) {
    localStorage.setItem(STORAGE_ALERT_KEY, new Date().toISOString());
    var pct = Math.round((est.usage / est.quota) * 100);
    if (pct >= 80) {
      document.getElementById('alertStorageText').innerHTML = 'Stockage <strong>' + pct + '%</strong> utilisé.';
      document.getElementById('alertStorage').classList.add('show');
    }
  }).catch(function() {});
}
document.getElementById('alertStorageClose').addEventListener('click', function() {
  document.getElementById('alertStorage').classList.remove('show');
  localStorage.setItem(STORAGE_ALERT_KEY, new Date().toISOString());
});

/* ==========================================================================
   AUTOCOMPLETE SETUP
   ========================================================================== */
setupAutocomplete('intClient', 'intClientAutocomplete', function(c) {
  document.getElementById('intClient').value = c.nom || '';
  if (c.email) document.getElementById('intEmail').value = c.email;
  if (c.tel) document.getElementById('intTel').value = c.tel;
  if (c.adresse) document.getElementById('intAdresse').value = c.adresse;
});
setupAutocomplete('planClient', 'planClientAutocomplete', function(c) {
  document.getElementById('planClient').value = c.nom || '';
  if (c.tel) document.getElementById('planTel').value = c.tel;
  if (c.adresse) document.getElementById('planAdresse').value = c.adresse;
});
setupAutocomplete('devisClient', 'devisClientAutocomplete', function(c) {
  document.getElementById('devisClient').value = c.nom || '';
  if (c.email) document.getElementById('devisEmail').value = c.email;
  if (c.tel) document.getElementById('devisTel').value = c.tel;
  if (c.adresse) document.getElementById('devisAdresse').value = c.adresse;
});

document.getElementById('verifyAddressBtn').addEventListener('click', function() {
  var adresse = document.getElementById('intAdresse').value.trim();
  if (!adresse) { showToast('Saisissez une adresse', 'warning'); return; }
  window.open(getMapsHref(adresse), '_blank');
});

/* ==========================================================================
   ÉCHAPPE / RACCOURCIS
   ========================================================================== */
document.addEventListener('keydown', function(e) {
  if ((e.ctrlKey || e.metaKey) && e.key === 's') {
    e.preventDefault();
    storageDirty = true;
    saveToStorage().then(function() { showToast('Sauvegardé (Ctrl+S)', 'success'); });
  }
  if (e.key === 'Escape') {
    document.querySelectorAll('.modal-overlay.show').forEach(function(m) {
      if (m.id === 'signatureModal') saveSignatures();
      m.classList.remove('show');
    });
    var as = document.getElementById('actionSheet');
    if (as.classList.contains('show')) as.classList.remove('show');
    editingDevisId = null;
    editingPlanningId = null;
    convertDevisSourceId = null;
    currentAvoirSourceFactureId = null;
  }
});

window.addEventListener('beforeunload', function() { if (storageDirty) saveToStorage(); });
window.addEventListener('pagehide', function() { if (storageDirty) saveToStorage(); });
document.addEventListener('visibilitychange', function() {
  if (document.visibilityState === 'hidden' && storageDirty) saveToStorage();
});

if ('BroadcastChannel' in window) {
  try {
    broadcastChannel = new BroadcastChannel('pipepline_ch_sync');
    broadcastChannel.onmessage = function(e) {
      if (e.data && e.data.type === 'data-updated') {
        loadFromStorage().then(function() { renderAll(); });
      }
    };
  } catch(e) {}
}

/* ==========================================================================
   SWIPE ENTRE ONGLETS
   ========================================================================== */
(function setupSwipe() {
  var tabs = ['today', 'planning', 'interventions', 'factures', 'devis', 'recap'];
  var startX = 0, startY = 0, startTime = 0;
  var minSwipe = 80, maxTime = 600, maxVertical = 60;
  var target = document.querySelector('.app-container');
  if (!target) return;
  target.addEventListener('touchstart', function(e) {
    if (e.touches.length !== 1) return;
    startX = e.touches[0].clientX;
    startY = e.touches[0].clientY;
    startTime = Date.now();
  }, { passive: true });
  target.addEventListener('touchend', function(e) {
    if (e.changedTouches.length !== 1) return;
    var dx = e.changedTouches[0].clientX - startX;
    var dy = e.changedTouches[0].clientY - startY;
    var dt = Date.now() - startTime;
    if (dt > maxTime) return;
    if (Math.abs(dy) > maxVertical) return;
    if (Math.abs(dx) < minSwipe) return;
    if (document.querySelector('.modal-overlay.show')) return;
    if (document.getElementById('actionSheet').classList.contains('show')) return;
    var current = document.querySelector('.main-tab.active');
    if (!current) return;
    var idx = tabs.indexOf(current.dataset.tab);
    if (idx === -1) return;
    if (dx < 0 && idx < tabs.length - 1) switchTab(tabs[idx + 1]);
    else if (dx > 0 && idx > 0) switchTab(tabs[idx - 1]);
  }, { passive: true });
})();

/* ==========================================================================
   SWITCH TAB
   ========================================================================== */
function switchTab(tabName) {
  document.querySelectorAll('.main-tab').forEach(function(t) {
    if (t.dataset.tab === tabName) t.classList.add('active');
    else t.classList.remove('active');
  });
  document.querySelectorAll('.bottom-nav-item').forEach(function(t) {
    if (t.dataset.tab === tabName) t.classList.add('active');
    else t.classList.remove('active');
  });
  document.querySelectorAll('.tab-content').forEach(function(c) {
    if (c.id === 'tab-' + tabName) c.classList.add('active');
    else c.classList.remove('active');
  });
  if (tabName === 'recap') renderRecap();
  if (tabName === 'planning') renderPlanning();
  if (tabName === 'today') renderToday();
  clearTabNew(tabName);
  haptic(8);
}
document.querySelectorAll('.main-tab').forEach(function(tab) {
  tab.addEventListener('click', function() { switchTab(this.dataset.tab); });
});
document.querySelectorAll('.bottom-nav-item').forEach(function(tab) {
  tab.addEventListener('click', function() { switchTab(this.dataset.tab); });
});
document.getElementById('todayWeekBtn').addEventListener('click', function() {
  planningDate = new Date();
  selectedPlanningDate = new Date();
  switchTab('planning');
});
document.getElementById('todayWeekBtn2').addEventListener('click', function() {
  planningDate = new Date();
  selectedPlanningDate = new Date();
  renderPlanning();
});
document.getElementById('prevWeekBtn').addEventListener('click', function() { haptic(8); planningDate.setDate(planningDate.getDate() - 7); renderPlanning(); });
document.getElementById('nextWeekBtn').addEventListener('click', function() { haptic(8); planningDate.setDate(planningDate.getDate() + 7); renderPlanning(); });

setInterval(function() { if (storageDirty) saveToStorage(); }, 180000);

/* ==========================================================================
   PARAMÈTRES
   ========================================================================== */
document.getElementById('settingsBtn').addEventListener('click', function() {
  var statusEl = document.getElementById('offlineStatus');
  if (statusEl) {
    var jspdfReady = !!(window.jspdf && window.jspdf.jsPDF);
    var qrReady = !!(window.SwissQRBill && window.SwissQRBill.QRBill);
    if (jspdfReady && qrReady) {
      statusEl.innerHTML = '✅ <strong>Prêt hors ligne</strong> — jsPDF + SwissQRBill chargés.';
      statusEl.style.background = '#e8f5e9';
      statusEl.style.color = '#1b5e20';
    } else if (jspdfReady) {
      statusEl.innerHTML = '⏳ <strong>Partiel</strong> — jsPDF OK, SwissQRBill pas encore chargé. Testez un PDF QR.';
      statusEl.style.background = '#fff3e0';
      statusEl.style.color = '#7a3d00';
    } else {
      statusEl.innerHTML = '⏳ <strong>Chargement à la demande</strong> — testez un PDF pour vérifier.';
      statusEl.style.background = 'var(--bg-surface)';
      statusEl.style.color = 'var(--text-secondary)';
    }
  }
  document.getElementById('setTheme').value = getCurrentTheme();
  document.getElementById('setPinActive').checked = pinMeta.active || false;
  document.getElementById('setPin').value = '';
  document.getElementById('pinSetupBlock').style.display = (pinMeta.active || false) ? 'block' : 'none';
  document.getElementById('setEncryptExport').checked = settings.encryptExport || false;
  document.getElementById('setNom').value = settings.nom;
  document.getElementById('setAdresse').value = settings.adresse;
  document.getElementById('setZip').value = settings.zip || '';
  document.getElementById('setCity').value = settings.city || '';
  document.getElementById('setSiret').value = settings.siret;
  document.getElementById('setIban').value = settings.iban || '';
  updateIbanStatus();
  document.getElementById('setTel').value = settings.tel;
  document.getElementById('setEmail').value = settings.email;
  document.getElementById('setTaxe').value = settings.taxe;
  document.getElementById('setTva').value = settings.tva;
  document.getElementById('setTvaActive').checked = settings.tvaActive;
  document.getElementById('setKmRate').value = settings.kmRate || 0.70;
  document.getElementById('setAcompteSeuil').value = settings.acompteSeuil || 5000;
  document.getElementById('setTauxDefaut').value = settings.tauxDefaut;
  document.getElementById('setDeplacementDefaut').value = settings.deplacementDefaut;
  document.getElementById('setSeuilAlerte').value = settings.seuilAlerte || 30;
  document.getElementById('setSeuilSauvegarde').value = settings.seuilSauvegarde || 15;
  document.getElementById('setTvaIntra').value = settings.tvaIntra || '';
  document.getElementById('setAssuranceNom').value = settings.assuranceNom || '';
  document.getElementById('setAssuranceNum').value = settings.assuranceNum || '';
  document.getElementById('setDelaiPaiement').value = settings.delaiPaiement || 30;
  document.getElementById('settingsModal').classList.add('show');
});
document.getElementById('setPinActive').addEventListener('change', function() {
  document.getElementById('pinSetupBlock').style.display = this.checked ? 'block' : 'none';
});
function updateIbanStatus() {
  var iban = document.getElementById('setIban').value.trim();
  var status = document.getElementById('ibanStatus');
  if (!iban) { status.style.display = 'none'; return; }
  status.style.display = 'block';
  if (isValidSwissIBAN(iban)) {
    status.innerHTML = '✅ IBAN suisse valide — QR-facture activée sur les PDF';
    status.style.background = '#e8f5e9';
    status.style.color = '#1b5e20';
  } else {
    status.innerHTML = '⚠ IBAN invalide ou non suisse — QR-facture désactivée (PDF simple utilisé)';
    status.style.background = '#ffebee';
    status.style.color = '#c62828';
  }
}
document.getElementById('setIban').addEventListener('input', debounce(updateIbanStatus, 300));
document.getElementById('cancelSettings').addEventListener('click', function() {
  document.getElementById('settingsModal').classList.remove('show');
});
document.getElementById('saveSettings').addEventListener('click', function() {
  var newTheme = document.getElementById('setTheme').value;
  applyTheme(newTheme);
  var newPinActive = document.getElementById('setPinActive').checked;
  var newPin = document.getElementById('setPin').value;
  if (newPinActive && !pinMeta.active) {
    if (!newPin || newPin.length < 4) { showToast('Code PIN min. 4 chiffres requis', 'warning'); return; }
    var salt = generateSalt();
    var enc = new TextEncoder();
    crypto.subtle.digest('SHA-256', enc.encode(newPin)).then(function(hash) {
      pinMeta = {
        active: true,
        salt: uint8ToBase64(salt),
        pinHash: uint8ToBase64(new Uint8Array(hash)),
        pinLength: newPin.length,
        createdAt: new Date().toISOString()
      };
      return savePinMeta();
    }).then(function() {
      saveSettingsData();
      showToast('Code PIN activé. Rechargement...', 'success');
      setTimeout(function() { location.reload(); }, 1500);
    });
    return;
  } else if (!newPinActive && pinMeta.active) {
    pinMeta.active = false;
    savePinMeta();
    cryptoKey = null;
    showToast('Code PIN désactivé', 'warning');
  }
  saveSettingsData();
  document.getElementById('settingsModal').classList.remove('show');
  renderAll();
  checkBackupReminder();
  haptic(15);
  showToast('Paramètres sauvegardés', 'success');
});
function saveSettingsData() {
  settings.nom = document.getElementById('setNom').value.trim() || 'PipePline';
  settings.adresse = document.getElementById('setAdresse').value.trim();
  settings.zip = document.getElementById('setZip').value.trim();
  settings.city = document.getElementById('setCity').value.trim();
  settings.siret = document.getElementById('setSiret').value.trim();
  settings.iban = document.getElementById('setIban').value.trim();
  settings.tel = document.getElementById('setTel').value.trim();
  settings.email = document.getElementById('setEmail').value.trim();
  settings.taxe = parseFloat(document.getElementById('setTaxe').value) || 21.2;
  settings.tva = parseFloat(document.getElementById('setTva').value) || 8.1;
  settings.tvaActive = document.getElementById('setTvaActive').checked;
  settings.kmRate = parseFloat(document.getElementById('setKmRate').value) || 0.70;
  settings.acompteSeuil = parseFloat(document.getElementById('setAcompteSeuil').value) || 5000;
  settings.tauxDefaut = parseFloat(document.getElementById('setTauxDefaut').value) || 90;
  settings.deplacementDefaut = parseFloat(document.getElementById('setDeplacementDefaut').value) || 50;
  settings.seuilAlerte = parseInt(document.getElementById('setSeuilAlerte').value) || 30;
  settings.seuilSauvegarde = parseInt(document.getElementById('setSeuilSauvegarde').value) || 15;
  settings.tvaIntra = document.getElementById('setTvaIntra').value.trim();
  settings.assuranceNom = document.getElementById('setAssuranceNom').value.trim();
  settings.assuranceNum = document.getElementById('setAssuranceNum').value.trim();
  settings.delaiPaiement = parseInt(document.getElementById('setDelaiPaiement').value) || 30;
  settings.encryptExport = document.getElementById('setEncryptExport').checked;
  invalidateTotals();
  storageDirty = true;
  saveToStorage();
}

/* ==========================================================================
   RENDU GLOBAL
   ========================================================================== */
function renderAll() {
  renderStats();
  renderToday();
  renderInterventions();
  renderFactures();
  renderDevis();
  renderPlanning();
  renderRecap();
  updateTabNewDots();
}

/* ==========================================================================
   INITIALISATION
   ========================================================================== */
function init() {
  applyTheme(getCurrentTheme());
  loadTabNews();

  loadPinMeta().then(function(meta) {
    if (meta && meta.active) {
      showPinOverlay();
    } else {
      isAuthenticated = true;
      startApp();
    }
  });
}

function startApp() {
  showSkeleton(document.getElementById('interventionsGroups'), 3);
  showSkeleton(document.getElementById('factureList'), 3);

  loadFromStorage().then(function() {
    renderAll();
    updateSaveIndicator(true);
    if (interventions.length > 0 || devisList.length > 0) {
      setTimeout(function() { showToast('Données locales chargées', 'success'); }, 500);
    }
    setTimeout(showTvaBanner, 800);
  });

  setTimeout(checkBackupReminder, 1500);
  setTimeout(checkStorageUsage, 3000);
}

/* ==========================================================================
   DÉMARRAGE
   ========================================================================== */
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
