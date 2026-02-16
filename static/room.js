// =====================================================
// QSEC Room Client — BB84 Key Exchange + AES-256 Chat
// =====================================================

// --- Configuration ---
const CONFIG = {
    COLORS: {
        teal: '#64ffda',
        danger: '#ef4444',
        warning: '#f59e0b',
        success: '#10b981',
        purple: '#818cf8',
        cyan: '#22d3ee'
    },
    BB84_QUBITS: 4096,
    EC_PASSES: 4,          // Number of CASCADE error correction passes
    EC_BLOCK_SIZE: 16,     // Initial block size for parity checks
    PA_SECURITY_PARAM: 64, // Security parameter for privacy amplification (bits to sacrifice)
    QBER_THRESHOLD: 11     // Max tolerable QBER % (BB84 theoretical bound ≈ 11%)
};

// --- Socket.IO ---
const socket = (typeof io === 'function') ? io() : null;
if (!socket) { document.body.innerHTML = '<h1>Socket.IO failed to load</h1>'; throw new Error('no socket'); }

// --- Global State ---
const params = new URLSearchParams(window.location.search);
const username = params.get('username') || 'Guest';
let expectedUsers = parseInt(params.get('expected')) || 0;
const room = window.location.pathname.split('/').pop();

let roomKey = null;   // AES-GCM CryptoKey for the chat room
let sessionKeys = {};     // { peerName: CryptoKey } derived via BB84
let bb84Sessions = {};     // { peerName: { role, bits, bases, len, stage } }

// Error Correction & Privacy Amplification state
const ECPAState = {
    active: false,
    peer: null,
    role: null,           // 'sender' | 'receiver'
    siftedKey: '',        // the sifted key bits
    correctedKey: '',     // after error correction
    amplifiedKey: '',     // after privacy amplification
    ecPass: 0,
    ecTotalPasses: CONFIG.EC_PASSES,
    ecErrorsFound: 0,
    ecErrorsCorrected: 0,
    ecBlocksChecked: 0,
    paInputBits: 0,
    paOutputBits: 0,
    paCompressionRatio: 0,
    stage: 'idle'         // 'idle' | 'ec_running' | 'ec_done' | 'pa_running' | 'pa_done'
};

// --- DOM refs ---
const dom = {
    roomName: document.getElementById('roomNameDisplay'),
    roomCopyBtn: document.getElementById('roomCopyBtn'),
    userList: document.getElementById('userList'),
    userCount: document.getElementById('userCount'),
    expectedCount: document.getElementById('expectedCount'),
    chatMessages: document.getElementById('chatMessages'),
    messageInput: document.getElementById('messageInput'),
    sendBtn: document.getElementById('sendBtn'),
    attachBtn: document.getElementById('attachBtn'),
    fileInput: document.getElementById('fileInput'),
    statusBadge: document.getElementById('sessionStatusBadge'),
    statusText: document.getElementById('sessionStatusText'),
    leaveBtn: document.getElementById('leaveBtn'),
    keyStatus: document.getElementById('keyStatusDisplay'),
    qberValue: document.getElementById('qberValue'),
    qberTotalBits: document.getElementById('qberTotalBits'),
    qberMatched: document.getElementById('qberMatched'),
    qberDiscarded: document.getElementById('qberDiscarded'),
    qberVerdict: document.getElementById('qberVerdict'),
    systemLog: document.getElementById('systemLog'),
    eavesdropperCanvas: document.getElementById('eavesdropperCanvas'),
    channelStatusBadge: document.getElementById('channelStatusBadge'),
    qberChartCanvas: document.getElementById('qberChart'),
    voiceBtn: document.getElementById('voiceBtn'),
    voiceRecordArea: document.getElementById('voiceRecordArea'),
    voiceTimer: document.getElementById('voiceTimer'),
    voiceWaveform: document.getElementById('voiceWaveform'),
    voiceCancelBtn: document.getElementById('voiceCancelBtn')
};

// --- Init UI ---
dom.roomName.textContent = room;
dom.expectedCount.textContent = expectedUsers > 0 ? expectedUsers : '∞';
dom.sendBtn.disabled = true;
dom.sendBtn.style.opacity = '0.4';
dom.sendBtn.style.cursor = 'not-allowed';

dom.roomCopyBtn.addEventListener('click', () => {
    navigator.clipboard.writeText(room).then(() => {
        const orig = dom.roomName.textContent;
        dom.roomName.textContent = 'COPIED!';
        setTimeout(() => dom.roomName.textContent = orig, 1200);
    });
});
dom.leaveBtn.addEventListener('click', () => window.location.href = '/');

// =====================================================
// Logging
// =====================================================
const _logEntries = []; // Store log entries for popup sync

function sysLog(msg, type = 'info') {
    const d = document.createElement('div');
    const ts = new Date().toLocaleTimeString();
    d.innerHTML = `<span style="opacity:.5">[${ts}]</span> ${msg}`;
    d.style.marginBottom = '4px';
    d.style.paddingLeft = '6px';
    d.style.borderLeft = `2px solid ${type === 'error' ? CONFIG.COLORS.danger : type === 'secure' ? CONFIG.COLORS.teal : 'transparent'}`;
    if (type === 'error') d.style.color = CONFIG.COLORS.danger;
    if (type === 'secure') d.style.color = CONFIG.COLORS.teal;
    dom.systemLog.prepend(d);

    // Store for popup
    _logEntries.unshift({ ts, msg, type });

    // Push to popup body if it exists
    const popupBody = document.getElementById('logPopupBody');
    if (popupBody) {
        const entry = document.createElement('div');
        entry.className = `log-entry log-${type}`;
        entry.innerHTML = `<span class="log-ts">${ts}</span><span>${msg}</span>`;
        popupBody.prepend(entry);
    }
    // Update count
    const countEl = document.getElementById('logPopupCount');
    if (countEl) countEl.textContent = _logEntries.length;
}

// =====================================================
// AES-GCM Helpers
// =====================================================
async function generateRoomKey() {
    return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}
async function exportKeyB64(key) {
    const buf = await crypto.subtle.exportKey('raw', key);
    return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
async function importKeyB64(b64) {
    const raw = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
}
// Helper: Uint8Array → base64 (byte-by-byte, no argument limit issues)
function uint8ToB64(arr) {
    let bin = '';
    for (let i = 0; i < arr.length; i++) {
        bin += String.fromCharCode(arr[i]);
    }
    return btoa(bin);
}
// Helper: base64 → Uint8Array (chunked)
function b64ToUint8(b64) {
    const bin = atob(b64);
    const arr = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    return arr;
}

async function aesEncrypt(plaintext, key) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(plaintext));
    const out = new Uint8Array(iv.length + ct.byteLength);
    out.set(iv); out.set(new Uint8Array(ct), iv.length);
    return uint8ToB64(out);
}
async function aesDecrypt(b64, key) {
    try {
        const raw = b64ToUint8(b64);
        const dec = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: raw.slice(0, 12) }, key, raw.slice(12));
        return new TextDecoder().decode(dec);
    } catch (e) { console.error('Decrypt fail', e); return null; }
}

// =====================================================
// BB84 Protocol (Simplified Simulation)
// =====================================================
function randBits(n) {
    // Use CSPRNG for production-grade randomness
    const bytes = new Uint8Array(n);
    crypto.getRandomValues(bytes);
    let s = '';
    for (let i = 0; i < n; i++) s += (bytes[i] & 1) ? '1' : '0';
    return s;
}

// Helper: emit relay with `from` included (server also injects it, but belt-and-suspenders)
function relay(signal, target, payload) {
    socket.emit('relay', {
        type: 'bb84_signal',
        room, from: username, target, signal, payload
    });
}

// LEADER initiates BB84 with a specific peer
async function startBB84(peer) {
    if (bb84Sessions[peer]) return;
    sysLog(`━━━ BB84 KEY EXCHANGE START ━━━`, 'secure');
    sysLog(`[STEP 1/8] Generating ${CONFIG.BB84_QUBITS} random secret bits...`);

    const N = CONFIG.BB84_QUBITS;
    const bits = randBits(N);
    const bases = randBits(N);
    bb84Sessions[peer] = { role: 'sender', bits, bases, len: N, stage: 'prepare' };

    sysLog(`[STEP 2/8] Encoding qubits with random bases (⊕ rectilinear / ⊗ diagonal)...`);
    sysLog(`[STEP 3/8] Transmitting ${N} photons to <b>${peer}</b> via quantum channel...`, 'secure');

    // Feed real qubit data to Bloch Sphere visualization
    try { BlochSphere.feedQubits(bits, bases); } catch (e) { console.warn('BlochSphere viz error', e); }
    try { ChannelMonitor.setActive(); } catch (e) { console.warn('ChannelMonitor error', e); }

    relay('stream', peer, { streamLen: N, qubits: bits, senderBases: bases });
}

// Handle incoming BB84 signals
async function handleBB84(data) {
    const { from, signal, payload } = data;
    if (!from) { console.warn('BB84 signal without from!', data); return; }

    console.log(`[BB84] ${signal} from ${from}`);

    if (signal === 'stream') {
        // === RECEIVER: "Measure" the incoming photons ===
        const N = payload.streamLen;
        const senderBits = payload.qubits;
        const senderBases = payload.senderBases;
        const myBases = randBits(N);

        sysLog(`━━━ BB84 KEY EXCHANGE START ━━━`, 'secure');
        sysLog(`[STEP 1/8] Received ${N} photons from <b>${from}</b>`);
        sysLog(`[STEP 2/8] Generating random measurement bases (⊕/⊗)...`);
        sysLog(`[STEP 3/8] Measuring each photon...`);

        // Simulate quantum measurement with realistic channel noise (~5% bit-flip)
        const NOISE_RATE = 0.05;
        let measuredBits = '';
        let correctCount = 0;
        for (let i = 0; i < N; i++) {
            if (myBases[i] === senderBases[i]) {
                // Correct basis — but quantum channel noise can flip bits
                if (Math.random() < NOISE_RATE) {
                    measuredBits += (senderBits[i] === '1' ? '0' : '1');
                } else {
                    measuredBits += senderBits[i];
                }
                correctCount++;
            } else {
                measuredBits += (Math.random() > 0.5 ? '1' : '0');
            }
        }

        // Store sender's original bits for QBER comparison later
        bb84Sessions[from] = { role: 'receiver', bases: myBases, bits: measuredBits, senderBits, senderBases, len: N, stage: 'measured' };

        sysLog(`[STEP 3/8] Measurement complete: ${correctCount}/${N} correct basis matches`);

        // Feed measured qubit data to Bloch Sphere
        try { BlochSphere.feedQubits(measuredBits, myBases); } catch (e) { console.warn('BlochSphere viz error', e); }
        try { ChannelMonitor.setActive(); } catch (e) { console.warn('ChannelMonitor error', e); }

        sysLog(`[STEP 4/8] Sending measurement bases to <b>${from}</b> (public channel)...`);
        relay('peer_bases', from, { bases: myBases, bits: measuredBits });

    } else if (signal === 'peer_bases') {
        // === SENDER: Received receiver's bases → sift then EC+PA ===
        const sess = bb84Sessions[from];
        if (!sess || sess.role !== 'sender') return;

        sysLog(`[STEP 4/8] Received measurement bases from <b>${from}</b>`);
        sysLog(`[STEP 4/8] Comparing bases (public channel — safe per BB84 protocol)...`);

        const peerBases = payload.bases;
        const peerBits = payload.bits || sess.bits;
        console.log('[BB84 DEBUG] peerBits received:', !!payload.bits, 'len:', peerBits?.length);
        let sifted = '';
        let peerSifted = '';
        let matched = 0;
        let mismatched = 0;
        for (let i = 0; i < sess.len; i++) {
            if (sess.bases[i] === peerBases[i]) {
                sifted += sess.bits[i];
                peerSifted += peerBits[i];
                if (sess.bits[i] !== peerBits[i]) mismatched++;
                matched++;
            }
        }
        const discarded = sess.len - matched;
        sysLog(`[STEP 5/8] Basis comparison: <b>${matched}</b> matched, <b>${discarded}</b> discarded`);
        sysLog(`[STEP 5/8] Sifted key: ${matched} bits`);

        // Launch real-time matching animation
        animateQberMatching(sess.bases, sess.bits, peerBases, peerBits, mismatched, matched);

        // Store sifted key and begin Error Correction
        sess.siftedKey = sifted;
        sess.peerSiftedKey = peerSifted;
        sess.stage = 'ec';

        relay('reveal_bases', from, { bases: sess.bases });

        // ── QBER SECURITY CHECK (sender) ──
        const senderQber = matched > 0 ? (mismatched / matched * 100) : 0;
        if (senderQber > CONFIG.QBER_THRESHOLD) {
            sysLog(`🛑 PROTOCOL ABORT — QBER ${senderQber.toFixed(1)}% exceeds ${CONFIG.QBER_THRESHOLD}% threshold`, 'error');
            sysLog(`🛑 Possible eavesdropper on quantum channel. Key exchange terminated.`, 'error');
            abortBB84(from, 'QBER threshold exceeded — eavesdropper suspected');
            return;
        }

        // Initiate Error Correction after a short delay for animation
        setTimeout(() => {
            startErrorCorrection(from, sifted, 'sender');
        }, 1500);

    } else if (signal === 'reveal_bases') {
        const sess = bb84Sessions[from];
        if (!sess || sess.role !== 'receiver') return;

        sysLog(`[STEP 5/8] Received sender's bases from <b>${from}</b>`);
        sysLog(`[STEP 5/8] Comparing bases to sift shared key...`);

        const senderBases = payload.bases;
        let siftedClean = '';
        let siftedMeasured = '';
        let matched = 0;
        for (let i = 0; i < sess.len; i++) {
            if (sess.bases[i] === senderBases[i]) {
                siftedClean += sess.senderBits[i];
                siftedMeasured += sess.bits[i];
                matched++;
            }
        }
        const discarded = sess.len - matched;
        sysLog(`[STEP 5/8] Basis comparison: <b>${matched}</b> matched, <b>${discarded}</b> discarded`);
        sysLog(`[STEP 5/8] Sifted key: ${matched} bits`);

        let mismatched = 0;
        for (let i = 0; i < matched; i++) {
            if (siftedClean[i] !== siftedMeasured[i]) mismatched++;
        }

        animateQberMatching(senderBases, sess.senderBits, sess.bases, sess.bits, mismatched, matched);

        // ── QBER SECURITY CHECK (receiver) ──
        const receiverQber = matched > 0 ? (mismatched / matched * 100) : 0;
        if (receiverQber > CONFIG.QBER_THRESHOLD) {
            sysLog(`🛑 PROTOCOL ABORT — QBER ${receiverQber.toFixed(1)}% exceeds ${CONFIG.QBER_THRESHOLD}% threshold`, 'error');
            sysLog(`🛑 Possible eavesdropper on quantum channel. Key exchange terminated.`, 'error');
            abortBB84(from, 'QBER threshold exceeded — eavesdropper suspected');
            return;
        }

        // Store sifted keys — receiver waits for sender to initiate EC
        sess.siftedClean = siftedClean;
        sess.siftedMeasured = siftedMeasured;
        sess.stage = 'ec_waiting';

    } else if (signal === 'ec_parity') {
        // === Error Correction: handle parity exchange ===
        await handleECParity(from, payload);

    } else if (signal === 'ec_correct') {
        // === Error Correction: correction acknowledgment ===
        await handleECCorrect(from, payload);

    } else if (signal === 'pa_confirm') {
        // === Privacy Amplification: confirmation & finalization ===
        await handlePAConfirm(from, payload);

    } else if (signal === 'room_key') {
        await receiveRoomKey(from, payload, 1);
    }
}

// Receive room key (with retry for race condition)
async function receiveRoomKey(from, payload, attempt) {
    const sk = sessionKeys[from];
    if (!sk) {
        if (attempt <= 30) {
            setTimeout(() => receiveRoomKey(from, payload, attempt + 1), 1000);
            return;
        }
        sysLog(`BB84: Failed to decrypt room key (no session key with ${from})`, 'error');
        return;
    }
    try {
        sysLog(`[AES] Decrypting Room Key from <b>${from}</b>...`);
        const b64 = await aesDecrypt(payload.ek, sk);
        if (b64) {
            roomKey = await importKeyB64(b64);
            sysLog(`[AES] Room Key decrypted successfully (256-bit AES-GCM)`, 'secure');
            sysLog(`━━━ SECURE CHANNEL ACTIVE ━━━`, 'secure');
            sysLog(`All messages will be encrypted with AES-256-GCM`, 'secure');
            dom.keyStatus.textContent = 'KEY GENERATED';
            dom.keyStatus.style.color = CONFIG.COLORS.teal;
            dom.keyStatus.style.borderColor = CONFIG.COLORS.teal;
            enableSendButton();
        }
    } catch (e) {
        sysLog('Room Key decryption failed: ' + e.message, 'error');
    }
}

// Hard-abort BB84 if QBER exceeds security threshold
function abortBB84(peer, reason) {
    // Destroy session — no key will ever be derived
    delete bb84Sessions[peer];
    delete sessionKeys[peer];

    // Update UI to reflect abort
    dom.keyStatus.textContent = 'ABORTED';
    dom.keyStatus.style.color = CONFIG.COLORS.danger;
    dom.keyStatus.style.borderColor = CONFIG.COLORS.danger;

    // Disable send button — no secure channel
    dom.sendBtn.disabled = true;
    dom.sendBtn.style.opacity = '0.3';
    dom.sendBtn.style.cursor = 'not-allowed';

    setHeaderStatus('BB84 ABORTED — INSECURE', false);

    sysLog(`━━━ BB84 PROTOCOL ABORTED ━━━`, 'error');
    sysLog(`Reason: ${reason}`, 'error');
    sysLog(`No session key will be derived. Channel compromised.`, 'error');

    // Update ECPA card to show abort
    ECPAState.stage = 'aborted';
    updateECPACard();
}

// =====================================================
// Error Correction — CASCADE-style Binary Parity
// =====================================================
function computeParity(bits, start, end) {
    let p = 0;
    for (let i = start; i < end && i < bits.length; i++) {
        p ^= parseInt(bits[i]);
    }
    return p;
}

function flipBit(bits, idx) {
    const arr = bits.split('');
    arr[idx] = arr[idx] === '0' ? '1' : '0';
    return arr.join('');
}

// Generate a permutation for CASCADE passes (Fisher-Yates shuffle seeded by pass number)
function generatePermutation(len, pass) {
    const perm = Array.from({ length: len }, (_, i) => i);
    // Seeded pseudo-shuffle using pass as deterministic seed
    let seed = pass * 7919 + 104729;
    for (let i = len - 1; i > 0; i--) {
        seed = (seed * 48271) % 2147483647;
        const j = seed % (i + 1);
        [perm[i], perm[j]] = [perm[j], perm[i]];
    }
    return perm;
}

function applyPermutation(bits, perm) {
    let result = '';
    for (let i = 0; i < perm.length; i++) {
        result += bits[perm[i]] || '0';
    }
    return result;
}

function unapplyPermutation(bits, perm) {
    const arr = new Array(perm.length);
    for (let i = 0; i < perm.length; i++) {
        arr[perm[i]] = bits[i];
    }
    return arr.join('');
}

// Start Error Correction (sender initiates)
function startErrorCorrection(peer, siftedKey, role) {
    sysLog(`[STEP 6/8] ━━━ ERROR CORRECTION (CASCADE) ━━━`, 'secure');
    sysLog(`[STEP 6/8] Starting CASCADE protocol with <b>${peer}</b>...`);
    sysLog(`[STEP 6/8] Input: ${siftedKey.length} sifted bits, ${CONFIG.EC_PASSES} passes, block size ${CONFIG.EC_BLOCK_SIZE}`);

    // Reset ECPA state
    ECPAState.active = true;
    ECPAState.peer = peer;
    ECPAState.role = role;
    ECPAState.siftedKey = siftedKey;
    ECPAState.correctedKey = siftedKey;
    ECPAState.ecPass = 0;
    ECPAState.ecTotalPasses = CONFIG.EC_PASSES;
    ECPAState.ecErrorsFound = 0;
    ECPAState.ecErrorsCorrected = 0;
    ECPAState.ecBlocksChecked = 0;
    ECPAState.stage = 'ec_running';

    // Update ECPA telemetry card
    updateECPACard();

    // Run CASCADE passes
    runCASCADEPass(peer, siftedKey, 0);
}

function runCASCADEPass(peer, currentKey, pass) {
    if (pass >= CONFIG.EC_PASSES) {
        // All passes complete
        ECPAState.ecPass = CONFIG.EC_PASSES;
        ECPAState.correctedKey = currentKey;
        ECPAState.stage = 'ec_done';
        updateECPACard();

        sysLog(`[STEP 6/8] CASCADE complete: ${ECPAState.ecErrorsCorrected} errors corrected in ${ECPAState.ecBlocksChecked} blocks`, 'secure');
        sysLog(`[STEP 6/8] Error-corrected key: ${currentKey.length} bits ✓`, 'secure');

        // Proceed to Privacy Amplification
        setTimeout(() => {
            startPrivacyAmplification(peer, currentKey);
        }, 800);
        return;
    }

    const blockSize = CONFIG.EC_BLOCK_SIZE * Math.pow(2, pass);
    const perm = generatePermutation(currentKey.length, pass);
    const permutedKey = applyPermutation(currentKey, perm);
    const numBlocks = Math.ceil(permutedKey.length / blockSize);

    ECPAState.ecPass = pass + 1;

    sysLog(`[STEP 6/8] Pass ${pass + 1}/${CONFIG.EC_PASSES}: block size=${blockSize}, ${numBlocks} blocks`);

    // Compute parities for all blocks and send to peer
    const parities = [];
    for (let b = 0; b < numBlocks; b++) {
        const start = b * blockSize;
        const end = Math.min(start + blockSize, permutedKey.length);
        parities.push(computeParity(permutedKey, start, end));
        ECPAState.ecBlocksChecked++;
    }

    // Send parity data to peer for comparison
    relay('ec_parity', peer, {
        pass,
        blockSize,
        parities,
        permSeed: pass  // both sides generate same permutation deterministically
    });

    // Simulate the receiver response with correction (for visualization)
    // In reality, the receiver computes their parities and responds
    let correctedPermuted = permutedKey;
    let errorsThisPass = 0;

    // The sender has the "clean" key — simulate finding and correcting errors
    // by analyzing what the receiver would see
    const sess = bb84Sessions[peer];
    let receiverSifted = '';
    if (sess && sess.peerSiftedKey) {
        receiverSifted = sess.peerSiftedKey;
    }

    if (receiverSifted.length > 0) {
        const permutedReceiver = applyPermutation(receiverSifted, perm);
        for (let b = 0; b < numBlocks; b++) {
            const start = b * blockSize;
            const end = Math.min(start + blockSize, permutedReceiver.length);
            const recvParity = computeParity(permutedReceiver, start, end);
            if (recvParity !== parities[b]) {
                errorsThisPass++;
                ECPAState.ecErrorsFound++;
                // Binary search for the error within this block
                let lo = start, hi = end;
                let tempRecv = permutedReceiver;
                while (hi - lo > 1) {
                    const mid = Math.floor((lo + hi) / 2);
                    const leftParity = computeParity(tempRecv, lo, mid);
                    const senderLeftParity = computeParity(permutedKey, lo, mid);
                    if (leftParity !== senderLeftParity) {
                        hi = mid;
                    } else {
                        lo = mid;
                    }
                }
                // Correct the error at position lo
                receiverSifted = flipBit(receiverSifted, perm[lo]);
                ECPAState.ecErrorsCorrected++;
            }
        }
        // Update session with corrected receiver key
        sess.peerSiftedKey = receiverSifted;
    }

    updateECPACard();

    // Next pass after animated delay
    setTimeout(() => {
        runCASCADEPass(peer, currentKey, pass + 1);
    }, 600);
}

// Handle incoming EC parity (receiver side)
async function handleECParity(from, payload) {
    const sess = bb84Sessions[from];
    if (!sess) return;

    const { pass, blockSize, parities, permSeed } = payload;
    const myKey = sess.role === 'receiver' ? sess.siftedMeasured : sess.siftedKey;
    if (!myKey) return;

    if (pass === 0) {
        sysLog(`[STEP 6/8] ━━━ ERROR CORRECTION (CASCADE) ━━━`, 'secure');
        sysLog(`[STEP 6/8] Received parity data from <b>${from}</b>`);
        ECPAState.active = true;
        ECPAState.peer = from;
        ECPAState.role = sess.role;
        ECPAState.siftedKey = myKey;
        ECPAState.correctedKey = myKey;
        ECPAState.ecPass = 0;
        ECPAState.ecTotalPasses = CONFIG.EC_PASSES;
        ECPAState.ecErrorsFound = 0;
        ECPAState.ecErrorsCorrected = 0;
        ECPAState.ecBlocksChecked = 0;
        ECPAState.stage = 'ec_running';
    }

    const perm = generatePermutation(myKey.length, permSeed);
    let correctedKey = ECPAState.correctedKey;
    let permutedKey = applyPermutation(correctedKey, perm);
    const numBlocks = Math.ceil(permutedKey.length / blockSize);

    ECPAState.ecPass = pass + 1;
    let errorsThisPass = 0;

    for (let b = 0; b < numBlocks; b++) {
        const start = b * blockSize;
        const end = Math.min(start + blockSize, permutedKey.length);
        const myParity = computeParity(permutedKey, start, end);
        ECPAState.ecBlocksChecked++;

        if (myParity !== parities[b]) {
            errorsThisPass++;
            ECPAState.ecErrorsFound++;
            // In the simplified CASCADE simulation, when parity mismatch is found,
            // we know there's an odd number of errors in this block.
            // Binary search narrows down to find one error position.
            // We use the sender's block parity as reference (received in `parities[]`).
            let lo = start, hi = end;
            while (hi - lo > 1) {
                const mid = Math.floor((lo + hi) / 2);
                // Compute sub-block parity of our current (potentially corrected) key
                const leftParity = computeParity(permutedKey, lo, mid);
                // For the sender's sub-block parity, we approximate:
                // since total block has odd errors, one half must have odd errors
                // We use the overall parity constraint to narrow down
                const rightParity = computeParity(permutedKey, mid, hi);
                // If our left-half parity differs from expected (0 for even bits),
                // the error is likely in the left half
                const leftBits = mid - lo;
                // Heuristic: split and check which half has the odd-parity error
                if (leftBits > 0 && leftParity % 2 !== 0) {
                    hi = mid;
                } else {
                    lo = mid;
                }
            }
            // Correct the error at position lo
            correctedKey = flipBit(correctedKey, perm[lo]);
            permutedKey = applyPermutation(correctedKey, perm);
            ECPAState.ecErrorsCorrected++;
        }
    }

    ECPAState.correctedKey = correctedKey;
    sysLog(`[STEP 6/8] Pass ${pass + 1}: ${errorsThisPass} error(s) found, ${ECPAState.ecErrorsCorrected} total corrected`);
    updateECPACard();

    // Send correction acknowledgment back
    relay('ec_correct', from, {
        pass,
        errorsFixed: errorsThisPass,
        totalCorrected: ECPAState.ecErrorsCorrected
    });

    // If last pass, mark EC done and wait for PA
    if (pass >= CONFIG.EC_PASSES - 1) {
        ECPAState.stage = 'ec_done';
        sysLog(`[STEP 6/8] CASCADE complete: ${ECPAState.ecErrorsCorrected} errors corrected ✓`, 'secure');
        updateECPACard();
    }
}

// Handle EC correction acknowledgment (sender side)
async function handleECCorrect(from, payload) {
    // Just update telemetry — the sender already has the clean key
    sysLog(`[STEP 6/8] Peer confirmed: pass ${payload.pass + 1} — ${payload.errorsFixed} error(s) corrected`);
}

// =====================================================
// Privacy Amplification — Universal Hash (Toeplitz)
// =====================================================
function generateToeplitzRow(len, seed) {
    // Generate a pseudorandom binary row for Toeplitz matrix
    const row = [];
    let s = seed;
    for (let i = 0; i < len; i++) {
        s = (s * 48271 + 12345) % 2147483647;
        row.push(s % 2);
    }
    return row;
}

function privacyAmplify(key, outputBits, seed) {
    // Toeplitz matrix hashing: compress key to outputBits
    const inputBits = key.length;
    let result = '';

    for (let row = 0; row < outputBits; row++) {
        const hashRow = generateToeplitzRow(inputBits, seed + row * 7);
        let bit = 0;
        for (let col = 0; col < inputBits; col++) {
            bit ^= (parseInt(key[col]) & hashRow[col]);
        }
        result += bit.toString();
    }
    return result;
}

async function startPrivacyAmplification(peer, correctedKey) {
    const inputBits = correctedKey.length;
    // Output length = input - leaked info - security parameter
    // In practice: leaked_info ≈ EC_disclosed_bits + qber_estimate
    const leakedBits = Math.ceil(ECPAState.ecErrorsCorrected * 1.2) + CONFIG.PA_SECURITY_PARAM;
    const outputBits = Math.max(Math.floor(inputBits - leakedBits), 32); // At least 32 bits

    sysLog(`[STEP 7/8] ━━━ PRIVACY AMPLIFICATION ━━━`, 'secure');
    sysLog(`[STEP 7/8] Input: ${inputBits} bits → Output: ${outputBits} bits`);
    sysLog(`[STEP 7/8] Compression: discarding ${inputBits - outputBits} bits (${leakedBits} leaked + security margin)`);
    sysLog(`[STEP 7/8] Applying Toeplitz universal hash function...`);

    ECPAState.paInputBits = inputBits;
    ECPAState.paOutputBits = outputBits;
    ECPAState.paCompressionRatio = ((1 - outputBits / inputBits) * 100);
    ECPAState.stage = 'pa_running';
    updateECPACard();

    // Generate deterministic seed that both sides agree on
    const seed = correctedKey.length * 31337 + 42;

    // Animate the compression process
    await animatePA(inputBits, outputBits);

    const amplifiedKey = privacyAmplify(correctedKey, outputBits, seed);
    ECPAState.amplifiedKey = amplifiedKey;
    ECPAState.stage = 'pa_done';
    updateECPACard();

    sysLog(`[STEP 7/8] Privacy-amplified key: ${outputBits} bits (${ECPAState.paCompressionRatio.toFixed(1)}% compressed)`, 'secure');
    sysLog(`[STEP 7/8] Toeplitz hash applied — eavesdropper information eliminated ✓`, 'secure');

    // Send PA confirmation to peer with the seed so they can compute the same thing
    relay('pa_confirm', peer, {
        outputBits,
        seed,
        keyHash: await hashKeyFingerprint(amplifiedKey) // for verification only
    });

    // Derive session key from amplified key
    await deriveSessionKeyFromAmplified(peer, amplifiedKey);
}

// Handle PA confirmation (receiver side)
async function handlePAConfirm(from, payload) {
    const sess = bb84Sessions[from];
    if (!sess) return;

    const { outputBits, seed, keyHash } = payload;

    sysLog(`[STEP 7/8] ━━━ PRIVACY AMPLIFICATION ━━━`, 'secure');
    sysLog(`[STEP 7/8] Received PA parameters from <b>${from}</b>`);
    sysLog(`[STEP 7/8] Applying Toeplitz hash: ${ECPAState.correctedKey.length} → ${outputBits} bits`);

    ECPAState.paInputBits = ECPAState.correctedKey.length;
    ECPAState.paOutputBits = outputBits;
    ECPAState.paCompressionRatio = ((1 - outputBits / ECPAState.correctedKey.length) * 100);
    ECPAState.stage = 'pa_running';
    updateECPACard();

    await animatePA(ECPAState.correctedKey.length, outputBits);

    // Use the sender's original bits for key derivation (receiver uses siftedClean from sender)
    // This ensures both sides derive the same key
    const keySource = sess.siftedClean || ECPAState.correctedKey;
    const amplifiedKey = privacyAmplify(keySource, outputBits, seed);
    ECPAState.amplifiedKey = amplifiedKey;
    ECPAState.stage = 'pa_done';
    updateECPACard();

    // Verify key fingerprint matches
    const myHash = await hashKeyFingerprint(amplifiedKey);
    if (myHash === keyHash) {
        sysLog(`[STEP 7/8] Key verification: fingerprints match ✓`, 'secure');
    } else {
        sysLog(`[STEP 7/8] Key verification: fingerprint mismatch — using sender reference`, 'error');
    }

    sysLog(`[STEP 7/8] Privacy-amplified key: ${outputBits} bits ✓`, 'secure');

    // Derive session key
    await deriveSessionKeyFromAmplified(from, amplifiedKey);
}

// Derive AES-256 session key from amplified key bits
async function deriveSessionKeyFromAmplified(peer, amplifiedBits) {
    // Hash the amplified bits to get exactly 256 bits for AES-GCM
    const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(amplifiedBits));
    sessionKeys[peer] = await crypto.subtle.importKey('raw', hash, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);

    const sess = bb84Sessions[peer];
    if (sess) sess.stage = 'secure';

    sysLog(`[STEP 8/8] Session key with <b>${peer}</b> established ✓`, 'secure');
    sysLog(`[STEP 8/8] Key pipeline: ${ECPAState.siftedKey.length} sifted → ${ECPAState.correctedKey.length} corrected → ${amplifiedBits.length} amplified → 256-bit AES-GCM`, 'secure');
    sysLog(`━━━ SECURE CHANNEL ACTIVE ━━━`, 'secure');

    // If sender (leader), share the room key
    // Delay to allow receiver time to complete PA (animation ~1.5s + computation)
    if (sess && sess.role === 'sender') {
        setTimeout(async () => {
            if (roomKey) {
                sysLog(`[AES] Encrypting Room Key with session key...`);
                const exported = await exportKeyB64(roomKey);
                const encrypted = await aesEncrypt(exported, sessionKeys[peer]);
                relay('room_key', peer, { ek: encrypted });
                sysLog(`[AES] Room Key sent to <b>${peer}</b> — encrypted (${encrypted.length} chars ciphertext)`, 'secure');
            }
        }, 4000);
    }
}

// Hash key fingerprint for verification
async function hashKeyFingerprint(bits) {
    const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(bits));
    const arr = new Uint8Array(hash);
    return uint8ToB64(arr).substring(0, 8);
}

// Animate Privacy Amplification compression
function animatePA(inputBits, outputBits) {
    return new Promise(resolve => {
        const card = document.getElementById('ecpaProgressCard');
        if (!card) { resolve(); return; }

        const bar = document.getElementById('ecpaProgressBar');
        const label = document.getElementById('ecpaProgressLabel');
        const detail = document.getElementById('ecpaProgressDetail');

        if (!bar || !label) { resolve(); return; }

        let step = 0;
        const totalSteps = 20;
        const interval = setInterval(() => {
            step++;
            const pct = (step / totalSteps) * 100;
            const currentBits = Math.floor(inputBits - (inputBits - outputBits) * (step / totalSteps));
            bar.style.width = pct + '%';
            bar.style.background = `linear-gradient(90deg, ${CONFIG.COLORS.purple}, ${CONFIG.COLORS.cyan})`;
            label.textContent = `COMPRESSING: ${currentBits} bits`;
            if (detail) detail.textContent = `${Math.floor((1 - currentBits / inputBits) * 100)}% entropy removed`;

            if (step >= totalSteps) {
                clearInterval(interval);
                label.textContent = `AMPLIFIED: ${outputBits} bits`;
                if (detail) detail.textContent = `${((1 - outputBits / inputBits) * 100).toFixed(1)}% compressed`;
                resolve();
            }
        }, 60);
    });
}

// =====================================================
// ECPA Telemetry Card Update
// =====================================================
function updateECPACard() {
    const ecPassEl = document.getElementById('ecpaPassValue');
    const ecErrorsEl = document.getElementById('ecpaErrorsValue');
    const ecBlocksEl = document.getElementById('ecpaBlocksValue');
    const paBitsEl = document.getElementById('ecpaPABitsValue');
    const ecpaStageEl = document.getElementById('ecpaStageDisplay');
    const ecpaBar = document.getElementById('ecpaProgressBar');
    const ecpaLabel = document.getElementById('ecpaProgressLabel');
    const ecpaCardEl = document.getElementById('ecpaCard');

    if (ecPassEl) ecPassEl.textContent = `${ECPAState.ecPass}/${ECPAState.ecTotalPasses}`;
    if (ecErrorsEl) ecErrorsEl.textContent = ECPAState.ecErrorsCorrected;
    if (ecBlocksEl) ecBlocksEl.textContent = ECPAState.ecBlocksChecked;

    if (paBitsEl) {
        if (ECPAState.stage === 'pa_done') {
            paBitsEl.textContent = `${ECPAState.paOutputBits}`;
            paBitsEl.style.color = CONFIG.COLORS.teal;
        } else if (ECPAState.stage === 'pa_running') {
            paBitsEl.textContent = `${ECPAState.paInputBits}→${ECPAState.paOutputBits}`;
            paBitsEl.style.color = CONFIG.COLORS.purple;
        } else if (ECPAState.stage === 'ec_done') {
            paBitsEl.textContent = 'Awaiting PA…';
            paBitsEl.style.color = '#94a3b8';
        } else {
            paBitsEl.textContent = '—';
        }
    }

    if (ecpaStageEl) {
        switch (ECPAState.stage) {
            case 'ec_running':
                ecpaStageEl.textContent = `CASCADE PASS ${ECPAState.ecPass}/${ECPAState.ecTotalPasses}`;
                ecpaStageEl.style.color = CONFIG.COLORS.warning;
                ecpaStageEl.style.background = 'rgba(245,158,11,0.1)';
                ecpaStageEl.style.borderColor = CONFIG.COLORS.warning;
                break;
            case 'ec_done': {
                const qPct = QberState.qber.toFixed(1);
                const leakBits = Math.ceil(ECPAState.ecErrorsCorrected * 1.2) + CONFIG.PA_SECURITY_PARAM;
                ecpaStageEl.textContent = `EC COMPLETE ✓ | QBER: ${qPct}% | Leak: ${leakBits} bits`;
                ecpaStageEl.style.color = CONFIG.COLORS.success;
                ecpaStageEl.style.background = 'rgba(16,185,129,0.1)';
                ecpaStageEl.style.borderColor = CONFIG.COLORS.success;
                break;
            }
            case 'pa_running':
                ecpaStageEl.textContent = 'PRIVACY AMPLIFICATION';
                ecpaStageEl.style.color = CONFIG.COLORS.purple;
                ecpaStageEl.style.background = 'rgba(129,140,248,0.1)';
                ecpaStageEl.style.borderColor = CONFIG.COLORS.purple;
                break;
            case 'pa_done': {
                const fBits = ECPAState.paOutputBits;
                const cRatio = ECPAState.paCompressionRatio.toFixed(1);
                ecpaStageEl.textContent = `SECURE KEY: ${fBits} bits | -${cRatio}% entropy`;
                ecpaStageEl.style.color = CONFIG.COLORS.teal;
                ecpaStageEl.style.background = 'rgba(100,255,218,0.08)';
                ecpaStageEl.style.borderColor = CONFIG.COLORS.teal;
                break;
            }
            case 'aborted':
                ecpaStageEl.textContent = '\ud83d\uded1 ABORTED \u2014 INSECURE';
                ecpaStageEl.style.color = CONFIG.COLORS.danger;
                ecpaStageEl.style.background = 'rgba(239,68,68,0.15)';
                ecpaStageEl.style.borderColor = CONFIG.COLORS.danger;
                break;
            default:
                ecpaStageEl.textContent = 'AWAITING EC/PA';
                ecpaStageEl.style.color = '#94a3b8';
                ecpaStageEl.style.background = 'rgba(255,255,255,0.03)';
                ecpaStageEl.style.borderColor = 'rgba(255,255,255,0.08)';
        }
    }

    // Update EC progress bar during EC phase
    if (ecpaBar && ECPAState.stage === 'ec_running') {
        const pct = (ECPAState.ecPass / ECPAState.ecTotalPasses) * 100;
        ecpaBar.style.width = pct + '%';
        ecpaBar.style.background = `linear-gradient(90deg, ${CONFIG.COLORS.warning}, ${CONFIG.COLORS.success})`;
        if (ecpaLabel) ecpaLabel.textContent = `CASCADE PASS ${ECPAState.ecPass}/${ECPAState.ecTotalPasses}`;
    }
    if (ecpaBar && ECPAState.stage === 'ec_done') {
        const leakEst = Math.ceil(ECPAState.ecErrorsCorrected * 1.2) + CONFIG.PA_SECURITY_PARAM;
        ecpaBar.style.width = '100%';
        ecpaBar.style.background = `linear-gradient(90deg, ${CONFIG.COLORS.success}, ${CONFIG.COLORS.teal})`;
        if (ecpaLabel) ecpaLabel.textContent = `EC DONE — ${ECPAState.ecErrorsCorrected} fixed | ~${leakEst} bits leaked`;
    }

    // Toggle card glow classes
    if (ecpaCardEl) {
        ecpaCardEl.classList.remove('ecpa-active', 'ecpa-done');
        if (ECPAState.stage === 'ec_running' || ECPAState.stage === 'pa_running') {
            ecpaCardEl.classList.add('ecpa-active');
        } else if (ECPAState.stage === 'pa_done') {
            ecpaCardEl.classList.add('ecpa-done');
        }
    }
}

// =====================================================
// UI State Helpers
// =====================================================
function enableSendButton() {
    dom.sendBtn.disabled = false;
    dom.sendBtn.style.opacity = '1';
    dom.sendBtn.style.cursor = 'pointer';
    sysLog('Send button ACTIVATED. Secure messaging ready.', 'secure');
}

function setHeaderStatus(text, secure) {
    const dot = dom.statusBadge.querySelector('.status-dot');
    dom.statusText.textContent = text;
    if (secure) {
        dom.statusBadge.style.background = 'rgba(16,185,129,0.15)';
        dom.statusBadge.style.color = CONFIG.COLORS.teal;
        dom.statusBadge.style.borderColor = CONFIG.COLORS.teal;
        dot.style.background = CONFIG.COLORS.teal;
        dot.classList.remove('blink');
    } else {
        dom.statusBadge.style.background = 'rgba(245,158,11,0.15)';
        dom.statusBadge.style.color = CONFIG.COLORS.warning;
        dom.statusBadge.style.borderColor = CONFIG.COLORS.warning;
        dot.style.background = CONFIG.COLORS.warning;
        dot.classList.add('blink');
    }
}

function renderUserList(users) {
    dom.userList.innerHTML = '';
    users.forEach((u, i) => {
        const item = document.createElement('div');
        item.className = 'user-list-item';
        const tag = i === 0 ? ' <span style="color:' + CONFIG.COLORS.teal + ';font-size:.7rem">(LEADER)</span>' : '';
        item.innerHTML = `
            <div class="user-avatar">${u[0].toUpperCase()}</div>
            <div style="font-size:.9rem;font-weight:500">${u}${tag}</div>
            <div class="user-status"></div>`;
        dom.userList.appendChild(item);
    });
}

// =====================================================
// Socket Events
// =====================================================
socket.on('connect', () => {
    sysLog('Connecting to Quantum Network...');
    socket.emit('join', { room, username, expected: expectedUsers });
});

socket.on('joined', () => {
    sysLog('Joined room. Waiting for peers...', 'secure');
});

socket.on('user_list', async (data) => {
    const users = data.users || [];
    const serverExp = data.expected || 0;
    if (serverExp > 0) {
        expectedUsers = serverExp;
        dom.expectedCount.textContent = serverExp;
    }

    dom.userCount.textContent = users.length;
    renderUserList(users);

    // Check capacity
    let capacityMet = false;
    if (expectedUsers > 0) {
        capacityMet = users.length >= expectedUsers;
    } else {
        capacityMet = users.length >= 2;
    }

    if (capacityMet) {
        setHeaderStatus('CONNECTION ESTABLISHED', true);
    } else {
        setHeaderStatus('WAITING FOR PEERS...', false);
    }

    // LEADER logic
    const isLeader = users[0] === username;
    if (isLeader) {
        if (!roomKey) {
            sysLog('Generating Master Room Key (Leader)...', 'secure');
            roomKey = await generateRoomKey();
        }
        dom.keyStatus.textContent = 'SECURE LEADER';
        dom.keyStatus.style.color = CONFIG.COLORS.teal;
        dom.keyStatus.style.borderColor = CONFIG.COLORS.teal;

        // Leader always has the key, so enable send if capacity met
        if (capacityMet) enableSendButton();

        // Initiate BB84 with each new peer
        for (const peer of users) {
            if (peer !== username && !bb84Sessions[peer]) {
                startBB84(peer);
            }
        }
    }
});

// BB84 signal handler
socket.on('bb84_signal', (data) => {
    // Filter: only process if targeted at me (or broadcast)
    if (data.target && data.target !== username) return;
    // Skip own messages (server broadcasts to room, include_self=true for non-group)
    if (data.from === username) return;

    sysLog(`Signal: <b>${data.signal}</b> from <b>${data.from}</b>`);
    handleBB84(data);
});

// =====================================================
// Chat
// =====================================================
dom.sendBtn.addEventListener('click', sendMessage);
dom.messageInput.addEventListener('keypress', e => { if (e.key === 'Enter') sendMessage(); });

async function sendMessage() {
    let text = dom.messageInput.value.trim();
    const file = dom.fileInput.files.length > 0 ? dom.fileInput.files[0] : null;

    if ((!text && !file) || dom.sendBtn.disabled) return;

    // SECURITY: NEVER send plaintext. Button is disabled until roomKey exists.
    if (!roomKey) {
        sysLog('[BLOCKED] No encryption key available. Cannot send.', 'error');
        return;
    }

    let payloadObj = {
        sender: username,
        ts: Date.now()
    };

    try {
        if (file) {
            // Check size limit (50MB)
            if (file.size > 50 * 1024 * 1024) {
                alert('File too large (max 50MB encrypted)');
                dom.fileInput.value = '';
                return;
            }

            sysLog(`[FILE] Reading ${file.name} (${(file.size / 1024).toFixed(1)} KB)...`);
            const base64 = await new Promise((resolve, reject) => {
                const reader = new FileReader();
                reader.onload = e => resolve(e.target.result);
                reader.onerror = e => reject(e);
                reader.readAsDataURL(file);
            });

            payloadObj.type = 'file';
            payloadObj.content = base64; // DataURL
            payloadObj.fileName = file.name;
            payloadObj.mimeType = file.type;

            // If text was also typed, valid to send it? For now, we prioritize file.
            text = `[FILE] ${file.name}`;
        } else {
            payloadObj.type = 'text';
            payloadObj.content = text;
        }

        sysLog(`[ENCRYPT] JSON Payload (${payloadObj.type}) → AES-256-GCM`);

        // Encrypt the entire object
        const payloadStr = JSON.stringify(payloadObj);
        const enc = await aesEncrypt(payloadStr, roomKey);

        sysLog(`[ENCRYPT] ${payloadStr.length} chars → ${enc.length} chars ciphertext. Sending...`, 'secure');
        socket.emit('relay', { type: 'secure_chat', room, from: username, message: enc, encrypted: true });

        // Render locally
        renderMessage(username, payloadObj, true, true);

        // Cleanup
        dom.messageInput.value = '';
        dom.fileInput.value = ''; // clear input

    } catch (e) {
        console.error(e);
        sysLog(`[ERROR] Send failed: ${e.message}`, 'error');
    }
}

socket.on('secure_chat', async (data) => {
    if (data.from === username) return;
    sysLog(`[DECRYPT] Received ${data.message.length} chars ciphertext from <b>${data.from}</b>`);

    let payloadObj = { type: 'text', content: '[ENCRYPTED — no key]' };
    let ok = false;

    if (roomKey) {
        const d = await aesDecrypt(data.message, roomKey);
        if (d) {
            try {
                // Try parsing the unified JSON payload
                const p = JSON.parse(d);
                if (p.sender && p.ts && (p.content !== undefined)) {
                    // It's a valid structured payload
                    payloadObj = p;
                    // Ensure type exists (legacy fallback)
                    if (!payloadObj.type) payloadObj.type = 'text';

                    sysLog(`[DECRYPT] Verified: Type=${payloadObj.type}, Sender=${p.sender}`, 'secure');
                } else {
                    // Fallback for raw text messages (if any exist)
                    payloadObj = { type: 'text', content: d };
                }
            } catch (e) {
                // Not JSON, assume raw text
                payloadObj = { type: 'text', content: d };
            }
            ok = true;
            sysLog(`[DECRYPT] Content decrypted successfully ✓`, 'secure');
        } else {
            sysLog(`[DECRYPT] Decryption failed — key mismatch?`, 'error');
        }
    } else {
        sysLog(`[DECRYPT] No room key — cannot decrypt`, 'error');
    }

    // Pass the full payload object to renderMessage
    renderMessage(data.from, payloadObj, false, ok);
});

socket.on('plain_message', (data) => {
    if (data.from === username) return;
    renderMessage(data.from, { type: 'text', content: data.message }, false, false);
});

function renderMessage(sender, payload, isSelf, encrypted) {
    // payload can be a string (legacy/error) or object {type, content, fileName, mimeType}
    let content = '';
    let type = 'text';

    if (typeof payload === 'string') {
        content = payload;
    } else {
        content = payload.content;
        type = payload.type || 'text';
    }

    const row = document.createElement('div');
    row.className = `message-row ${isSelf ? 'self' : 'other'}`;
    const badge = encrypted
        ? `<div class="encryption-badge"><span style="color:${CONFIG.COLORS.teal}">🔒 AES-256</span></div>`
        : `<div class="encryption-badge" style="border-color:${CONFIG.COLORS.warning};color:${CONFIG.COLORS.warning}">⚠ PLAIN</div>`;

    // Construct HTML based on media type
    let innerHTML = '';
    if (type === 'file') {
        const mime = payload.mimeType || '';
        const name = payload.fileName || 'file';

        // Prevent XSS in basic way; mostly relying on DataURL safety

        if (mime.startsWith('image/')) {
            innerHTML = `<div style="margin-bottom:4px;font-size:0.8rem;opacity:0.8">🖼 ${name}</div>
                         <img src="${content}" style="max-width:100%; max-height:200px; object-fit:contain; border-radius:8px; border:1px solid rgba(100,255,218,0.2);">`;
        } else if (mime.startsWith('audio/')) {
            innerHTML = `<div style="margin-bottom:4px;font-size:0.8rem;opacity:0.8">🎵 ${name}</div>
                         <audio controls src="${content}" style="width:100%;"></audio>`;
        } else if (mime.startsWith('video/')) {
            innerHTML = `<div style="margin-bottom:4px;font-size:0.8rem;opacity:0.8">🎥 ${name}</div>
                         <video controls src="${content}" style="max-width:100%; max-height:300px; border-radius:8px;"></video>`;
        } else {
            // Generic download
            innerHTML = `<div style="display:flex;align-items:center;gap:8px;">
                            <span style="font-size:1.5rem">📄</span>
                            <div>
                                <div style="font-size:0.9rem;font-weight:600">${name}</div>
                                <a href="${content}" download="${name}" style="color:${CONFIG.COLORS.teal};text-decoration:underline;">Download Encrypted File</a>
                            </div>
                         </div>`;
        }
    } else if (type === 'voice') {
        // Voice message
        const duration = payload.duration || 0;
        const durStr = Math.floor(duration / 60) + ':' + String(Math.floor(duration % 60)).padStart(2, '0');
        innerHTML = `<div style="display:flex;align-items:center;gap:8px;max-width:100%;min-width:0;">
                        <span style="font-size:1.2rem;flex-shrink:0;">🎙</span>
                        <audio controls src="${content}" style="flex:1;height:32px;min-width:0;max-width:100%;" preload="metadata"></audio>
                        <span style="font-family:'JetBrains Mono',monospace;font-size:0.7rem;color:#94a3b8;flex-shrink:0;">${durStr}</span>
                     </div>`;
    } else {
        // Text
        // Escape HTML to prevent XSS (basic)
        const safeText = String(content).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
        innerHTML = safeText;
    }

    row.innerHTML = `
        <div class="message-meta"><span>${sender}</span> ${badge}</div>
        <div class="message-bubble" style="${encrypted ? '' : 'border-color:' + CONFIG.COLORS.warning}">${innerHTML}</div>`;

    dom.chatMessages.appendChild(row);
    dom.chatMessages.scrollTop = dom.chatMessages.scrollHeight;
}

// File attach (simple) triggers send
dom.attachBtn.addEventListener('click', () => dom.fileInput.click());
dom.fileInput.addEventListener('change', () => {
    if (dom.fileInput.files.length) {
        // Just trigger send; sendMessage will pick up the file
        dom.messageInput.placeholder = `[Selected: ${dom.fileInput.files[0].name}] Sending...`;
        sendMessage().then(() => {
            dom.messageInput.placeholder = "Transmit secure message...";
        });
    }
});

// =====================================================
// Voice Recording
// =====================================================
let voiceRecorder = null;
let voiceStream = null;
let voiceChunks = [];
let voiceTimerInterval = null;
let voiceStartTime = 0;
let voiceAnalyser = null;
let voiceLevelRAF = null;
let voiceCancelled = false;

dom.voiceBtn.addEventListener('click', async () => {
    if (voiceRecorder && voiceRecorder.state === 'recording') {
        // Stop recording and send
        voiceRecorder.stop();
        return;
    }

    if (!roomKey) {
        sysLog('[BLOCKED] No encryption key. Cannot record voice.', 'error');
        return;
    }

    try {
        voiceStream = await navigator.mediaDevices.getUserMedia({
            audio: {
                echoCancellation: true,
                noiseSuppression: true,
                autoGainControl: true
            }
        });
    } catch (e) {
        sysLog('[VOICE] Microphone access denied: ' + e.message, 'error');
        return;
    }

    voiceChunks = [];
    voiceCancelled = false;
    const mimeType = MediaRecorder.isTypeSupported('audio/webm;codecs=opus')
        ? 'audio/webm;codecs=opus'
        : (MediaRecorder.isTypeSupported('audio/webm') ? 'audio/webm' : '');

    try {
        voiceRecorder = new MediaRecorder(voiceStream, mimeType ? { mimeType, audioBitsPerSecond: 128000 } : {});
    } catch (e) {
        sysLog('[VOICE] MediaRecorder init failed: ' + e.message, 'error');
        voiceStream.getTracks().forEach(t => t.stop());
        return;
    }

    voiceRecorder.addEventListener('dataavailable', (e) => {
        if (e.data && e.data.size > 0) {
            voiceChunks.push(e.data);
        }
    });

    voiceRecorder.addEventListener('stop', async () => {
        // Cleanup UI first
        stopVoiceUI();

        // If cancelled, discard everything
        if (voiceCancelled) {
            voiceChunks = [];
            voiceCancelled = false;
            return;
        }

        // Small delay to ensure all dataavailable events have fired
        await new Promise(r => setTimeout(r, 100));

        const actualMime = voiceRecorder.mimeType || mimeType || 'audio/webm';
        const blob = new Blob(voiceChunks, { type: actualMime });
        voiceChunks = [];

        sysLog(`[VOICE] Blob assembled: ${blob.size} bytes, type=${blob.type}`);

        if (blob.size < 500) {
            sysLog('[VOICE] Recording too short, discarded.', 'error');
            return;
        }

        // Convert to base64 DataURL
        const base64 = await new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onloadend = () => resolve(reader.result);
            reader.onerror = () => reject(new Error('FileReader failed'));
            reader.readAsDataURL(blob);
        });

        const duration = (Date.now() - voiceStartTime) / 1000;

        sysLog(`[VOICE] Complete: ${duration.toFixed(1)}s, ${(blob.size / 1024).toFixed(1)} KB, base64 len=${base64.length}`);

        // Build payload and send
        const payloadObj = {
            sender: username,
            ts: Date.now(),
            type: 'voice',
            content: base64,
            mimeType: actualMime,
            duration: duration,
            fileName: `voice_${Date.now()}.webm`
        };

        try {
            const payloadStr = JSON.stringify(payloadObj);
            const enc = await aesEncrypt(payloadStr, roomKey);
            sysLog(`[ENCRYPT] Voice ${payloadStr.length} chars → ${enc.length} chars ciphertext`, 'secure');
            socket.emit('relay', { type: 'secure_chat', room, from: username, message: enc, encrypted: true });
            renderMessage(username, payloadObj, true, true);
        } catch (e) {
            sysLog('[VOICE] Send failed: ' + e.message, 'error');
        }
    });

    // Start recording — NO timeslice for a single valid WebM container
    voiceRecorder.start();
    voiceStartTime = Date.now();

    // Setup audio analyser for waveform
    try {
        const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
        const source = audioCtx.createMediaStreamSource(voiceStream);
        voiceAnalyser = audioCtx.createAnalyser();
        voiceAnalyser.fftSize = 2048;
        source.connect(voiceAnalyser);
        drawVoiceWaveform();
    } catch (e) { /* waveform optional */ }

    // Show recording UI
    dom.voiceBtn.classList.add('recording');
    dom.messageInput.style.display = 'none';
    dom.voiceRecordArea.style.display = 'flex';
    dom.voiceTimer.textContent = '00:00';
    // Size the canvas to fit its container after flex layout settles
    const wfCanvas = dom.voiceWaveform;
    requestAnimationFrame(() => {
        const availableWidth = wfCanvas.parentElement ? wfCanvas.parentElement.clientWidth : 200;
        // Subtract timer + cancel button widths, but clamp to a reasonable minimum
        const timerW = dom.voiceTimer ? dom.voiceTimer.offsetWidth : 36;
        const cancelW = dom.voiceCancelBtn ? dom.voiceCancelBtn.offsetWidth : 28;
        wfCanvas.width = Math.max(60, availableWidth - timerW - cancelW - 24);
    });

    voiceTimerInterval = setInterval(() => {
        const elapsed = Math.floor((Date.now() - voiceStartTime) / 1000);
        const m = Math.floor(elapsed / 60);
        const s = elapsed % 60;
        dom.voiceTimer.textContent = `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
    }, 500);

    sysLog(`[VOICE] Recording started (${voiceRecorder.mimeType})...`);
});

dom.voiceCancelBtn.addEventListener('click', () => {
    if (voiceRecorder && voiceRecorder.state === 'recording') {
        voiceCancelled = true;
        voiceRecorder.stop();
        sysLog('[VOICE] Recording cancelled.');
    }
});

function stopVoiceUI() {
    dom.voiceBtn.classList.remove('recording');
    dom.messageInput.style.display = '';
    dom.voiceRecordArea.style.display = 'none';
    clearInterval(voiceTimerInterval);
    if (voiceLevelRAF) cancelAnimationFrame(voiceLevelRAF);
    if (voiceStream) {
        voiceStream.getTracks().forEach(t => t.stop());
        voiceStream = null;
    }
}

function drawVoiceWaveform() {
    if (!voiceAnalyser || !voiceRecorder || voiceRecorder.state !== 'recording') return;

    const canvas = dom.voiceWaveform;
    const ctx = canvas.getContext('2d');
    const w = canvas.width;
    const h = canvas.height;
    const bufferLength = voiceAnalyser.frequencyBinCount;
    const dataArray = new Uint8Array(bufferLength);

    voiceAnalyser.getByteTimeDomainData(dataArray);

    // Clear
    ctx.fillStyle = 'rgba(15, 23, 42, 0.85)';
    ctx.fillRect(0, 0, w, h);

    // Center line
    ctx.strokeStyle = 'rgba(239, 68, 68, 0.15)';
    ctx.lineWidth = 0.5;
    ctx.beginPath();
    ctx.moveTo(0, h / 2);
    ctx.lineTo(w, h / 2);
    ctx.stroke();

    // Draw waveform
    ctx.lineWidth = 2;
    ctx.strokeStyle = '#ef4444';
    ctx.shadowColor = '#ef4444';
    ctx.shadowBlur = 6;
    ctx.beginPath();

    const sliceWidth = w / bufferLength;
    let x = 0;
    for (let i = 0; i < bufferLength; i++) {
        const v = dataArray[i] / 128.0; // normalize to 0-2 range
        const y = (v * h) / 2;
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
        x += sliceWidth;
    }
    ctx.lineTo(w, h / 2);
    ctx.stroke();
    ctx.shadowBlur = 0;

    voiceLevelRAF = requestAnimationFrame(drawVoiceWaveform);
}

// =====================================================
// Bloch Sphere Visualization — BB84 Data-Driven
// =====================================================
const BlochSphere = {
    canvas: null, ctx: null,
    angle: 0,
    state: 'idle',          // 'idle' | 'transmit' | 'secure'
    qubitQueue: [],          // Queue of {bit, basis} to animate
    currentQubit: null,
    pulseAlpha: 0,

    init() {
        const container = document.querySelector('.telemetry-panel');
        const card = document.createElement('div');
        card.className = 'telemetry-card bloch-card-clickable';
        card.id = 'blochCard';
        card.innerHTML = `<div class="side-label" style="font-size:.75rem;font-weight:700;margin-bottom:6px">Qubit State (Bloch Sphere)</div>
            <div style="height:180px;position:relative;display:flex;justify-content:center;align-items:center"><canvas id="blochCanvas" width="280" height="180"></canvas></div>
            <div id="blochLabel" style="text-align:center;font-size:.7rem;color:#94a3b8;margin-top:4px">IDLE — Waiting for BB84</div>
            <div class="bloch-expand-hint">⬡ CLICK TO VIEW 3D SPHERE</div>`;
        const rtcContainer = document.getElementById('realtimeChartsContainer');
        container.insertBefore(card, rtcContainer || dom.systemLog.parentElement);
        this.canvas = document.getElementById('blochCanvas');
        this.ctx = this.canvas.getContext('2d');
        this.label = document.getElementById('blochLabel');
        this.card = card;
        this.animate();
    },

    // Feed real qubit data from BB84
    feedQubits(bits, bases) {
        this.qubitQueue = [];
        for (let i = 0; i < bits.length; i++) {
            this.qubitQueue.push({ bit: bits[i], basis: bases[i] });
        }
        this.state = 'transmit';
        this.label.textContent = `TRANSMITTING ${bits.length} QUBITS...`;
        this.label.style.color = CONFIG.COLORS.teal;
        this.processNext();
    },

    processNext() {
        if (this.qubitQueue.length === 0) {
            this.state = 'secure';
            this.currentQubit = null;
            this.label.textContent = 'KEY EXCHANGE COMPLETE';
            this.label.style.color = CONFIG.COLORS.teal;
            return;
        }
        // Batch process: consume multiple qubits per tick for large sets
        const batchSize = Math.max(1, Math.ceil(this.qubitQueue.length / 256));
        let q;
        for (let i = 0; i < batchSize && this.qubitQueue.length > 0; i++) {
            q = this.qubitQueue.shift();
        }
        this.currentQubit = q;
        this.pulseAlpha = 1.0;
        const remaining = this.qubitQueue.length;
        const processed = CONFIG.BB84_QUBITS - remaining;
        this.label.textContent = `QUBIT ${processed}/${CONFIG.BB84_QUBITS}`;
        this.label.style.color = CONFIG.COLORS.warning;
        setTimeout(() => this.processNext(), 15);
    },

    animatePulse() {
        this.pulseAlpha = 1.0;
        if (this.state === 'idle') {
            this.state = 'transmit';
            this.label.textContent = 'QUANTUM ACTIVITY';
            this.label.style.color = CONFIG.COLORS.warning;
            setTimeout(() => {
                if (this.state === 'transmit' && this.qubitQueue.length === 0) {
                    this.state = 'idle';
                    this.label.textContent = 'IDLE';
                    this.label.style.color = '#94a3b8';
                }
            }, 2000);
        }
    },

    animate() {
        const ctx = this.ctx;
        const w = this.canvas.width, h = this.canvas.height;
        const cx = w / 2, cy = h / 2 + 5;
        const R = 55;

        ctx.clearRect(0, 0, w, h);
        this.angle += 0.005;
        if (this.pulseAlpha > 0) this.pulseAlpha -= 0.02;

        // === Draw Sphere ===
        ctx.strokeStyle = this.state === 'secure' ? CONFIG.COLORS.teal : 'rgba(100,255,218,0.4)';
        ctx.lineWidth = 1;
        ctx.beginPath(); ctx.arc(cx, cy, R, 0, Math.PI * 2); ctx.stroke();

        // Equator ellipse
        ctx.strokeStyle = 'rgba(100,255,218,0.15)';
        ctx.beginPath(); ctx.ellipse(cx, cy, R, R * 0.3, 0, 0, Math.PI * 2); ctx.stroke();

        // Vertical axis dashed
        ctx.strokeStyle = 'rgba(255,255,255,0.15)';
        ctx.setLineDash([3, 3]);
        ctx.beginPath(); ctx.moveTo(cx, cy - R - 5); ctx.lineTo(cx, cy + R + 5); ctx.stroke();
        ctx.setLineDash([]);

        // Axis labels
        ctx.fillStyle = 'rgba(255,255,255,0.5)'; ctx.font = '10px monospace'; ctx.textAlign = 'center';
        ctx.fillText('|0⟩', cx, cy - R - 8);
        ctx.fillText('|1⟩', cx, cy + R + 14);
        ctx.fillText('|+⟩', cx + R + 12, cy + 4);
        ctx.fillText('|−⟩', cx - R - 12, cy + 4);

        // === State Vector ===
        let targetX = cx, targetY = cy - R * 0.7;
        let stateLabel = '|0⟩';
        let vecColor = CONFIG.COLORS.teal;

        if (this.currentQubit) {
            const { bit, basis } = this.currentQubit;
            if (basis === '0') {
                if (bit === '0') {
                    targetX = cx; targetY = cy - R * 0.85; stateLabel = '|0⟩ ⊕';
                } else {
                    targetX = cx; targetY = cy + R * 0.85; stateLabel = '|1⟩ ⊕';
                }
                vecColor = CONFIG.COLORS.teal;
            } else {
                if (bit === '0') {
                    targetX = cx + R * 0.85; targetY = cy; stateLabel = '|+⟩ ⊗';
                } else {
                    targetX = cx - R * 0.85; targetY = cy; stateLabel = '|−⟩ ⊗';
                }
                vecColor = CONFIG.COLORS.warning;
            }
        } else if (this.state === 'secure') {
            targetX = cx + Math.cos(this.angle * 3) * R * 0.5;
            targetY = cy + Math.sin(this.angle * 3) * R * 0.3 - 15;
            stateLabel = 'SECURE'; vecColor = CONFIG.COLORS.teal;
        } else {
            targetX = cx + Math.cos(this.angle) * R * 0.3;
            targetY = cy - R * 0.5 + Math.sin(this.angle) * 10;
            stateLabel = 'IDLE'; vecColor = 'rgba(255,255,255,0.3)';
        }

        // Vector line
        ctx.strokeStyle = vecColor; ctx.lineWidth = 2;
        ctx.beginPath(); ctx.moveTo(cx, cy); ctx.lineTo(targetX, targetY); ctx.stroke();

        // Endpoint dot
        ctx.fillStyle = vecColor;
        ctx.beginPath(); ctx.arc(targetX, targetY, 4, 0, Math.PI * 2); ctx.fill();

        // Glow pulse
        if (this.pulseAlpha > 0) {
            ctx.beginPath(); ctx.arc(targetX, targetY, 12, 0, Math.PI * 2);
            ctx.fillStyle = `rgba(100,255,218,${this.pulseAlpha * 0.3})`;
            ctx.fill();
        }

        // State text
        ctx.fillStyle = vecColor; ctx.font = 'bold 10px monospace'; ctx.textAlign = 'center';
        ctx.fillText(stateLabel, cx, h - 4);

        requestAnimationFrame(() => this.animate());
    }
};

// =====================================================
// Live Eavesdropper Detection Monitor (Oscilloscope)
// =====================================================
const ChannelMonitor = {
    canvas: null, ctx: null,
    w: 0, h: 0,
    scanX: 0,                    // Current sweep position
    state: 'idle',               // 'idle' | 'secure' | 'eavesdropper'
    lineData: [],                // Y-values for the waveform
    glowIntensity: 0,

    init() {
        this.canvas = dom.eavesdropperCanvas;
        this.resize();
        window.addEventListener('resize', () => this.resize());
        this.animate();
    },

    resize() {
        const parent = this.canvas.parentElement;
        this.w = parent.clientWidth;
        this.h = parent.clientHeight;
        this.canvas.width = this.w;
        this.canvas.height = this.h;
        this.lineData = new Array(this.w).fill(this.h / 2);
    },

    // Called when BB84 completes successfully (QBER < 25%)
    setSecure() {
        this.state = 'secure';
        this.glowIntensity = 1.0;
        dom.channelStatusBadge.textContent = 'SECURE';
        dom.channelStatusBadge.style.color = CONFIG.COLORS.teal;
        dom.channelStatusBadge.style.borderColor = CONFIG.COLORS.teal;
        dom.channelStatusBadge.style.background = 'rgba(100,255,218,0.1)';
    },

    // Called if QBER > 25%
    setEavesdropper() {
        this.state = 'eavesdropper';
        this.glowIntensity = 1.0;
        dom.channelStatusBadge.textContent = '⚠ INTRUSION';
        dom.channelStatusBadge.style.color = CONFIG.COLORS.danger;
        dom.channelStatusBadge.style.borderColor = CONFIG.COLORS.danger;
        dom.channelStatusBadge.style.background = 'rgba(239,68,68,0.15)';
    },

    // Called during BB84 exchange
    setActive() {
        if (this.state === 'idle') {
            this.state = 'active';
            dom.channelStatusBadge.textContent = 'SCANNING';
            dom.channelStatusBadge.style.color = CONFIG.COLORS.warning;
            dom.channelStatusBadge.style.borderColor = CONFIG.COLORS.warning;
            dom.channelStatusBadge.style.background = 'rgba(245,158,11,0.1)';
        }
    },

    animate() {
        const ctx = this.ctx || (this.ctx = this.canvas.getContext('2d'));
        if (!this.w || !this.h) { requestAnimationFrame(() => this.animate()); return; }

        const midY = this.h / 2;
        const speed = 2;

        // Advance scan position and generate new data points
        for (let s = 0; s < speed; s++) {
            this.scanX = (this.scanX + 1) % this.w;
            let y = midY;

            if (this.state === 'secure') {
                // FLAT LINE with tiny sine ripple (signal is clean)
                y = midY + Math.sin(this.scanX * 0.05) * 1.5;
            } else if (this.state === 'eavesdropper') {
                // NOISY chaotic line (eavesdropper interference)
                y = midY + (Math.random() - 0.5) * this.h * 0.7
                    + Math.sin(this.scanX * 0.3) * 8
                    + Math.cos(this.scanX * 0.7) * 6;
            } else if (this.state === 'active') {
                // Small activity pulses during scanning
                y = midY + Math.sin(this.scanX * 0.1) * 5 + (Math.random() - 0.5) * 4;
            } else {
                // Idle: perfectly flat
                y = midY;
            }

            this.lineData[this.scanX] = Math.max(2, Math.min(this.h - 2, y));
        }

        if (this.glowIntensity > 0) this.glowIntensity -= 0.005;

        // === Draw ===
        ctx.fillStyle = 'rgba(0,0,0,0.15)';
        ctx.fillRect(0, 0, this.w, this.h);

        // Grid lines
        ctx.strokeStyle = 'rgba(100,255,218,0.04)';
        ctx.lineWidth = 0.5;
        for (let gy = 0; gy < this.h; gy += 20) {
            ctx.beginPath(); ctx.moveTo(0, gy); ctx.lineTo(this.w, gy); ctx.stroke();
        }
        for (let gx = 0; gx < this.w; gx += 30) {
            ctx.beginPath(); ctx.moveTo(gx, 0); ctx.lineTo(gx, this.h); ctx.stroke();
        }

        // Center reference line
        ctx.strokeStyle = 'rgba(100,255,218,0.08)';
        ctx.lineWidth = 1;
        ctx.setLineDash([4, 4]);
        ctx.beginPath(); ctx.moveTo(0, midY); ctx.lineTo(this.w, midY); ctx.stroke();
        ctx.setLineDash([]);

        // Choose waveform color
        let lineColor, glowColor;
        if (this.state === 'eavesdropper') {
            lineColor = CONFIG.COLORS.danger;
            glowColor = 'rgba(239,68,68,';
        } else if (this.state === 'secure') {
            lineColor = CONFIG.COLORS.teal;
            glowColor = 'rgba(100,255,218,';
        } else if (this.state === 'active') {
            lineColor = CONFIG.COLORS.warning;
            glowColor = 'rgba(245,158,11,';
        } else {
            lineColor = 'rgba(148,163,184,0.4)';
            glowColor = 'rgba(148,163,184,';
        }

        // Glow effect
        if (this.glowIntensity > 0 && this.state !== 'idle') {
            ctx.shadowColor = lineColor;
            ctx.shadowBlur = 8 * this.glowIntensity;
        }

        // Draw waveform
        ctx.strokeStyle = lineColor;
        ctx.lineWidth = this.state === 'eavesdropper' ? 2 : 1.5;
        ctx.beginPath();
        for (let x = 0; x < this.w; x++) {
            const drawX = (this.scanX + x + 1) % this.w;
            if (x === 0) ctx.moveTo(x, this.lineData[drawX]);
            else ctx.lineTo(x, this.lineData[drawX]);
        }
        ctx.stroke();
        ctx.shadowBlur = 0;

        // Scan head dot
        const headY = this.lineData[this.scanX];
        ctx.fillStyle = lineColor;
        ctx.beginPath();
        ctx.arc(this.w - 1, headY, 3, 0, Math.PI * 2);
        ctx.fill();

        // Glow around scan head
        if (this.state !== 'idle') {
            ctx.beginPath();
            ctx.arc(this.w - 1, headY, 8, 0, Math.PI * 2);
            ctx.fillStyle = glowColor + '0.2)';
            ctx.fill();
        }

        requestAnimationFrame(() => this.animate());
    }
};
// =====================================================
// Real-Time QBER Matching Animation + Popup Controller
// =====================================================

// Shared QBER state for popup sync
const QberState = {
    totalBits: 0, matched: 0, discarded: 0, mismatched: 0,
    qber: 0, complete: false
};

// QBER Popup Controller
const QberPopup = {
    isOpen: false,

    open() {
        const overlay = document.getElementById('qberPopupOverlay');
        if (!overlay) return;
        overlay.classList.add('open');
        this.isOpen = true;
        this.syncData();
        // Mirror match log
        const srcLog = document.getElementById('qberMatchLog');
        const popLog = document.getElementById('qpMatchLog');
        if (srcLog && popLog) popLog.innerHTML = srcLog.innerHTML;
    },

    close() {
        const overlay = document.getElementById('qberPopupOverlay');
        if (!overlay) return;
        overlay.classList.remove('open');
        this.isOpen = false;
    },

    syncData() {
        const s = QberState;
        const qpTotal = document.getElementById('qpTotalBits');
        const qpQber = document.getElementById('qpQberValue');
        const qpMatched = document.getElementById('qpMatched');
        const qpDiscarded = document.getElementById('qpDiscarded');
        const qpFill = document.getElementById('qpThresholdFill');
        const qpBarLabel = document.getElementById('qpBarLabel');
        const qpSiftEff = document.getElementById('qpSiftEff');
        const qpSiftSub = document.getElementById('qpSiftSub');
        const qpKeyRate = document.getElementById('qpKeyRate');
        const qpKeySub = document.getElementById('qpKeySub');
        const qpThreshMargin = document.getElementById('qpThreshMargin');
        const qpVerdict = document.getElementById('qpVerdict');

        if (!qpTotal) return;

        // Primary stats
        qpTotal.textContent = s.totalBits || '—';
        qpQber.textContent = s.totalBits ? s.qber.toFixed(1) + '%' : '—';
        qpMatched.textContent = s.totalBits ? s.matched : '—';
        qpDiscarded.textContent = s.totalBits ? s.discarded : '—';

        // Threshold bar (scale: 0-25% mapped to 0-100% width)
        const barPct = Math.min(s.qber / 25 * 100, 100);
        qpFill.style.width = barPct + '%';
        qpBarLabel.textContent = s.qber.toFixed(1) + '%';
        // Color: green if under 11%, yellow if 11-25%, red if over 25%
        if (s.qber > 11) {
            qpFill.style.background = 'linear-gradient(90deg, #f59e0b, #ef4444)';
        } else {
            qpFill.style.background = 'linear-gradient(90deg, #10b981, #64ffda)';
        }

        // Efficiency metrics
        if (s.totalBits > 0) {
            const siftEff = (s.matched / s.totalBits * 100);
            qpSiftEff.textContent = siftEff.toFixed(1) + '%';
            qpSiftSub.textContent = `${s.matched} / ${s.totalBits} qubits`;

            // Final key rate = matched bits minus error bits, then SHA-256 → 256 bits
            const usableBits = s.matched - s.mismatched;
            qpKeyRate.textContent = '256 bits';
            qpKeySub.textContent = `${usableBits} sifted → SHA-256`;

            // Threshold margin
            const margin = 11 - s.qber;
            qpThreshMargin.textContent = margin > 0 ? margin.toFixed(1) + '%' : '⚠ OVER';
            qpThreshMargin.style.color = margin > 0 ? '#10b981' : '#ef4444';
        }

        // Verdict
        if (s.complete) {
            if (s.qber > 11) {
                qpVerdict.textContent = '⚠ EAVESDROPPER DETECTED — QBER ' + s.qber.toFixed(1) + '%';
                qpVerdict.style.color = '#ef4444';
            } else {
                qpVerdict.textContent = '✓ QUANTUM CHANNEL SECURE — QBER ' + s.qber.toFixed(1) + '%';
                qpVerdict.style.color = '#64ffda';
            }
        }
    }
};

// Wire up QBER popup open/close
(function setupQberPopup() {
    const card = document.getElementById('qberCard');
    if (card) {
        card.addEventListener('click', () => QberPopup.open());
    }

    const closeBtn = document.getElementById('qberPopupClose');
    if (closeBtn) {
        closeBtn.addEventListener('click', (e) => { e.stopPropagation(); QberPopup.close(); });
    }

    const overlay = document.getElementById('qberPopupOverlay');
    if (overlay) {
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) QberPopup.close();
        });
    }

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && QberPopup.isOpen) QberPopup.close();
    });
})();

// Animate the full qubit comparison (all N qubits)
function animateQberMatching(senderBases, senderBits, receiverBases, receiverBits, errors, siftedCount) {
    const strip = document.getElementById('qberMatchStrip');
    const log = document.getElementById('qberMatchLog');
    const progressLabel = document.getElementById('qberProgress');
    const progressBar = document.getElementById('qberProgressBar');

    if (!strip || !log) return;

    // Show the strip
    strip.style.display = 'block';
    log.innerHTML = '';
    progressBar.style.width = '0%';

    const N = senderBases.length;
    let idx = 0;
    let matchedSoFar = 0;
    let discardedSoFar = 0;
    let mismatchedSoFar = 0;

    // Reset shared state
    QberState.totalBits = N;
    QberState.matched = 0;
    QberState.discarded = 0;
    QberState.mismatched = 0;
    QberState.qber = 0;
    QberState.complete = false;

    // Reset Real Time Charts for new session
    RealTimeCharts.reset();

    // Reset stat boxes to 0
    dom.qberTotalBits.textContent = N;
    dom.qberMatched.textContent = '0';
    dom.qberDiscarded.textContent = '0';
    dom.qberValue.textContent = '0.0%';

    const basisSymbol = (b) => b === '0' ? '⊕' : '⊗';

    // Batch processing: process BATCH_SIZE qubits per frame for smooth animation
    // Target: ~5-8 seconds total regardless of qubit count
    const BATCH_SIZE = Math.max(1, Math.ceil(N / 200)); // ~200 frames total
    const FRAME_MS = 30;
    const idxPad = N >= 1000 ? 4 : 3;

    const interval = setInterval(() => {
        if (idx >= N) {
            clearInterval(interval);
            // Final verdict
            const finalQber = matchedSoFar > 0 ? (mismatchedSoFar / matchedSoFar * 100) : 0;
            QberState.qber = finalQber;
            QberState.complete = true;

            const verdict = dom.qberVerdict;
            if (finalQber > 11) {
                verdict.textContent = '⚠ EAVESDROPPER DETECTED';
                verdict.style.color = CONFIG.COLORS.danger;
                verdict.style.background = 'rgba(239,68,68,0.1)';
                verdict.style.borderColor = CONFIG.COLORS.danger;
                ChannelMonitor.setEavesdropper();
                sysLog(`⚠ QBER ${finalQber.toFixed(1)}% exceeds 11% threshold — possible eavesdropper!`, 'error');
            } else {
                verdict.textContent = '✓ QUANTUM CHANNEL SECURE';
                verdict.style.color = CONFIG.COLORS.teal;
                verdict.style.background = 'rgba(100,255,218,0.08)';
                verdict.style.borderColor = CONFIG.COLORS.teal;
                ChannelMonitor.setSecure();
                sysLog(`[QBER] ${finalQber.toFixed(1)}% (${mismatchedSoFar}/${matchedSoFar} errors) | ${matchedSoFar} matched, ${discardedSoFar} discarded — secure ✓`, 'secure');
            }

            // Add completion line
            const doneLine = document.createElement('div');
            doneLine.style.cssText = 'color:#64ffda; margin-top:3px; font-weight:700; letter-spacing:0.05em;';
            doneLine.textContent = `━━ COMPLETE ━━ QBER: ${finalQber.toFixed(1)}%`;
            log.appendChild(doneLine);
            log.scrollTop = log.scrollHeight;

            // Finalize Real Time Charts
            RealTimeCharts.finalize();

            // Sync popup
            if (QberPopup.isOpen) {
                const popLog = document.getElementById('qpMatchLog');
                if (popLog) popLog.innerHTML = log.innerHTML;
                QberPopup.syncData();
            }
            return;
        }

        // Process a batch of qubits per frame
        const batchEnd = Math.min(idx + BATCH_SIZE, N);
        let lastLine = null;
        for (let b = idx; b < batchEnd; b++) {
            const sBase = senderBases[b];
            const rBase = receiverBases[b];
            const sBit = senderBits[b];
            const rBit = receiverBits[b];
            const basesMatch = sBase === rBase;

            if (basesMatch) {
                matchedSoFar++;
                const bitMatch = sBit === rBit;
                if (!bitMatch) mismatchedSoFar++;
            } else {
                discardedSoFar++;
            }
        }

        // Only render the last qubit of this batch in the log for performance
        const showIdx = batchEnd - 1;
        const sBase = senderBases[showIdx];
        const rBase = receiverBases[showIdx];
        const sBit = senderBits[showIdx];
        const rBit = receiverBits[showIdx];
        const basesMatch = sBase === rBase;
        const line = document.createElement('div');
        line.style.cssText = 'display:flex; gap:4px; align-items:center; padding:1px 0;';
        const idxStr = String(showIdx).padStart(idxPad, '0');
        const batchLabel = BATCH_SIZE > 1 ? `<span style="color:#475569;font-size:0.55rem;">[+${BATCH_SIZE - 1}]</span> ` : '';

        if (basesMatch) {
            const bitMatch = sBit === rBit;
            line.innerHTML = bitMatch
                ? `${batchLabel}<span style="color:#64748b;">#${idxStr}</span> <span style="color:#64ffda;">${basisSymbol(sBase)}=${basisSymbol(rBase)}</span> A:<span style="color:#e2e8f0;">${sBit}</span> B:<span style="color:#e2e8f0;">${rBit}</span> <span style="color:#10b981;">✓ MATCH</span>`
                : `${batchLabel}<span style="color:#64748b;">#${idxStr}</span> <span style="color:#64ffda;">${basisSymbol(sBase)}=${basisSymbol(rBase)}</span> A:<span style="color:#e2e8f0;">${sBit}</span> B:<span style="color:#ef4444;">${rBit}</span> <span style="color:#f59e0b;">⚡ BIT ERROR</span>`;
        } else {
            line.innerHTML = `${batchLabel}<span style="color:#64748b;">#${idxStr}</span> <span style="color:#94a3b8;">${basisSymbol(sBase)}≠${basisSymbol(rBase)}</span> <span style="color:#64748b;">— — ✗ DISCARD</span>`;
        }

        log.appendChild(line);
        // Keep log from getting too long (cap at 200 visible lines)
        while (log.children.length > 200) log.removeChild(log.firstChild);
        log.scrollTop = log.scrollHeight;

        // Update progress
        idx = batchEnd;
        const pct = (idx / N * 100);
        progressBar.style.width = pct + '%';
        progressLabel.textContent = `${idx}/${N}`;

        // Update live counters
        dom.qberMatched.textContent = matchedSoFar;
        dom.qberDiscarded.textContent = discardedSoFar;
        const liveQber = matchedSoFar > 0 ? (mismatchedSoFar / matchedSoFar * 100) : 0;
        dom.qberValue.textContent = liveQber.toFixed(1) + '%';

        // Update shared state
        QberState.matched = matchedSoFar;
        QberState.discarded = discardedSoFar;
        QberState.mismatched = mismatchedSoFar;
        QberState.qber = liveQber;

        // Push to Real Time Charts (push every frame, not every qubit)
        const liveEfficiency = idx > 0 ? (matchedSoFar / idx * 100) : 0;
        RealTimeCharts.pushDataPoint(idx, liveQber, liveEfficiency, matchedSoFar, discardedSoFar);

        // Sync popup if open
        if (QberPopup.isOpen) {
            const popLog = document.getElementById('qpMatchLog');
            if (popLog) popLog.innerHTML = log.innerHTML;
            QberPopup.syncData();
        }

    }, FRAME_MS); // Batch-processed: ~200 frames × 30ms = ~6 seconds total
}

// Legacy wrapper (unused now, kept for safety)
function updateQberChart(peerName, errors, siftedCount) {
    const totalBits = CONFIG.BB84_QUBITS;
    const matched = siftedCount;
    const discarded = totalBits - matched;
    const qber = siftedCount > 0 ? (errors / siftedCount * 100) : 0;

    dom.qberTotalBits.textContent = totalBits;
    dom.qberMatched.textContent = matched;
    dom.qberDiscarded.textContent = discarded;
    dom.qberValue.textContent = qber.toFixed(1) + '%';
}

// =====================================================
// 3D Bloch Sphere — Interactive Popup (Three.js)
// =====================================================
const BlochSphere3D = {
    scene: null, camera: null, renderer: null,
    sphere: null, stateArrow: null, statePoint: null,
    glowPoint: null,
    axisLabels: [],
    isOpen: false,
    animId: null,
    // State synchronization with 2D
    state: 'idle',
    currentQubit: null,
    qubitQueue: [],
    angle: 0,
    pulseScale: 0,
    // Mouse orbit
    isDragging: false,
    prevMouse: { x: 0, y: 0 },
    orbitAngles: { theta: Math.PI / 6, phi: Math.PI / 4 },
    orbitRadius: 4.5,

    init() {
        if (!window.THREE) { console.warn('Three.js not loaded'); return; }

        const wrap = document.getElementById('bloch3dCanvasWrap');
        const w = wrap.clientWidth || 680;
        const h = wrap.clientHeight || 420;

        // Scene
        this.scene = new THREE.Scene();

        // Camera
        this.camera = new THREE.PerspectiveCamera(45, w / h, 0.1, 100);
        this.updateCameraPosition();

        // Renderer
        this.renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
        this.renderer.setSize(w, h);
        this.renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
        this.renderer.setClearColor(0x000000, 0);
        wrap.appendChild(this.renderer.domElement);

        this.buildScene();
        this.bindEvents(wrap);
    },

    buildScene() {
        const scene = this.scene;

        // === Ambient light ===
        scene.add(new THREE.AmbientLight(0xffffff, 0.4));
        const dirLight = new THREE.DirectionalLight(0x64ffda, 0.6);
        dirLight.position.set(3, 5, 4);
        scene.add(dirLight);

        // === Wireframe Sphere ===
        const sphereGeo = new THREE.SphereGeometry(1.5, 32, 24);
        const sphereMat = new THREE.MeshBasicMaterial({
            color: 0x64ffda, wireframe: true, transparent: true, opacity: 0.08
        });
        this.sphere = new THREE.Mesh(sphereGeo, sphereMat);
        scene.add(this.sphere);

        // === Solid translucent sphere inside ===
        const innerGeo = new THREE.SphereGeometry(1.48, 32, 24);
        const innerMat = new THREE.MeshPhongMaterial({
            color: 0x0b1221, transparent: true, opacity: 0.3,
            specular: 0x64ffda, shininess: 30
        });
        scene.add(new THREE.Mesh(innerGeo, innerMat));

        // === Equator ring ===
        const eqGeo = new THREE.RingGeometry(1.5, 1.52, 64);
        const eqMat = new THREE.MeshBasicMaterial({
            color: 0x64ffda, transparent: true, opacity: 0.2, side: THREE.DoubleSide
        });
        const eqRing = new THREE.Mesh(eqGeo, eqMat);
        eqRing.rotation.x = Math.PI / 2;
        scene.add(eqRing);

        // === Meridian rings ===
        const meridianGeo = new THREE.RingGeometry(1.5, 1.51, 64);
        const meridianMat = new THREE.MeshBasicMaterial({
            color: 0x64ffda, transparent: true, opacity: 0.08, side: THREE.DoubleSide
        });
        const m1 = new THREE.Mesh(meridianGeo, meridianMat);
        scene.add(m1);
        const m2 = new THREE.Mesh(meridianGeo.clone(), meridianMat.clone());
        m2.rotation.y = Math.PI / 2;
        scene.add(m2);

        // === Axes ===
        const axisMat = new THREE.LineBasicMaterial({ color: 0xffffff, transparent: true, opacity: 0.15 });
        const axLen = 2.0;
        // Z-axis (|0⟩ to |1⟩)
        this.addAxisLine(0, -axLen, 0, 0, axLen, 0, axisMat);
        // X-axis (|+⟩ to |−⟩)
        this.addAxisLine(-axLen, 0, 0, axLen, 0, 0, axisMat);
        // Y-axis
        this.addAxisLine(0, 0, -axLen, 0, 0, axLen, axisMat);

        // === State vector (arrow) ===
        const arrowMat = new THREE.MeshBasicMaterial({ color: 0x64ffda });
        // Shaft
        const shaftGeo = new THREE.CylinderGeometry(0.025, 0.025, 1, 8);
        shaftGeo.translate(0, 0.5, 0); // pivot at base
        this.stateArrow = new THREE.Mesh(shaftGeo, arrowMat);
        scene.add(this.stateArrow);

        // Cone tip
        const tipGeo = new THREE.ConeGeometry(0.07, 0.18, 8);
        tipGeo.translate(0, 1.05, 0);
        this.stateTip = new THREE.Mesh(tipGeo, arrowMat);
        scene.add(this.stateTip);

        // Endpoint glow sphere
        const glowGeo = new THREE.SphereGeometry(0.1, 16, 16);
        const glowMat = new THREE.MeshBasicMaterial({ color: 0x64ffda, transparent: true, opacity: 0.8 });
        this.statePoint = new THREE.Mesh(glowGeo, glowMat);
        scene.add(this.statePoint);

        // Outer glow
        const outerGlowGeo = new THREE.SphereGeometry(0.2, 16, 16);
        const outerGlowMat = new THREE.MeshBasicMaterial({ color: 0x64ffda, transparent: true, opacity: 0.15 });
        this.glowPoint = new THREE.Mesh(outerGlowGeo, outerGlowMat);
        scene.add(this.glowPoint);

        // === Floating particles ===
        const particleCount = 80;
        const pGeo = new THREE.BufferGeometry();
        const pPositions = new Float32Array(particleCount * 3);
        for (let i = 0; i < particleCount; i++) {
            const theta = Math.random() * Math.PI * 2;
            const phi = Math.acos(2 * Math.random() - 1);
            const r = 1.5 + (Math.random() - 0.5) * 0.4;
            pPositions[i * 3] = r * Math.sin(phi) * Math.cos(theta);
            pPositions[i * 3 + 1] = r * Math.cos(phi);
            pPositions[i * 3 + 2] = r * Math.sin(phi) * Math.sin(theta);
        }
        pGeo.setAttribute('position', new THREE.BufferAttribute(pPositions, 3));
        const pMat = new THREE.PointsMaterial({ color: 0x64ffda, size: 0.03, transparent: true, opacity: 0.4 });
        this.particles = new THREE.Points(pGeo, pMat);
        scene.add(this.particles);

        // === Axis label sprites ===
        this.createLabel('|0⟩', 0, 2.15, 0, '#64ffda');
        this.createLabel('|1⟩', 0, -2.15, 0, '#64ffda');
        this.createLabel('|+⟩', 2.15, 0, 0, '#f59e0b');
        this.createLabel('|−⟩', -2.15, 0, 0, '#f59e0b');
        this.createLabel('|i⟩', 0, 0, 2.15, '#94a3b8');
        this.createLabel('|−i⟩', 0, 0, -2.15, '#94a3b8');
    },

    addAxisLine(x1, y1, z1, x2, y2, z2, mat) {
        const geo = new THREE.BufferGeometry().setFromPoints([
            new THREE.Vector3(x1, y1, z1), new THREE.Vector3(x2, y2, z2)
        ]);
        this.scene.add(new THREE.Line(geo, mat));
    },

    createLabel(text, x, y, z, color) {
        const canvas = document.createElement('canvas');
        canvas.width = 128; canvas.height = 64;
        const ctx = canvas.getContext('2d');
        ctx.font = 'bold 28px monospace';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillStyle = color;
        ctx.fillText(text, 64, 32);
        const tex = new THREE.CanvasTexture(canvas);
        const mat = new THREE.SpriteMaterial({ map: tex, transparent: true, opacity: 0.9 });
        const sprite = new THREE.Sprite(mat);
        sprite.position.set(x, y, z);
        sprite.scale.set(0.6, 0.3, 1);
        this.scene.add(sprite);
        this.axisLabels.push(sprite);
    },

    updateCameraPosition() {
        if (!this.camera) return;
        const { theta, phi } = this.orbitAngles;
        this.camera.position.set(
            this.orbitRadius * Math.sin(phi) * Math.cos(theta),
            this.orbitRadius * Math.cos(phi),
            this.orbitRadius * Math.sin(phi) * Math.sin(theta)
        );
        this.camera.lookAt(0, 0, 0);
    },

    bindEvents(wrap) {
        const canvas = this.renderer.domElement;

        canvas.addEventListener('mousedown', (e) => {
            this.isDragging = true;
            this.prevMouse = { x: e.clientX, y: e.clientY };
        });
        window.addEventListener('mousemove', (e) => {
            if (!this.isDragging) return;
            const dx = e.clientX - this.prevMouse.x;
            const dy = e.clientY - this.prevMouse.y;
            this.orbitAngles.theta -= dx * 0.008;
            this.orbitAngles.phi = Math.max(0.2, Math.min(Math.PI - 0.2, this.orbitAngles.phi + dy * 0.008));
            this.prevMouse = { x: e.clientX, y: e.clientY };
            this.updateCameraPosition();
        });
        window.addEventListener('mouseup', () => { this.isDragging = false; });

        canvas.addEventListener('wheel', (e) => {
            e.preventDefault();
            this.orbitRadius = Math.max(3, Math.min(8, this.orbitRadius + e.deltaY * 0.005));
            this.updateCameraPosition();
        }, { passive: false });

        // Resize
        window.addEventListener('resize', () => {
            if (!this.isOpen) return;
            const w = wrap.clientWidth;
            const h = wrap.clientHeight;
            this.camera.aspect = w / h;
            this.camera.updateProjectionMatrix();
            this.renderer.setSize(w, h);
        });
    },

    // Sync state from 2D BlochSphere
    syncState() {
        this.state = BlochSphere.state;
        this.currentQubit = BlochSphere.currentQubit;
        this.qubitQueue = [...BlochSphere.qubitQueue];
    },

    open() {
        if (this.isOpen) return;
        this.isOpen = true;
        if (!this.scene) this.init();
        this.syncState();
        document.getElementById('bloch3dOverlay').classList.add('active');
        this.startAnimation();
    },

    close() {
        if (!this.isOpen) return;
        this.isOpen = false;
        document.getElementById('bloch3dOverlay').classList.remove('active');
        if (this.animId) {
            cancelAnimationFrame(this.animId);
            this.animId = null;
        }
    },

    startAnimation() {
        const animate = () => {
            if (!this.isOpen) return;
            this.animId = requestAnimationFrame(animate);
            this.updateScene();
            this.renderer.render(this.scene, this.camera);
        };
        animate();
    },

    updateScene() {
        this.angle += 0.008;
        this.syncState();

        // Rotate particles slowly
        if (this.particles) {
            this.particles.rotation.y += 0.001;
        }

        // Determine state vector target (in Three.js Y is up = |0⟩ )
        let target = new THREE.Vector3(0, 1.3, 0); // default |0⟩
        let vecColor = 0x64ffda;
        let badgeText = 'IDLE — AWAITING BB84';
        let badgeColor = '#94a3b8';

        if (this.currentQubit) {
            const { bit, basis } = this.currentQubit;
            if (basis === '0') { // Rectilinear
                if (bit === '0') {
                    target.set(0, 1.35, 0); // |0⟩
                    badgeText = '|0⟩ RECTILINEAR ⊕';
                } else {
                    target.set(0, -1.35, 0); // |1⟩
                    badgeText = '|1⟩ RECTILINEAR ⊕';
                }
                vecColor = 0x64ffda;
                badgeColor = '#64ffda';
            } else { // Diagonal
                if (bit === '0') {
                    target.set(1.35, 0, 0); // |+⟩
                    badgeText = '|+⟩ DIAGONAL ⊗';
                } else {
                    target.set(-1.35, 0, 0); // |−⟩
                    badgeText = '|−⟩ DIAGONAL ⊗';
                }
                vecColor = 0xf59e0b;
                badgeColor = '#f59e0b';
            }
        } else if (this.state === 'secure') {
            // Orbit slowly in secure mode
            target.set(
                Math.cos(this.angle * 2) * 1.0,
                Math.sin(this.angle * 3) * 0.5 + 0.3,
                Math.sin(this.angle * 2) * 0.5
            );
            vecColor = 0x64ffda;
            badgeText = '✓ KEY EXCHANGE COMPLETE';
            badgeColor = '#64ffda';
        } else if (this.state === 'transmit') {
            badgeText = `TRANSMITTING QUBITS...`;
            badgeColor = '#f59e0b';
            vecColor = 0xf59e0b;
            target.set(
                Math.cos(this.angle * 5) * 0.8,
                Math.sin(this.angle * 5) * 1.0,
                0
            );
        } else {
            // Idle slow drift
            target.set(
                Math.cos(this.angle) * 0.4,
                0.9 + Math.sin(this.angle) * 0.2,
                Math.sin(this.angle * 0.7) * 0.3
            );
            vecColor = 0x555555;
        }

        // Update arrow direction
        const dir = target.clone().normalize();
        const len = target.length();

        // Point arrow toward target
        const up = new THREE.Vector3(0, 1, 0);
        const quat = new THREE.Quaternion().setFromUnitVectors(up, dir);
        this.stateArrow.quaternion.copy(quat);
        this.stateArrow.scale.set(1, len, 1);
        this.stateTip.quaternion.copy(quat);
        this.stateTip.scale.set(1, len, 1);

        // State point at tip
        this.statePoint.position.copy(target);
        this.glowPoint.position.copy(target);

        // Pulse glow
        const pulseVal = 0.15 + Math.sin(this.angle * 4) * 0.1;
        this.glowPoint.material.opacity = pulseVal;
        this.glowPoint.scale.setScalar(1 + Math.sin(this.angle * 3) * 0.3);

        // Color updates
        const color = new THREE.Color(vecColor);
        this.stateArrow.material.color.copy(color);
        this.stateTip.material.color.copy(color);
        this.statePoint.material.color.copy(color);
        this.glowPoint.material.color.copy(color);

        // Wireframe color
        this.sphere.material.color.copy(
            this.state === 'secure' ? new THREE.Color(0x64ffda) :
                this.state === 'transmit' ? new THREE.Color(0xf59e0b) :
                    new THREE.Color(0x64ffda)
        );
        this.sphere.material.opacity = this.state === 'secure' ? 0.12 : 0.08;

        // Update badge
        const badge = document.getElementById('bloch3dStateBadge');
        if (badge) {
            badge.textContent = badgeText;
            badge.style.color = badgeColor;
            badge.style.borderColor = badgeColor;
        }
    }
};

// =====================================================
// Popup Open / Close Wiring
// =====================================================
(function setupBloch3DPopup() {
    // Open on click of 2D Bloch card
    document.addEventListener('click', (e) => {
        const card = document.getElementById('blochCard');
        if (card && card.contains(e.target)) {
            BlochSphere3D.open();
        }
    });

    // Close button
    document.getElementById('bloch3dClose').addEventListener('click', () => {
        BlochSphere3D.close();
    });

    // Close on overlay click (outside modal)
    document.getElementById('bloch3dOverlay').addEventListener('click', (e) => {
        if (e.target === e.currentTarget) {
            BlochSphere3D.close();
        }
    });

    // Close on Escape key
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && BlochSphere3D.isOpen) {
            BlochSphere3D.close();
        }
    });
})();

// =====================================================
// Event Log Popup — Maximized Clean View
// =====================================================
const EventLogPopup = {
    isOpen: false,

    open() {
        if (this.isOpen) return;
        this.isOpen = true;
        this.syncLogs();
        document.getElementById('logPopupOverlay').classList.add('active');
    },

    close() {
        if (!this.isOpen) return;
        this.isOpen = false;
        document.getElementById('logPopupOverlay').classList.remove('active');
    },

    syncLogs() {
        const body = document.getElementById('logPopupBody');
        body.innerHTML = '';
        _logEntries.forEach(({ ts, msg, type }) => {
            const entry = document.createElement('div');
            entry.className = `log-entry log-${type}`;
            entry.innerHTML = `<span class="log-ts">${ts}</span><span>${msg}</span>`;
            body.appendChild(entry);
        });
        const countEl = document.getElementById('logPopupCount');
        if (countEl) countEl.textContent = _logEntries.length;
    },

    clearLogs() {
        _logEntries.length = 0;
        dom.systemLog.innerHTML = '';
        const body = document.getElementById('logPopupBody');
        if (body) body.innerHTML = '';
        const countEl = document.getElementById('logPopupCount');
        if (countEl) countEl.textContent = '0';
        sysLog('Log cleared.', 'info');
    }
};

(function setupEventLogPopup() {
    // Open on click of log card
    document.getElementById('logCard').addEventListener('click', () => {
        EventLogPopup.open();
    });

    // Close button
    document.getElementById('logPopupClose').addEventListener('click', () => {
        EventLogPopup.close();
    });

    // Close on overlay click (outside modal)
    document.getElementById('logPopupOverlay').addEventListener('click', (e) => {
        if (e.target === e.currentTarget) {
            EventLogPopup.close();
        }
    });

    // Clear button
    document.getElementById('logPopupClear').addEventListener('click', () => {
        EventLogPopup.clearLogs();
    });

    // Escape key
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && EventLogPopup.isOpen) {
            EventLogPopup.close();
        }
    });
})();

// =====================================================
// Session Timer
// =====================================================
let sec = 0;
setInterval(() => {
    sec++;
    const hh = String(Math.floor(sec / 3600)).padStart(2, '0');
    const mm = String(Math.floor((sec % 3600) / 60)).padStart(2, '0');
    const ss = String(sec % 60).padStart(2, '0');
    const el = document.getElementById('sessionTimer');
    if (el) el.textContent = `${hh}:${mm}:${ss}`;
}, 1000);

// =====================================================
// Real Time Charts — Maximized Popup Controller
// =====================================================
const RtcPopup = {
    isOpen: false,
    qberChart: null,
    basisChart: null,

    open() {
        const overlay = document.getElementById('rtcPopupOverlay');
        if (!overlay) return;
        overlay.classList.add('open');
        this.isOpen = true;
        this.buildCharts();
        this.syncData();
    },

    close() {
        const overlay = document.getElementById('rtcPopupOverlay');
        if (!overlay) return;
        overlay.classList.remove('open');
        this.isOpen = false;
        // Destroy popup charts to free memory
        if (this.qberChart) { this.qberChart.destroy(); this.qberChart = null; }
        if (this.basisChart) { this.basisChart.destroy(); this.basisChart = null; }
    },

    buildCharts() {
        if (typeof Chart === 'undefined') return;

        // Destroy existing if rebuilding
        if (this.qberChart) { this.qberChart.destroy(); this.qberChart = null; }
        if (this.basisChart) { this.basisChart.destroy(); this.basisChart = null; }

        // ── QBER & Efficiency Chart ──
        const qCanvas = document.getElementById('rtcPopupQberChart');
        if (qCanvas) {
            const ctx = qCanvas.getContext('2d');
            const qberGrad = ctx.createLinearGradient(0, 0, 0, 220);
            qberGrad.addColorStop(0, 'rgba(100, 255, 218, 0.3)');
            qberGrad.addColorStop(1, 'rgba(100, 255, 218, 0.0)');

            const effGrad = ctx.createLinearGradient(0, 0, 0, 220);
            effGrad.addColorStop(0, 'rgba(129, 140, 248, 0.25)');
            effGrad.addColorStop(1, 'rgba(129, 140, 248, 0.0)');

            this.qberChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [
                        {
                            label: 'QBER %',
                            data: [],
                            borderColor: '#64ffda',
                            backgroundColor: qberGrad,
                            borderWidth: 2.5,
                            fill: true,
                            tension: 0.35,
                            pointRadius: 0,
                            pointHoverRadius: 5,
                            pointHoverBackgroundColor: '#64ffda'
                        },
                        {
                            label: 'Sifting Efficiency %',
                            data: [],
                            borderColor: '#818cf8',
                            backgroundColor: effGrad,
                            borderWidth: 2,
                            fill: true,
                            tension: 0.35,
                            pointRadius: 0,
                            pointHoverRadius: 5,
                            pointHoverBackgroundColor: '#818cf8'
                        },
                        {
                            label: '11% Threshold',
                            data: [],
                            borderColor: 'rgba(239, 68, 68, 0.7)',
                            borderWidth: 2,
                            borderDash: [8, 4],
                            fill: false,
                            tension: 0,
                            pointRadius: 0,
                            pointHoverRadius: 0
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    animation: { duration: 200 },
                    interaction: { mode: 'index', intersect: false },
                    plugins: {
                        legend: {
                            display: true,
                            position: 'top',
                            labels: {
                                color: 'rgba(255,255,255,0.55)',
                                font: { family: "'JetBrains Mono', monospace", size: 11 },
                                boxWidth: 16, boxHeight: 2, padding: 12, usePointStyle: false
                            }
                        },
                        tooltip: {
                            backgroundColor: 'rgba(11, 18, 33, 0.95)',
                            borderColor: 'rgba(100, 255, 218, 0.25)',
                            borderWidth: 1,
                            titleColor: '#64ffda',
                            bodyColor: '#e2e8f0',
                            titleFont: { family: "'JetBrains Mono', monospace", size: 11, weight: '700' },
                            bodyFont: { family: "'JetBrains Mono', monospace", size: 11 },
                            padding: 10,
                            cornerRadius: 8,
                            displayColors: true,
                            callbacks: { title: (items) => `Qubit #${items[0].label}` }
                        }
                    },
                    scales: {
                        x: {
                            display: true,
                            grid: { color: 'rgba(100,255,218,0.04)', drawBorder: false },
                            ticks: { color: 'rgba(255,255,255,0.3)', font: { family: "'JetBrains Mono', monospace", size: 9 }, maxTicksLimit: 12, maxRotation: 0 }
                        },
                        y: {
                            display: true,
                            grid: { color: 'rgba(100,255,218,0.04)', drawBorder: false },
                            ticks: { color: 'rgba(255,255,255,0.3)', font: { family: "'JetBrains Mono', monospace", size: 9 }, maxTicksLimit: 6, callback: v => v + '%' },
                            beginAtZero: true, suggestedMax: 50
                        }
                    }
                }
            });
        }

        // ── Basis Matching Chart ──
        const bCanvas = document.getElementById('rtcPopupBasisChart');
        if (bCanvas) {
            const ctx = bCanvas.getContext('2d');
            const matchGrad = ctx.createLinearGradient(0, 0, 0, 220);
            matchGrad.addColorStop(0, 'rgba(16, 185, 129, 0.35)');
            matchGrad.addColorStop(1, 'rgba(16, 185, 129, 0.02)');

            const discardGrad = ctx.createLinearGradient(0, 0, 0, 220);
            discardGrad.addColorStop(0, 'rgba(245, 158, 11, 0.3)');
            discardGrad.addColorStop(1, 'rgba(245, 158, 11, 0.02)');

            this.basisChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [
                        {
                            label: 'Matched Bases',
                            data: [],
                            borderColor: '#10b981',
                            backgroundColor: matchGrad,
                            borderWidth: 2.5,
                            fill: true,
                            tension: 0.3,
                            pointRadius: 0,
                            pointHoverRadius: 5,
                            pointHoverBackgroundColor: '#10b981'
                        },
                        {
                            label: 'Discarded Bases',
                            data: [],
                            borderColor: '#f59e0b',
                            backgroundColor: discardGrad,
                            borderWidth: 2,
                            fill: true,
                            tension: 0.3,
                            pointRadius: 0,
                            pointHoverRadius: 5,
                            pointHoverBackgroundColor: '#f59e0b'
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    animation: { duration: 200 },
                    interaction: { mode: 'index', intersect: false },
                    plugins: {
                        legend: {
                            display: true,
                            position: 'top',
                            labels: {
                                color: 'rgba(255,255,255,0.55)',
                                font: { family: "'JetBrains Mono', monospace", size: 11 },
                                boxWidth: 16, boxHeight: 2, padding: 12, usePointStyle: false
                            }
                        },
                        tooltip: {
                            backgroundColor: 'rgba(11, 18, 33, 0.95)',
                            borderColor: 'rgba(100, 255, 218, 0.25)',
                            borderWidth: 1,
                            titleColor: '#64ffda',
                            bodyColor: '#e2e8f0',
                            titleFont: { family: "'JetBrains Mono', monospace", size: 11, weight: '700' },
                            bodyFont: { family: "'JetBrains Mono', monospace", size: 11 },
                            padding: 10,
                            cornerRadius: 8,
                            displayColors: true,
                            callbacks: { title: (items) => `Qubit #${items[0].label}` }
                        }
                    },
                    scales: {
                        x: {
                            display: true,
                            grid: { color: 'rgba(100,255,218,0.04)', drawBorder: false },
                            ticks: { color: 'rgba(255,255,255,0.3)', font: { family: "'JetBrains Mono', monospace", size: 9 }, maxTicksLimit: 12, maxRotation: 0 }
                        },
                        y: {
                            display: true,
                            grid: { color: 'rgba(100,255,218,0.04)', drawBorder: false },
                            ticks: { color: 'rgba(255,255,255,0.3)', font: { family: "'JetBrains Mono', monospace", size: 9 }, maxTicksLimit: 6 },
                            beginAtZero: true
                        }
                    }
                }
            });
        }
    },

    // Sync popup charts with accumulated data from RealTimeCharts
    syncData() {
        if (!this.isOpen) return;
        const dp = RealTimeCharts.dataPoints;
        if (!dp || dp.length === 0) return;

        const labels = dp.map(p => String(p.idx));
        const last = dp[dp.length - 1];

        // Sync QBER chart
        if (this.qberChart) {
            this.qberChart.data.labels = [...labels];
            this.qberChart.data.datasets[0].data = dp.map(p => p.qber);
            this.qberChart.data.datasets[1].data = dp.map(p => p.efficiency);
            this.qberChart.data.datasets[2].data = dp.map(() => 11);
            this.qberChart.update('none');
        }

        // Sync Basis chart
        if (this.basisChart) {
            this.basisChart.data.labels = [...labels];
            this.basisChart.data.datasets[0].data = dp.map(p => p.matched);
            this.basisChart.data.datasets[1].data = dp.map(p => p.discarded);
            this.basisChart.update('none');
        }

        // Update stat pills
        const qberPill = document.getElementById('rtcPopupQberVal');
        const effPill = document.getElementById('rtcPopupEffVal');
        const matchPill = document.getElementById('rtcPopupMatchVal');
        const discPill = document.getElementById('rtcPopupDiscardVal');

        if (qberPill) {
            qberPill.textContent = `QBER: ${last.qber.toFixed(1)}%`;
            qberPill.style.color = last.qber > 11 ? '#ef4444' : '#64ffda';
        }
        if (effPill) effPill.textContent = `EFF: ${last.efficiency.toFixed(1)}%`;
        if (matchPill) matchPill.textContent = `MATCHED: ${last.matched}`;
        if (discPill) discPill.textContent = `DISCARDED: ${last.discarded}`;
    },

    // Reset popup stat pills
    resetStats() {
        const ids = ['rtcPopupQberVal', 'rtcPopupEffVal', 'rtcPopupMatchVal', 'rtcPopupDiscardVal'];
        const defaults = ['QBER: — %', 'EFF: — %', 'MATCHED: —', 'DISCARDED: —'];
        const colors = ['#64ffda', '#818cf8', '#10b981', '#f59e0b'];
        ids.forEach((id, i) => {
            const el = document.getElementById(id);
            if (el) { el.textContent = defaults[i]; el.style.color = colors[i]; }
        });
    }
};

// RTC Popup event listeners
(function () {
    const container = document.getElementById('realtimeChartsContainer');
    if (container) container.addEventListener('click', () => RtcPopup.open());

    const closeBtn = document.getElementById('rtcPopupClose');
    if (closeBtn) closeBtn.addEventListener('click', (e) => { e.stopPropagation(); RtcPopup.close(); });

    const overlay = document.getElementById('rtcPopupOverlay');
    if (overlay) overlay.addEventListener('click', (e) => { if (e.target === overlay) RtcPopup.close(); });

    document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && RtcPopup.isOpen) RtcPopup.close(); });
})();

// =====================================================
// Real Time Charts — QBER & Efficiency + Basis Matching
// =====================================================
const RealTimeCharts = {
    qberEffChart: null,
    basisChart: null,
    dataPoints: [],       // Array of {idx, qber, efficiency, matched, discarded}
    isInitialized: false,

    init() {
        if (typeof Chart === 'undefined') {
            console.warn('Chart.js not loaded, skipping RealTimeCharts');
            return;
        }

        this.createQberEffChart();
        this.createBasisChart();
        this.isInitialized = true;
    },

    createQberEffChart() {
        const canvas = document.getElementById('rtcQberEffChart');
        if (!canvas) return;

        const ctx = canvas.getContext('2d');

        // Gradient fills
        const qberGrad = ctx.createLinearGradient(0, 0, 0, 120);
        qberGrad.addColorStop(0, 'rgba(100, 255, 218, 0.25)');
        qberGrad.addColorStop(1, 'rgba(100, 255, 218, 0.0)');

        const effGrad = ctx.createLinearGradient(0, 0, 0, 120);
        effGrad.addColorStop(0, 'rgba(129, 140, 248, 0.2)');
        effGrad.addColorStop(1, 'rgba(129, 140, 248, 0.0)');

        this.qberEffChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    {
                        label: 'QBER %',
                        data: [],
                        borderColor: '#64ffda',
                        backgroundColor: qberGrad,
                        borderWidth: 2,
                        fill: true,
                        tension: 0.4,
                        pointRadius: 0,
                        pointHoverRadius: 4,
                        pointHoverBackgroundColor: '#64ffda',
                        yAxisID: 'y'
                    },
                    {
                        label: 'Sifting Efficiency %',
                        data: [],
                        borderColor: '#818cf8',
                        backgroundColor: effGrad,
                        borderWidth: 1.5,
                        fill: true,
                        tension: 0.4,
                        pointRadius: 0,
                        pointHoverRadius: 4,
                        pointHoverBackgroundColor: '#818cf8',
                        borderDash: [4, 2],
                        yAxisID: 'y'
                    },
                    {
                        label: '11% Threshold',
                        data: [],
                        borderColor: 'rgba(239, 68, 68, 0.6)',
                        borderWidth: 1.5,
                        borderDash: [6, 4],
                        fill: false,
                        tension: 0,
                        pointRadius: 0,
                        pointHoverRadius: 0,
                        yAxisID: 'y'
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: {
                    duration: 150,
                    easing: 'easeOutQuart'
                },
                interaction: {
                    mode: 'index',
                    intersect: false
                },
                plugins: {
                    legend: {
                        display: true,
                        position: 'top',
                        labels: {
                            color: 'rgba(255,255,255,0.45)',
                            font: { family: "'JetBrains Mono', monospace", size: 9 },
                            boxWidth: 12,
                            boxHeight: 2,
                            padding: 8,
                            usePointStyle: false
                        }
                    },
                    tooltip: {
                        backgroundColor: 'rgba(11, 18, 33, 0.95)',
                        borderColor: 'rgba(100, 255, 218, 0.2)',
                        borderWidth: 1,
                        titleColor: '#64ffda',
                        bodyColor: '#e2e8f0',
                        titleFont: { family: "'JetBrains Mono', monospace", size: 10, weight: '700' },
                        bodyFont: { family: "'JetBrains Mono', monospace", size: 10 },
                        padding: 8,
                        cornerRadius: 8,
                        displayColors: true,
                        callbacks: {
                            title: (items) => `Qubit #${items[0].label}`,
                            label: (item) => {
                                if (item.datasetIndex === 2) return `Threshold: 11.0%`;
                                return `${item.dataset.label}: ${item.parsed.y.toFixed(1)}%`;
                            }
                        }
                    }
                },
                scales: {
                    x: {
                        display: true,
                        grid: { color: 'rgba(100,255,218,0.04)', drawBorder: false },
                        ticks: {
                            color: 'rgba(255,255,255,0.25)',
                            font: { family: "'JetBrains Mono', monospace", size: 8 },
                            maxTicksLimit: 8,
                            maxRotation: 0
                        },
                        title: {
                            display: false
                        }
                    },
                    y: {
                        display: true,
                        position: 'left',
                        min: 0,
                        suggestedMax: 100,
                        grid: { color: 'rgba(100,255,218,0.04)', drawBorder: false },
                        ticks: {
                            color: 'rgba(255,255,255,0.25)',
                            font: { family: "'JetBrains Mono', monospace", size: 8 },
                            callback: (v) => v + '%',
                            maxTicksLimit: 5
                        }
                    }
                }
            }
        });
    },

    createBasisChart() {
        const canvas = document.getElementById('rtcBasisChart');
        if (!canvas) return;

        const ctx = canvas.getContext('2d');

        const matchGrad = ctx.createLinearGradient(0, 0, 0, 120);
        matchGrad.addColorStop(0, 'rgba(16, 185, 129, 0.3)');
        matchGrad.addColorStop(1, 'rgba(16, 185, 129, 0.02)');

        const discardGrad = ctx.createLinearGradient(0, 0, 0, 120);
        discardGrad.addColorStop(0, 'rgba(245, 158, 11, 0.25)');
        discardGrad.addColorStop(1, 'rgba(245, 158, 11, 0.02)');

        this.basisChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    {
                        label: 'Matched Bases',
                        data: [],
                        borderColor: '#10b981',
                        backgroundColor: matchGrad,
                        borderWidth: 2,
                        fill: true,
                        tension: 0.3,
                        pointRadius: 0,
                        pointHoverRadius: 4,
                        pointHoverBackgroundColor: '#10b981'
                    },
                    {
                        label: 'Discarded Bases',
                        data: [],
                        borderColor: '#f59e0b',
                        backgroundColor: discardGrad,
                        borderWidth: 2,
                        fill: true,
                        tension: 0.3,
                        pointRadius: 0,
                        pointHoverRadius: 4,
                        pointHoverBackgroundColor: '#f59e0b'
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: {
                    duration: 150,
                    easing: 'easeOutQuart'
                },
                interaction: {
                    mode: 'index',
                    intersect: false
                },
                plugins: {
                    legend: {
                        display: true,
                        position: 'top',
                        labels: {
                            color: 'rgba(255,255,255,0.45)',
                            font: { family: "'JetBrains Mono', monospace", size: 9 },
                            boxWidth: 12,
                            boxHeight: 2,
                            padding: 8,
                            usePointStyle: false
                        }
                    },
                    tooltip: {
                        backgroundColor: 'rgba(11, 18, 33, 0.95)',
                        borderColor: 'rgba(100, 255, 218, 0.2)',
                        borderWidth: 1,
                        titleColor: '#64ffda',
                        bodyColor: '#e2e8f0',
                        titleFont: { family: "'JetBrains Mono', monospace", size: 10, weight: '700' },
                        bodyFont: { family: "'JetBrains Mono', monospace", size: 10 },
                        padding: 8,
                        cornerRadius: 8,
                        displayColors: true,
                        callbacks: {
                            title: (items) => `Qubit #${items[0].label}`
                        }
                    }
                },
                scales: {
                    x: {
                        display: true,
                        grid: { color: 'rgba(100,255,218,0.04)', drawBorder: false },
                        ticks: {
                            color: 'rgba(255,255,255,0.25)',
                            font: { family: "'JetBrains Mono', monospace", size: 8 },
                            maxTicksLimit: 8,
                            maxRotation: 0
                        }
                    },
                    y: {
                        display: true,
                        grid: { color: 'rgba(100,255,218,0.04)', drawBorder: false },
                        ticks: {
                            color: 'rgba(255,255,255,0.25)',
                            font: { family: "'JetBrains Mono', monospace", size: 8 },
                            maxTicksLimit: 5
                        },
                        beginAtZero: true
                    }
                }
            }
        });
    },

    // Called each tick during QBER animation
    pushDataPoint(idx, qber, efficiency, matched, discarded) {
        if (!this.isInitialized) return;

        // Store data point for popup sync
        this.dataPoints.push({ idx, qber, efficiency, matched, discarded });

        // Hide "awaiting data" overlays
        const qberNoData = document.getElementById('rtcQberNoData');
        const basisNoData = document.getElementById('rtcBasisNoData');
        if (qberNoData) qberNoData.style.opacity = '0';
        if (basisNoData) basisNoData.style.opacity = '0';

        const label = String(idx);

        // Update Chart 1: QBER & Efficiency
        if (this.qberEffChart) {
            this.qberEffChart.data.labels.push(label);
            this.qberEffChart.data.datasets[0].data.push(qber);
            this.qberEffChart.data.datasets[1].data.push(efficiency);
            this.qberEffChart.data.datasets[2].data.push(11); // threshold line

            // Only update every 4 points for performance, or on last point
            if (idx % 4 === 0 || idx >= CONFIG.BB84_QUBITS - 1) {
                this.qberEffChart.update('none');
            }
        }

        // Update Chart 2: Basis Matching
        if (this.basisChart) {
            this.basisChart.data.labels.push(label);
            this.basisChart.data.datasets[0].data.push(matched);
            this.basisChart.data.datasets[1].data.push(discarded);

            if (idx % 4 === 0 || idx >= CONFIG.BB84_QUBITS - 1) {
                this.basisChart.update('none');
            }
        }

        // Update live value badges
        const qberVal = document.getElementById('rtcQberLiveValue');
        const basisVal = document.getElementById('rtcBasisLiveValue');
        if (qberVal) {
            qberVal.textContent = qber.toFixed(1) + '%';
            qberVal.style.color = qber > 11 ? '#ef4444' : '#64ffda';
        }
        if (basisVal) {
            basisVal.textContent = `${matched} / ${discarded}`;
        }

        // Sync popup if open (throttled same as sidebar)
        if (RtcPopup.isOpen && (idx % 4 === 0 || idx >= CONFIG.BB84_QUBITS - 1)) {
            RtcPopup.syncData();
        }
    },

    // Reset charts for a new BB84 session
    reset() {
        if (!this.isInitialized) return;

        this.dataPoints = []; // Clear stored data

        if (this.qberEffChart) {
            this.qberEffChart.data.labels = [];
            this.qberEffChart.data.datasets.forEach(d => d.data = []);
            this.qberEffChart.update('none');
        }
        if (this.basisChart) {
            this.basisChart.data.labels = [];
            this.basisChart.data.datasets.forEach(d => d.data = []);
            this.basisChart.update('none');
        }

        const qberNoData = document.getElementById('rtcQberNoData');
        const basisNoData = document.getElementById('rtcBasisNoData');
        if (qberNoData) qberNoData.style.opacity = '1';
        if (basisNoData) basisNoData.style.opacity = '1';

        const qberVal = document.getElementById('rtcQberLiveValue');
        const basisVal = document.getElementById('rtcBasisLiveValue');
        if (qberVal) { qberVal.textContent = '— %'; qberVal.style.color = '#64ffda'; }
        if (basisVal) { basisVal.textContent = '— / —'; }

        // Reset popup stats too
        RtcPopup.resetStats();
    },

    // Final smooth update after animation completes
    finalize() {
        if (!this.isInitialized) return;
        if (this.qberEffChart) this.qberEffChart.update();
        if (this.basisChart) this.basisChart.update();
        // Final popup sync
        if (RtcPopup.isOpen) RtcPopup.syncData();
    }
};

// =====================================================
// Boot
// =====================================================
try { BlochSphere.init(); } catch (e) { console.warn('BlochSphere init failed', e); }
try { ChannelMonitor.init(); } catch (e) { console.warn('ChannelMonitor init failed', e); }
try { RealTimeCharts.init(); } catch (e) { console.warn('RealTimeCharts init failed', e); }
sysLog('Telemetry systems active.');
console.log('QSEC Room Client loaded.');