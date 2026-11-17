// tails1154 account: sign-in, session storage and an end-to-end encrypted vault.
//
// The vault is encrypted in the browser with AES-GCM. Its key is derived from the
// account password with PBKDF2. The server only ever stores the ciphertext, so it
// cannot read the synced data. Note: the password is sent to the server during
// sign-in (it is forwarded to the account CGI), so the server sees it at that moment.
//
// Site cookies from the browser are NOT synced: they are live logins, and the
// browser keeps them in its own profile. Only the OS settings listed in
// SYNC_SETTINGS are stored in the vault.
//
// Auto sync: when signed in and "account-autosync" is on, changes to the synced
// settings are pushed (debounced). On boot the vault is pulled if it is newer than
// the last sync on this device.

const VAULT_KEY = "nura_vault";
const PBKDF2_ITERATIONS = 310000;
const MAX_VAULT_BYTES = 10240;
const AUTOSYNC_DELAY_MS = 2000;
const SYNC_SETTINGS = [
	"sir-yes-sir",
	"blur-disable",
	"disable-animation",
	"launcher-keybind",
	"applist",
];

const enc = new TextEncoder();
const dec = new TextDecoder();

let applyingRemote = false;
let autoSyncTimer: number | undefined;

const idb = () => (window as any).idbKeyval;

function toB64(bytes: Uint8Array): string {
	let s = "";
	for (const b of bytes) s += String.fromCharCode(b);
	return btoa(s);
}

function fromB64(text: string): Uint8Array {
	return Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
}

async function deriveKey(
	password: string,
	salt: Uint8Array,
): Promise<CryptoKey> {
	const base = await crypto.subtle.importKey(
		"raw",
		enc.encode(password),
		"PBKDF2",
		false,
		["deriveKey"],
	);
	return crypto.subtle.deriveKey(
		{
			name: "PBKDF2",
			salt: salt as any,
			iterations: PBKDF2_ITERATIONS,
			hash: "SHA-256",
		},
		base,
		{ name: "AES-GCM", length: 256 },
		true,
		["encrypt", "decrypt"],
	);
}

async function importDeviceKey(rawB64: string): Promise<CryptoKey> {
	return crypto.subtle.importKey(
		"raw",
		fromB64(rawB64) as any,
		{ name: "AES-GCM" },
		true,
		["encrypt", "decrypt"],
	);
}

async function encryptVault(key: CryptoKey, salt: Uint8Array, data: unknown) {
	const iv = crypto.getRandomValues(new Uint8Array(12));
	const ct = await crypto.subtle.encrypt(
		{ name: "AES-GCM", iv: iv as any },
		key,
		enc.encode(JSON.stringify(data)) as any,
	);
	return JSON.stringify({
		v: 1,
		salt: toB64(salt),
		iv: toB64(iv),
		ct: toB64(new Uint8Array(ct)),
	});
}

async function decryptVault(key: CryptoKey, envelope: string) {
	const env = JSON.parse(envelope);
	const pt = await crypto.subtle.decrypt(
		{ name: "AES-GCM", iv: fromB64(env.iv) as any },
		key,
		fromB64(env.ct) as any,
	);
	return JSON.parse(dec.decode(pt));
}

type AccountSession = { username: string; auth: string };

async function getSession(): Promise<AccountSession | null> {
	try {
		return (await idb().get("account-session")) ?? null;
	} catch {
		return null;
	}
}

// Apply settings from a decrypted vault. Change events from these writes are
// ignored, so restoring does not push the same values straight back.
async function applyRemote(remote: any) {
	applyingRemote = true;
	try {
		for (const name of SYNC_SETTINGS) {
			if (remote.settings && name in remote.settings) {
				await anura.settings.set(name, remote.settings[name]);
			}
		}
		await idb().set("account-lastsync", remote.updatedAt ?? 0);
	} finally {
		applyingRemote = false;
	}
}

// Sign in, then either pull the existing vault or create a new one.
async function signIn(username: string, password: string) {
	const loginRes = await fetch("/api/account/login", {
		method: "POST",
		headers: { "content-type": "application/json" },
		body: JSON.stringify({ username, password }),
	});
	const login = await loginRes.json();
	if (!loginRes.ok || !login.ok) {
		throw new Error(login.error || "Sign-in failed");
	}
	const auth: string = login.auth;

	const getRes = await fetch(`/api/account/get?key=${VAULT_KEY}`, {
		headers: { "x-account-auth": auth },
	});
	const got = await getRes.json();

	let key: CryptoKey;
	let salt: Uint8Array;
	let remote: any = null;
	if (got.ok && got.value) {
		salt = fromB64(JSON.parse(got.value).salt);
		key = await deriveKey(password, salt);
		try {
			remote = await decryptVault(key, got.value);
		} catch {
			throw new Error("Your synced data uses a different password");
		}
	} else {
		salt = crypto.getRandomValues(new Uint8Array(16));
		key = await deriveKey(password, salt);
	}

	const raw = new Uint8Array(await crypto.subtle.exportKey("raw", key));
	await idb().set("account-session", { username: login.username, auth });
	await idb().set("account-key", toB64(raw));
	await idb().set("account-salt", toB64(salt));
	if (anura.settings.get("account-autosync") === undefined) {
		await anura.settings.set("account-autosync", true);
	}

	if (remote) {
		await applyRemote(remote);
	} else {
		await syncNow();
	}
	return { username: login.username };
}

// Encrypt the synced settings with the device key and upload the ciphertext.
async function syncNow() {
	const session = await getSession();
	if (!session) throw new Error("Not signed in");
	const rawKey = await idb().get("account-key");
	const saltB64 = await idb().get("account-salt");
	if (!rawKey || !saltB64) {
		throw new Error("Account key missing, sign in again");
	}

	const key = await importDeviceKey(rawKey);
	const settings: Record<string, unknown> = {};
	for (const name of SYNC_SETTINGS) settings[name] = anura.settings.get(name);

	const updatedAt = Date.now();
	const envelope = await encryptVault(key, fromB64(saltB64), {
		v: 1,
		updatedAt,
		settings,
	});
	if (enc.encode(envelope).length > MAX_VAULT_BYTES) {
		throw new Error("Synced data is larger than 10 KB");
	}

	const res = await fetch("/api/account/save", {
		method: "POST",
		headers: {
			"content-type": "application/json",
			"x-account-auth": session.auth,
		},
		body: JSON.stringify({ key: VAULT_KEY, value: envelope }),
	});
	const data = await res.json();
	if (!res.ok || !data.ok) throw new Error(data.error || "Sync failed");
	await idb().set("account-lastsync", updatedAt);
	return { updatedAt };
}

// Pull the vault when the server copy is newer than this device's last sync.
async function restoreNow() {
	const session = await getSession();
	if (!session) return { restored: false };
	const rawKey = await idb().get("account-key");
	if (!rawKey) return { restored: false };

	const res = await fetch(`/api/account/get?key=${VAULT_KEY}`, {
		headers: { "x-account-auth": session.auth },
	});
	const got = await res.json();
	if (!got.ok) {
		if (res.status === 401) {
			throw new Error("Your tails1154 session expired. Sign in again to sync.");
		}
		return { restored: false };
	}
	if (!got.value) return { restored: false };

	const key = await importDeviceKey(rawKey);
	const remote = await decryptVault(key, got.value);
	const lastSync = (await idb().get("account-lastsync")) ?? 0;
	if ((remote.updatedAt ?? 0) > lastSync) {
		await applyRemote(remote);
		return { restored: true };
	}
	return { restored: false };
}

// Forget the session and the device key. Synced data on the server is kept.
async function signOut() {
	await idb().del("account-session");
	await idb().del("account-key");
	await idb().del("account-salt");
	await idb().del("account-lastsync");
}

async function autoSync() {
	if (applyingRemote) return;
	if (anura.settings.get("account-autosync") !== true) return;
	if (!(await getSession())) return;
	try {
		await syncNow();
	} catch (e) {
		console.warn("Auto sync failed", e);
	}
}

// Debounce changes to synced settings into one upload.
document.addEventListener("anura-settings-changed", (event: Event) => {
	const prop = (event as CustomEvent).detail?.prop;
	if (!SYNC_SETTINGS.includes(prop)) return;
	window.clearTimeout(autoSyncTimer);
	autoSyncTimer = window.setTimeout(autoSync, AUTOSYNC_DELAY_MS);
});

// On boot, pull newer settings from the account.
document.addEventListener("anura-login-completed", async () => {
	if (anura.settings.get("account-autosync") !== true) return;
	try {
		await restoreNow();
	} catch (e: any) {
		console.warn("Account restore failed", e);
		anura.notifications.add({
			title: "Account sync",
			description: e?.message || String(e),
			timeout: 8000,
		});
	}
});

// Create an account on the tails1154 server, then sign in with it.
async function register(username: string, password: string) {
	const res = await fetch("/api/account/register", {
		method: "POST",
		headers: { "content-type": "application/json" },
		body: JSON.stringify({ username, password }),
	});
	const data = await res.json();
	if (!res.ok || !data.ok) {
		throw new Error(data.error || "Registration failed");
	}
	return signIn(username, password);
}

(window as any).nuraAccount = {
	register,
	getSession,
	signIn,
	syncNow,
	restoreNow,
	signOut,
};
