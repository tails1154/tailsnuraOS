// Proxy for the tails1154 account CGI endpoints (loginext / loggedin / saveext / getext).
//
// The OS talks to this server only. The server forwards each request to the
// account CGI and passes the `auth` cookie along, so the browser never needs
// cross-site cookies or CORS access to tails1154.com.

import express from "express";

const ACCOUNT_BASE = (
	process.env.ACCOUNT_BASE || "https://tails1154.com:9782/cgi-bin"
).replace(/\/+$/, "");
const TIMEOUT_MS = 15000;
const MAX_VALUE_BYTES = 10240;

export const accountRouter = express.Router();
accountRouter.use(express.json({ limit: "16kb" }));

function upstream(
	path,
	{ method = "GET", auth, body, timeoutMs = TIMEOUT_MS } = {},
) {
	const headers = {};
	if (auth) headers.cookie = `auth=${auth}`;
	if (body) headers["content-type"] = "application/x-www-form-urlencoded";
	return fetch(`${ACCOUNT_BASE}/${path}`, {
		method,
		headers,
		body: body ? new URLSearchParams(body) : undefined,
		signal: AbortSignal.timeout(timeoutMs),
	});
}

async function text(res) {
	return (await res.text()).trim();
}

function authFromRequest(req) {
	const header = req.get("x-account-auth") || "";
	// Only accept the cookie value characters the CGI sets (hex hash).
	return /^[A-Za-z0-9]{1,256}$/.test(header) ? header : null;
}

// Sign in. Returns the `auth` cookie value the OS keeps for later calls.
accountRouter.post("/login", async (req, res) => {
	const username = String(req.body?.username ?? "");
	const password = String(req.body?.password ?? "");
	if (!username || !password) {
		return res
			.status(400)
			.json({ ok: false, error: "Username and password are required" });
	}
	try {
		const upstreamRes = await upstream("loginext.py", {
			method: "POST",
			body: { username, password },
		});
		const body = await text(upstreamRes);
		if (body !== "OK") {
			return res
				.status(401)
				.json({ ok: false, error: "Wrong username or password" });
		}
		const setCookie = upstreamRes.headers
			.getSetCookie()
			.find((c) => c.startsWith("auth="));
		const auth = setCookie?.match(/^auth=([^;]+)/)?.[1];
		if (!auth) {
			return res
				.status(502)
				.json({ ok: false, error: "Account server did not return a session" });
		}
		res.json({ ok: true, username, auth });
	} catch (err) {
		res
			.status(502)
			.json({ ok: false, error: `Account server unreachable: ${err.message}` });
	}
});

// Is this auth cookie still valid?
accountRouter.get("/loggedin", async (req, res) => {
	const auth = authFromRequest(req);
	if (!auth) return res.json({ loggedIn: false });
	try {
		const body = await text(await upstream("loggedin.py", { auth }));
		res.json({ loggedIn: body === "YES" });
	} catch (err) {
		res.status(502).json({ error: err.message });
	}
});

// Read a value stored on the account.
accountRouter.get("/get", async (req, res) => {
	const auth = authFromRequest(req);
	const key = String(req.query.key || "");
	if (!auth) return res.status(401).json({ ok: false, error: "Not signed in" });
	if (!key)
		return res.status(400).json({ ok: false, error: "key is required" });
	try {
		const body = await text(
			await upstream(`getext.py?key=${encodeURIComponent(key)}`, { auth }),
		);
		if (body === "ERR")
			return res.status(401).json({ ok: false, error: "Not signed in" });
		res.json({ ok: true, key, value: body });
	} catch (err) {
		res.status(502).json({ ok: false, error: err.message });
	}
});

// Store a value on the account (max 10 KB, same cap the CGI enforces).
accountRouter.post("/save", async (req, res) => {
	const auth = authFromRequest(req);
	const key = String(req.body?.key ?? "");
	const value = req.body?.value;
	if (!auth) return res.status(401).json({ ok: false, error: "Not signed in" });
	if (!key || typeof value !== "string") {
		return res
			.status(400)
			.json({ ok: false, error: "Body must be { key, value }" });
	}
	if (Buffer.byteLength(value, "utf8") > MAX_VALUE_BYTES) {
		return res
			.status(413)
			.json({ ok: false, error: "Value is larger than 10 KB" });
	}
	try {
		const body = await text(
			await upstream("saveext.py", {
				method: "POST",
				auth,
				body: { key, value },
			}),
		);
		if (body !== "OK")
			return res.status(401).json({ ok: false, error: "Not signed in" });
		res.json({ ok: true, key });
	} catch (err) {
		res.status(502).json({ ok: false, error: err.message });
	}
});

// Create an account. The account CGI creates it immediately for the hidden
// default ID (444444), the same as the site's register page does.
accountRouter.post("/register", async (req, res) => {
	const username = String(req.body?.username ?? "").trim();
	const password = String(req.body?.password ?? "");
	if (!username || !password) {
		return res
			.status(400)
			.json({ ok: false, error: "Username and password are required" });
	}
	try {
		const body = await text(
			await upstream("register.py", {
				method: "POST",
				body: { username, password, email: "444444" },
				timeoutMs: 60000,
			}),
		);
		if (body.includes("Account created")) {
			return res.json({ ok: true, username });
		}
		const message = body
			.replace(/<[^>]+>/g, " ")
			.replace(/\s+/g, " ")
			.trim();
		res
			.status(400)
			.json({ ok: false, error: message || "Registration failed" });
	} catch (err) {
		res
			.status(502)
			.json({ ok: false, error: `Account server unreachable: ${err.message}` });
	}
});
