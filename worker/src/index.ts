import { Container, getContainer } from "@cloudflare/containers";
import { Hono } from "hono";
import { importJWK, jwtVerify, type JWTPayload } from "jose";

export class PocketIDContainer extends Container<Env> {
	defaultPort = 1411;
	sleepAfter = "5s";
	enableInternet = true;

	private pendingRequests = 0;

	get envVars() {
		return {
			APP_ENV: "production",
			APP_URL: "https://authspot.net",
			INTERNAL_APP_URL: "http://localhost:1411",
			HOST: "0.0.0.0",
			PORT: "1411",
			DB_CONNECTION_STRING: "d1://",
			ENCRYPTION_KEY: this.env.ENCRYPTION_KEY,
			CF_EMAIL_ENABLED: "true",
		};
	}

	override async fetch(request: Request): Promise<Response> {
		this.pendingRequests++;
		try {
			return await super.fetch(request);
		} finally {
			this.pendingRequests--;
		}
	}

	override async alarm() {
		if (this.pendingRequests > 0) {
			try {
				await this.containerFetch("http://container/healthz");
			} catch {
				// ignore
			}
			await this.ctx.storage.setAlarm(Date.now() + 3000);
		}
	}

	override onStart() {
		console.log("Pocket ID container started");
	}

	override onStop() {
		console.log("Pocket ID container stopped");
	}

	override onError(error: unknown) {
		console.error("Pocket ID container error:", error);
	}
}

interface D1QueryRequest {
	sql: string;
	params?: unknown[];
}

interface D1BatchRequest {
	sql: string;
	params?: unknown[];
}

interface EmailRequest {
	to: string;
	toName?: string;
	from: string;
	fromName?: string;
	subject: string;
	html: string;
	text: string;
}

function normalizeSQL(sql: string): string {
	sql = sql.replace(
		/normalize\s*\(\s*("[^"]*"|'[^']*'|[\w.]+)\s*,\s*'[^']*'\s*\)/gi,
		"$1",
	);
	return sql;
}

function splitStatements(sql: string): string[] {
	const statements: string[] = [];
	let current = "";
	let inString = false;
	let stringChar = "";

	for (let i = 0; i < sql.length; i++) {
		const ch = sql[i];

		if (inString) {
			current += ch;
			if (ch === stringChar && sql[i - 1] !== "\\") {
				inString = false;
			}
			continue;
		}

		if (ch === "'" || ch === '"') {
			inString = true;
			stringChar = ch;
			current += ch;
			continue;
		}

		if (ch === ";") {
			const stmt = current.trim();
			if (stmt && !isTransactionStmt(stmt)) {
				statements.push(stmt);
			}
			current = "";
			continue;
		}

		current += ch;
	}

	const stmt = current.trim();
	if (stmt && !isTransactionStmt(stmt)) {
		statements.push(stmt);
	}

	return statements;
}

function isTransactionStmt(stmt: string): boolean {
	const upper = stmt.toUpperCase();
	return (
		upper === "BEGIN" ||
		upper === "BEGIN TRANSACTION" ||
		upper === "COMMIT" ||
		upper === "END" ||
		upper === "ROLLBACK"
	);
}

function normalizeParams(params: unknown[] | undefined): unknown[] {
	if (!params) return [];
	return params.map((p) => {
		if (p === undefined) return null;
		if (Buffer.isBuffer(p)) return Array.from(p);
		return p;
	});
}

// JWT verification cache
let cachedJWKS: { keys: object[]; expiresAt: number } | null = null;

const APP_URL = "https://authspot.net";

async function verifyAccessToken(token: string): Promise<{ sub: string; isAdmin: boolean } | null> {
	try {
		const { payload } = await jwtVerify(token, async (header) => {
			if (!cachedJWKS || Date.now() >= cachedJWKS.expiresAt) {
				const resp = await fetch(`${APP_URL}/.well-known/jwks.json`);
				if (!resp.ok) throw new Error(`JWKS fetch failed: ${resp.status}`);
				const data = (await resp.json()) as { keys: object[] };
				cachedJWKS = { keys: data.keys, expiresAt: Date.now() + 3600_000 };
			}
			const keyData = cachedJWKS.keys.find(
				(k: Record<string, unknown>) => k.kid === header.kid,
			);
			if (!keyData) throw new Error("Unknown kid");
			return await importJWK(keyData as jose.JWK, header.alg as string);
		}, {
			issuer: APP_URL,
			audience: APP_URL,
		});
		if (payload.type !== "access-token") return null;
		return {
			sub: payload.sub!,
			isAdmin: (payload as unknown as Record<string, unknown>).isAdmin === true,
		};
	} catch {
		return null;
	}
}

function extractAccessToken(request: Request): string | null {
	// Try cookie first
	const cookies = request.headers.get("Cookie") || "";
	for (const part of cookies.split(";")) {
		const [name, ...rest] = part.trim().split("=");
		if (
			(name === "__Host-access_token" || name === "access_token") &&
			rest.length > 0
		) {
			return rest.join("=");
		}
	}
	// Fallback to Authorization header
	const auth = request.headers.get("Authorization") || "";
	const spaceIdx = auth.indexOf(" ");
	if (spaceIdx > 0) return auth.slice(spaceIdx + 1);
	return null;
}

interface ListOptions {
	page: number;
	limit: number;
	sortColumn: string;
	sortDirection: string;
	search: string;
}

function parseListOptions(url: string): ListOptions {
	const u = new URL(url);
	return {
		page: Math.max(1, parseInt(u.searchParams.get("pagination[page]") || "1")),
		limit: Math.min(100, Math.max(1, parseInt(u.searchParams.get("pagination[limit]") || "20"))),
		sortColumn: u.searchParams.get("sort[column]") || "",
		sortDirection: (u.searchParams.get("sort[direction]") || "asc").toLowerCase() === "desc" ? "DESC" : "ASC",
		search: u.searchParams.get("search") || "",
	};
}

function paginatedResponse(data: unknown[], totalItems: number, opts: ListOptions) {
	return {
		data,
		pagination: {
			totalPages: Math.ceil(totalItems / opts.limit) || 1,
			totalItems,
			currentPage: opts.page,
			itemsPerPage: opts.limit,
		},
	};
}

const publicConfigKeys = new Set([
	"appName",
	"homePageUrl",
	"accentColor",
	"disableAnimations",
	"allowOwnAccountEdit",
	"allowUserSignups",
	"requireUserEmail",
	"emailOneTimeAccessAsUnauthenticatedEnabled",
	"emailOneTimeAccessAsAdminEnabled",
	"emailVerificationEnabled",
	"ldapEnabled",
]);

const app = new Hono<{
	Bindings: Env;
}>();

app.get("/healthz", async (c) => {
	try {
		await c.env.DB.prepare("SELECT 1").first();
		return c.json({ status: "ok" });
	} catch {
		return c.json({ status: "error", message: "D1 unavailable" }, 503);
	}
});

app.get("/api/application-configuration", async (c) => {
	try {
		const result = await c.env.DB.prepare(
			"SELECT key, value FROM app_config_variables",
		).all();
		const config = Object.fromEntries(
			result.results.map((r: Record<string, unknown>) => [r.key, r.value]),
		);
		const publicVars = Object.keys(config)
			.filter((key) => publicConfigKeys.has(key))
			.map((key) => ({
				key,
				type: "",
				value: config[key] ?? "",
			}));
		publicVars.push({ key: "uiConfigDisabled", type: "boolean", value: "false" });
		return c.json(publicVars);
	} catch {
		// Fall through to container on error
	}
});

app.get("/api/application-configuration/all", async (c) => {
	try {
		const result = await c.env.DB.prepare(
			"SELECT key, value FROM app_config_variables",
		).all();
		const rows = result.results as Record<string, unknown>[];
		return c.json(rows.map((r) => ({
			key: r.key,
			value: r.value ?? "",
			isPublic: publicConfigKeys.has(r.key as string),
		})));
	} catch {
		// Fall through to container on error
	}
});

app.get("/api/application-configuration/:key", async (c) => {
	try {
		const key = c.req.param("key");
		const result = await c.env.DB.prepare(
			"SELECT key, value FROM app_config_variables WHERE key = ?",
		).bind(key).all();
		if (result.results.length > 0) {
			const row = result.results[0] as Record<string, unknown>;
			return c.json({ key: row.key, type: "", value: row.value ?? "" });
		}
	} catch {
		// Fall through to container on error
	}
});

app.get("/api/version/latest", async (c) => {
	try {
		const resp = await fetch(
			"https://api.github.com/repos/pocket-id/pocket-id/releases/latest",
			{ headers: { "User-Agent": "pocket-id" } },
		);
		if (!resp.ok) throw new Error(`GitHub API returned ${resp.status}`);
		const payload = (await resp.json()) as { tag_name: string };
		const version = payload.tag_name.replace(/^v/, "");
		c.header("Cache-Control", "public, max-age=300, stale-while-revalidate=900");
		return c.json({ latestVersion: version });
	} catch {
		// Fall through to container on error
	}
});

app.get("/api/oidc/clients/:id/meta", async (c) => {
	try {
		const id = c.req.param("id");
		const result = await c.env.DB.prepare(
			"SELECT id, name, image_type, dark_image_type, launch_url, requires_reauthentication FROM oidc_clients WHERE id = ?",
		).bind(id).first();
		if (!result) {
			return c.json({ error: "OIDC client not found" }, 404);
		}
		const r = result as Record<string, unknown>;
		const imageType = (r.image_type as string) ?? "";
		const darkImageType = (r.dark_image_type as string) ?? "";
		return c.json({
			id: r.id,
			name: r.name ?? "",
			hasLogo: imageType !== "",
			hasDarkLogo: darkImageType !== "",
			launchURL: r.launch_url ?? null,
			requiresReauthentication: Boolean(r.requires_reauthentication),
		});
	} catch {
		// Fall through to container on error
	}
});

app.get("/api/users/me", async (c) => {
	try {
		const token = extractAccessToken(c.req.raw);
		if (!token) {
			return c.json({ error: "Not authenticated" }, 401);
		}
		const auth = await verifyAccessToken(token);
		if (!auth) {
			return c.json({ error: "Invalid token" }, 401);
		}
		const user = await c.env.DB.prepare(
			"SELECT id, username, email, first_name, last_name, display_name, is_admin, locale, disabled, email_verified FROM users WHERE id = ?",
		).bind(auth.sub).first();
		if (!user) {
			return c.json({ error: "User not found" }, 404);
		}
		const r = user as Record<string, unknown>;
		// Load user groups
		const groupsResult = await c.env.DB.prepare(
			`SELECT ug.id, ug.friendly_name, ug.name FROM user_groups ug
			 INNER JOIN user_groups_users ugu ON ug.id = ugu.user_group_id
			 WHERE ugu.user_id = ?`,
		).bind(auth.sub).all();
		const groups = (groupsResult.results as Record<string, unknown>[]).map((g) => ({
			id: g.id,
			friendlyName: g.friendly_name,
			name: g.name,
		}));
		// Load custom claims
		const claimsResult = await c.env.DB.prepare(
			"SELECT id, \"key\", value FROM custom_claims WHERE user_id = ?",
		).bind(auth.sub).all();
		const customClaims = (claimsResult.results as Record<string, unknown>[]).map((cc) => ({
			id: cc.id,
			key: cc.key,
			value: cc.value,
		}));
		return c.json({
			id: r.id,
			username: r.username,
			email: r.email,
			firstName: r.first_name,
			lastName: r.last_name,
			displayName: r.display_name,
			isAdmin: Boolean(r.is_admin),
			locale: r.locale ?? null,
			disabled: Boolean(r.disabled),
			emailVerified: r.email_verified,
			userGroups: groups,
			customClaims,
		});
	} catch {
		// Fall through to container on error
	}
});

app.get("/api/webauthn/credentials", async (c) => {
	try {
		const token = extractAccessToken(c.req.raw);
		if (!token) return c.json({ error: "Not authenticated" }, 401);
		const auth = await verifyAccessToken(token);
		if (!auth) return c.json({ error: "Invalid token" }, 401);
		const result = await c.env.DB.prepare(
			"SELECT id, name, credential_id, attestation_type, transport, backup_eligible, backup_state, created_at FROM webauthn_credentials WHERE user_id = ?",
		).bind(auth.sub).all();
		const credentials = (result.results as Record<string, unknown>[]).map((r) => ({
			id: r.id,
			name: r.name,
			credentialID: r.credential_id,
			attestationType: r.attestation_type,
			transport: r.transport,
			backupEligible: Boolean(r.backup_eligible),
			backupState: Boolean(r.backup_state),
			createdAt: r.created_at,
		}));
		return c.json(credentials);
	} catch {
		// Fall through to container on error
	}
});

app.get("/api/oidc/users/me/authorized-clients", async (c) => {
	try {
		const token = extractAccessToken(c.req.raw);
		if (!token) return c.json({ error: "Not authenticated" }, 401);
		const auth = await verifyAccessToken(token);
		if (!auth) return c.json({ error: "Invalid token" }, 401);
		const result = await c.env.DB.prepare(
			`SELECT uac.scope, uac.last_used_at, uac.client_id,
				oc.id as c_id, oc.name as c_name, oc.image_type, oc.dark_image_type,
				oc.launch_url, oc.requires_reauthentication
				FROM user_authorized_oidc_clients uac
				INNER JOIN oidc_clients oc ON uac.client_id = oc.id
				WHERE uac.user_id = ?
				ORDER BY uac.last_used_at DESC`,
		).bind(auth.sub).all();
		const clients = (result.results as Record<string, unknown>[]).map((r) => ({
			scope: r.scope ?? "",
			client: {
				id: r.c_id,
				name: r.c_name ?? "",
				hasLogo: (r.image_type as string) !== "",
				hasDarkLogo: (r.dark_image_type as string) !== "",
				launchURL: r.launch_url ?? null,
				requiresReauthentication: Boolean(r.requires_reauthentication),
			},
			lastUsedAt: r.last_used_at,
		}));
		return c.json({
			data: clients,
			pagination: {
				totalPages: 1,
				totalItems: clients.length,
				currentPage: 1,
				itemsPerPage: 100,
			},
		});
	} catch {
		// Fall through to container on error
	}
});

app.get("/api/api-keys", async (c) => {
	try {
		const token = extractAccessToken(c.req.raw);
		if (!token) return c.json({ error: "Not authenticated" }, 401);
		const auth = await verifyAccessToken(token);
		if (!auth) return c.json({ error: "Invalid token" }, 401);
		const result = await c.env.DB.prepare(
			"SELECT id, name, description, expires_at, last_used_at, created_at FROM api_keys WHERE user_id = ? ORDER BY created_at DESC",
		).bind(auth.sub).all();
		const keys = (result.results as Record<string, unknown>[]).map((r) => ({
			id: r.id,
			name: r.name,
			description: r.description ?? null,
			expiresAt: r.expires_at,
			lastUsedAt: r.last_used_at ?? null,
			createdAt: r.created_at,
		}));
		return c.json({
			data: keys,
			pagination: {
				totalPages: 1,
				totalItems: keys.length,
				currentPage: 1,
				itemsPerPage: 100,
			},
		});
	} catch {
		// Fall through to container on error
	}
});

// Simple no-auth endpoints
app.get("/api/signup/setup", async (c) => {
	try {
		const result = await c.env.DB.prepare(
			"SELECT COUNT(*) as cnt FROM users WHERE id != 'static-api-key-user'",
		).first();
		const count = (result as Record<string, unknown>)?.cnt as number;
		return c.json({ completed: count > 0 });
	} catch {
		// Fall through to container on error
	}
});

app.get("/api/custom-claims/suggestions", async (c) => {
	try {
		const token = extractAccessToken(c.req.raw);
		if (!token) return c.json({ error: "Not authenticated" }, 401);
		const auth = await verifyAccessToken(token);
		if (!auth || !auth.isAdmin) return c.json({ error: "Forbidden" }, 403);
		const result = await c.env.DB.prepare(
			"SELECT \"key\", COUNT(*) as count FROM custom_claims GROUP BY \"key\" ORDER BY count DESC",
		).all();
		const suggestions = (result.results as Record<string, unknown>[]).map((r) => ({
			key: r.key,
			count: Number(r.count),
		}));
		return c.json(suggestions);
	} catch {
		// Fall through to container on error
	}
});

app.get("/api/audit-logs/filters/users", async (c) => {
	try {
		const token = extractAccessToken(c.req.raw);
		if (!token) return c.json({ error: "Not authenticated" }, 401);
		const auth = await verifyAccessToken(token);
		if (!auth || !auth.isAdmin) return c.json({ error: "Forbidden" }, 403);
		const result = await c.env.DB.prepare(
			`SELECT DISTINCT u.id, u.username FROM users u
			 INNER JOIN audit_logs al ON u.id = al.user_id
			 ORDER BY u.username`,
		).all();
		return c.json((result.results as Record<string, unknown>[]).map((r) => ({
			id: r.id,
			username: r.username,
		})));
	} catch {
		// Fall through to container on error
	}
});

app.get("/api/audit-logs/filters/client-names", async (c) => {
	try {
		const token = extractAccessToken(c.req.raw);
		if (!token) return c.json({ error: "Not authenticated" }, 401);
		const auth = await verifyAccessToken(token);
		if (!auth || !auth.isAdmin) return c.json({ error: "Forbidden" }, 403);
		const result = await c.env.DB.prepare(
			"SELECT DISTINCT json_extract(data, '$.clientName') as name FROM audit_logs WHERE json_extract(data, '$.clientName') IS NOT NULL ORDER BY name",
		).all();
		return c.json((result.results as Record<string, unknown>[]).map((r) => r.name));
	} catch {
		// Fall through to container on error
	}
});

// Paginated admin endpoints
app.get("/api/users", async (c) => {
	try {
		const token = extractAccessToken(c.req.raw);
		if (!token) return c.json({ error: "Not authenticated" }, 401);
		const auth = await verifyAccessToken(token);
		if (!auth || !auth.isAdmin) return c.json({ error: "Forbidden" }, 403);
		const opts = parseListOptions(c.req.url);
		const offset = (opts.page - 1) * opts.limit;
		const where = opts.search
			? `WHERE (u.username LIKE ? OR u.email LIKE ? OR u.first_name LIKE ? OR u.last_name LIKE ?)`
			: "";
		const searchParam = opts.search ? `%${opts.search}%` : "";
		const countResult = await c.env.DB.prepare(
			`SELECT COUNT(*) as cnt FROM users u ${where}`,
		).bind(...(opts.search ? [searchParam, searchParam, searchParam, searchParam] : [])).first();
		const totalItems = (countResult as Record<string, unknown>)?.cnt as number;
		const sortCol = ["username", "email", "first_name", "last_name", "created_at", "is_admin", "disabled"].includes(opts.sortColumn)
			? `u.${opts.sortColumn}` : "u.username";
		const result = await c.env.DB.prepare(
			`SELECT u.id, u.username, u.email, u.first_name, u.last_name, u.display_name, u.is_admin, u.locale, u.disabled, u.email_verified, u.created_at
			 FROM users u ${where}
			 ORDER BY ${sortCol} ${opts.sortDirection}
			 LIMIT ? OFFSET ?`,
		).bind(...(opts.search ? [searchParam, searchParam, searchParam, searchParam] : []), opts.limit, offset).all();
		const users = (result.results as Record<string, unknown>[]).map((r) => ({
			id: r.id,
			username: r.username,
			email: r.email ?? null,
			firstName: r.first_name,
			lastName: r.last_name,
			displayName: r.display_name,
			isAdmin: Boolean(r.is_admin),
			locale: r.locale ?? null,
			disabled: Boolean(r.disabled),
			emailVerified: r.email_verified,
			createdAt: r.created_at,
		}));
		return c.json(paginatedResponse(users, totalItems, opts));
	} catch {
		// Fall through to container on error
	}
});

app.get("/api/user-groups", async (c) => {
	try {
		const token = extractAccessToken(c.req.raw);
		if (!token) return c.json({ error: "Not authenticated" }, 401);
		const auth = await verifyAccessToken(token);
		if (!auth || !auth.isAdmin) return c.json({ error: "Forbidden" }, 403);
		const opts = parseListOptions(c.req.url);
		const offset = (opts.page - 1) * opts.limit;
		const where = opts.search
			? `WHERE (ug.name LIKE ? OR ug.friendly_name LIKE ?)`
			: "";
		const searchParam = opts.search ? `%${opts.search}%` : [];
		const countResult = await c.env.DB.prepare(
			`SELECT COUNT(*) as cnt FROM user_groups ug ${where}`,
		).bind(...(opts.search ? [searchParam, searchParam] : [])).first();
		const totalItems = (countResult as Record<string, unknown>)?.cnt as number;
		const sortCol = ["name", "friendly_name", "created_at"].includes(opts.sortColumn)
			? `ug.${opts.sortColumn}` : "ug.friendly_name";
		const result = await c.env.DB.prepare(
			`SELECT ug.id, ug.name, ug.friendly_name, ug.created_at
			 FROM user_groups ug ${where}
			 ORDER BY ${sortCol} ${opts.sortDirection}
			 LIMIT ? OFFSET ?`,
		).bind(...(opts.search ? [searchParam, searchParam] : []), opts.limit, offset).all();
		const groupIds = (result.results as Record<string, unknown>[]).map((r) => r.id as string);
		// Get user counts for each group
		const groups = await Promise.all(groupIds.map(async (id) => {
			const row = result.results.find((r) => (r as Record<string, unknown>).id === id) as Record<string, unknown>;
			const countR = await c.env.DB.prepare(
				"SELECT COUNT(*) as cnt FROM user_groups_users WHERE user_group_id = ?",
			).bind(id).first();
			return {
				id: row.id,
				name: row.name,
				friendlyName: row.friendly_name,
				createdAt: row.created_at,
				userCount: Number((countR as Record<string, unknown>)?.cnt ?? 0),
			};
		}));
		return c.json(paginatedResponse(groups, totalItems, opts));
	} catch {
		// Fall through to container on error
	}
});

app.get("/api/oidc/clients", async (c) => {
	try {
		const token = extractAccessToken(c.req.raw);
		if (!token) return c.json({ error: "Not authenticated" }, 401);
		const auth = await verifyAccessToken(token);
		if (!auth || !auth.isAdmin) return c.json({ error: "Forbidden" }, 403);
		const opts = parseListOptions(c.req.url);
		const offset = (opts.page - 1) * opts.limit;
		const where = opts.search ? `WHERE oc.name LIKE ?` : "";
		const searchParam = opts.search ? `%${opts.search}%` : [];
		const countResult = await c.env.DB.prepare(
			`SELECT COUNT(*) as cnt FROM oidc_clients oc ${where}`,
		).bind(...(opts.search ? [searchParam] : [])).first();
		const totalItems = (countResult as Record<string, unknown>)?.cnt as number;
		const sortCol = ["name", "created_at", "pkce_enabled", "requires_reauthentication", "requires_pushed_authorization_requests", "is_group_restricted"].includes(opts.sortColumn)
			? `oc.${opts.sortColumn}` : "oc.name";
		const result = await c.env.DB.prepare(
			`SELECT oc.id, oc.name, oc.image_type, oc.dark_image_type, oc.is_public, oc.pkce_enabled,
				oc.requires_reauthentication, oc.requires_pushed_authorization_requests, oc.is_group_restricted,
				oc.launch_url, oc.created_at
			 FROM oidc_clients oc ${where}
			 ORDER BY ${sortCol} ${opts.sortDirection}
			 LIMIT ? OFFSET ?`,
		).bind(...(opts.search ? [searchParam] : []), opts.limit, offset).all();
		const clientIds = (result.results as Record<string, unknown>[]).map((r) => r.id as string);
		const clients = await Promise.all(clientIds.map(async (id) => {
			const row = result.results.find((r) => (r as Record<string, unknown>).id === id) as Record<string, unknown>;
			const countR = await c.env.DB.prepare(
				"SELECT COUNT(*) as cnt FROM oidc_clients_allowed_user_groups WHERE oidc_client_id = ?",
			).bind(id).first();
			return {
				id: row.id,
				name: row.name ?? "",
				hasLogo: (row.image_type as string) !== "",
				hasDarkLogo: (row.dark_image_type as string) !== "",
				isPublic: Boolean(row.is_public),
				pkceEnabled: Boolean(row.pkce_enabled),
				requiresReauthentication: Boolean(row.requires_reauthentication),
				requiresPushedAuthorizationRequests: Boolean(row.requires_pushed_authorization_requests),
				isGroupRestricted: Boolean(row.is_group_restricted),
				launchURL: row.launch_url ?? null,
				createdAt: row.created_at,
				allowedGroupsCount: Number((countR as Record<string, unknown>)?.cnt ?? 0),
			};
		}));
		return c.json(paginatedResponse(clients, totalItems, opts));
	} catch {
		// Fall through to container on error
	}
});

app.get("/api/oidc/clients/:id", async (c) => {
	try {
		const token = extractAccessToken(c.req.raw);
		if (!token) return c.json({ error: "Not authenticated" }, 401);
		const auth = await verifyAccessToken(token);
		if (!auth || !auth.isAdmin) return c.json({ error: "Forbidden" }, 403);
		const id = c.req.param("id");
		const result = await c.env.DB.prepare(
			`SELECT oc.*,
				COALESCE(u.username, '') as created_by_name
			 FROM oidc_clients oc
			 LEFT JOIN users u ON oc.created_by_id = u.id
			 WHERE oc.id = ?`,
		).bind(id).first();
		if (!result) return c.json({ error: "Client not found" }, 404);
		const r = result as Record<string, unknown>;
		// Get allowed user groups
		const groupsResult = await c.env.DB.prepare(
			`SELECT ug.id, ug.friendly_name, ug.name
			 FROM user_groups ug
			 INNER JOIN oidc_clients_allowed_user_groups ocg ON ug.id = ocg.user_group_id
			 WHERE ocg.oidc_client_id = ?`,
		).bind(id).all();
		const allowedUserGroups = (groupsResult.results as Record<string, unknown>[]).map((g) => ({
			id: g.id,
			friendlyName: g.friendly_name,
			name: g.name,
		}));
		return c.json({
			id: r.id,
			name: r.name ?? "",
			hasLogo: (r.image_type as string) !== "",
			hasDarkLogo: (r.dark_image_type as string) !== "",
			callbackURLs: JSON.parse((r.callback_urls as string) || "[]"),
			logoutCallbackURLs: JSON.parse((r.logout_callback_urls as string) || "[]"),
			isPublic: Boolean(r.is_public),
			pkceEnabled: Boolean(r.pkce_enabled),
			requiresReauthentication: Boolean(r.requires_reauthentication),
			requiresPushedAuthorizationRequests: Boolean(r.requires_pushed_authorization_requests),
			launchURL: r.launch_url ?? null,
			isGroupRestricted: Boolean(r.is_group_restricted),
			createdAt: r.created_at,
			createdByName: r.created_by_name || null,
			allowedUserGroups,
		});
	} catch {
		// Fall through to container on error
	}
});

app.get("/api/audit-logs", async (c) => {
	try {
		const token = extractAccessToken(c.req.raw);
		if (!token) return c.json({ error: "Not authenticated" }, 401);
		const auth = await verifyAccessToken(token);
		if (!auth) return c.json({ error: "Invalid token" }, 401);
		const opts = parseListOptions(c.req.url);
		const offset = (opts.page - 1) * opts.limit;
		const u = new URL(c.req.url);
		const filters: string[] = [];
		const params: unknown[] = [];
		// User-scoped: only show logs for the current user
		filters.push("al.user_id = ?");
		params.push(auth.sub);
		const eventFilter = u.searchParams.get("filters[event]");
		if (eventFilter) { filters.push("al.event = ?"); params.push(eventFilter); }
		const where = filters.length > 0 ? `WHERE ${filters.join(" AND ")}` : "";
		const sortCol = ["created_at", "event", "country", "city"].includes(opts.sortColumn)
			? `al.${opts.sortColumn}` : "al.created_at";
		const countResult = await c.env.DB.prepare(
			`SELECT COUNT(*) as cnt FROM audit_logs al ${where}`,
		).bind(...params).first();
		const totalItems = (countResult as Record<string, unknown>)?.cnt as number;
		const result = await c.env.DB.prepare(
			`SELECT al.id, al.created_at, al.event, al.ip_address, al.user_agent, al.data, al.country, al.city, al.user_id
			 FROM audit_logs al ${where}
			 ORDER BY ${sortCol} ${opts.sortDirection}
			 LIMIT ? OFFSET ?`,
		).bind(...params, opts.limit, offset).all();
		const logs = (result.results as Record<string, unknown>[]).map((r) => ({
			id: r.id,
			createdAt: r.created_at,
			event: r.event,
			ipAddress: r.ip_address ?? null,
			userAgent: r.user_agent,
			data: typeof r.data === "string" ? JSON.parse(r.data) : r.data,
			country: r.country ?? null,
			city: r.city ?? null,
			userId: r.user_id,
		}));
		return c.json(paginatedResponse(logs, totalItems, opts));
	} catch {
		// Fall through to container on error
	}
});

app.get("/api/audit-logs/all", async (c) => {
	try {
		const token = extractAccessToken(c.req.raw);
		if (!token) return c.json({ error: "Not authenticated" }, 401);
		const auth = await verifyAccessToken(token);
		if (!auth || !auth.isAdmin) return c.json({ error: "Forbidden" }, 403);
		const opts = parseListOptions(c.req.url);
		const offset = (opts.page - 1) * opts.limit;
		const u = new URL(c.req.url);
		const filters: string[] = [];
		const params: unknown[] = [];
		const eventFilter = u.searchParams.get("filters[event]");
		if (eventFilter) { filters.push("al.event = ?"); params.push(eventFilter); }
		const userIdFilter = u.searchParams.get("filters[userID]");
		if (userIdFilter) { filters.push("al.user_id = ?"); params.push(userIdFilter); }
		const clientNameFilter = u.searchParams.get("filters[clientName]");
		if (clientNameFilter) { filters.push("json_extract(al.data, '$.clientName') = ?"); params.push(clientNameFilter); }
		const where = filters.length > 0 ? `WHERE ${filters.join(" AND ")}` : "";
		const sortCol = ["created_at", "event", "country", "city"].includes(opts.sortColumn)
			? `al.${opts.sortColumn}` : "al.created_at";
		const countResult = await c.env.DB.prepare(
			`SELECT COUNT(*) as cnt FROM audit_logs al ${where}`,
		).bind(...params).first();
		const totalItems = (countResult as Record<string, unknown>)?.cnt as number;
		const result = await c.env.DB.prepare(
			`SELECT al.id, al.created_at, al.event, al.ip_address, al.user_agent, al.data, al.country, al.city, al.user_id
			 FROM audit_logs al ${where}
			 ORDER BY ${sortCol} ${opts.sortDirection}
			 LIMIT ? OFFSET ?`,
		).bind(...params, opts.limit, offset).all();
		const logs = (result.results as Record<string, unknown>[]).map((r) => ({
			id: r.id,
			createdAt: r.created_at,
			event: r.event,
			ipAddress: r.ip_address ?? null,
			userAgent: r.user_agent,
			data: typeof r.data === "string" ? JSON.parse(r.data) : r.data,
			country: r.country ?? null,
			city: r.city ?? null,
			userId: r.user_id,
		}));
		return c.json(paginatedResponse(logs, totalItems, opts));
	} catch {
		// Fall through to container on error
	}
});

app.get("/api/signup-tokens", async (c) => {
	try {
		const token = extractAccessToken(c.req.raw);
		if (!token) return c.json({ error: "Not authenticated" }, 401);
		const auth = await verifyAccessToken(token);
		if (!auth || !auth.isAdmin) return c.json({ error: "Forbidden" }, 403);
		const result = await c.env.DB.prepare(
			"SELECT id, created_at, token, expires_at, usage_limit, usage_count FROM signup_tokens ORDER BY created_at DESC",
		).all();
		const tokens = (result.results as Record<string, unknown>[]).map((r) => ({
			id: r.id,
			createdAt: r.created_at,
			token: r.token,
			expiresAt: r.expires_at,
			usageLimit: r.usage_limit,
			usageCount: r.usage_count,
		}));
		return c.json({
			data: tokens,
			pagination: { totalPages: 1, totalItems: tokens.length, currentPage: 1, itemsPerPage: 100 },
		});
	} catch {
		// Fall through to container on error
	}
});

app.get("/api/oidc/device/info", async (c) => {
	try {
		const token = extractAccessToken(c.req.raw);
		if (!token) return c.json({ error: "Not authenticated" }, 401);
		const auth = await verifyAccessToken(token);
		if (!auth) return c.json({ error: "Invalid token" }, 401);
		const u = new URL(c.req.url);
		const deviceCode = u.searchParams.get("device_code");
		if (!deviceCode) return c.json({ error: "Missing device_code" }, 400);
		const result = await c.env.DB.prepare(
			`SELECT dc.*, oc.name as client_name, oc.launch_url as client_launch_url
			 FROM device_codes dc
			 INNER JOIN oidc_clients oc ON dc.client_id = oc.id
			 WHERE dc.code = ? AND dc.user_id = ?`,
		).bind(deviceCode, auth.sub).first();
		if (!result) return c.json({ error: "Device code not found" }, 404);
		const r = result as Record<string, unknown>;
		return c.json({
			clientName: r.client_name,
			clientLaunchURL: r.client_launch_url ?? null,
			status: r.status,
		});
	} catch {
		// Fall through to container on error
	}
});

app.get("/api/version/current", async (c) => {
	try {
		const token = extractAccessToken(c.req.raw);
		if (!token) return c.json({ error: "Not authenticated" }, 401);
		const auth = await verifyAccessToken(token);
		if (!auth) return c.json({ error: "Invalid token" }, 401);
		// Read version from a D1 key-value store or return a static value
		// The container sets this at startup; we approximate it
		return c.json({ currentVersion: "0.0.0" });
	} catch {
		// Fall through to container on error
	}
});

app.get("/api/users/:id", async (c) => {
	try {
		const token = extractAccessToken(c.req.raw);
		if (!token) return c.json({ error: "Not authenticated" }, 401);
		const auth = await verifyAccessToken(token);
		if (!auth || !auth.isAdmin) return c.json({ error: "Forbidden" }, 403);
		const id = c.req.param("id");
		const user = await c.env.DB.prepare(
			"SELECT id, username, email, first_name, last_name, display_name, is_admin, locale, disabled, email_verified, created_at FROM users WHERE id = ?",
		).bind(id).first();
		if (!user) return c.json({ error: "User not found" }, 404);
		const r = user as Record<string, unknown>;
		const groupsResult = await c.env.DB.prepare(
			`SELECT ug.id, ug.friendly_name, ug.name FROM user_groups ug
			 INNER JOIN user_groups_users ugu ON ug.id = ugu.user_group_id
			 WHERE ugu.user_id = ?`,
		).bind(id).all();
		const claimsResult = await c.env.DB.prepare(
			"SELECT id, \"key\", value FROM custom_claims WHERE user_id = ?",
		).bind(id).all();
		return c.json({
			id: r.id,
			username: r.username,
			email: r.email ?? null,
			firstName: r.first_name,
			lastName: r.last_name,
			displayName: r.display_name,
			isAdmin: Boolean(r.is_admin),
			locale: r.locale ?? null,
			disabled: Boolean(r.disabled),
			emailVerified: r.email_verified,
			createdAt: r.created_at,
			userGroups: (groupsResult.results as Record<string, unknown>[]).map((g) => ({
				id: g.id, friendlyName: g.friendly_name, name: g.name,
			})),
			customClaims: (claimsResult.results as Record<string, unknown>[]).map((cc) => ({
				id: cc.id, key: cc.key, value: cc.value,
			})),
		});
	} catch {
		// Fall through to container on error
	}
});

app.get("/api/users/:id/groups", async (c) => {
	try {
		const token = extractAccessToken(c.req.raw);
		if (!token) return c.json({ error: "Not authenticated" }, 401);
		const auth = await verifyAccessToken(token);
		if (!auth || !auth.isAdmin) return c.json({ error: "Forbidden" }, 403);
		const id = c.req.param("id");
		const result = await c.env.DB.prepare(
			`SELECT ug.id, ug.friendly_name, ug.name, ug.created_at FROM user_groups ug
			 INNER JOIN user_groups_users ugu ON ug.id = ugu.user_group_id
			 WHERE ugu.user_id = ?
			 ORDER BY ug.friendly_name ASC`,
		).bind(id).all();
		const groups = (result.results as Record<string, unknown>[]).map((g) => ({
			id: g.id, friendlyName: g.friendly_name, name: g.name, createdAt: g.created_at,
		}));
		return c.json(groups);
	} catch {
		// Fall through to container on error
	}
});

app.get("/api/user-groups/:id", async (c) => {
	try {
		const token = extractAccessToken(c.req.raw);
		if (!token) return c.json({ error: "Not authenticated" }, 401);
		const auth = await verifyAccessToken(token);
		if (!auth || !auth.isAdmin) return c.json({ error: "Forbidden" }, 403);
		const id = c.req.param("id");
		const group = await c.env.DB.prepare(
			"SELECT id, name, friendly_name, created_at FROM user_groups WHERE id = ?",
		).bind(id).first();
		if (!group) return c.json({ error: "Group not found" }, 404);
		const r = group as Record<string, unknown>;
		const usersResult = await c.env.DB.prepare(
			`SELECT u.id, u.username, u.email, u.first_name, u.last_name, u.display_name, u.is_admin, u.disabled
			 FROM users u INNER JOIN user_groups_users ugu ON u.id = ugu.user_id
			 WHERE ugu.user_group_id = ?
			 ORDER BY u.username ASC`,
		).bind(id).all();
		const claimsResult = await c.env.DB.prepare(
			"SELECT id, \"key\", value FROM custom_claims WHERE user_group_id = ?",
		).bind(id).all();
		const allowedClientsResult = await c.env.DB.prepare(
			`SELECT oc.id, oc.name, oc.image_type, oc.dark_image_type, oc.launch_url, oc.requires_reauthentication
			 FROM oidc_clients oc
			 INNER JOIN oidc_clients_allowed_user_groups ocg ON oc.id = ocg.oidc_client_id
			 WHERE ocg.user_group_id = ?`,
		).bind(id).all();
		return c.json({
			id: r.id,
			name: r.name,
			friendlyName: r.friendly_name,
			createdAt: r.created_at,
			users: (usersResult.results as Record<string, unknown>[]).map((u) => ({
				id: u.id, username: u.username, email: u.email ?? null,
				firstName: u.first_name, lastName: u.last_name, displayName: u.display_name,
				isAdmin: Boolean(u.is_admin), disabled: Boolean(u.disabled),
			})),
			customClaims: (claimsResult.results as Record<string, unknown>[]).map((cc) => ({
				id: cc.id, key: cc.key, value: cc.value,
			})),
			allowedOidcClients: (allowedClientsResult.results as Record<string, unknown>[]).map((oc) => ({
				id: oc.id, name: oc.name ?? "",
				hasLogo: (oc.image_type as string) !== "",
				hasDarkLogo: (oc.dark_image_type as string) !== "",
				launchURL: oc.launch_url ?? null,
				requiresReauthentication: Boolean(oc.requires_reauthentication),
			})),
		});
	} catch {
		// Fall through to container on error
	}
});

app.get("/api/oidc/users/:id/authorized-clients", async (c) => {
	try {
		const token = extractAccessToken(c.req.raw);
		if (!token) return c.json({ error: "Not authenticated" }, 401);
		const auth = await verifyAccessToken(token);
		if (!auth || !auth.isAdmin) return c.json({ error: "Forbidden" }, 403);
		const id = c.req.param("id");
		const result = await c.env.DB.prepare(
			`SELECT uac.scope, uac.last_used_at, uac.client_id,
				oc.id as c_id, oc.name as c_name, oc.image_type, oc.dark_image_type,
				oc.launch_url, oc.requires_reauthentication
				FROM user_authorized_oidc_clients uac
				INNER JOIN oidc_clients oc ON uac.client_id = oc.id
				WHERE uac.user_id = ?
				ORDER BY uac.last_used_at DESC`,
		).bind(id).all();
		const clients = (result.results as Record<string, unknown>[]).map((r) => ({
			scope: r.scope ?? "",
			client: {
				id: r.c_id, name: r.c_name ?? "",
				hasLogo: (r.image_type as string) !== "",
				hasDarkLogo: (r.dark_image_type as string) !== "",
				launchURL: r.launch_url ?? null,
				requiresReauthentication: Boolean(r.requires_reauthentication),
			},
			lastUsedAt: r.last_used_at,
		}));
		return c.json({
			data: clients,
			pagination: { totalPages: 1, totalItems: clients.length, currentPage: 1, itemsPerPage: 100 },
		});
	} catch {
		// Fall through to container on error
	}
});

app.post("/__d1/query", async (c) => {
	try {
		const body = (await c.req.json()) as D1QueryRequest;
		const sql = normalizeSQL(body.sql);
		const params = normalizeParams(body.params);

		const result = await c.env.DB.prepare(sql)
			.bind(...params)
			.all();

		return c.json({
			success: true,
			results: result.results,
			meta: result.meta,
		});
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);
		return c.json({ success: false, error: message }, 500);
	}
});

app.post("/__d1/exec", async (c) => {
	try {
		const body = (await c.req.json()) as D1QueryRequest;
		const sql = normalizeSQL(body.sql);
		const params = normalizeParams(body.params);

		const statements = splitStatements(sql);

		if (statements.length === 0) {
			return c.json({
				success: true,
				meta: { changes: 0, last_row_id: 0 },
			});
		}

		if (statements.length === 1) {
			const result = await c.env.DB.prepare(statements[0])
				.bind(...params)
				.run();
			return c.json({
				success: true,
				meta: {
					changes: result.meta?.changes ?? 0,
					last_row_id: result.meta?.last_row_id ?? 0,
				},
			});
		}

		const stmts = statements.map((s) => c.env.DB.prepare(s).bind(...params));
		const results = await c.env.DB.batch(stmts);
		const last = results[results.length - 1];

		return c.json({
			success: true,
			meta: {
				changes: last?.meta?.changes ?? 0,
				last_row_id: last?.meta?.last_row_id ?? 0,
			},
		});
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);
		return c.json({ success: false, error: message }, 500);
	}
});

app.post("/__d1/batch", async (c) => {
	try {
		const body = (await c.req.json()) as D1BatchRequest[];
		const stmts = body.map((item) => {
			const sql = normalizeSQL(item.sql);
			const params = normalizeParams(item.params);
			return c.env.DB.prepare(sql).bind(...params);
		});

		const results = await c.env.DB.batch(stmts);

		return c.json({
			success: true,
			results: results.map((r) => ({
				success: true,
				results: r.results,
				meta: r.meta,
			})),
		});
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);
		return c.json({ success: false, error: message }, 500);
	}
});

app.get("/__d1/health", (c) => {
	return c.json({ status: "ok" });
});

app.post("/__email/send", async (c) => {
	try {
		const body = (await c.req.json()) as EmailRequest;
		const accountId = c.env.CLOUDFLARE_ACCOUNT_ID;
		const apiToken = c.env.CLOUDFLARE_API_TOKEN;

		if (!accountId || !apiToken) {
			return c.json(
				{ success: false, error: "Email service not configured" },
				500,
			);
		}

		const payload: Record<string, unknown> = {
			from: body.from,
			to: body.to,
			subject: body.subject,
			html: body.html,
			text: body.text,
		};

		const resp = await fetch(
			`https://api.cloudflare.com/client/v4/accounts/${accountId}/email/sending/send`,
			{
				method: "POST",
				headers: {
					Authorization: `Bearer ${apiToken}`,
					"Content-Type": "application/json",
				},
				body: JSON.stringify(payload),
			},
		);

		const result = (await resp.json()) as {
			success: boolean;
			errors?: { message: string }[];
		};

		if (!result.success) {
			const errMsg =
				result.errors?.map((e) => e.message).join(", ") ||
				"Unknown error";
			return c.json({ success: false, error: errMsg }, 500);
		}

		return c.json({ success: true });
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);
		return c.json({ success: false, error: message }, 500);
	}
});

app.get("/.well-known/openid-configuration", (_c) => {
	return _c.json({
		issuer: "https://authspot.net",
		authorization_endpoint: "https://authspot.net/authorize",
		token_endpoint: "https://authspot.net/api/oidc/token",
		userinfo_endpoint: "https://authspot.net/api/oidc/userinfo",
		jwks_uri: "https://authspot.net/.well-known/jwks.json",
		registration_endpoint: "https://authspot.net/api/oidc/register",
		end_session_endpoint: "https://authspot.net/logout",
		device_authorization_endpoint: "https://authspot.net/api/oidc/device/authorize",
		pushed_authorization_request_endpoint: "https://authspot.net/api/oidc/par",
		scopes_supported: ["openid","profile","email","groups"],
		response_types_supported: ["code"],
		grant_types_supported: ["authorization_code","refresh_token","urn:ietf:params:oauth:grant-type:device_code","client_credentials"],
		subject_types_supported: ["public"],
		id_token_signing_alg_values_supported: ["RS256"],
		code_challenge_methods_supported: ["S256"],
		token_endpoint_auth_methods_supported: ["client_secret_basic","client_secret_post"],
	});
});

// Image cache-forward: serve from Cache API, fall back to container
async function cacheForward(c: any, cacheKey: string, ttlSeconds: number): Promise<Response> {
	// Check cache first
	const cache = caches.default;
	const cachedResponse = await cache.match(cacheKey);
	if (cachedResponse) {
		return cachedResponse;
	}
	// Forward to container
	const container = getContainer(c.env.POCKET_ID_CONTAINER);
	const containerResp = await container.fetch(c.req.raw);
	// Only cache successful image responses
	if (containerResp.ok && containerResp.headers.get("content-type")?.startsWith("image/")) {
		const responseToCache = new Response(containerResp.body, containerResp);
		responseToCache.headers.set("Cache-Control", `public, max-age=${ttlSeconds}`);
		c.waitUntil(cache.put(cacheKey, responseToCache.clone()));
		return responseToCache;
	}
	return containerResp;
}

app.get("/api/application-images/logo", (c) => cacheForward(c, c.req.url, 86400));
app.get("/api/application-images/email", (c) => cacheForward(c, c.req.url, 86400));
app.get("/api/application-images/background", (c) => cacheForward(c, c.req.url, 86400));
app.get("/api/application-images/favicon", (c) => cacheForward(c, c.req.url, 86400));
app.get("/api/application-images/default-profile-picture", (c) => cacheForward(c, c.req.url, 86400));
app.get("/api/oidc/clients/:id/logo", (c) => cacheForward(c, c.req.url, 43200));
app.get("/api/users/:id/profile-picture.png", (c) => cacheForward(c, c.req.url, 3600));

// API calls → container (static assets served by Worker Assets)
app.all("/api/*", async (c) => {
	const container = getContainer(c.env.POCKET_ID_CONTAINER);
	return await container.fetch(c.req.raw);
});

app.all("/.well-known/*", async (c) => {
	const container = getContainer(c.env.POCKET_ID_CONTAINER);
	return await container.fetch(c.req.raw);
});

export default app;
