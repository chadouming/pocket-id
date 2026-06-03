import { Container, getContainer } from "@cloudflare/containers";
import { Hono } from "hono";

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
