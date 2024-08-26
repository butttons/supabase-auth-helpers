import type {
	Session,
	UserAppMetadata,
	UserMetadata,
} from "@supabase/supabase-js";
import debugFactory from "debug";
import { type JWTPayload, jwtVerify } from "jose";
import type { ReadonlyRequestCookies } from "next/dist/server/web/spec-extension/adapters/request-cookies";
import { parseCookies } from "oslo/cookie";

const debug = debugFactory("@butttons/supabase-auth-helpers");

/**
 * @module
 * @name @butttons/supabase-auth-helper
 * @description A utility to work with Supabase Auth.
 */

/**
 * Options for the `SupabaseAuthHelper` class.
 */
export type SupabaseAuthHelperOptions = {
	/**
	 * The Supabase project ID. This is used to identify the the supabase cookies in the request.
	 * If you are using custom domains, this should be the subdomain. For example,
	 * if your custom domain is `auth.example.com`, the `supabaseId` should be `auth`.
	 *
	 * You can find out the cookie name by looking at the cookies in the browser. The cookie name should be in the format `sb-[SUPABASE_ID]-auth-token.[NUMBER]`.
	 */
	supabaseId: string;
	/**
	 * The Supabase project URL. This is used to verify the issuer of the JWT.
	 */
	supabaseUrl: string;
	/**
	 * The JWT secret used to sign the JWT.
	 */
	jwtSecret: string;
};

/**
 * A simple user object in the JWT payload. This is safer than `getSession().session.user`.
 */
export type SupabaseTokenUser = {
	id: string;
	email: string;
	phone: string;
	role: string;
	is_anonymous: boolean;
	app_metadata: UserAppMetadata;
	user_metadata: UserMetadata;
	session_id: string;
};

type SafeResponse<T> =
	| { type: "success"; payload: T }
	| { type: "error"; error: unknown };

/**
 * A helper utility to work with Supabase Auth.
 * Provides methods to get the session, authenticate tokens, and get the user object from the token.
 *
 * @example
 *
 * ```ts
 * const supabaseAuthHelper = new SupabaseAuthHelper({
 *  supabaseId: 'your-supabase-id',
 *  supabaseUrl: 'https://your-supabase-id.supabase.co',
 *  jwtSecret: 'your-jwt-secret',
 * });
 *
 * const session = await supabaseAuthHelper.getUserFromRequest(req);
 *
 * ```
 */
export class SupabaseAuthHelper {
	public options: SupabaseAuthHelperOptions;

	constructor(options: SupabaseAuthHelperOptions) {
		this.options = options;
	}

	/**
	 * Decodes the Supabase auth cookie and returns the session object.
	 *
	 * This method is used internally to get the session object from the request.
	 * @param cookies {Map<string, string>}
	 * @returns Session or null if the cookie is not parsable.
	 */
	private decodeAuthCookie = (cookies: Map<string, string>): Session | null => {
		const supabaseCookie = Array.from(cookies.entries())
			.sort(([a, b]) => a[0].localeCompare(b[0]))
			.filter(([name, value]) =>
				name.includes(`${this.options.supabaseId}-auth-token`),
			)
			.map(([name, value]) => value)
			.join("");

		try {
			return JSON.parse(supabaseCookie) as Session;
		} catch {
			debug("decodeAuthCookie(): Failed to parse cookie: %s.", supabaseCookie);
			return null;
		}
	};

	/**
	 * Returns the session object from the request. Similar to `supabase.auth.getSession()`.
	 * The data returned here should be treated as untrusted.
	 *
	 * Use the `getUserFromRequest(req)` method to get the validated payload.
	 * @param req
	 * @returns - Supabase Session from `@supabase/supabase-js`
	 */
	public getUnsafeSession = (req: Request): Session | null => {
		const cookieHeader = req.headers.get("cookie");
		if (!cookieHeader) {
			debug("getUnsafeSession(): Cookies not found");
			return null;
		}

		const session = this.decodeAuthCookie(parseCookies(cookieHeader));
		return session;
	};

	/**
	 * Authenticates the token and returns the payload.
	 * Updated the payload to include the `id` field from the `sub` field.
	 * @param token
	 * @returns A minimal user object from the JWT payload.
	 */
	public authenticateToken = async (
		token: string,
	): Promise<SupabaseTokenUser & JWTPayload> => {
		const { payload } = await jwtVerify<SupabaseTokenUser>(
			token,
			new TextEncoder().encode(this.options.jwtSecret),
			{
				issuer: new URL("/auth/v1", this.options.supabaseUrl).toString(),
			},
		);
		payload.id = payload.sub ?? payload.id;
		return payload;
	};

	/**
	 * Alternative to `authenticateToken` that returns a `SafeResponse` object, instead of throwing the error.
	 * @param token
	 * @returns A `SafeResponse` object which contains the payload or the error.
	 *
	 * @example
	 *
	 * ```ts
	 * const result = await supabaseHelper.authenticateTokenSafely(token);
	 *
	 * if (result.type === 'error') {
	 *  console.error('Could not verify token', result.error);
	 *  return;
	 * }
	 *
	 * const payload = result.payload;
	 *
	 * ```
	 */
	public authenticateTokenSafely = async (
		token: string,
	): Promise<SafeResponse<SupabaseTokenUser & JWTPayload>> => {
		try {
			const payload = await this.authenticateToken(token);
			return { type: "success", payload };
		} catch (error) {
			return { type: "error", error };
		}
	};

	/**
	 * Gets the minimal user object from the request.
	 * @param req Request
	 * @returns The token payload or null if the token is invalid.
	 */
	public getUserFromRequest = async (
		req: Request,
	): Promise<(SupabaseTokenUser & JWTPayload) | null> => {
		const session = this.getUnsafeSession(req);
		if (!session) {
			debug("getUserFromRequest(): Session not found in the request");
			return null;
		}

		const result = await this.authenticateTokenSafely(session.access_token);
		if (result.type === "error") {
			debug("getUserFromRequest(): Failed to parse token - %o", result.error);
			return null;
		}

		return result.payload;
	};

	/**
	 * Gets the minimal user object from the cookies.
	 * This is useful when working with next.js server actions.
	 * @param cookieStore
	 * @returns The token payload or null if the token is invalid.
	 */
	public getUserFromCookies = async (
		cookieStore: ReadonlyRequestCookies,
	): Promise<(SupabaseTokenUser & JWTPayload) | null> => {
		const cookieMap = cookieStore
			.getAll()
			.reduce<Map<string, string>>((acc, ck) => {
				acc.set(ck.name, ck.value);
				return acc;
			}, new Map());
		const session = this.decodeAuthCookie(cookieMap);
		if (!session) {
			debug("getUserFromCookies(): Session not found in the cookies");
			return null;
		}

		const result = await this.authenticateTokenSafely(session.access_token);
		if (result.type === "error") {
			debug("getUserFromCookies(): Failed to parse token - %o", result.error);
			return null;
		}

		return result.payload;
	};

	/**
	 * Gets the user object from the request or cookies.
	 * @returns The token payload or null if the token is invalid.
	 */
	public getUser = async (
		reqOrCookie: Request | ReadonlyRequestCookies,
	): Promise<(SupabaseTokenUser & JWTPayload) | null> => {
		if (reqOrCookie instanceof Request) {
			return this.getUserFromRequest(reqOrCookie);
		}
		return this.getUserFromCookies(reqOrCookie);
	};
}
