import { Cookie, SetCookie, type SetCookieInit } from "@mjackson/headers";
import createDebug from "debug";
import { Strategy } from "remix-auth/strategy";
import { redirect } from "./lib/redirect.js";

const debug = createDebug("LinkedInStrategy");

export type LinkedInScope = "openid" | "profile" | "email";

/**
 * This type declares what configuration the strategy needs from the
 * developer to correctly work.
 * @see {@link https://docs.microsoft.com/en-us/linkedin/shared/authentication/authorization-code-flow LinkedIn Auth Flow}
 */
export type LinkedInStrategyOptions = {
	clientID: string;
	clientSecret: string;
	callbackURL: string;
	/**
	 * @default "openid profile email"
	 * @see {@link https://docs.microsoft.com/en-us/linkedin/shared/authentication/authentication?context=linkedin/context#permission-types Permisision}
	 */
	scope?: LinkedInScope[] | string;
};

/**
 * In order to be complaint with the OAuth2Profile type as much as possible
 * based on the information Linkedin gives us.
 */
export interface LinkedInProfile {
	id: string;
	displayName: string;
	name: {
		givenName: string;
		familyName: string;
	};
	emails: Array<{ value: string }>;
	photos: Array<{ value: string }>;
	_json: {
		sub: string;
		name: string;
		given_name: string;
		family_name: string;
		picture: string;
		locale: string;
		email: string;
		email_verified: boolean;
	};
}

export type LinkedInExtraParams = {
	scope: string;
} & Record<string, string | number>;

export const LinkedInStrategyDefaultName = "linkedin";
export const LinkedInStrategyScopeSeparator = " ";
export const LinkedInStrategyDefaultScopes: string = [
	"openid",
	"profile",
	"email",
].join(LinkedInStrategyScopeSeparator);

export class LinkedInStrategy<User> extends Strategy<
	User,
	LinkedInStrategy.VerifyOptions
> {
	name = LinkedInStrategyDefaultName;

	constructor(
		protected options: LinkedInStrategy.ConstructorOptions,
		verify: Strategy.VerifyFunction<User, LinkedInStrategy.VerifyOptions>,
	) {
		super(verify);
	}

	private get cookieName() {
		if (typeof this.options.cookie === "string") {
			return this.options.cookie || "linkedin";
		}
		return this.options.cookie?.name ?? "linkedin";
	}

	private get cookieOptions() {
		if (typeof this.options.cookie !== "object") return {};
		return this.options.cookie ?? {};
	}

	// Allow users the option to pass a scope string, or typed array
	private getScope(scope?: LinkedInScope[] | string): string {
		if (!scope) {
			return LinkedInStrategyDefaultScopes;
		}
		if (Array.isArray(scope)) {
			return scope.join(LinkedInStrategyScopeSeparator);
		}
		return scope;
	}

	override async authenticate(request: Request): Promise<User> {
		debug("Request URL", request.url);

		let url = new URL(request.url);
		let code = url.searchParams.get("code");
		let state = url.searchParams.get("state");
		let error = url.searchParams.get("error");

		if (error) {
			let description = url.searchParams.get("error_description");
			let uri = url.searchParams.get("error_uri");
			throw new Error(`LinkedIn OAuth error: ${error}, ${description}, ${uri}`);
		}

		if (!state) {
			debug("No state found in the URL, redirecting to authorization endpoint");

			// Generate a random state
			let newState = crypto.randomUUID();
			debug("Generated State", newState);

			// Create authorization URL
			let authorizationURL = new URL(
				"https://www.linkedin.com/oauth/v2/authorization",
			);
			authorizationURL.searchParams.set("client_id", this.options.clientId);
			authorizationURL.searchParams.set(
				"redirect_uri",
				this.options.redirectURI.toString(),
			);
			authorizationURL.searchParams.set("response_type", "code");
			authorizationURL.searchParams.set(
				"scope",
				this.getScope(this.options.scopes),
			);
			authorizationURL.searchParams.set("state", newState);

			// Add any additional params
			const params = this.authorizationParams(
				authorizationURL.searchParams,
				request,
			);
			authorizationURL.search = params.toString();

			debug("Authorization URL", authorizationURL.toString());

			// Set cookie with state for verification later
			let header = new SetCookie({
				name: this.cookieName,
				value: new URLSearchParams({ state: newState }).toString(),
				httpOnly: true,
				maxAge: 60 * 5, // 5 minutes
				path: "/",
				sameSite: "Lax",
				...this.cookieOptions,
			});

			throw redirect(authorizationURL.toString(), {
				headers: { "Set-Cookie": header.toString() },
			});
		}

		if (!code) throw new ReferenceError("Missing code in the URL");

		// Verify state
		let cookie = new Cookie(request.headers.get("cookie") ?? "");
		let params = new URLSearchParams(cookie.get(this.cookieName) || "");

		if (!params.has("state")) {
			throw new ReferenceError("Missing state on cookie.");
		}

		if (params.get("state") !== state) {
			throw new RangeError("State in URL doesn't match state in cookie.");
		}

		debug("Validating authorization code");

		// Exchange code for tokens
		const formData = new URLSearchParams();
		formData.set("client_id", this.options.clientId);
		formData.set("client_secret", this.options.clientSecret);
		formData.set("grant_type", "authorization_code");
		formData.set("code", code);
		formData.set("redirect_uri", this.options.redirectURI.toString());

		const tokenResponse = await fetch(
			"https://www.linkedin.com/oauth/v2/accessToken",
			{
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: formData,
			},
		);

		if (!tokenResponse.ok) {
			const error = await tokenResponse.text();
			throw new Error(`Failed to get access token: ${error}`);
		}

		const tokens = (await tokenResponse.json()) as {
			access_token: string;
			token_type: string;
			expires_in: number;
			refresh_token?: string;
			scope?: string;
		};

		// Get user profile
		const profile = await this.userProfile(tokens.access_token);

		debug("Verifying the user profile");
		let user = await this.verify({ request, tokens, profile });

		debug("User authenticated");
		return user;
	}

	/**
	 * Return extra parameters to be included in the authorization request.
	 */
	protected authorizationParams(
		params: URLSearchParams,
		request: Request,
	): URLSearchParams {
		return new URLSearchParams(params);
	}

	/**
	 * Retrieve user profile from LinkedIn
	 */
	protected async userProfile(accessToken: string): Promise<LinkedInProfile> {
		const response = await fetch("https://api.linkedin.com/v2/userinfo", {
			headers: {
				Authorization: `Bearer ${accessToken}`,
			},
		});

		if (!response.ok) {
			const error = await response.text();
			throw new Error(`Failed to fetch user profile: ${error}`);
		}

		const raw = (await response.json()) as LinkedInProfile["_json"];
		const profile: LinkedInProfile = {
			id: raw.sub,
			displayName: raw.name,
			name: {
				familyName: raw.family_name,
				givenName: raw.given_name,
			},
			emails: [{ value: raw.email }],
			photos: [{ value: raw.picture }],
			_json: raw,
		};

		return profile;
	}

	/**
	 * Refresh the access token using a refresh token
	 */
	public async refreshToken(refreshToken: string) {
		const formData = new URLSearchParams();
		formData.set("client_id", this.options.clientId);
		formData.set("client_secret", this.options.clientSecret);
		formData.set("grant_type", "refresh_token");
		formData.set("refresh_token", refreshToken);

		const response = await fetch(
			"https://www.linkedin.com/oauth/v2/accessToken",
			{
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: formData,
			},
		);

		if (!response.ok) {
			const error = await response.text();
			throw new Error(`Failed to refresh token: ${error}`);
		}

		return response.json();
	}
}

export namespace LinkedInStrategy {
	export interface VerifyOptions {
		/** The request that triggered the verification flow */
		request: Request;
		/** The OAuth2 tokens retrieved from LinkedIn */
		tokens: {
			access_token: string;
			token_type: string;
			expires_in: number;
			refresh_token?: string;
			scope?: string;
		};
		/** The LinkedIn profile */
		profile: LinkedInProfile;
	}

	export interface ConstructorOptions {
		/**
		 * The name of the cookie used to keep state around.
		 * @default "linkedin"
		 */
		cookie?: string | (Omit<SetCookieInit, "value"> & { name: string });

		/**
		 * This is the Client ID of your LinkedIn application
		 */
		clientId: string;

		/**
		 * This is the Client Secret of your LinkedIn application
		 */
		clientSecret: string;

		/**
		 * The URL of your application where LinkedIn will redirect after authentication
		 */
		redirectURI: URL | string;

		/**
		 * The scopes you want to request from LinkedIn
		 * @default ["openid", "profile", "email"]
		 */
		scopes?: LinkedInScope[] | string;
	}
}
