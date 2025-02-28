import { Cookie, SetCookie, type SetCookieInit } from "@mjackson/headers";
import {
	LinkedIn,
	OAuth2RequestError,
	type OAuth2Tokens,
	UnexpectedErrorResponseBodyError,
	UnexpectedResponseError,
	generateState,
} from "arctic";
import createDebug from "debug";
import { Strategy } from "remix-auth/strategy";
import { redirect } from "./lib/redirect.js";

type URLConstructor = ConstructorParameters<typeof URL>[0];

const debug = createDebug("LinkedInStrategy");

export type LinkedInScope = "openid" | "profile" | "email";

export {
	OAuth2RequestError,
	UnexpectedResponseError,
	UnexpectedErrorResponseBodyError,
};

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

	protected client: LinkedIn;

	constructor(
		protected options: LinkedInStrategy.ConstructorOptions,
		verify: Strategy.VerifyFunction<User, LinkedInStrategy.VerifyOptions>,
	) {
		super(verify);

		this.client = new LinkedIn(
			options.clientId,
			options.clientSecret,
			options.redirectURI.toString(),
		);
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

		let stateUrl = url.searchParams.get("state");
		let error = url.searchParams.get("error");

		if (error) {
			let description = url.searchParams.get("error_description");
			let uri = url.searchParams.get("error_uri");
			throw new OAuth2RequestError(error, description, uri, stateUrl);
		}

		if (!stateUrl) {
			debug("No state found in the URL, redirecting to authorization endpoint");

			let state = generateState();

			debug("Generated State", state);

			let url = this.client.createAuthorizationURL(
				state,
				Array.isArray(this.options.scopes)
					? this.options.scopes
					: this.options.scopes
						? (this.options.scopes.split(
								LinkedInStrategyScopeSeparator,
							) as LinkedInScope[])
						: (["openid", "profile", "email"] as LinkedInScope[]),
			);

			url.search = this.authorizationParams(
				url.searchParams,
				request,
			).toString();

			debug("Authorization URL", url.toString());

			let header = new SetCookie({
				name: this.cookieName,
				value: new URLSearchParams({ state }).toString(),
				httpOnly: true, // Prevents JavaScript from accessing the cookie
				maxAge: 60 * 5, // 5 minutes
				path: "/", // Allow the cookie to be sent to any path
				sameSite: "Lax", // Prevents it from being sent in cross-site requests
				...this.cookieOptions,
			});

			throw redirect(url.toString(), {
				headers: { "Set-Cookie": header.toString() },
			});
		}

		let code = url.searchParams.get("code");

		if (!code) throw new ReferenceError("Missing code in the URL");

		let cookie = new Cookie(request.headers.get("cookie") ?? "");
		let params = new URLSearchParams(cookie.get(this.cookieName) || "");

		if (!params.has("state")) {
			throw new ReferenceError("Missing state on cookie.");
		}

		if (params.get("state") !== stateUrl) {
			throw new RangeError("State in URL doesn't match state in cookie.");
		}

		debug("Validating authorization code");
		let tokens = await this.client.validateAuthorizationCode(code);

		debug("Fetching user profile");
		let profile = await this.userProfile(tokens.accessToken());

		debug("Verifying the user profile");
		let user = await this.verify({ request, tokens, profile });

		debug("User authenticated");
		return user;
	}

	/**
	 * Return extra parameters to be included in the authorization request.
	 *
	 * Some OAuth 2.0 providers allow additional, non-standard parameters to be
	 * included when requesting authorization.  Since these parameters are not
	 * standardized by the OAuth 2.0 specification, OAuth 2.0-based authentication
	 * strategies can override this function in order to populate these
	 * parameters as required by the provider.
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
	 * Get a new OAuth2 Tokens object using the refresh token once the previous
	 * access token has expired.
	 * @param refreshToken The refresh token to use to get a new access token
	 * @returns The new OAuth2 tokens object
	 * @example
	 * ```ts
	 * let tokens = await strategy.refreshToken(refreshToken);
	 * console.log(tokens.accessToken());
	 * ```
	 */
	public refreshToken(refreshToken: string) {
		return this.client.refreshAccessToken(refreshToken);
	}
}

export namespace LinkedInStrategy {
	export interface VerifyOptions {
		/** The request that triggered the verification flow */
		request: Request;
		/** The OAuth2 tokens retrieved from LinkedIn */
		tokens: OAuth2Tokens;
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
		redirectURI: URLConstructor;

		/**
		 * The scopes you want to request from LinkedIn
		 * @default ["openid", "profile", "email"]
		 */
		scopes?: LinkedInScope[] | string;
	}
}
