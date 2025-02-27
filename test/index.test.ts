import { afterEach, beforeEach, describe, expect, mock, test } from "bun:test";
import { Cookie, SetCookie } from "@mjackson/headers";
import {
	LinkedInScope,
	LinkedInStrategy,
	LinkedInStrategyDefaultName,
	LinkedInStrategyDefaultScopes,
} from "../src/index.js";
import { catchResponse } from "../src/test/helpers.js";

// Mock Arctic's fetch calls
const originalFetch = global.fetch;

describe(LinkedInStrategy.name, () => {
	let verify = mock();

	let options = Object.freeze({
		clientId: "LINKEDIN_CLIENT_ID",
		clientSecret: "LINKEDIN_CLIENT_SECRET",
		redirectURI: "https://example.com/auth/linkedin/callback",
		scopes: ["openid", "profile", "email"] as LinkedInScope[],
	} satisfies LinkedInStrategy.ConstructorOptions);

	interface User {
		id: string;
		email: string;
	}

	beforeEach(() => {
		// Mock fetch requests
		global.fetch = mock((input) => {
			const url =
				typeof input === "string"
					? input
					: input instanceof URL
						? input.toString()
						: input.url;

			if (url.includes("oauth/v2/accessToken")) {
				return Promise.resolve(
					new Response(
						JSON.stringify({
							access_token: "mocked-access-token",
							expires_in: 3600,
							refresh_token: "mocked-refresh-token",
							scope: "openid profile email",
							token_type: "Bearer",
						}),
						{ status: 200, headers: { "Content-Type": "application/json" } },
					),
				);
			}

			if (url.includes("api.linkedin.com/v2/userinfo")) {
				return Promise.resolve(
					new Response(
						JSON.stringify({
							sub: "12345",
							name: "John Doe",
							given_name: "John",
							family_name: "Doe",
							picture: "https://example.com/profile.jpg",
							locale: "en-US",
							email: "john.doe@example.com",
							email_verified: true,
						}),
						{ status: 200, headers: { "Content-Type": "application/json" } },
					),
				);
			}

			return Promise.reject(new Error(`Unhandled fetch to ${url}`));
		});
	});

	afterEach(() => {
		verify.mockReset();
		global.fetch = originalFetch;
	});

	test("should have the name of the strategy", () => {
		let strategy = new LinkedInStrategy<User>(options, verify);
		expect(strategy.name).toBe(LinkedInStrategyDefaultName);
	});

	test("should allow changing the scope", async () => {
		let customScopes = ["openid", "profile"] as LinkedInScope[];
		let strategy = new LinkedInStrategy<User>(
			{ ...options, scopes: customScopes },
			verify,
		);

		// Test if the scope is correctly set
		let request = new Request("https://remix.auth/login");

		let response = await catchResponse(strategy.authenticate(request));
		let location = response.headers.get("location");
		expect(location).toContain("scope=openid+profile");
	});

	test(`should have the scope ${LinkedInStrategyDefaultScopes} as default`, async () => {
		let strategy = new LinkedInStrategy<User>(
			{ ...options, scopes: undefined },
			verify,
		);

		// Test if the default scope is correctly set
		let request = new Request("https://remix.auth/login");

		let response = await catchResponse(strategy.authenticate(request));
		let location = response.headers.get("location");
		expect(location).toContain("scope=openid+profile+email");
	});

	test("should correctly format the authorization URL", async () => {
		let strategy = new LinkedInStrategy<User>(options, verify);

		let request = new Request("https://remix.auth/login");

		let response = await catchResponse(strategy.authenticate(request));

		// biome-ignore lint/style/noNonNullAssertion: This is a test
		let redirect = new URL(response.headers.get("location")!);

		let setCookie = new SetCookie(response.headers.get("set-cookie") ?? "");
		let params = new URLSearchParams(setCookie.value);

		expect(redirect.hostname).toBe("www.linkedin.com");
		expect(redirect.pathname).toBe("/oauth/v2/authorization");
		expect(redirect.searchParams.get("client_id")).toBe(options.clientId);
		expect(redirect.searchParams.get("redirect_uri")).toBe(
			options.redirectURI.toString(),
		);
		expect(redirect.searchParams.has("state")).toBeTruthy();

		// Use a more flexible check, as different environments may have different encodings
		const scope = redirect.searchParams.get("scope");
		expect(scope).toBeTruthy();
		expect(scope?.includes("openid")).toBeTruthy();
		expect(scope?.includes("profile")).toBeTruthy();
		expect(scope?.includes("email")).toBeTruthy();

		expect(redirect.searchParams.get("response_type")).toBe("code");

		expect(params.has("state")).toBeTruthy();
		expect(params.get("state")).toBe(redirect.searchParams.get("state"));
	});

	test("throws if there's no state in the session", async () => {
		let strategy = new LinkedInStrategy<User>(options, verify);

		let request = new Request(
			"https://example.com/callback?state=random-state&code=random-code",
		);

		expect(strategy.authenticate(request)).rejects.toThrowError(
			new ReferenceError("Missing state on cookie."),
		);
	});

	test("throws if the state in the url doesn't match the state in the session", async () => {
		let strategy = new LinkedInStrategy<User>(options, verify);

		let cookie = new Cookie();
		cookie.set(
			"linkedin",
			new URLSearchParams({ state: "random-state" }).toString(),
		);

		let request = new Request(
			"https://example.com/callback?state=another-state&code=random-code",
			{ headers: { Cookie: cookie.toString() } },
		);

		expect(strategy.authenticate(request)).rejects.toThrowError(
			new RangeError("State in URL doesn't match state in cookie."),
		);
	});

	test("calls verify with the tokens, profile and request", async () => {
		let strategy = new LinkedInStrategy<User>(options, verify);

		let cookie = new Cookie();
		cookie.set(
			"linkedin",
			new URLSearchParams({ state: "random-state" }).toString(),
		);

		let request = new Request(
			"https://example.com/callback?state=random-state&code=random-code",
			{ headers: { cookie: cookie.toString() } },
		);

		await strategy.authenticate(request);

		expect(verify).toHaveBeenCalled();
		const verifyArg = verify.mock.calls[0][0];
		expect(verifyArg).toHaveProperty("request");
		expect(verifyArg).toHaveProperty("tokens");
		expect(verifyArg).toHaveProperty("profile");

		expect(verifyArg.tokens.accessToken()).toBe("mocked-access-token");
		expect(verifyArg.profile.id).toBe("12345");
		expect(verifyArg.profile.emails[0].value).toBe("john.doe@example.com");
	});

	test("returns the result of verify", async () => {
		let user = { id: "12345", email: "john.doe@example.com" };
		verify.mockResolvedValueOnce(user);

		let strategy = new LinkedInStrategy<User>(options, verify);

		let cookie = new Cookie();
		cookie.set(
			"linkedin",
			new URLSearchParams({ state: "random-state" }).toString(),
		);

		let request = new Request(
			"https://example.com/callback?state=random-state&code=random-code",
			{ headers: { cookie: cookie.toString() } },
		);

		const result = await strategy.authenticate(request);
		expect(result).toEqual(user);
	});

	test("should handle custom cookie name", async () => {
		let strategy = new LinkedInStrategy<User>(
			{ ...options, cookie: "custom-linkedin-cookie" },
			verify,
		);

		let request = new Request("https://remix.auth/login");

		let response = await catchResponse(strategy.authenticate(request));
		let setCookie = new SetCookie(response.headers.get("set-cookie") ?? "");

		expect(setCookie.name).toBe("custom-linkedin-cookie");
	});

	test("should handle custom cookie options", async () => {
		let strategy = new LinkedInStrategy<User>(
			{
				...options,
				cookie: {
					name: "custom-linkedin-cookie",
					sameSite: "Strict",
					secure: true,
					maxAge: 600, // 10 minutes
				},
			},
			verify,
		);

		let request = new Request("https://remix.auth/login");

		let response = await catchResponse(strategy.authenticate(request));
		let setCookie = new SetCookie(response.headers.get("set-cookie") ?? "");

		expect(setCookie.name).toBe("custom-linkedin-cookie");
		expect(setCookie.sameSite).toBe("Strict");
		expect(setCookie.secure).toBe(true);
		expect(setCookie.maxAge).toBe(600);
	});

	test("should handle refresh token", async () => {
		// Mock for refresh token testing
		const refreshMock = mock((input) => {
			const url =
				typeof input === "string"
					? input
					: input instanceof URL
						? input.toString()
						: input.url;

			if (url.includes("oauth/v2/accessToken")) {
				return Promise.resolve(
					new Response(
						JSON.stringify({
							access_token: "new-access-token",
							expires_in: 3600,
							refresh_token: "new-refresh-token",
							scope: "openid profile email",
							token_type: "Bearer",
						}),
						{ status: 200, headers: { "Content-Type": "application/json" } },
					),
				);
			}

			return Promise.reject(new Error(`Unhandled fetch to ${url}`));
		});

		// Replace global fetch
		global.fetch = refreshMock;

		let strategy = new LinkedInStrategy<User>(options, verify);
		const tokens = await strategy.refreshToken("mocked-refresh-token");

		expect(tokens.accessToken()).toBe("new-access-token");
		expect(tokens.refreshToken()).toBe("new-refresh-token");
	});
});
