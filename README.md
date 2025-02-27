# Remix Auth LinkedIn Strategy

The LinkedIn strategy is used for [Remix Auth](https://github.com/sergiodxa/remix-auth) authentication using OAuth 2.0 and OpenID Connect protocols with LinkedIn.

## Supported runtimes

| Runtime    | Has Support |
| ---------- | ----------- |
| Node.js    | ✅          |
| Cloudflare | ✅          |

## Installation

```bash
npm install remix-auth-linkedin
```

## Usage

### Create an OAuth application

First, create a new application in the [LinkedIn Developers portal](https://developer.linkedin.com/). Read the [LinkedIn documentation](https://learn.microsoft.com/en-us/linkedin/consumer/integrations/self-serve/sign-in-with-linkedin-v2) for details on configuring your app and understanding the authentication flow.

### Create the strategy instance

```ts
import { Authenticator } from "remix-auth";
import { LinkedInStrategy } from "remix-auth-linkedin";

// Create an instance of the authenticator
const authenticator = new Authenticator<User>();

// Register the LinkedIn strategy
authenticator.use(
  new LinkedInStrategy(
    {
      clientId: "YOUR_CLIENT_ID",
      clientSecret: "YOUR_CLIENT_SECRET",
      // LinkedIn requires a full URL, not a relative path
      redirectURI: "https://example.com/auth/linkedin/callback",
      // Optional: customize scopes
      scopes: ["openid", "profile", "email"],
    },
    async ({ profile, tokens, request }) => {
      // Find or create a user in your database
      return {
        id: profile.id,
        email: profile.emails[0].value,
        name: profile.displayName,
        accessToken: tokens.accessToken(),
        refreshToken: tokens.refreshToken ? tokens.refreshToken() : null,
      };
    }
  )
);
```

### Setup your routes

```tsx
// app/routes/login.tsx
import { Form } from "react-router";

export default function Login() {
  return (
    <Form action="/auth/linkedin" method="post">
      <button>Login with LinkedIn</button>
    </Form>
  );
}
```

```tsx
// app/routes/auth/linkedin.tsx
import type { ActionFunctionArgs } from "react-router";
import { authenticator } from "~/services/auth.server";

export function loader() {
  return { message: "This route is not meant to be visited directly." };
}

export async function action({ request }: ActionFunctionArgs) {
  return await authenticator.authenticate("linkedin", request);
}
```

### Handling the callback

The callback route handles the OAuth flow completion when LinkedIn redirects back to your application:

```tsx
// app/routes/auth/linkedin/callback.tsx
import type { LoaderFunctionArgs } from "react-router";
import { authenticator } from "~/services/auth.server";
import { redirect } from "react-router";
import { sessionStorage } from "~/services/session.server";

export async function loader({ request }: LoaderFunctionArgs) {
  // Check for required parameters (optional but recommended)
  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');

  if (!code || !state) {
    return redirect('/login?error=missing_params');
  }

  try {
    // Authenticate the user
    const user = await authenticator.authenticate("linkedin", request);
    
    // Create session and store the authenticated user
    // Reference implementation: https://github.com/sergiodxa/sergiodxa.com/blob/main/app/routes/auth.%24provider.callback.ts
    const session = await sessionStorage.getSession(
      request.headers.get("cookie")
    );
    
    session.set("user", user);
    
    // Prepare headers for the response
    const headers = new Headers();
    
    // Add the session cookie to headers
    headers.append(
      "Set-Cookie", 
      await sessionStorage.commitSession(session)
    );
    
    // Optional: Add a cookie to clear the auth state
    // If you're using the stateless approach with commitSession, you don't need this
    // headers.append("Set-Cookie", await auth.clear(request));
    
    // Redirect to dashboard with the session cookie
    return redirect('/dashboard', { headers });
  } catch (error) {
    // Handle authentication errors
    console.error('Authentication failed', error);
    return redirect('/login?error=auth_failed');
  }
}
```



## Configuration Options

`LinkedInStrategy` accepts the following configuration options:

```ts
interface LinkedInStrategy.ConstructorOptions {
  /**
   * The client ID for your LinkedIn application
   */
  clientId: string;
  
  /**
   * The client secret for your LinkedIn application
   */
  clientSecret: string;
  
  /**
   * The URL LinkedIn will redirect to after authentication
   */
  redirectURI: URL | string;
  
  /**
   * The scopes to request from LinkedIn
   * @default ["openid", "profile", "email"]
   */
  scopes?: LinkedInScope[] | string;
  
  /**
   * The name and options for the cookie used to store state
   * @default "linkedin"
   */
  cookie?: string | (Omit<SetCookieInit, "value"> & { name: string });
}
```

## User Profile

After successful authentication, you'll receive user data in this format:

```ts
interface LinkedInProfile {
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
```

## Refresh Token

If you need to refresh an access token, you can use the `refreshToken` method:

```ts
const strategy = new LinkedInStrategy(options, verify);
const tokens = await strategy.refreshToken(refreshToken);
```

The most common approach is to store the refresh token in the user data and then update it after refreshing:

```ts
authenticator.use(
  new LinkedInStrategy(
    options,
    async ({ tokens, profile, request }) => {
      let user = await findOrCreateUser(profile);
      return {
        ...user,
        accessToken: tokens.accessToken(),
        refreshToken: tokens.refreshToken ? tokens.refreshToken() : null,
      };
    }
  )
);

// Later in your code you can use it to get new tokens
const tokens = await strategy.refreshToken(user.refreshToken);
```

## Version Compatibility

- Version 3.x is compatible with Remix Auth v4.x
- Version 2.x is compatible with Remix Auth v3.x
- Version 1.x is compatible with Remix Auth v1.x and v2.x

## License

MIT
