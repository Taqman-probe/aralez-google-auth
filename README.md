# aralez-google-auth

`aralez-google-auth` is a Google OAuth 2.0 authentication plugin designed for the aralez reverse proxy.

It provides a stateless authentication flow utilizing PKCE (Proof Key for Code Exchange) alongside a custom cookie-based session management system.

## Features
- PKCE (S256) Support: Implements SHA-256 based PKCE within the Google OAuth authorization code flow to ensure secure code exchanges. 
- Stateless Architecture: Utilizes a signed temporary JWT in the `state` parameter during the authorization flow. This allows the server to restore the user's original destination URL without holding any session state on the server side.
- Custom JWT Sessions: Extracts the authenticated user's email address from Google to issue a custom session JWT (valid for 24 hours), which manages access authorization via Cookies.
- Plug & Play: Integrates seamlessly via the `inventory` plugin system. Simply configure it, and it will be dynamically loaded and registered automatically.

## Authentication Flow

1. Access Validation: The plugin checks and validates the session JWT present in the incoming request's Cookie. If the request is fully authenticated, it is proxied directly to the backend.
2. Redirection to Google Authorization: If the user is unauthenticated, the plugin generates a PKCE code challenge and a state-restoration JWT (`state`). It then redirects the user to the Google Authorization page ([https://accounts.google.com/o/oauth2/v2/auth](https://accounts.google.com/o/oauth2/v2/auth)).
3. Callback Processing & Token Validation: After the user authenticates with Google, they are redirected back to the path defined in `redirect_uri` along with an authorization code. The plugin captures this code and requests an ID token from the Google Token API.
4. Session Issuance & Final Redirection: The plugin extracts the user's email from the validated ID token, generates a custom session JWT, and sets it using a `Set-Cookie` header. Finally, the user is redirected back to the URL they originally attempted to access.

## Required Environment Variables
The plugin requires the following environment variable to be set for cryptographic operations:
- `JWT_KEY`: The secret key used for signing and decrypting the stateless `state` tokens as well as the custom session JWTs.  

## Configuration
You can configure this plugin using your application's configuration file (compatible with ``noyalib` / YAML structures) by specifying the `google` auth plugin type.

## Configuration Items (GoogleAuthConfig)

| Key | Type | Required | Description |
| --- | --- | --- | --- |
| `type` | String | Required | Must be set to `"google"` to select this plugin. |
| `data` | Object | Required | The configuration data for the Google Auth plugin. |
| `└─client_id` | String | Required | The Client ID obtained from your Google Cloud Console. |
| `└─client_secret` | String | Required | The Client Secret obtained from your Google Cloud Console. |
| `└─redirect_uri` | String | Required | The authorized OAuth 2.0 redirect URI (e.g., [https://myproxy.example.com/auth/google/callback](https://myproxy.example.com/auth/google/callback)). |
| `└─cookie_name` | String | Optional | The name of the Cookie used to store the session JWT. Defaults to `"aralez_session"` if omitted. |

## Configuration Example (YAML)
### upstreams.yaml
```yaml
  authorization:
    type: "google"
    data:
      client_id: "1234567890-example.apps.googleusercontent.com"
      client_secret: "GOCSPX-example_secret"
      redirect_uri: "https://myproxy.example.com/auth/google/callback"
      cookie_name: "aralez_session"
```

## License

Licensed under the Apache License, Version 2.0.
