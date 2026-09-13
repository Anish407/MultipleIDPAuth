# Lab 1 — Configure Entra ID for the WPF app

[Back to lab index](../../README.md)

This guide covers the implemented part of Lab 1: Entra app registrations, the shared WPF OIDC client, configuration, browser callbacks, and login troubleshooting. AWS deployment and API authentication tests will be documented as they are implemented.

Build this provider-neutral client once. A later Lab 2 guide will reuse the code with Cognito configuration.

## Current status

- The WPF project targets .NET Framework 4.8.1 and has Duende.IdentityModel.OidcClient 7.1.0 installed.
- The login UI, configuration loader, and browser callback adapter exist in source.
- Entra IDs are configured locally; portal settings have not been independently inspected.
- The reported discovery endpoint allowlist error was corrected. Successful login after that correction is not yet recorded.
- DPAPI persistence, startup restore, timer refresh, and local sign-out are implemented and covered by isolated session tests. Live Entra refresh, sleep/resume, API calls, and ALB enforcement still need end-to-end verification.

## Contents

- [Minimum design](#minimum-design)
- [Prerequisites](#prerequisites)
- [Entra app registrations](#entra-app-registrations)
- [WPF configuration](#wpf-configuration)
- [Code walkthrough](#code-walkthrough)
- [Build and verify client login](#build-and-verify-client-login)
- [Troubleshooting](#troubleshooting)

## Minimum design

```text
1. WPF reads provider configuration and discovers OIDC endpoints.
2. Duende prepares an authorization request with PKCE and state.
3. SystemBrowser starts a localhost callback listener and opens the browser.
4. The user signs in to Entra.
5. Entra redirects the browser to localhost with a code and state.
6. The adapter returns the callback URL to Duende.
7. Duende processes the response and exchanges the code for tokens.
8. WPF encrypts the session with Windows DPAPI and atomically persists it for restart.
9. Later: WPF sends the access token through CloudFront to ALB and ECS.
```

The browser receives an authorization code in this flow; the library exchanges it for tokens. PKCE binds the exchange to the client that initiated login using a per-login verifier and challenge. We do not write that protocol logic ourselves.

## Prerequisites

1. Use Visual Studio with WPF/.NET desktop tooling and the .NET Framework 4.8.1 targeting pack for the existing project.
2. Open `MultipleIDPAuth/MultipleIDPAuth.slnx` with a Visual Studio version that supports the solution format.
3. Restore NuGet packages.
4. Confirm the WPF project references `System.Configuration` and the installed Duende package.
5. Have access to an Entra tenant, permission to create registrations, and an administrator who can grant consent.
6. Use a test account allowed to sign in to the tenant.

Duende's OIDC client is provider-neutral, supports WPF/.NET Framework through .NET Standard, and is Apache-2.0 licensed. The maintained package is `Duende.IdentityModel.OidcClient`; the old unprefixed repository was moved. See the [library documentation](https://docs.duendesoftware.com/identitymodel-oidcclient/) and [maintained source](https://github.com/DuendeSoftware/foss).

## Entra app registrations

Create two registrations in the same tenant. They represent two OAuth roles, not two different IdPs or lab implementations.

| Registration | Purpose | ID used as |
|---|---|---|
| InfrastructureAuth-PoC-API | Resource receiving API access tokens | `API_APP_ID` |
| InfrastructureAuth-PoC-WPF | Public desktop client requesting tokens | `WPF_CLIENT_ID` |

### Register the API

1. Open [Entra admin center](https://entra.microsoft.com).
2. Navigate to **Entra ID → App registrations → New registration**.
3. Name it `InfrastructureAuth-PoC-API`.
4. Choose **Accounts in this organizational directory only**.
5. Leave the redirect URI empty and select **Register**.
6. Record **Application (client) ID** as `API_APP_ID` and **Directory (tenant) ID** as `TENANT_ID`.

The API registration supplies the identity of the resource. It does not install middleware or deploy an API. It needs no secret for this experiment.

### Expose the delegated scope

Under **Expose an API**, set the Application ID URI to `api://API_APP_ID`. Select **Add a scope**:

| Field | Value |
|---|---|
| Scope name | `access_as_user` |
| Who can consent | Admins only |
| Admin consent display name | Access the PoC API as the signed-in user |
| Admin consent description | Allows the desktop application to call the PoC API on behalf of the signed-in user. |
| State | Enabled |

The complete scope is `api://API_APP_ID/access_as_user`. It is a delegated permission because the application acts on behalf of a signed-in user. Creating this scope does not move business authorization to ALB. See [Microsoft's API scope guide](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-configure-app-expose-web-apis).

### Request v2 access tokens

In the **API registration → Manifest**, find the existing `api` object and set its `requestedAccessTokenVersion` property to `2`. Preserve the existing scope definitions and other properties. This is a fragment, not a replacement manifest:

```json
"api": {
  "requestedAccessTokenVersion": 2
}
```

The resource registration controls access-token format independently of which authorization endpoint the client uses. Setting a `/v2.0` authority alone does not guarantee a v2 access token. See [Microsoft's apiApplication reference](https://learn.microsoft.com/en-us/graph/api/resources/apiapplication?view=graph-rest-1.0).

### Register the WPF client

1. Create another registration named `InfrastructureAuth-PoC-WPF`.
2. Select the same single-tenant account type.
3. Register it and record its Application (client) ID as `WPF_CLIENT_ID`.
4. Open **Authentication → Add a platform → Mobile and desktop applications**.
5. Add the custom redirect URI `http://localhost:7890/callback/` and save.

Use the desktop platform, not Web or SPA. Preserve the callback path and trailing slash used by the adapter. Do not create a client secret. Do not enable implicit-grant ID/access-token checkboxes: tokens are obtained through code exchange.

The separate **Allow public client flows** fallback switch is not required for this redirect-based desktop authorization-code flow; configuring the mobile/desktop redirect identifies the client type. It is relevant to other flows such as device code. See [Microsoft's desktop registration guide](https://learn.microsoft.com/en-us/entra/identity-platform/scenario-desktop-app-registration) and [redirect URI rules](https://learn.microsoft.com/en-us/entra/identity-platform/reply-url).

### Grant API permission and consent

In the **WPF registration**:

1. Open **API permissions → Add a permission → My APIs**.
2. Select `InfrastructureAuth-PoC-API`.
3. Choose **Delegated permissions → access_as_user**.
4. Add the permission.
5. Have an authorized administrator select **Grant admin consent** for the tenant.
6. Confirm the permission is granted.

Microsoft Graph `User.Read` is not required for this experiment. If tenant policy or enterprise-app assignment restricts sign-in, ensure the test user is allowed. Consent and user assignment are separate checks.

## WPF configuration

Add these settings inside the existing `<configuration>` element of [App.config](../../MultipleIDPAuth.Client/App.config). Preserve startup settings and any binding redirects added by NuGet.

```xml
<appSettings>
  <add key="Oidc.LoginPrompt" value="select_account" />
  <add key="Session.AbsoluteLifetimeMinutes" value="180" />
  <add key="Oidc.Authority"
       value="https://login.microsoftonline.com/TENANT_ID/v2.0" />
  <add key="Oidc.ClientId" value="WPF_CLIENT_ID" />
  <add key="Oidc.RedirectUri" value="http://localhost:7890/callback/" />
  <add key="Oidc.Scope"
       value="openid profile offline_access api://API_APP_ID/access_as_user" />
  <add key="Oidc.AdditionalEndpointBaseAddresses"
       value="https://login.microsoftonline.com/TENANT_ID;https://login.microsoftonline.com/common;https://graph.microsoft.com" />
</appSettings>
```

### What each setting means

| Setting | Meaning |
|---|---|
| Authority | Tenant-specific issuer/discovery base; the client retrieves its OIDC metadata |
| ClientId | WPF registration ID, not the API registration ID |
| RedirectUri | Browser callback on the user's computer; not an ECS or CloudFront endpoint |
| Scope | Space-separated permissions and OIDC scopes requested during login |
| AdditionalEndpointBaseAddresses | Our custom configuration key mapped to Duende's discovery endpoint allowlist; entries are semicolon-separated |

| Scope | Purpose |
|---|---|
| `openid` | Request OpenID Connect sign-in and an ID token |
| `profile` | Request standard profile claims; individual claims may be absent |
| `offline_access` | Request refresh-token capability from Entra, subject to provider policy |
| `api://API_APP_ID/access_as_user` | Request an access token for our API |

### Why additional endpoint addresses are needed

The authority contains `login.microsoftonline.com/TENANT_ID/v2.0`, but discovery can advertise endpoints on different paths or hosts. Entra's UserInfo endpoint is `https://graph.microsoft.com/oidc/userinfo`.

Duende validates discovered endpoint locations. The explicit allowlist accommodates the known layout without turning off endpoint validation. The tenant base permits endpoints outside `/v2.0`; `/common` accommodates shared Entra endpoint paths; the Graph base permits the advertised UserInfo location. Only retain addresses required by the provider metadata used by the deployment.

This key is not an OIDC protocol parameter, permission grant, audience setting, or list of accepted token issuers. Allowing Graph here neither requests a Graph token nor grants Graph permissions. See [Duende's discovery policy documentation](https://docs.duendesoftware.com/identitymodel/endpoints/discovery/).

## Code walkthrough

The linked source files are the implementation; this walkthrough explains their behavior without maintaining a second full copy of the code.

### MainWindow.xaml — UI

[MainWindow.xaml](../../MultipleIDPAuth.Client/MainWindow.xaml) contains a `LoginButton` connected to `LoginButton_Click` and a wrapping `StatusText`. Status shows token presence and expiration, not raw token contents.

### MainWindow.xaml.cs — session orchestration

[MainWindow.xaml.cs](../../MultipleIDPAuth.Client/MainWindow.xaml.cs) retains the provider configuration methods. It now uses `TokenSessionService` instead of holding the original `LoginResult` indefinitely.

- On startup, it reads the encrypted cache and refreshes if necessary before reporting the session as restored.
- A one-shot `DispatcherTimer` schedules the next expiration-based check. Network/storage failures retry after 30 seconds. The request-time service method remains necessary after sleep/resume.
- Interactive login captures a cache generation before opening the browser. Saving succeeds only if that generation is still current, so a concurrent logout or account change prevents stale login completion from restoring a session.
- Interactive login and refresh use separate `OidcClient` objects to avoid concurrent modification of discovery options.
- The **Clear local session** button clears persisted credentials. It does not revoke already-issued JWTs or end the IdP browser session.
- Closing the window stops the timer and cancels pending work; it intentionally retains the encrypted session for restart.
- UI errors use fixed messages rather than exposing token response contents.

Every future API call must obtain a token immediately before sending:

```csharp
var token = await _session.GetValidAccessTokenAsync(cancellationToken);
request.Headers.Authorization =
    new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
```

Use this only for the intended API host. The service does not automatically replay API requests or treat arbitrary 403 responses as refresh signals. No API button or backend endpoint is added by this session change.

### DpapiTokenStore.cs — encrypted persistence

[DpapiTokenStore.cs](../../MultipleIDPAuth.Client/DpapiTokenStore.cs) writes to:

```text
%LOCALAPPDATA%\MultipleIDPAuth\Auth\<configuration-hash>\session.dat
```

The hash includes authority, client ID, and normalized scopes. Records contain schema version, configuration binding, session generation, subject, display name, access token, refresh token, expiry, and refresh/retry timing. ID tokens are not persisted because no implemented feature needs them.

Windows DPAPI `CurrentUser` encrypts the serialized record; the directory ACL grants access only to the current Windows user. A temporary encrypted file is flushed to disk before atomic replacement. Temporary files are removed after normal write failure/success. A process crash can leave an encrypted temporary file; it is never used as the active cache.

Plain serialized byte buffers are cleared after use. Managed token strings necessarily exist transiently during use and cannot be reliably zeroed. DPAPI protects data at rest, not against a compromised process or malicious code running as the same Windows user.

Missing, invalid-version, mismatched, corrupt, or undecryptable records become an empty encrypted record with a new generation. Access-denied and other I/O failures are surfaced; they are not treated as successful logout. The empty generation record is deliberately retained after logout so pending login writes cannot resurrect cleared credentials.

### TokenSessionService.cs — refresh and concurrency

[TokenSessionService.cs](../../MultipleIDPAuth.Client/TokenSessionService.cs) executes cache transactions on worker threads. A named Windows mutex, scoped by Windows user and configuration, coordinates processes. The lock is acquired and released on the same worker thread; no `await` crosses mutex ownership.

Each refresh transaction reloads the latest stored record and rechecks expiration. Only one process refreshes at a time, and waiting callers consume the committed replacement. Refresh happens up to 60 seconds early (20% of remaining lifetime for short-lived tokens). A replacement refresh token is retained when supplied; omission preserves the prior refresh token.

After successful remote rotation, the service attempts to persist the new tokens even if cancellation has just arrived. Local logout waits for this transaction and then clears the record. A crash between remote rotation and local persistence cannot be made transactional across the IdP and filesystem; interactive sign-in may be needed to recover.

`invalid_grant`, `login_required`, `interaction_required`, and `consent_required` clear credentials and require login. Other refresh failures retain the cache and persist a 30-second retry delay. No expired token is returned after refresh failure. Repeated configuration failures require investigation; the UI intentionally does not display raw provider responses.

An application instance binds to a session generation. If another instance changes accounts or signs out, the old instance requires login instead of silently adopting another account. The current design supports one active account per provider/client/scope configuration; it is not a multi-account picker.

### Session validation

The dependency-free console test project is [SessionTests](../../SessionTests/SessionTests.csproj). It compiles the session sources and uses a fake OIDC refresh response, with dummy tokens in a supplied test directory. It does not read the production token cache or call Entra.

From a Visual Studio Developer PowerShell in the solution directory:

```powershell
msbuild SessionTests/SessionTests.csproj /t:Build
& ./SessionTests/bin/Debug/SessionTests.exe "$PWD/SessionTests/artifacts/$([Guid]::NewGuid().ToString('N'))"
```

Verified: encrypted roundtrip, absence of plaintext token in cache, scope normalization, configuration isolation, concurrent cross-process updates, corrupt-cache recovery, concurrent refresh deduplication, persisted rotation, logout versus pending login, and normal temporary-file cleanup.

Still required before production deployment: real Entra refresh/revocation, Cognito compatibility in Lab 2, laptop sleep/resume, process termination during write/rotation, actual Windows-user isolation, disk-full/permission-denied behavior, application close/logout under slow network, and API request integration. Automated tests are evidence for these components, not a production security certification.

### SystemBrowser.cs — browser and callback transport

[SystemBrowser.cs](../../MultipleIDPAuth.Client/SystemBrowser.cs) implements Duende's `IBrowser.InvokeAsync`:

1. Parses `options.EndUrl`, requiring HTTP, `localhost`, and a trailing slash.
2. Creates `HttpListener` for that callback prefix **before** opening the browser.
3. Creates a linked cancellation source with a hard-coded five-minute timeout.
4. Opens `options.StartUrl` using the operating system's default browser through `UseShellExecute = true`.
5. Awaits incoming callback requests asynchronously.
6. Returns 404 for a non-GET request, wrong path, or request with neither `code` nor `error`.
7. Returns a small HTML page with `Cache-Control: no-store` and `Referrer-Policy: no-referrer`.
8. Passes the full callback URL back to Duende for protocol processing.
9. Closes the listener on cancellation/disposal and distinguishes cancellation from timeout in its result.

`BrowserResultType.Success` means a callback was transported successfully. It does not mean authentication succeeded: the callback can contain an OAuth error, and Duende still processes state and the token exchange.

The adapter intentionally does not construct authorization requests, generate PKCE, exchange codes, or parse JWTs. Those belong to the library. Its current limitations are a fixed port, GET/query callbacks only, and a hard-coded timeout rather than using the requested browser timeout. A callback-write failure can also surface as a login error. It is a minimal PoC adapter, not a complete desktop session manager.

## Build and verify client login

1. Save the configuration with the actual Entra values.
2. Set `MultipleIDPAuth.Client` as the startup project.
3. Stop any running instance, rebuild, and run it.
4. Click **Sign in** and complete browser authentication/consent.
5. Confirm the browser callback page appears and return to WPF.
6. Confirm WPF reports an ID token and an access token, a user identifier, and an expiration time.
7. Record whether a refresh token was returned.

Configuration changes require rebuilding/restarting the Visual Studio run: `App.config` is copied into the application's output configuration and `_oidcClient` caches its options for the current process.

Successful browser login proves client credential acquisition only. It does not prove ALB enforcement. Tokens should remain out of logs and documentation; use local debugging to inspect claims when needed. Decoding a JWT for diagnostics is not signature validation.

## Troubleshooting

| Symptom | Explanation / next check |
|---|---|
| Different-host error for Graph UserInfo | Add the expected Graph endpoint base to configuration; keep discovery validation enabled |
| Same error after editing config | Stop/rebuild/restart; inspect the output `.exe.config` and ensure the intended startup project is running |
| Redirect URI mismatch | Compare the requested callback with the desktop registration, especially path and trailing slash |
| Invalid scope / consent required | Check API scope spelling, enabled state, WPF delegated permission, and admin consent |
| Secret required / invalid client | Verify WPF client ID and mobile/desktop platform; do not solve a desktop registration mistake by embedding a secret |
| Listener access denied / port conflict | Inspect local listener permissions and port 7890 ownership; do not assume the whole app needs administrator privileges |
| Browser closed, WPF still waiting | Closing a browser tab does not send a callback; the current adapter waits until cancellation or its five-minute timeout |
| Tokens returned but API rejects request | Verify access-token audience/issuer/expiration and ALB policy separately |

### Recorded discovery issue

Observed error:

```text
Sign-in failed: Error loading discovery document:
Endpoint is on a different host than authority:
https://graph.microsoft.com/oidc/userinfo
```

The local allowlist originally contained only the tenant base. We added the Graph and `/common` bases. The Graph addition directly addresses the reported endpoint rejection. XML validity was checked; successful login after this correction has not yet been recorded. This failure occurred during discovery, before user authentication.




## Configurable application-session duration

`Session.AbsoluteLifetimeMinutes` in the WPF `App.config` is required and defaults in this deployment to `180` (three hours). Valid values are whole minutes from 1 to 525600. Rebuild/restart after configuration changes.

- Successful interactive sign-in starts a new duration.
- Application restart resets the duration when cached credentials exist. Startup still checks access-token validity and refreshes when needed; it cannot restore revoked refresh tokens.
- Token refresh during the same run does not extend the deadline.
- Timer scheduling is capped by the session deadline, including during refresh retry backoff.
- Request-time checks enforce the deadline after sleep/resume. The service also checks after an in-flight refresh completes.
- At expiry, stored credentials are cleared and interactive login is required. Restart after credentials were cleared does not recover them.
- `Oidc.LoginPrompt` controls interactive sign-in. The Entra test configuration uses `select_account` to show remembered accounts and a Use another account option. This requests account selection, not mandatory password re-entry. `login` requests reauthentication. Provider support must be verified when switching to Cognito. Session expiration still clears the local credentials regardless of this prompt setting.
- Each running instance retains its own deadline so starting another instance cannot extend it. Credentials are shared for the same configuration: logout or expiry in one instance clears the shared cache for all instances.

This is a desktop application-session limit. It does not revoke previously issued access tokens, cancel already-running API operations, or constitute an infrastructure-enforced maximum IdP authentication age. Local configuration and clock are controlled by the machine; a mandatory security boundary against client tampering must also be enforced by the IdP/infrastructure. Restart reset is intentional and means a user can extend application access by restarting before the local deadline.

Tests cover unchanged deadline on refresh, reset on restart, expiry at the exact deadline without a refresh attempt, isolation from another running instance's restart, and restart with a cleared cache.

