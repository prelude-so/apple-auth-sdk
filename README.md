# Readme
### Usage

The Apple Auth SDK lets you sign users into your iOS app and manages the resulting session (tokens, refresh, logout) against the Prelude Auth API.

It is provided as a regular Swift package that you can [import as a dependency directly into your iOS application](https://developer.apple.com/documentation/xcode/adding-package-dependencies-to-your-app).

### Requirements

- iOS deployment target **15.0+**
- Swift tools **5.7+** (Xcode 14 or later)

#### Email OTP login

Send a one-time code to the user's email address, then submit the code they entered. The SDK persists the resulting tokens in the Keychain.

```
import PreludeAuth

let client = try PreludeAuthClient()

try await client.startOTPLogin(
    StartOTPLoginOptions(
        identifier: PreludeIdentifier(type: .emailAddress, value: "alice@example.com")
    )
)

let user = try await client.checkOTP("123456")
```

If the user wants the code resent, call `client.resendOTP()`.

#### Email and password login

```
let user = try await client.loginWithPassword(
    LoginWithPasswordOptions(
        emailAddress: "alice@example.com",
        password: "correct horse battery staple"
    )
)
```

#### Password validation

Validate a candidate password against the project's policy in one call:

```
let result = try await client.validatePassword("candidate")
if result.valid {
    // ok to submit
}
```

Or fetch the policy once and classify locally, useful for live-as-you-type validation:

```
let policy = try await client.passwordCompliancy()
let result = PreludeAuthClient.validate(password: "candidate", against: policy)
```

#### Session lifecycle

```
try await client.refresh()      // refreshes the access token
try await client.logout()       // revokes the session and clears local tokens

let profile = await client.profile      // currently signed-in user, if any
let token   = await client.accessToken  // the access token, if any
```

Protected requests auto-refresh expired access tokens transparently, so most apps will not need to call `refresh()` explicitly.

#### Step-up authentication

Some operations (e.g. changing the password) require a fresh proof of identity. Request the scope, deliver the OTP, then submit the code:

```
let challenge = try await client.requestStepUp(scope: "prld:pwd:write")
try await client.sendStepUpOTP(challenge)            // POST /otp
let next = try await client.submitStepUpOTP(challenge, code: "123456")

// `next == nil` means the flow completed and the session now
// carries the requested scope. A non-nil value is the next
// challenge in a multi-step flow — call `sendStepUpOTP` on it
// to deliver the next code.
```

When `challenge.currentStep` is `verify_passkey`, advance the step by asserting a passkey instead of submitting a code:

```
let next = try await client.continueStepUpWithPasskey(challenge)
```

`client.activeStepUp` exposes the most recent in-flight challenge so a UI can resume from a cold start.

#### Passkeys

Register a passkey, sign in with one, and manage them. Registration requires the session to hold `prld:passkey:write`, which is granted by a step-up — elevate first, then register:

```
let challenge = try await client.requestStepUp(scope: "prld:passkey:write")
try await client.sendStepUpOTP(challenge)
try await client.submitStepUpOTP(challenge, code: "123456")

let result = try await client.registerPasskey(
    RegisterPasskeyOptions(username: "you@example.com")
)
```

Passwordless sign-in — no OTP or password. Pass `.init(autofill: true)` to surface passkeys inline on a username field instead of a modal sheet:

```
let user = try await client.loginWithPasskey()
```

List, rename, and remove credentials. An empty `nickname` clears the label:

```
let passkeys = try await client.listPasskeys()
try await client.renamePasskey(passkeys[0].credentialID, nickname: "My iPhone")
try await client.deletePasskey(passkeys[0].credentialID)
```

**Prerequisite — Associated Domains.** Add the `webcredentials:<rp-id>` entitlement to your app, where `<rp-id>` is the relying-party id from your app's passkey configuration — the host that serves `/.well-known/apple-app-site-association`. The system verifies this association before any passkey ceremony; without it registration and login fail. Requires iOS 16 or later.

Operators enable passkeys by setting the passkey configuration on the app (relying-party id, allowed origins, `login_enabled`, and the authorised `ios_app_ids`). The relying-party host then serves the association document automatically.

The step-up that grants `prld:passkey:write` must use grant mode `session-bound` or `profile-bound`, not `single-use` — registration verifies the scope against the session, so a single-use grant (which lives only on the token) is not honoured.

#### Change password

After completing a step-up for `prld:pwd:write`:

```
try await client.changePassword(RedactedString("new-password"))
```

The SDK drops the granted scope locally on success so the same token cannot reset the password again.

#### Manage active sessions

List the user's sessions across devices and revoke them individually or in bulk:

```
let page = try await client.listSessions(ListSessionsOptions(limit: 20))

try await client.revokeSessions(.others)            // keep this device, sign out the rest
try await client.revokeSessions(.session(id: id))   // revoke a specific session
try await client.revokeSessions(.all)               // including this device
```

Revoking the current session (`.all`, `.mine`, or its specific id) also wipes the local credentials, mirroring `logout()`.

#### Migrate a legacy session

Exchange an existing bearer token from a previous authentication system for a Prelude session:

```
let user = try await client.migrate(MigrateOptions(token: "legacy-bearer"))
```

Idempotent: a valid cached session short-circuits the network call, so it is safe to call on every launch.

#### Endpoint configuration

```
let client = try PreludeAuthClient(
    endpoint: .default,                   // or .custom("https://staging.example")
    timeout: 10.0
)
```

Use `.default` in production. `.custom(...)` is intended for staging or local development.
