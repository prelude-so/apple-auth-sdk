import Foundation

// MARK: - Public types

/// Identity providers supported for OAuth login.
public enum OAuthProvider: String, CaseIterable, Sendable {
    case google
    case apple
    case microsoft
    case github
    case okta
    case facebook
}

/// Options for ``PreludeAuthClient/initiateOAuthLogin(_:)``.
public struct InitiateOAuthLoginOptions: Sendable {
    /// Provider to authenticate against.
    public var provider: OAuthProvider

    /// Where the server redirects once authentication completes.
    /// Must be allowlisted by the app's configuration.
    public var redirectURI: String

    public init(provider: OAuthProvider, redirectURI: String) {
        self.provider = provider
        self.redirectURI = redirectURI
    }
}

/// Outcome of redeeming an OAuth login callback.
public enum FinalizeOAuthLoginResult: Sendable {
    /// Session established.
    case loggedIn(PreludeUser)

    /// The provider returned an unverified email; the server sent a
    /// one-time code to `email`. Redeem `challenge` with
    /// ``PreludeAuthClient/checkOAuthEmailOTP(_:resuming:)`` to
    /// complete the login.
    case otpRequired(_ challenge: OAuthEmailChallenge, email: String?)
}

/// An OAuth-email-link verification awaiting its one-time code.
/// Returned in ``FinalizeOAuthLoginResult/otpRequired(_:email:)`` and
/// redeemed by ``PreludeAuthClient/checkOAuthEmailOTP(_:resuming:)``.
///
/// Value-typed so it carries its own verification token: concurrent
/// logins never clash, and completion doesn't depend on shared
/// cookies. Safe to log — the token is redacted from every textual
/// surface.
public struct OAuthEmailChallenge: Sendable {
    /// Verification token issued when the code was sent, replayed as
    /// the `X-Verification-Token` header on the check.
    let verificationToken: String
}

/// An in-progress OAuth login. Returned by
/// ``PreludeAuthClient/initiateOAuthLogin(_:)`` and redeemed by
/// ``PreludeAuthClient/finalizeOAuthLogin(_:challengeToken:)``. Carries
/// this attempt's PKCE verifier, so parallel logins can't clobber it.
public struct OAuthLoginContext: Sendable {
    /// Authorization URL to present in a web authentication context.
    public let authorizationURL: URL

    /// PKCE verifier paired with the `code_challenge` sent at initiate.
    let codeVerifier: String
}

// MARK: - Public facade

extension PreludeAuthClient {
    /// Begin an OAuth login, returning a context to present in a web
    /// authentication context.
    ///
    /// Generates a PKCE pair bound to the returned
    /// ``OAuthLoginContext``; pass that same context to
    /// ``finalizeOAuthLogin(_:challengeToken:)``. Each call is
    /// self-contained, so concurrent logins never share a verifier.
    public func initiateOAuthLogin(
        _ options: InitiateOAuthLoginOptions
    ) async throws -> OAuthLoginContext {
        try await impl.initiateOAuthLogin(options)
    }

    /// Redeem the `challenge_token` delivered to `context`'s redirect
    /// URI and establish a session.
    public func finalizeOAuthLogin(
        _ context: OAuthLoginContext,
        challengeToken: String
    ) async throws -> FinalizeOAuthLoginResult {
        try await impl.finalizeOAuthLogin(context, challengeToken: challengeToken)
    }

    /// Submit the email OTP for an OAuth-link `challenge` and establish
    /// the session.
    ///
    /// Pass the ``OAuthEmailChallenge`` from a
    /// ``FinalizeOAuthLoginResult/otpRequired(_:email:)`` result, which
    /// is returned when the provider's email must be proven before the
    /// login can complete.
    public func checkOAuthEmailOTP(
        _ code: String,
        resuming challenge: OAuthEmailChallenge
    ) async throws -> PreludeUser {
        try await impl.checkOAuthEmailOTP(code, resuming: challenge)
    }
}

// MARK: - Implementation

extension PreludeAuthClient.Impl {
    func initiateOAuthLogin(
        _ options: InitiateOAuthLoginOptions
    ) async throws -> OAuthLoginContext {
        let codeVerifier = try PKCE.generateCodeVerifier()
        let codeChallenge = PKCE.codeChallenge(for: codeVerifier)
        let dispatchID = try await dispatchSignalsIfConfigured()

        var request = buildRequest(
            path: "login/oauth/\(options.provider.rawValue)/authorize"
        )
        request.httpBody = try JSONEncoder().encode(
            OAuthAuthorizeRequestBody(
                redirectURI: options.redirectURI,
                codeChallenge: codeChallenge,
                codeChallengeMethod: "S256",
                dispatchID: dispatchID
            )
        )

        // Unauthenticated: the PKCE pair is the flow's only binding.
        let (body, _) = try await httpClient.sendJSON(
            request,
            interceptors: [],
            as: OAuthAuthorizeResponseBody.self
        )

        guard let rawURL = body.authorizationURL,
              let url = URL(string: rawURL),
              url.scheme != nil
        else {
            throw PreludeAuthError.generic(
                code: "invalid_authorization_url",
                message: "authorize response did not include a valid authorization URL"
            )
        }

        return OAuthLoginContext(authorizationURL: url, codeVerifier: codeVerifier)
    }

    func finalizeOAuthLogin(
        _ context: OAuthLoginContext,
        challengeToken: String
    ) async throws -> FinalizeOAuthLoginResult {
        guard !challengeToken.isEmpty else {
            throw PreludeAuthError.missingChallengeToken(
                "Missing challenge token from login callback"
            )
        }

        let jwt = try JWT.decode(challengeToken)
        let link = try? JSONDecoder().decode(OAuthLinkClaims.self, from: jwt.payloadJSON)

        if link?.grantMode == "oauth-email-link" {
            // Unverified provider email: deliver the verification code
            // and hand back a resumable challenge so the caller can
            // drive its OTP screen. The verification token — not the
            // challenge token — carries the flow's state through to the
            // check; the PKCE verifier isn't used on this path.
            guard let verificationToken = try await sendOTP(challengeToken: challengeToken),
                  !verificationToken.isEmpty
            else {
                throw PreludeAuthError.generic(
                    code: "missing_verification_token",
                    message: "otp response did not include a verification token"
                )
            }
            return .otpRequired(
                OAuthEmailChallenge(verificationToken: verificationToken),
                email: link?.metadata?.oauthEmail
            )
        }

        let user = try await finalizeLogin(
            challengeToken: challengeToken,
            codeVerifier: context.codeVerifier
        )
        return .loggedIn(user)
    }

    func checkOAuthEmailOTP(
        _ code: String,
        resuming challenge: OAuthEmailChallenge
    ) async throws -> PreludeUser {
        // The verification token issued at `/otp` carries the OAuth-link
        // state; replay it so `/otp/check` resolves the flow without a
        // session or DPoP. Login finalizes one step later.
        try await finalizeOTPCheck(
            code: code,
            verificationToken: challenge.verificationToken
        )
    }
}

// MARK: - Logging hygiene

extension OAuthEmailChallenge: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String {
        "OAuthEmailChallenge(verificationToken: <redacted>)"
    }

    public var debugDescription: String {
        description
    }

    public var customMirror: Mirror {
        Mirror(self, children: ["verificationToken": "<redacted>"], displayStyle: .struct)
    }
}

// MARK: - Wire types

struct OAuthAuthorizeRequestBody: Encodable {
    var redirectURI: String
    var codeChallenge: String
    var codeChallengeMethod: String
    var dispatchID: String?

    enum CodingKeys: String, CodingKey {
        case redirectURI = "redirect_uri"
        case codeChallenge = "code_challenge"
        case codeChallengeMethod = "code_challenge_method"
        case dispatchID = "dispatch_id"
    }
}

struct OAuthAuthorizeResponseBody: Decodable {
    var authorizationURL: String?

    enum CodingKeys: String, CodingKey {
        case authorizationURL = "authorization_url"
    }
}

/// Claims carried by OAuth-link challenge tokens.
struct OAuthLinkClaims: Decodable {
    var grantMode: String?
    var metadata: OAuthLinkMetadata?

    enum CodingKeys: String, CodingKey {
        case grantMode = "grant_mode"
        case metadata
    }
}

struct OAuthLinkMetadata: Decodable {
    var oauthEmail: String?

    enum CodingKeys: String, CodingKey {
        case oauthEmail = "oauth_email"
    }
}
