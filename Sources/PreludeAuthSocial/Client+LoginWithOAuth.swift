import Foundation
import PreludeAuth

extension PreludeAuthClient {
    /// Authenticate against an identity provider in a system web
    /// session and establish a session.
    ///
    /// One-shot: requests the authorization URL, presents the
    /// provider's page, and redeems the callback. Only one login
    /// can be presented at a time; concurrent calls throw
    /// ``PreludeAuthError/conflict(_:)``. A dismissed sheet throws
    /// ``PreludeAuthError/cancelled``.
    public func loginWithOAuth(
        _ options: OAuthLoginOptions
    ) async throws -> FinalizeOAuthLoginResult {
        try await loginWithOAuth(options, presenter: WebAuthPresenter())
    }

    /// Testable core of ``loginWithOAuth(_:)``.
    func loginWithOAuth(
        _ options: OAuthLoginOptions,
        presenter: WebAuthPresenting
    ) async throws -> FinalizeOAuthLoginResult {
        guard let scheme = options.redirectURI.scheme?.lowercased(),
              scheme != "http", scheme != "https"
        else {
            throw PreludeAuthError.invalidConfiguration(
                "redirectURI must use the app's custom URL scheme"
            )
        }

        guard await OAuthLoginGate.acquire() else {
            throw PreludeAuthError.conflict(
                "Another social login is already in progress"
            )
        }

        do {
            let result = try await run(options, scheme: scheme, presenter: presenter)
            await OAuthLoginGate.release()
            return result
        } catch {
            await OAuthLoginGate.release()
            throw error
        }
    }

    private func run(
        _ options: OAuthLoginOptions,
        scheme: String,
        presenter: WebAuthPresenting
    ) async throws -> FinalizeOAuthLoginResult {
        let context = try await initiateOAuthLogin(
            InitiateOAuthLoginOptions(
                provider: options.provider,
                redirectURI: options.redirectURI.absoluteString
            )
        )

        let callbackURL = try await presenter.authenticate(
            url: context.authorizationURL,
            callbackScheme: scheme,
            prefersEphemeralSession: options.prefersEphemeralSession
        )

        let redirect = OAuthRedirect.parse(callbackURL)
        if let error = redirect.error {
            throw error
        }
        guard case let .challenge(token) = redirect else {
            throw PreludeAuthError.missingChallengeToken(
                OAuthRedirect.missingTokenMessage
            )
        }
        return try await finalizeOAuthLogin(context, challengeToken: token)
    }
}

/// Serializes login presentation: the system shows at most one web
/// authentication session at a time.
@MainActor
enum OAuthLoginGate {
    private static var active = false

    static func acquire() -> Bool {
        guard !active else { return false }
        active = true
        return true
    }

    static func release() {
        active = false
    }
}
