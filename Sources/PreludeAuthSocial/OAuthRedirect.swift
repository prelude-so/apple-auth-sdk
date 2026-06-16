import Foundation
import PreludeAuth

/// Decoded query parameters of the post-login redirect.
enum OAuthRedirect: Equatable {
    case challenge(token: String)
    case failure(code: String, message: String)

    /// Message surfaced when a callback carries no challenge token.
    static let missingTokenMessage = "Missing challenge token from login callback"

    /// Parse the redirect URL delivered to the app's callback
    /// scheme. Server-reported failures win over a missing token.
    static func parse(_ url: URL) -> Self {
        let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?
            .queryItems ?? []

        func value(_ name: String) -> String? {
            items.first(where: { $0.name == name })?.value
        }

        if let code = value("error"), !code.isEmpty {
            return .failure(
                code: code,
                message: value("error_description") ?? "Authentication failed"
            )
        }

        guard let token = value("challenge_token"), !token.isEmpty else {
            return .failure(
                code: "missing_challenge_token",
                message: Self.missingTokenMessage
            )
        }

        return .challenge(token: token)
    }

    /// Typed error for a `failure` case.
    var error: PreludeAuthError? {
        guard case let .failure(code, message) = self else { return nil }
        switch code {
        case "missing_challenge_token":
            return .missingChallengeToken(message)
        case "email_already_in_use":
            return .conflict(message)
        case "server_error":
            return .internalServerError(message)
        default:
            return .generic(code: code, message: message)
        }
    }
}
