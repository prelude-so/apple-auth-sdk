import Foundation

/// Errors thrown by ``PreludeAuthClient``.
///
/// Wire-protocol errors from the server are mapped to typed
/// cases (`unauthorized`, `invalidPassword`, `insufficientScope`,
/// `expiredChallengeToken`, …); the associated `String` carries
/// the server's display message. Transport failures surface as
/// ``network(underlying:)`` or ``timeout``. Codes the SDK
/// doesn't recognise round-trip through ``generic(code:message:)``.
public enum PreludeAuthError: Error, Sendable {
    case badRequest(String)
    case unauthorized(String)
    case rateLimited(String)
    case internalServerError(String)
    /// Server response lacked an expected challenge token.
    case missingChallengeToken(String)
    /// Backend-issued challenge token is invalid or its step-up
    /// state machine cannot progress (e.g. step skipped or not
    /// completed). Recover via ``requestStepUp(scope:)``.
    case invalidChallengeToken(String)
    /// Challenge token expired before it was redeemed. Recover
    /// via ``requestStepUp(scope:)``.
    case expiredChallengeToken(String)
    /// Single-use token was replayed. Surfaces from `/login/finalize`,
    /// `/otp/check`, and `/stepup/continue` on a 409.
    case tokenReused(String)
    /// OTP code submitted during login was wrong or expired. Distinct
    /// from ``unauthorized``: retry the code, don't re-login.
    case invalidOTPCode(String)
    /// The current session could not be refreshed.
    case refreshFailed(String)
    case timeout
    /// The person dismissed the login UI before completing it.
    case cancelled
    case invalidConfiguration(String)
    /// The app has no login configuration accepting this identifier's
    /// channel. Create one via the Auth Management API.
    case noLoginConfig(String)
    /// Password rejected by the server's policy. Distinct from
    /// ``unauthorized(_:)`` ("wrong password").
    case invalidPassword(String)
    /// Returned by `/login/email/password` when the user exists but has
    /// no password credential stored. Distinct from ``unauthorized(_:)``
    /// ("wrong password"); recover via a password reset/set flow
    /// instead of retrying the password.
    case passwordNotSet(String)
    /// Caller is authenticated but policy denies this action.
    case forbidden(String)
    /// Access token lacks a scope the endpoint requires. Recover via
    /// ``requestStepUp(scope:)``.
    case insufficientScope(String)
    /// Resource the request referenced does not exist.
    case notFound(String)
    /// Resource state conflicts with the request (e.g. duplicate
    /// identifier on sign-up).
    case conflict(String)
    /// OTP or other login method refused because the identifier's
    /// email domain is enforced to use SAML SSO. Recover by
    /// restarting the flow via the SAML initiate endpoint.
    case samlLoginRequired(String)
    /// App has no PasskeyConfig set (Relying Party identity is
    /// missing). Route the user to a different MFA factor.
    case passkeyNotConfigured(String)
    /// Server rejected the attestation from the registration
    /// ceremony — bad challenge, bad origin, or malformed response.
    case passkeyRegistrationFailed(String)
    /// verify_passkey step cannot be driven (no credentials,
    /// assertion failed, or no PasskeyConfig). Fall back to a
    /// different step (e.g. SMS OTP).
    case passkeyStepUnavailable(String)
    /// Passkeys are unavailable on this platform version
    /// (requires iOS 16 or later).
    case passkeyNotSupported(String)
    case network(underlying: Error)
    /// Error code not recognised by the SDK.
    case generic(code: String, message: String)
}

extension PreludeAuthError {
    static func from(apiError: APIErrorJSON) -> PreludeAuthError {
        let message = apiError.displayMessage
        switch apiError.code {
        case "bad_request",
             "invalid_identifier",
             "invalid_metadata",
             "invalid_pagination_limit",
             "invalid_pagination_offset",
             "invalid_redirect_uri",
             "invalid_verification_token",
             "oauth_provider_not_configured",
             "oauth_provider_disabled",
             "email_domain_not_verified",
             "insufficient_balance":
            return .badRequest(message)
        case "unauthorized",
             "invalid_dpop_proof",
             "dpop_key_mismatch",
             "missing_dpop_proof",
             "use_dpop_nonce":
            return .unauthorized(message)
        case "bad_check_code":
            return .invalidOTPCode(message)
        case "rate_limited", "too_many_requests":
            return .rateLimited(message)
        case "internal", "internal_server_error":
            return .internalServerError(message)
        case "missing_challenge_token":
            return .missingChallengeToken(message)
        case "invalid_challenge_token",
             "step_not_completed",
             "step_not_found",
             "step_bypassed",
             "token_mismatch":
            return .invalidChallengeToken(message)
        case "expired_challenge_token":
            return .expiredChallengeToken(message)
        case "token_reused":
            return .tokenReused(message)
        case "invalid_password":
            return .invalidPassword(message)
        case "password_not_set":
            return .passwordNotSet(message)
        case "no_login_config":
            return .noLoginConfig(message)
        case "forbidden",
             "auth_blocked",
             "scope_not_allowed",
             "not_configured",
             "direct_scope_identifier_mismatch",
             "invalid_verify_configuration",
             "suspended_account",
             "invalid_api_key",
             "email_verification_not_allowed",
             "saml_connection_disabled":
            return .forbidden(message)
        case "insufficient_scope":
            return .insufficientScope(message)
        case "saml_login_required":
            return .samlLoginRequired(message)
        case "passkey_not_configured":
            return .passkeyNotConfigured(message)
        case "passkey_registration_failed":
            return .passkeyRegistrationFailed(message)
        case "passkey_step_unavailable", "passkey_authenticator_blocked":
            return .passkeyStepUnavailable(message)
        case "not_found",
             "saml_connection_not_configured",
             "saml_no_connection_for_email":
            return .notFound(message)
        case "conflict", "identifier_already_exists":
            return .conflict(message)
        default:
            return .generic(code: apiError.code, message: message)
        }
    }
}

extension PreludeAuthError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case let .badRequest(message):
            return "BadRequest: \(message)"
        case let .unauthorized(message):
            return "Unauthorized: \(message)"
        case let .rateLimited(message):
            return "RateLimited: \(message)"
        case let .internalServerError(message):
            return "InternalServerError: \(message)"
        case let .missingChallengeToken(message):
            return "MissingChallengeToken: \(message)"
        case let .invalidChallengeToken(message):
            return "InvalidChallengeToken: \(message)"
        case let .expiredChallengeToken(message):
            return "ExpiredChallengeToken: \(message)"
        case let .tokenReused(message):
            return "TokenReused: \(message)"
        case let .invalidOTPCode(message):
            return "InvalidOTPCode: \(message)"
        case let .refreshFailed(message):
            return "RefreshFailed: \(message)"
        case .timeout:
            return "Timeout"
        case .cancelled:
            return "Cancelled"
        case let .invalidConfiguration(message):
            return "InvalidConfiguration: \(message)"
        case let .noLoginConfig(message):
            return "NoLoginConfig: \(message)"
        case let .invalidPassword(message):
            return "InvalidPassword: \(message)"
        case let .passwordNotSet(message):
            return "PasswordNotSet: \(message)"
        case let .forbidden(message):
            return "Forbidden: \(message)"
        case let .insufficientScope(message):
            return "InsufficientScope: \(message)"
        case let .notFound(message):
            return "NotFound: \(message)"
        case let .conflict(message):
            return "Conflict: \(message)"
        case let .samlLoginRequired(message):
            return "SAMLLoginRequired: \(message)"
        case let .passkeyNotConfigured(message):
            return "PasskeyNotConfigured: \(message)"
        case let .passkeyRegistrationFailed(message):
            return "PasskeyRegistrationFailed: \(message)"
        case let .passkeyStepUnavailable(message):
            return "PasskeyStepUnavailable: \(message)"
        case let .passkeyNotSupported(message):
            return "PasskeyNotSupported: \(message)"
        case let .network(underlying):
            return "Network: \(underlying.localizedDescription)"
        case let .generic(code, message):
            return "\(code): \(message)"
        }
    }
}

extension PreludeAuthError: CustomStringConvertible {
    public var description: String {
        errorDescription ?? "Unknown session error"
    }
}
