import Foundation

/// Options for ``PreludeAuthClient/registerPasskey(_:)``.
public struct RegisterPasskeyOptions: Sendable {
    /// Shown by the authenticator; usually the user's email or phone.
    public var username: String
    /// Human-friendly name; defaults to ``username`` when `nil`.
    public var displayName: String?
    /// Optional server-side label ("MacBook", "iPhone").
    public var nickname: String?

    public init(username: String, displayName: String? = nil, nickname: String? = nil) {
        self.username = username
        self.displayName = displayName
        self.nickname = nickname
    }
}

/// Options for ``PreludeAuthClient/loginWithPasskey(_:)``.
public struct PasskeyLoginOptions: Sendable {
    /// Offer matching passkeys inline via AutoFill on a username
    /// field instead of a modal sheet.
    public var autofill: Bool

    public init(autofill: Bool = false) {
        self.autofill = autofill
    }
}

/// A passkey registered to the authenticated user.
public struct PasskeyCredential: Sendable, Equatable {
    public let credentialID: String
    public let nickname: String?
    public let transports: [String]
    public let backupState: Bool
    /// Unix seconds.
    public let createdAt: Int
    /// Unix seconds; equals ``createdAt`` until first use.
    public let lastUsedAt: Int
}

extension PasskeyCredential {
    init(_ json: PasskeyCredentialJSON) {
        self.init(
            credentialID: json.credentialID,
            nickname: json.nickname,
            transports: json.transports ?? [],
            backupState: json.backupState ?? false,
            createdAt: json.createdAt ?? 0,
            lastUsedAt: json.lastUsedAt ?? 0
        )
    }
}
