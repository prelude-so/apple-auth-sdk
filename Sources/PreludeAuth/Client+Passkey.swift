import Foundation

// MARK: - Public facade

extension PreludeAuthClient {
    /// Register a passkey for the authenticated user.
    ///
    /// Runs the registration ceremony and returns the stored
    /// credential. ``PasskeyRegistrationResult/alreadyRegistered``
    /// is `true` when the authenticator re-offered an existing
    /// credential. Requires the session to hold `prld:passkey:write`.
    @discardableResult
    public func registerPasskey(
        _ options: RegisterPasskeyOptions
    ) async throws -> PasskeyRegistrationResult {
        try await registerPasskey(options, authenticator: Self.makeDefaultAuthenticator())
    }

    /// Testable core of ``registerPasskey(_:)``.
    @discardableResult
    func registerPasskey(
        _ options: RegisterPasskeyOptions,
        authenticator: any PasskeyAuthenticating
    ) async throws -> PasskeyRegistrationResult {
        try await impl.registerPasskey(options, authenticator: authenticator)
    }

    /// Sign in with a registered passkey — no OTP or password.
    ///
    /// Set ``PasskeyLoginOptions/autofill`` to surface credentials
    /// inline on a username field. A dismissed sheet throws
    /// ``PreludeAuthError/cancelled``.
    public func loginWithPasskey(
        _ options: PasskeyLoginOptions = .init()
    ) async throws -> PreludeUser {
        try await loginWithPasskey(options, authenticator: Self.makeDefaultAuthenticator())
    }

    /// Testable core of ``loginWithPasskey(_:)``.
    func loginWithPasskey(
        _ options: PasskeyLoginOptions,
        authenticator: any PasskeyAuthenticating
    ) async throws -> PreludeUser {
        try await impl.loginWithPasskey(options, authenticator: authenticator)
    }

    /// List the authenticated user's registered passkeys.
    public func listPasskeys() async throws -> [PasskeyCredential] {
        try await impl.listPasskeys()
    }

    /// Rename a passkey. An empty `nickname` clears the label.
    public func renamePasskey(_ credentialID: String, nickname: String) async throws {
        try await impl.renamePasskey(credentialID, nickname: nickname)
    }

    /// Delete a passkey.
    public func deletePasskey(_ credentialID: String) async throws {
        try await impl.deletePasskey(credentialID)
    }

    /// Concrete ceremony driver, or a clear error on iOS < 16.
    @MainActor
    static func makeDefaultAuthenticator() throws -> any PasskeyAuthenticating {
        if #available(iOS 16.0, macOS 12.0, *) {
            return PasskeyAuthenticator()
        }
        throw PreludeAuthError.passkeyNotSupported("Passkeys require iOS 16 or later")
    }
}

/// Outcome of ``PreludeAuthClient/registerPasskey(_:)``.
public struct PasskeyRegistrationResult: Sendable, Equatable {
    public let credential: PasskeyCredential
    /// `true` when the credential already existed server-side.
    public let alreadyRegistered: Bool
}

// MARK: - Implementation

extension PreludeAuthClient.Impl {
    @discardableResult
    func registerPasskey(
        _ options: RegisterPasskeyOptions,
        authenticator: any PasskeyAuthenticating
    ) async throws -> PasskeyRegistrationResult {
        guard !options.username.isEmpty else {
            throw PreludeAuthError.invalidConfiguration("registerPasskey requires a non-empty username")
        }

        var beginRequest = buildRequest(path: "me/passkeys/register/begin")
        beginRequest.httpBody = try JSONEncoder().encode(
            PasskeyRegisterBeginBody(
                username: options.username,
                displayName: options.displayName,
                nickname: options.nickname
            )
        )
        let (begin, _) = try await httpClient.sendJSON(
            beginRequest,
            interceptors: [autoRefreshInterceptor],
            as: PasskeyRegisterBeginResponse.self
        )
        guard !begin.registrationToken.isEmpty else {
            throw PreludeAuthError.passkeyRegistrationFailed("Registration did not start")
        }

        let attestation = try await authenticator.register(begin.publicKey)

        var finishRequest = buildRequest(path: "me/passkeys/register/finish")
        finishRequest.httpBody = try JSONEncoder().encode(
            PasskeyRegisterFinishBody(registrationToken: begin.registrationToken, attestation: attestation)
        )
        let (finish, _) = try await httpClient.sendJSON(
            finishRequest,
            interceptors: [autoRefreshInterceptor],
            as: PasskeyRegisterFinishResponse.self
        )

        // A new passkey may flip the has_passkey claim; refresh so
        // the next access token reflects it.
        try await refreshAfterPasskeyMutation()

        return PasskeyRegistrationResult(
            credential: PasskeyCredential(finish.credential),
            alreadyRegistered: finish.alreadyRegistered ?? false
        )
    }

    func loginWithPasskey(
        _ options: PasskeyLoginOptions,
        authenticator: any PasskeyAuthenticating
    ) async throws -> PreludeUser {
        let dispatchID = try await dispatchSignalsIfConfigured()

        var beginRequest = buildRequest(path: "login/passkey/begin")
        beginRequest.httpBody = try JSONEncoder().encode(PasskeyLoginBeginBody(dispatchID: dispatchID))
        // Unauthenticated: the login token binds begin to finish.
        let (begin, _) = try await httpClient.sendJSON(
            beginRequest,
            interceptors: [],
            as: PasskeyLoginBeginResponse.self
        )
        guard !begin.loginToken.isEmpty else {
            throw PreludeAuthError.missingChallengeToken("Passkey login did not start")
        }

        let assertion = try await authenticator.assert(begin.publicKey, autofill: options.autofill)

        var finishRequest = buildRequest(path: "login/passkey/finish")
        finishRequest.httpBody = try JSONEncoder().encode(
            PasskeyLoginFinishBody(loginToken: begin.loginToken, assertion: assertion)
        )
        let (finish, _) = try await httpClient.sendJSON(
            finishRequest,
            interceptors: [],
            as: ChallengeTokenResponse.self
        )
        guard let challengeToken = finish.challengeToken, !challengeToken.isEmpty else {
            throw PreludeAuthError.missingChallengeToken("Missing challenge token from passkey login")
        }

        return try await finalizeLogin(challengeToken: challengeToken)
    }
}
