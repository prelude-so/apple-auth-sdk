import Foundation

// MARK: - Public facade

extension PreludeAuthClient {
    /// Start an OTP login by sending a one-time code to
    /// `identifier`. Unauthenticated; when a ``signalsDispatcher``
    /// is configured its `dispatch_id` is attached for anti-fraud.
    public func startOTPLogin(_ options: StartOTPLoginOptions) async throws {
        try await impl.startOTPLogin(options)
    }

    /// Ask the server to resend the most recently-issued OTP.
    public func resendOTP() async throws {
        try await impl.resendOTP()
    }

    /// Submit an OTP code to complete the login flow.
    ///
    /// `POST /otp/check` returns a single-use `challenge_token`;
    /// the SDK exchanges it on `/login/finalize` for the access +
    /// refresh token.
    public func checkOTP(_ code: String) async throws -> PreludeUser {
        try await impl.checkOTP(code)
    }
}

// MARK: - Implementation

extension PreludeAuthClient.Impl {
    func startOTPLogin(_ options: StartOTPLoginOptions) async throws {
        let dispatchId = try await dispatchSignalsIfConfigured()

        var request = buildRequest(path: "otp")
        let body = StartOTPLoginRequestBody(
            identifier: options.identifier,
            loginConfigID: options.loginConfigID,
            dispatchID: dispatchId
        )
        request.httpBody = try JSONEncoder().encode(body)

        try await httpClient.sendExpectingNoBody(request)
    }

    func resendOTP() async throws {
        let request = buildRequest(path: "otp/retry")
        try await httpClient.sendExpectingNoBody(request)
    }

    /// Trigger OTP delivery for an in-flight challenge (`POST /otp`).
    /// Unauthenticated: the challenge token in the body identifies the
    /// caller, so no DPoP. Returns the issued verification token (the
    /// `X-Verification-Token` response header) so a session-less flow
    /// can replay it on `/otp/check` rather than rely on cookies.
    @discardableResult
    func sendOTP(challengeToken: String) async throws -> String? {
        let dispatchID = try await dispatchSignalsIfConfigured()

        var request = buildRequest(path: "otp")
        request.httpBody = try JSONEncoder().encode(
            SendOTPRequestBody(
                challengeToken: challengeToken,
                dispatchID: dispatchID
            )
        )

        let response = try await httpClient.perform(request)
        try HTTPClient.throwIfNonSuccess(response)
        return response.response.value(forHTTPHeaderField: HTTPHeader.verificationToken)
    }

    func checkOTP(_ code: String) async throws -> PreludeUser {
        // Plain login carries the verification token in a cookie.
        try await finalizeOTPCheck(code: code, verificationToken: nil)
    }

    /// Submit an OTP code to `/otp/check` and exchange the returned
    /// challenge token for a session. `verificationToken`, when set, is
    /// sent as the `X-Verification-Token` header to carry a session-less
    /// flow's state; the plain login leaves it nil and relies on the
    /// cookie.
    func finalizeOTPCheck(code: String, verificationToken: String?) async throws -> PreludeUser {
        var request = buildRequest(path: "otp/check")
        if let verificationToken {
            request.setValue(verificationToken, forHTTPHeaderField: HTTPHeader.verificationToken)
        }
        request.httpBody = try JSONEncoder().encode(CheckOTPRequestBody(code: code))

        // Unauthenticated: the OTP code in the body is the entire
        // credential. A DPoP proof has nothing legitimate to bind
        // to here — no session key exists yet (login hasn't
        // happened) and the challenge token only materialises in
        // the response. The device-to-token binding happens one
        // step later, on `/login/finalize`.
        let (body, _) = try await httpClient.sendJSON(
            request,
            as: ChallengeTokenResponse.self
        )

        guard let challengeToken = body.challengeToken, !challengeToken.isEmpty else {
            throw PreludeAuthError.missingChallengeToken(
                "Missing challenge token from OTP check response"
            )
        }

        return try await finalizeLogin(challengeToken: challengeToken)
    }

    /// Exchange a challenge token for an access token, persist the
    /// issued refresh token, and return the authenticated user.
    /// Shared between OTP, password, and migration login flows.
    ///
    /// `codeVerifier` carries the PKCE secret paired with a
    /// `code_challenge` sent earlier (e.g. by ``migrate(_:)``);
    /// omit when the originating exchange didn't bind a verifier.
    ///
    /// Multi-hop flows (``migrate(_:)``) pass `startEpoch` from
    /// before their first hop so a mid-flow ``logout()`` is caught.
    ///
    /// Only ``finalizeLogin`` and ``refresh()`` write to the
    /// refresh-token store.
    func finalizeLogin(
        challengeToken: String,
        codeVerifier: String? = nil,
        startEpoch: Int? = nil
    ) async throws -> PreludeUser {
        // Bail before writing if a ``logout()`` bumps the epoch mid-flight.
        let startEpoch = startEpoch ?? sessionEpoch

        // Carry over a refresh token from a previous session, if any, so the
        // server can revoke that session once the new one is established and
        // avoid leaving it dangling across a re-login. Captured before the
        // round-trip, since the response rotates the stored token below.
        let previousRefreshToken = try refreshTokenStore.get(domain: domain)?.refreshToken

        var request = buildRequest(path: "login/finalize")
        if let previousRefreshToken, !previousRefreshToken.isEmpty {
            request.setValue(previousRefreshToken, forHTTPHeaderField: HTTPHeader.refreshToken)
        }
        request.httpBody = try JSONEncoder().encode(
            FinalizeLoginRequestBody(
                challengeToken: challengeToken,
                codeVerifier: codeVerifier
            )
        )

        let (body, http) = try await httpClient.sendJSON(
            request,
            interceptors: [dpopInterceptor],
            as: RefreshTokenResponse.self
        )

        guard !body.accessToken.isEmpty else {
            throw PreludeAuthError.generic(
                code: "missing_access_token",
                message: "login/finalize response did not include an access token"
            )
        }

        guard sessionEpoch == startEpoch else {
            throw PreludeAuthError.unauthorized("session revoked during login")
        }

        if let refreshToken = http.response.value(forHTTPHeaderField: HTTPHeader.refreshToken),
           !refreshToken.isEmpty {
            let refreshTokenExpiresAt = http.response
                .value(forHTTPHeaderField: HTTPHeader.refreshTokenExpiresAt)
            try refreshTokenStore.set(
                domain: domain,
                record: RefreshTokenRecord(
                    refreshToken: refreshToken,
                    refreshTokenExpiresAt: refreshTokenExpiresAt
                )
            )
        }

        // Validate before persisting so a malformed token never
        // lands in the cache. Re-map — the challenge token was fine.
        let user: PreludeUser
        do {
            user = try PreludeAuthClient.makeUser(accessToken: body.accessToken)
        } catch PreludeAuthError.invalidChallengeToken(_) {
            throw PreludeAuthError.generic(
                code: "invalid_access_token",
                message: "login/finalize returned a malformed access token"
            )
        }

        try await storeAccessToken(
            body.accessToken,
            serverExpiresAt: body.expiresAt,
            timeDiffSec: http.timeDiffSec
        )

        return user
    }
}
