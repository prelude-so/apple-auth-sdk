import Foundation

// MARK: - Public facade

extension PreludeAuthClient {
    /// Change the currently-authenticated user's password.
    ///
    /// Requires the session to carry `prld:pwd:write` — obtain it
    /// via ``requestStepUp(scope:)`` + ``submitStepUpOTP(_:code:)``.
    /// Sessions without it throw
    /// ``PreludeAuthError/insufficientScope(_:)``.
    ///
    /// A thrown error means the change itself did not land; the
    /// post-success refresh that drops the spent scope is
    /// best-effort and its failures are swallowed.
    public func changePassword(_ newPassword: RedactedString) async throws {
        try await impl.changePassword(newPassword)
    }

    /// Whether the current session can call ``changePassword(_:)``
    /// without going through step-up first — i.e. whether its
    /// access token already carries `prld:pwd:write`.
    ///
    /// Refreshes the session to check: throws if that refresh
    /// fails, returns `false` when the refreshed token lacks the
    /// scope or the claim is missing/malformed.
    public func canChangePassword() async throws -> Bool {
        try await impl.canChangePassword()
    }
}

// MARK: - Implementation

extension PreludeAuthClient.Impl {
    func changePassword(_ newPassword: RedactedString) async throws {
        var request = buildRequest(path: "me/password/reset")
        request.httpBody = try JSONEncoder().encode(
            ChangePasswordRequestBody(password: newPassword.value)
        )

        // No DPoP on `/me/password/reset`: the route is
        // bearer-only, so the access token plus the
        // `prld:pwd:write` scope is the entire credential. Clear
        // the step-up handle on every outcome so a stale
        // challenge can't leak after the reset attempt.
        defer { activeStepUp = nil }

        try await httpClient.sendExpectingNoBody(
            request,
            interceptors: [autoRefreshInterceptor]
        )

        // Drop `prld:pwd:write` locally so a leaked token can't
        // change the password again without re-stepping up.
        try? await invalidateSession()
        _ = try? await refresh()
    }

    func canChangePassword() async throws -> Bool {
        // Invalidate, drain, then mint through the inflight slot
        // so a racing refresh can't land a stale-scope token in
        // the cache. Invalidate before drain keeps
        // ``startRefresh``'s invariant intact.
        try await accessTokenCache.invalidate(domain: domain)
        await drainInflightRefresh()
        let user = try await startRefresh(stepUpToken: nil).value

        let jwt = try JWT.decode(user.accessToken)
        guard
            let claims = try? JSONSerialization.jsonObject(
                with: jwt.payloadJSON
            ) as? [String: Any],
            let scope = claims["scope"] as? String
        else {
            return false
        }
        return scope.components(separatedBy: " ").contains("prld:pwd:write")
    }
}
