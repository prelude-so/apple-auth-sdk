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
    /// On success the SDK invalidates the cached token and runs a
    /// best-effort refresh so the next mint drops the now-spent
    /// scope. A thrown error means the change itself did not land;
    /// refresh-only failures are swallowed and picked up by the
    /// next authenticated call.
    public func changePassword(_ newPassword: RedactedString) async throws {
        try await impl.changePassword(newPassword)
    }

    /// Whether the current session can call ``changePassword(_:)``
    /// without going through step-up first — i.e. whether its
    /// access token already carries `prld:pwd:write`.
    ///
    /// Call before driving a "change password" UI to decide
    /// whether to prompt for step-up. Throws if the session
    /// refresh fails; returns `false` when the refreshed token
    /// lacks the scope or the claim is missing/malformed.
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
        // bearer-only — the access token plus the
        // `prld:pwd:write` scope is the entire credential.
        // Sending a proof would be ignored at best; on strict
        // proxies it's dead weight that can short-circuit the
        // request before the server can return its real status.
        //
        // The auto-refresh path still does the right thing: a
        // 401 here triggers ``Impl/refresh()``, which signs
        // `/refresh` with the standard ``dpopInterceptor`` itself.
        // Whichever way the request goes, the step-up that
        // granted `prld:pwd:write` is no longer in flight. Clear
        // the handle on every outcome so a stale challenge can't
        // leak after the reset attempt.
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
        // Same shape as `refreshAfterStepUp`: invalidate, drain
        // any in-flight refresh, then mint through the inflight
        // slot so a vanilla refresh racing to land a stale-scope
        // token in the cache can't beat us. Invalidate-before-
        // drain keeps `startRefresh`'s "slot empty, no await
        // since" invariant intact.
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
