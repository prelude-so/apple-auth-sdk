import Foundation

// MARK: - Public facade

extension PreludeAuthClient {
    /// List the authenticated user's active sessions.
    ///
    /// - Parameter options: optional `limit` / `offset` paging.
    ///   Both default to whatever the server picks.
    /// - Returns: a page of ``PreludeSessionView`` plus the
    ///   total / limit / offset echoed back by the server.
    ///
    /// Bearer-authenticated; ``AutoRefreshInterceptor`` recovers
    /// from a stale access token transparently.
    public func listSessions(
        _ options: ListSessionsOptions = .init()
    ) async throws -> ListSessionsResponse {
        try await impl.listSessions(options)
    }

    /// Revoke one or more of the authenticated user's sessions.
    ///
    /// Wire side effects:
    /// - ``RevokeTarget/all`` revokes every session on the user,
    ///   including this client's.
    /// - ``RevokeTarget/mine`` revokes only this client's session.
    /// - ``RevokeTarget/others`` keeps this client's session and
    ///   revokes the rest.
    /// - ``RevokeTarget/session(id:)`` revokes one session.
    ///
    /// Local side effects mirror those: when the call would
    /// terminate this client's own session, the SDK wipes its
    /// domain-scoped credentials too — same wipe ``logout()``
    /// performs — so a stale refresh can't resurrect them.
    public func revokeSessions(_ target: RevokeTarget) async throws {
        try await impl.revokeSessions(target)
    }
}

// MARK: - Implementation

extension PreludeAuthClient.Impl {
    func listSessions(
        _ options: ListSessionsOptions
    ) async throws -> ListSessionsResponse {
        let request = buildRequest(
            path: "me/list",
            method: "GET",
            queryItems: queryItems(for: options)
        )

        let (body, _) = try await httpClient.sendJSON(
            request,
            interceptors: [autoRefreshInterceptor],
            as: ListSessionsResponse.self
        )
        return body
    }

    func revokeSessions(_ target: RevokeTarget) async throws {
        // Reject empty / whitespace-only ids up front so
        // they surface as a configuration error rather than an
        // opaque server 400.
        if case let .session(id) = target,
           id.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            throw PreludeAuthError.invalidConfiguration(
                "RevokeTarget.session(id:) requires a non-empty id"
            )
        }

        // Snapshot the current session id *before* the network
        // call: a concurrent refresh could rotate the access token
        // (and therefore the `sid` claim) while /me/revoke is in
        // flight, which would race the wipe decision below.
        let snapshotSessionID = await sessionID

        let request = buildRequest(
            path: "me/revoke",
            method: "POST",
            queryItems: queryItems(for: target)
        )

        try await httpClient.sendExpectingNoBody(
            request,
            interceptors: [autoRefreshInterceptor]
        )

        // Any revocation that includes the current session
        // must also clear this client's domain-scoped
        // credentials; otherwise the next refresh would hit a
        // server-revoked token and silently log the user out
        // anyway.
        guard Self.shouldWipeAfterRevoke(
            target: target,
            currentSessionID: snapshotSessionID
        ) else { return }

        // Same concurrency invariants as ``logout()``. Bump the
        // epoch *before* draining: an in-flight refresh that
        // completes during the drain then sees the new value at
        // its post-network guard and throws instead of persisting
        // rotated tokens. Draining first would let those tokens
        // hit disk only to be wiped a moment later.
        sessionEpoch += 1
        await drainInflightRefresh()
        try await clearAllStores()
    }

    // MARK: - Helpers

    private func queryItems(for options: ListSessionsOptions) -> [URLQueryItem] {
        var items: [URLQueryItem] = []
        if let limit = options.limit {
            items.append(URLQueryItem(name: "limit", value: String(limit)))
        }
        if let offset = options.offset {
            items.append(URLQueryItem(name: "offset", value: String(offset)))
        }
        return items
    }

    private func queryItems(for target: RevokeTarget) -> [URLQueryItem] {
        var items = [URLQueryItem(name: "target", value: target.queryValue)]
        if case let .session(id) = target {
            items.append(URLQueryItem(name: "session_id", value: id))
        }
        return items
    }

    /// Pure decision so it's easy to unit-test without standing
    /// up the network stack. `nil` `currentSessionID` is treated
    /// as "we can't tell" — wipe defensively only on the
    /// unconditional ``RevokeTarget/all``/``RevokeTarget/mine``
    /// cases, never on ``RevokeTarget/session(id:)``.
    static func shouldWipeAfterRevoke(
        target: RevokeTarget,
        currentSessionID: String?
    ) -> Bool {
        switch target {
        case .all, .mine:
            return true
        case .others:
            return false
        case let .session(id):
            guard let currentSessionID else { return false }
            return id == currentSessionID
        }
    }
}
