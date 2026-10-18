import Foundation

// MARK: - Public facade

extension PreludeAuthClient {
    /// Return an authenticated ``PreludeUser``, refreshing the
    /// access token if the cached one has expired. Concurrent
    /// callers share a single in-flight refresh so the single-use
    /// refresh token is never spent twice.
    @discardableResult
    public func refresh() async throws -> PreludeUser {
        try await impl.refresh()
    }
}

// MARK: - Implementation

extension PreludeAuthClient.Impl {
    @discardableResult
    func refresh() async throws -> PreludeUser {
        try requireUnsealed()
        if let entry = await accessTokenCache.get(domain: domain) {
            return try PreludeAuthClient.makeUser(accessToken: entry.accessToken)
        }

        if let existing = inflightRefresh {
            return try await existing.value
        }

        return try await startRefresh(stepUpToken: nil).value
    }

    /// Wait until no refresh task is in flight. Looping closes the
    /// reentrancy window where a sibling caller installs a new
    /// task between the prior task's defer and our resumption.
    func drainInflightRefresh() async {
        while let inflight = inflightRefresh {
            _ = try? await inflight.value
        }
    }

    /// Atomically install a new refresh task in the inflight slot.
    /// Precondition: the slot was just observed empty with no `await`
    /// since. The unstructured `Task` keeps a cancelled awaiter from
    /// abandoning the rotated refresh token mid-flight.
    @discardableResult
    func startRefresh(stepUpToken: String?) -> Task<PreludeUser, Error> {
        let task = Task<PreludeUser, Error> {
            defer { self.inflightRefresh = nil }
            return try await self.doRefresh(stepUpToken: stepUpToken)
        }
        inflightRefresh = task
        return task
    }

    /// Perform the refresh round-trip.
    ///
    /// - Parameter stepUpToken: when non-nil, sent as
    ///   `step_up_token` so the server mints an access token
    ///   carrying the just-granted scope.
    func doRefresh(stepUpToken: String?) async throws -> PreludeUser {
        try requireUnsealed()
        let startEpoch = sessionEpoch

        // Re-check after taking the inflight slot — a sibling may
        // have populated the cache. Skip when a step-up token is
        // present: the whole point is to mint a NEW token carrying
        // the just-granted scope.
        if stepUpToken == nil, let entry = await accessTokenCache.get(domain: domain) {
            return try PreludeAuthClient.makeUser(accessToken: entry.accessToken)
        }

        let refreshToken = try refreshTokenStore.get(domain: domain)?.refreshToken

        // Fail fast on a wiped session: surface the same
        // `unauthorized` the in-flight epoch guard below produces,
        // so callers handle a single recovery path.
        guard let refreshToken, !refreshToken.isEmpty else {
            throw PreludeAuthError.unauthorized(
                "Session is not active; no refresh token available"
            )
        }

        var request = buildRequest(path: "refresh")
        request.setValue(refreshToken, forHTTPHeaderField: HTTPHeader.refreshToken)
        if let stepUpToken, !stepUpToken.isEmpty {
            request.httpBody = try JSONEncoder().encode(
                StepUpRefreshRequestBody(stepUpToken: stepUpToken)
            )
        }

        let (body, http) = try await httpClient.sendJSON(
            request,
            interceptors: [dpopInterceptor],
            as: RefreshTokenResponse.self
        )

        guard !body.accessToken.isEmpty else {
            throw PreludeAuthError.refreshFailed("Server returned an empty access token")
        }

        // Logout-during-refresh: throw and leave the wipe untouched.
        guard sessionEpoch == startEpoch else {
            throw PreludeAuthError.unauthorized("session revoked during refresh")
        }

        // /refresh rotates the refresh token on every successful
        // call (single-use). Persist the rotated token before the
        // access token so a failure here doesn't leave a stale
        // refresh on disk.
        if let rotated = http.response.value(forHTTPHeaderField: HTTPHeader.refreshToken),
           !rotated.isEmpty {
            let rotatedExpiresAt = http.response
                .value(forHTTPHeaderField: HTTPHeader.refreshTokenExpiresAt)
            try refreshTokenStore.set(
                domain: domain,
                record: RefreshTokenRecord(
                    refreshToken: rotated,
                    refreshTokenExpiresAt: rotatedExpiresAt
                )
            )
        }

        try await storeAccessToken(
            body.accessToken,
            serverExpiresAt: body.expiresAt,
            timeDiffSec: http.timeDiffSec
        )

        return try PreludeAuthClient.makeUser(accessToken: body.accessToken)
    }
}
