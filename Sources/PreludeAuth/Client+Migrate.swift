import Foundation

// MARK: - Public facade

extension PreludeAuthClient {
    /// Exchange a legacy bearer token for a Prelude session.
    ///
    /// Two hops: `POST /migration` trades the legacy token for a
    /// single-use `challenge_token`, redeemed on `/login/finalize`
    /// with the PKCE verifier.
    ///
    /// Safe on every launch: a cached session short-circuits without
    /// spending the token, concurrent callers share one in-flight
    /// exchange, and a racing ``logout()`` wins — nothing is
    /// persisted and the call throws ``PreludeAuthError/unauthorized(_:)``.
    @discardableResult
    public func migrate(_ options: MigrateOptions) async throws -> PreludeUser {
        try await impl.migrate(options)
    }
}

// MARK: - Implementation

extension PreludeAuthClient.Impl {
    @discardableResult
    func migrate(_ options: MigrateOptions) async throws -> PreludeUser {
        // Fast path: already migrated by an earlier launch / call.
        if let entry = await accessTokenCache.get(domain: domain) {
            return try makeUserForMigrate(accessToken: entry.accessToken)
        }

        if let existing = inflightMigration {
            return try await existing.value
        }

        // Unstructured `Task` decouples the migration from the
        // calling task's cancellation: a cancelled awaiter doesn't
        // abandon the legacy token mid-exchange.
        let task = Task<PreludeUser, Error> {
            defer { self.inflightMigration = nil }
            return try await self.doMigrate(token: options.token.value)
        }
        inflightMigration = task
        return try await task.value
    }

    private func doMigrate(token: String) async throws -> PreludeUser {
        // Re-check after taking the inflight slot — a sibling may
        // have populated the cache before we got here.
        if let entry = await accessTokenCache.get(domain: domain) {
            return try makeUserForMigrate(accessToken: entry.accessToken)
        }

        // Captured before the first hop so a `logout()` between the
        // hops still fails `finalizeLogin`'s pre-persist guard.
        let startEpoch = sessionEpoch

        let codeVerifier = try PKCE.generateCodeVerifier()
        let codeChallenge = PKCE.codeChallenge(for: codeVerifier)
        let dispatchID = try await dispatchSignalsIfConfigured()

        var request = buildRequest(path: "migration")
        request.httpBody = try JSONEncoder().encode(
            MigrateRequestBody(
                token: token,
                codeChallenge: codeChallenge,
                dispatchID: dispatchID
            )
        )

        // Unauthenticated: the legacy token in the body is the
        // entire credential, mirroring the OTP-check shape.
        let (body, _) = try await httpClient.sendJSON(
            request,
            interceptors: [],
            as: ChallengeTokenResponse.self
        )

        guard let challengeToken = body.challengeToken,
              !challengeToken.isEmpty else {
            throw PreludeAuthError.missingChallengeToken(
                "Missing challenge token from migration response"
            )
        }

        return try await finalizeLogin(
            challengeToken: challengeToken,
            codeVerifier: codeVerifier,
            startEpoch: startEpoch
        )
    }

    /// The JWT decoder reports any malformed token as
    /// `invalidChallengeToken`; re-map, since none is involved here.
    private func makeUserForMigrate(accessToken: String) throws -> PreludeUser {
        do {
            return try PreludeAuthClient.makeUser(accessToken: accessToken)
        } catch PreludeAuthError.invalidChallengeToken(_) {
            throw PreludeAuthError.generic(
                code: "invalid_access_token",
                message: "cached access token is malformed"
            )
        }
    }
}
