import Foundation

// MARK: - Public facade

extension PreludeAuthClient {
    /// Request a step-up to `scope`.
    ///
    /// Posts to `/stepup/request`. Returns a ``StepUpChallenge``
    /// handle — pass it to ``sendStepUpOTP(_:)`` to trigger code
    /// delivery, then to ``submitStepUpOTP(_:code:)`` to verify.
    ///
    /// OTP delivery is caller-driven on purpose: it avoids
    /// unsolicited deliveries on `review` flows and lets UIs
    /// defer firing `/otp` until the user lands on the
    /// code-entry screen (or taps "resend code").
    ///
    /// Multiple in-flight step-ups on one client are supported;
    /// each caller holds its own value.
    ///
    /// `metadata` is forwarded verbatim to the server's step-up
    /// audit hook. Server-side caps apply (max 5 keys, 12-char
    /// keys, 32-char values); a violation surfaces as
    /// ``PreludeAuthError/badRequest(_:)``.
    @discardableResult
    public func requestStepUp(
        scope: String,
        // swiftlint:disable:next discouraged_optional_collection
        metadata: [String: String]? = nil
    ) async throws -> StepUpChallenge {
        try await impl.requestStepUp(scope: scope, metadata: metadata)
    }

    /// Trigger OTP delivery (`POST /otp`) for an in-flight
    /// step-up `challenge`.
    ///
    /// Call this when `challenge.currentStep` is an OTP-delivery
    /// step (`verify_email` / `verify_sms`) so the user receives
    /// the code. Caller-driven so the UI decides when delivery
    /// fires.
    ///
    /// Throws ``PreludeAuthError/invalidChallengeToken(_:)``
    /// if `challenge` is blocked (carries no token).
    public func sendStepUpOTP(_ challenge: StepUpChallenge) async throws {
        try await impl.sendStepUpOTP(challenge)
    }

    /// Submit an OTP code for `challenge`.
    ///
    /// Returns the next ``StepUpChallenge`` for multi-step flows,
    /// or `nil` when the flow has completed and the session has
    /// been refreshed with the granted scope. For a multi-step
    /// flow whose next step is also OTP delivery, the caller must
    /// invoke ``sendStepUpOTP(_:)`` on the returned handle to
    /// trigger the next code.
    ///
    /// On a `bad_check_code` rejection the original `challenge`
    /// stays usable up to the server's bucket limit. On any other
    /// error the challenge is dead — recover via
    /// ``requestStepUp(scope:)``.
    @discardableResult
    public func submitStepUpOTP(
        _ challenge: StepUpChallenge,
        code: String
    ) async throws -> StepUpChallenge? {
        try await impl.submitStepUpOTP(challenge, code: code)
    }
}

// MARK: - Implementation

extension PreludeAuthClient.Impl {
    @discardableResult
    func requestStepUp(
        scope: String,
        // swiftlint:disable:next discouraged_optional_collection
        metadata: [String: String]?
    ) async throws -> StepUpChallenge {
        let dispatchID = try await dispatchSignalsIfConfigured()

        var request = buildRequest(path: "stepup/request")
        request.httpBody = try JSONEncoder().encode(
            StepUpRequestBody(
                scope: scope,
                metadata: metadata,
                dispatchID: dispatchID
            )
        )

        let (body, http) = try await httpClient.sendJSON(
            request,
            interceptors: [autoRefreshInterceptor, dpopInterceptor],
            as: StepUpRequestResponse.self
        )

        if body.status == .blocked {
            let blocked = StepUpChallenge.blocked(requestedScope: scope)
            activeStepUp = blocked
            return blocked
        }

        guard let challengeToken = body.challengeToken, !challengeToken.isEmpty else {
            throw PreludeAuthError.missingChallengeToken(
                "Missing challenge token from stepup/request response"
            )
        }

        let challenge = try PreludeAuthClient.makeChallenge(
            from: challengeToken,
            status: body.status,
            scope: scope,
            timeDiffSec: http.timeDiffSec,
            passkeyAssertionOptions: body.passkeyAssertionOptions
        )

        // Defensive: `/stepup/request` is contracted to emit
        // flows that need at least one verification step. A
        // response that arrives already at `completed` is a
        // server contract violation; throw before any
        // post-completion refresh could fire and consume the
        // refresh-token rotation.
        if challenge.currentStep == PreludeAuthClient.completedStepName {
            throw PreludeAuthError.invalidChallengeToken(
                "stepup/request returned an already-completed challenge"
            )
        }

        activeStepUp = challenge
        return challenge
    }

    func sendStepUpOTP(_ challenge: StepUpChallenge) async throws {
        guard !challenge.token.isEmpty else {
            // Blocked challenges carry no token. Catching here
            // means the SDK never fires `/otp` with an empty
            // token — the server would 400, which would leak as a
            // generic BadRequest and obscure the real cause.
            throw PreludeAuthError.invalidChallengeToken(
                "Cannot send OTP for a blocked step-up challenge"
            )
        }
        try await sendOTP(challengeToken: challenge.token)
    }

    @discardableResult
    func submitStepUpOTP(
        _ challenge: StepUpChallenge,
        code: String
    ) async throws -> StepUpChallenge? {
        try await advanceStepUp(challenge, path: "otp/check") {
            StepUpOTPCheckRequestBody(
                code: code,
                challengeToken: challenge.token
            )
        }
    }

    /// Shared advance path for step-up verification endpoints:
    /// validates the challenge, produces the step body, posts it
    /// with challenge-scoped DPoP, and rolls local state to the
    /// advanced challenge — refreshing the session on completion.
    @discardableResult
    func advanceStepUp(
        _ challenge: StepUpChallenge,
        path: String,
        bearerAuthenticated: Bool = false,
        makeBody: () async throws -> some Encodable
    ) async throws -> StepUpChallenge? {
        guard !challenge.token.isEmpty else {
            throw PreludeAuthError.invalidChallengeToken(
                "Cannot submit a blocked step-up challenge"
            )
        }

        // Local expiry guard. The server rejects an expired
        // challenge with an error indistinguishable from a failed
        // verification, so catching it here lets the UI surface
        // "expired, request a fresh one" cleanly.
        if challenge.expiresAt < Int(clock().timeIntervalSince1970) {
            throw PreludeAuthError.expiredChallengeToken(
                "Step-up challenge expired; call requestStepUp(scope:) again"
            )
        }

        let stepBody = try await makeBody()

        var request = buildRequest(path: path)
        request.httpBody = try JSONEncoder().encode(stepBody)

        // Challenge-scoped DPoP proves possession of the challenge.
        // `/stepup/continue` additionally sits behind the access-token
        // guard, so it needs the bearer header; `/otp/check` does not.
        // Its 401 is raised before the step is consumed, so the
        // refresh-and-retry cannot replay a spent proof.
        let challengeDPoP = ChallengeDPoPInterceptor(
            domain: domain,
            keyStore: keyStore,
            challengeToken: challenge.token
        )
        let interceptors: [Interceptor] = bearerAuthenticated
            ? [autoRefreshInterceptor, challengeDPoP]
            : [challengeDPoP]

        let (body, http) = try await httpClient.sendJSON(
            request,
            interceptors: interceptors,
            as: ChallengeTokenResponse.self
        )

        guard let advanced = body.challengeToken, !advanced.isEmpty else {
            throw PreludeAuthError.missingChallengeToken(
                "Missing challenge token from \(path) response"
            )
        }

        let next = try PreludeAuthClient.makeChallenge(
            from: advanced,
            status: challenge.status,
            scope: challenge.requestedScope,
            timeDiffSec: http.timeDiffSec,
            passkeyAssertionOptions: body.passkeyAssertionOptions
        )

        if next.currentStep == PreludeAuthClient.completedStepName {
            // The post-completion refresh consumes `advanced` and
            // mints an access token carrying the granted scope.
            _ = try await refreshAfterStepUp(challengeToken: advanced)
            activeStepUp = nil
            return nil
        }

        activeStepUp = next
        return next
    }

    /// Refresh with `step_up_token` so the next access token
    /// carries the granted scope. Invalidate first (the only
    /// `await` here), then drain — keeps ``startRefresh``'s
    /// "slot empty, no await since" invariant intact.
    func refreshAfterStepUp(challengeToken: String) async throws -> PreludeUser {
        try await accessTokenCache.invalidate(domain: domain)
        await drainInflightRefresh()
        return try await startRefresh(stepUpToken: challengeToken).value
    }
}

// MARK: - Step-name helpers

extension PreludeAuthClient {
    /// Final step name returned by the server when the step-up
    /// flow is finished and the next call should `/refresh` for
    /// the scoped access token.
    static let completedStepName = "completed"
}

// MARK: - Challenge-token decoding

extension PreludeAuthClient {
    static func makeChallenge(
        from token: String,
        status: StepUpStatus,
        scope: String,
        timeDiffSec: TimeInterval,
        passkeyAssertionOptions: RequestOptionsJSON? = nil
    ) throws -> StepUpChallenge {
        let (challengeID, currentStep) = try decodeChallengeMeta(from: token)
        let expiresAt = decodeChallengeExpiry(from: token, timeDiffSec: timeDiffSec)
        return StepUpChallenge(
            status: status,
            challengeID: challengeID,
            currentStep: currentStep,
            requestedScope: scope,
            token: token,
            expiresAt: expiresAt,
            passkeyAssertionOptions: passkeyAssertionOptions
        )
    }

    /// Extract `challenge_id` and `current_step` from a challenge
    /// token. Both are custom claims that ``JWTClaims`` doesn't
    /// model.
    static func decodeChallengeMeta(
        from challengeToken: String
    ) throws -> (challengeID: String, currentStep: String?) {
        let jwt = try JWT.decode(challengeToken)

        guard
            let claims = try? JSONSerialization.jsonObject(
                with: jwt.payloadJSON
            ) as? [String: Any]
        else {
            throw PreludeAuthError.invalidChallengeToken(
                "Challenge token payload is not a JSON object"
            )
        }

        guard let challengeID = claims["challenge_id"] as? String else {
            throw PreludeAuthError.invalidChallengeToken(
                "Challenge token is missing `challenge_id`"
            )
        }

        // `current_step` is optional on older servers.
        let currentStep = claims["current_step"] as? String

        return (challengeID, currentStep)
    }

    /// Clock-skew-adjusted expiry from a challenge token; `0` when
    /// `exp` is missing.
    static func decodeChallengeExpiry(
        from challengeToken: String,
        timeDiffSec: TimeInterval
    ) -> Int {
        guard let jwt = try? JWT.decode(challengeToken),
              let exp = jwt.claims.exp else {
            return 0
        }
        return adjustedLocalExpiresAt(serverExpiresAt: exp, timeDiffSec: timeDiffSec)
    }
}
