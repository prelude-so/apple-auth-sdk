import Foundation

// MARK: - Public facade

extension PreludeAuthClient {
    /// Advance a `verify_passkey` step-up by asserting a passkey.
    ///
    /// Use when `challenge.currentStep` is `verify_passkey`; use
    /// ``submitStepUpOTP(_:code:)`` for OTP steps. Returns the next
    /// ``StepUpChallenge`` for multi-step flows, or `nil` once the
    /// flow completes and the session is refreshed with the granted
    /// scope. Throws ``PreludeAuthError/passkeyStepUnavailable(_:)``
    /// when the current step carries no assertion options.
    @discardableResult
    public func continueStepUpWithPasskey(
        _ challenge: StepUpChallenge
    ) async throws -> StepUpChallenge? {
        try await continueStepUpWithPasskey(
            challenge,
            authenticator: Self.makeDefaultAuthenticator()
        )
    }

    /// Testable core of ``continueStepUpWithPasskey(_:)``.
    @discardableResult
    func continueStepUpWithPasskey(
        _ challenge: StepUpChallenge,
        authenticator: any PasskeyAuthenticating
    ) async throws -> StepUpChallenge? {
        try await impl.continueStepUpWithPasskey(challenge, authenticator: authenticator)
    }
}

// MARK: - Implementation

extension PreludeAuthClient.Impl {
    @discardableResult
    func continueStepUpWithPasskey(
        _ challenge: StepUpChallenge,
        authenticator: any PasskeyAuthenticating
    ) async throws -> StepUpChallenge? {
        // The body closure runs after the shared challenge guards,
        // so the system sheet never shows for a stale challenge.
        try await advanceStepUp(
            challenge,
            path: "stepup/continue",
            bearerAuthenticated: true
        ) {
            guard let options = challenge.passkeyAssertionOptions else {
                throw PreludeAuthError.passkeyStepUnavailable("Current step is not verify_passkey")
            }
            let assertion = try await authenticator.assert(options, autofill: false)
            return PasskeyStepUpContinueBody(
                challengeToken: challenge.token,
                passkeyAssertion: assertion
            )
        }
    }
}
