import Foundation

// MARK: - Public facade

extension PreludeAuthClient {
    /// Log in with an email identifier and a password.
    ///
    /// `POST /login/email/password` returns a short-lived
    /// `challenge_token`; the SDK exchanges it on `/login/finalize`.
    @discardableResult
    public func loginWithPassword(
        _ options: LoginWithPasswordOptions
    ) async throws -> PreludeUser {
        try await impl.loginWithPassword(options)
    }

    /// Fetch the server's password compliancy rules.
    /// Unauthenticated — the rules are public configuration.
    public func passwordCompliancy() async throws -> PreludePasswordCompliancy {
        try await impl.passwordCompliancy()
    }

    /// Validate a candidate password against the server's configured
    /// compliancy rules. One network call, then pure local
    /// classification that counts Unicode code points, not grapheme
    /// clusters.
    public func validatePassword(
        _ password: String
    ) async throws -> PreludePasswordCompliancyResults {
        try await impl.validatePassword(password)
    }
}

// MARK: - Implementation

extension PreludeAuthClient.Impl {
    func loginWithPassword(
        _ options: LoginWithPasswordOptions
    ) async throws -> PreludeUser {
        let dispatchId = try await dispatchSignalsIfConfigured()

        var request = buildRequest(path: "login/email/password")
        request.httpBody = try JSONEncoder().encode(
            LoginWithPasswordRequestBody(
                emailAddress: options.emailAddress,
                password: options.password.value,
                dispatchID: dispatchId
            )
        )

        let (body, _) = try await httpClient.sendJSON(
            request,
            interceptors: [],
            as: ChallengeTokenResponse.self
        )

        guard let challengeToken = body.challengeToken,
              !challengeToken.isEmpty else {
            throw PreludeAuthError.missingChallengeToken(
                "Missing challenge token from password login response"
            )
        }

        return try await finalizeLogin(challengeToken: challengeToken)
    }

    func passwordCompliancy() async throws -> PreludePasswordCompliancy {
        let request = buildRequest(path: "password/compliancy", method: "GET")

        let (body, _) = try await httpClient.sendJSON(
            request,
            interceptors: [],
            as: PreludePasswordCompliancy.self
        )
        return body
    }

    func validatePassword(
        _ password: String
    ) async throws -> PreludePasswordCompliancyResults {
        let compliancy = try await passwordCompliancy()
        return PreludeAuthClient.validate(password: password, against: compliancy)
    }
}

// MARK: - Pure classification

extension PreludeAuthClient {
    /// Classify a candidate password against `compliancy`. Pure
    /// local logic — no network call.
    public static func validate(
        password: String,
        against compliancy: PreludePasswordCompliancy
    ) -> PreludePasswordCompliancyResults {
        var uppercase = 0
        var lowercase = 0
        var numbers = 0
        var symbols = 0

        for scalar in password.unicodeScalars {
            switch scalar.properties.generalCategory {
            case .uppercaseLetter:
                uppercase += 1
            case .lowercaseLetter:
                lowercase += 1
            case .decimalNumber:
                numbers += 1
            default:
                symbols += 1
            }
        }

        let length = password.unicodeScalars.count

        let results: [PreludePasswordCompliancyResult] = [
            .init(
                criterion: .minLength,
                actual: length,
                expected: compliancy.minLength,
                valid: length >= compliancy.minLength
            ),
            .init(
                criterion: .maxLength,
                actual: length,
                expected: compliancy.maxLength,
                // maxLength == 0 is the "no upper bound" sentinel.
                valid: compliancy.maxLength == 0 || length <= compliancy.maxLength
            ),
            .init(
                criterion: .uppercase,
                actual: uppercase,
                expected: compliancy.uppercase,
                valid: uppercase >= compliancy.uppercase
            ),
            .init(
                criterion: .lowercase,
                actual: lowercase,
                expected: compliancy.lowercase,
                valid: lowercase >= compliancy.lowercase
            ),
            .init(
                criterion: .numbers,
                actual: numbers,
                expected: compliancy.numbers,
                valid: numbers >= compliancy.numbers
            ),
            .init(
                criterion: .symbols,
                actual: symbols,
                expected: compliancy.symbols,
                valid: symbols >= compliancy.symbols
            ),
        ]

        return PreludePasswordCompliancyResults(
            valid: results.allSatisfy(\.valid),
            results: results
        )
    }
}
