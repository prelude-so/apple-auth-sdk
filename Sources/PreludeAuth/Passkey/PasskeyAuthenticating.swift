import Foundation

/// Drives the platform passkey ceremony. Abstracted so the flows
/// can be exercised without system UI.
protocol PasskeyAuthenticating: Sendable {
    /// Create a credential and return its attestation.
    func register(_ options: CreationOptionsJSON) async throws -> AttestationJSON
    /// Assert an existing credential. `autofill` requests the
    /// AutoFill-assisted presentation.
    func assert(_ options: RequestOptionsJSON, autofill: Bool) async throws -> AssertionJSON
}
