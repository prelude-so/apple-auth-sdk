import AuthenticationServices
import Foundation
#if canImport(UIKit)
    import UIKit
#endif

/// `ASAuthorizationController`-backed passkey ceremony for platform
/// (iCloud Keychain) credentials.
@available(iOS 16.0, macOS 12.0, *)
@MainActor
final class PasskeyAuthenticator: NSObject, PasskeyAuthenticating {
    private var continuation: CheckedContinuation<ASAuthorization, Error>?
    private var controller: ASAuthorizationController?
    private var isCancelled = false
    private var hasStarted = false

    func register(_ options: CreationOptionsJSON) async throws -> AttestationJSON {
        guard let rpID = options.rp.id, !rpID.isEmpty else {
            throw PreludeAuthError.passkeyRegistrationFailed(
                "Registration options are missing a relying-party id"
            )
        }
        guard let challenge = Data.fromBase64URL(options.challenge),
              let userID = Data.fromBase64URL(options.user.id)
        else {
            throw PreludeAuthError.passkeyRegistrationFailed("Registration options are malformed")
        }

        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: rpID)
        let request = provider.createCredentialRegistrationRequest(
            challenge: challenge,
            name: options.user.name,
            userID: userID
        )
        if let preference = options.authenticatorSelection?.userVerification {
            request.userVerificationPreference = .init(rawValue: preference)
        }
        if let attestation = options.attestation {
            request.attestationPreference = .init(rawValue: attestation)
        }

        let authorization = try await perform([request])
        guard let registration = authorization.credential
            as? ASAuthorizationPlatformPublicKeyCredentialRegistration
        else {
            throw PreludeAuthError.passkeyRegistrationFailed("Unexpected credential from authenticator")
        }
        return try AttestationJSON(registration)
    }

    func assert(_ options: RequestOptionsJSON, autofill: Bool) async throws -> AssertionJSON {
        guard let rpID = options.rpId, !rpID.isEmpty else {
            throw PreludeAuthError.passkeyStepUnavailable(
                "Assertion options are missing a relying-party id"
            )
        }
        guard let challenge = Data.fromBase64URL(options.challenge) else {
            throw PreludeAuthError.passkeyStepUnavailable("Assertion options are malformed")
        }

        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: rpID)
        let request = provider.createCredentialAssertionRequest(challenge: challenge)
        if let preference = options.userVerification {
            request.userVerificationPreference = .init(rawValue: preference)
        }
        if let allowed = options.allowCredentials, !allowed.isEmpty {
            request.allowedCredentials = allowed.compactMap { descriptor in
                Data.fromBase64URL(descriptor.id).map(
                    ASAuthorizationPlatformPublicKeyCredentialDescriptor.init(credentialID:)
                )
            }
        }

        let authorization = try await perform([request], autofill: autofill)
        guard let assertion = authorization.credential
            as? ASAuthorizationPlatformPublicKeyCredentialAssertion
        else {
            throw PreludeAuthError.passkeyStepUnavailable("Unexpected credential from authenticator")
        }
        return try AssertionJSON(assertion)
    }

    // MARK: - Ceremony

    private func perform(
        _ requests: [ASAuthorizationRequest],
        autofill: Bool = false
    ) async throws -> ASAuthorization {
        // One ceremony per authenticator: `continuation` and
        // `controller` hold a single ceremony's state.
        guard !hasStarted else {
            throw PreludeAuthError.conflict("This authenticator has already run a ceremony")
        }
        hasStarted = true

        // AutoFill requests are non-modal and are meant to stay armed
        // alongside a button-driven ceremony, so only modal ones take
        // the gate.
        let takesGate = !autofill
        if takesGate {
            guard PasskeyCeremonyGate.acquire() else {
                throw PreludeAuthError.conflict("Another passkey ceremony is already in progress")
            }
        }
        defer {
            if takesGate {
                PasskeyCeremonyGate.release()
            }
        }

        return try await withTaskCancellationHandler(
            operation: {
                try await withCheckedThrowingContinuation { continuation in
                    // The task can already be cancelled here, in which
                    // case `onCancel` has run with no controller to stop.
                    guard !self.isCancelled else {
                        continuation.resume(throwing: PreludeAuthError.cancelled)
                        return
                    }
                    self.continuation = continuation
                    let controller = ASAuthorizationController(authorizationRequests: requests)
                    controller.delegate = self
                    controller.presentationContextProvider = self
                    self.controller = controller
                    #if os(iOS)
                        if autofill {
                            controller.performAutoFillAssistedRequests()
                        } else {
                            controller.performRequests()
                        }
                    #else
                        controller.performRequests()
                    #endif
                }
            },
            onCancel: {
                Task { @MainActor in self.cancelCeremony() }
            }
        )
    }

    /// Stops an in-flight ceremony, or resumes a pending one that was
    /// cancelled before its controller existed.
    private func cancelCeremony() {
        isCancelled = true
        if let controller {
            controller.cancel()
        } else {
            resume(.failure(PreludeAuthError.cancelled))
        }
    }

    /// Resumes at most once; later delegate callbacks are ignored.
    private func resume(_ result: Result<ASAuthorization, Error>) {
        guard let continuation else { return }
        self.continuation = nil
        controller = nil
        continuation.resume(with: result)
    }
}

@available(iOS 16.0, macOS 12.0, *)
extension PasskeyAuthenticator: ASAuthorizationControllerDelegate {
    func authorizationController(
        controller _: ASAuthorizationController,
        didCompleteWithAuthorization authorization: ASAuthorization
    ) {
        resume(.success(authorization))
    }

    func authorizationController(
        controller _: ASAuthorizationController,
        didCompleteWithError error: Error
    ) {
        resume(.failure(Self.mapError(error)))
    }

    /// A user-dismissed sheet is control flow, not an auth failure.
    private static func mapError(_ error: Error) -> Error {
        if let asError = error as? ASAuthorizationError, asError.code == .canceled {
            return PreludeAuthError.cancelled
        }
        return error
    }
}

@available(iOS 16.0, macOS 12.0, *)
extension PasskeyAuthenticator: ASAuthorizationControllerPresentationContextProviding {
    func presentationAnchor(for _: ASAuthorizationController) -> ASPresentationAnchor {
        #if canImport(UIKit)
            let keyWindow = UIApplication.shared.connectedScenes
                .compactMap { $0 as? UIWindowScene }
                .flatMap(\.windows)
                .first(where: \.isKeyWindow)
            return keyWindow ?? ASPresentationAnchor()
        #else
            return ASPresentationAnchor()
        #endif
    }
}

/// Serialises ceremony presentation: the system shows one sheet at
/// a time.
@MainActor
enum PasskeyCeremonyGate {
    private static var active = false

    static func acquire() -> Bool {
        guard !active else { return false }
        active = true
        return true
    }

    static func release() {
        active = false
    }
}

// MARK: - AuthenticationServices → WebAuthn JSON

@available(iOS 16.0, macOS 12.0, *)
extension AttestationJSON {
    init(_ registration: ASAuthorizationPlatformPublicKeyCredentialRegistration) throws {
        guard let attestationObject = registration.rawAttestationObject else {
            throw PreludeAuthError.passkeyRegistrationFailed("Authenticator returned no attestation object")
        }
        let id = registration.credentialID.base64URLEncodedString()
        self.init(
            id: id,
            rawId: id,
            authenticatorAttachment: "platform",
            response: Response(
                clientDataJSON: registration.rawClientDataJSON.base64URLEncodedString(),
                attestationObject: attestationObject.base64URLEncodedString(),
                transports: nil
            )
        )
    }
}

@available(iOS 16.0, macOS 12.0, *)
extension AssertionJSON {
    /// A non-discoverable credential can omit the user handle, and the
    /// signature fields are optional, so none of them can be forced.
    init(_ assertion: ASAuthorizationPlatformPublicKeyCredentialAssertion) throws {
        guard let authenticatorData = assertion.rawAuthenticatorData,
              let signature = assertion.signature
        else {
            throw PreludeAuthError.passkeyStepUnavailable("Authenticator returned an incomplete assertion")
        }
        let id = assertion.credentialID.base64URLEncodedString()
        self.init(
            id: id,
            rawId: id,
            authenticatorAttachment: "platform",
            response: Response(
                clientDataJSON: assertion.rawClientDataJSON.base64URLEncodedString(),
                authenticatorData: authenticatorData.base64URLEncodedString(),
                signature: signature.base64URLEncodedString(),
                userHandle: assertion.userID?.base64URLEncodedString()
            )
        )
    }
}
