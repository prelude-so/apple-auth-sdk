import Foundation

// Wire shapes mirror WebAuthn JSON, where an absent field is
// meaningful and distinct from an empty or false value.
// swiftlint:disable discouraged_optional_boolean discouraged_optional_collection

// MARK: - Server → client options (WebAuthn JSON)

/// Credential-creation options returned by `register/begin`.
struct CreationOptionsJSON: Decodable, Equatable {
    struct RelyingParty: Decodable, Equatable {
        let id: String?
        let name: String
    }

    struct User: Decodable, Equatable {
        let id: String
        let name: String
        let displayName: String
    }

    struct Param: Decodable, Equatable {
        let type: String
        let alg: Int
    }

    struct Descriptor: Decodable, Equatable {
        let id: String
        let type: String
        let transports: [String]?
    }

    struct AuthenticatorSelection: Decodable, Equatable {
        let authenticatorAttachment: String?
        let residentKey: String?
        let userVerification: String?
        let requireResidentKey: Bool?
    }

    let rp: RelyingParty // swiftlint:disable:this identifier_name
    let user: User
    let challenge: String
    let pubKeyCredParams: [Param]
    let timeout: Int?
    let excludeCredentials: [Descriptor]?
    let authenticatorSelection: AuthenticatorSelection?
    let attestation: String?
}

/// Credential-request (assertion) options returned by
/// `login/begin` and carried on a `verify_passkey` step-up.
struct RequestOptionsJSON: Decodable, Equatable {
    struct Descriptor: Decodable, Equatable {
        let id: String
        let type: String
        let transports: [String]?
    }

    let challenge: String
    let timeout: Int?
    let rpId: String?
    let allowCredentials: [Descriptor]?
    let userVerification: String?
}

// MARK: - Client → server ceremony output (WebAuthn JSON)

/// Attestation posted to `register/finish`.
struct AttestationJSON: Encodable, Equatable {
    struct Response: Encodable, Equatable {
        let clientDataJSON: String
        let attestationObject: String
        let transports: [String]?
    }

    let id: String
    let rawId: String
    let type = "public-key"
    let authenticatorAttachment: String?
    let response: Response
}

/// Assertion posted to `login/finish` and `stepup/continue`.
struct AssertionJSON: Encodable, Equatable {
    struct Response: Encodable, Equatable {
        let clientDataJSON: String
        let authenticatorData: String
        let signature: String
        let userHandle: String?
    }

    let id: String
    let rawId: String
    let type = "public-key"
    let authenticatorAttachment: String?
    let response: Response
}

// MARK: - Begin/finish request bodies

struct PasskeyRegisterBeginBody: Encodable {
    let username: String
    let displayName: String?
    let nickname: String?

    enum CodingKeys: String, CodingKey {
        case username
        case displayName = "display_name"
        case nickname
    }
}

struct PasskeyRegisterFinishBody: Encodable {
    let registrationToken: String
    let attestation: AttestationJSON

    enum CodingKeys: String, CodingKey {
        case registrationToken = "registration_token"
        case attestation
    }
}

struct PasskeyLoginFinishBody: Encodable {
    let loginToken: String
    let assertion: AssertionJSON

    enum CodingKeys: String, CodingKey {
        case loginToken = "login_token"
        case assertion
    }
}

struct PasskeyStepUpContinueBody: Encodable {
    let challengeToken: String
    let passkeyAssertion: AssertionJSON

    enum CodingKeys: String, CodingKey {
        case challengeToken = "challenge_token"
        case passkeyAssertion = "passkey_assertion"
    }
}

struct PasskeyRenameBody: Encodable {
    let nickname: String
}

struct PasskeyLoginBeginBody: Encodable {
    let dispatchID: String?

    enum CodingKeys: String, CodingKey {
        case dispatchID = "dispatch_id"
    }
}

// MARK: - Response bodies

struct PasskeyRegisterBeginResponse: Decodable {
    let publicKey: CreationOptionsJSON
    let registrationToken: String

    enum CodingKeys: String, CodingKey {
        case publicKey = "public_key"
        case registrationToken = "registration_token"
    }
}

struct PasskeyLoginBeginResponse: Decodable {
    let publicKey: RequestOptionsJSON
    let loginToken: String

    enum CodingKeys: String, CodingKey {
        case publicKey = "public_key"
        case loginToken = "login_token"
    }
}

struct PasskeyRegisterFinishResponse: Decodable {
    let credential: PasskeyCredentialJSON
    let alreadyRegistered: Bool?

    enum CodingKeys: String, CodingKey {
        case credential
        case alreadyRegistered = "already_registered"
    }
}

struct PasskeyListResponse: Decodable {
    let credentials: [PasskeyCredentialJSON]?
}

struct PasskeyCredentialJSON: Decodable {
    let credentialID: String
    let nickname: String?
    let transports: [String]?
    let backupState: Bool?
    let createdAt: Int?
    let lastUsedAt: Int?

    enum CodingKeys: String, CodingKey {
        case credentialID = "credential_id"
        case nickname
        case transports
        case backupState = "backup_state"
        case createdAt = "created_at"
        case lastUsedAt = "last_used_at"
    }
}

// MARK: - Redaction

// Ceremony bodies carry single-use bearer tokens. Keep them out of
// `description` / `debugDescription` / `dump()`; `Encodable` still
// writes them verbatim to the wire.

extension PasskeyRegisterFinishBody: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    var description: String {
        "PasskeyRegisterFinishBody(registrationToken: <redacted>, attestation: \(attestation))"
    }

    var debugDescription: String {
        description
    }

    var customMirror: Mirror {
        Mirror(self, children: [
            "registrationToken": "<redacted>",
            "attestation": attestation,
        ], displayStyle: .struct)
    }
}

extension PasskeyLoginFinishBody: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    var description: String {
        "PasskeyLoginFinishBody(loginToken: <redacted>, assertion: \(assertion))"
    }

    var debugDescription: String {
        description
    }

    var customMirror: Mirror {
        Mirror(self, children: [
            "loginToken": "<redacted>",
            "assertion": assertion,
        ], displayStyle: .struct)
    }
}

extension PasskeyStepUpContinueBody: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    var description: String {
        "PasskeyStepUpContinueBody(challengeToken: <redacted>, passkeyAssertion: \(passkeyAssertion))"
    }

    var debugDescription: String {
        description
    }

    var customMirror: Mirror {
        Mirror(self, children: [
            "challengeToken": "<redacted>",
            "passkeyAssertion": passkeyAssertion,
        ], displayStyle: .struct)
    }
}

// swiftlint:enable discouraged_optional_boolean discouraged_optional_collection
