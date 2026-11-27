import CryptoKit
import Foundation
import Security

/// PKCE primitives (RFC 7636). The verifier is high-entropy random
/// bytes; the S256 challenge is its SHA-256 digest. Both are
/// base64url-encoded.
enum PKCE {
    /// 32 random bytes, base64url-encoded — well above the 43-char
    /// minimum verifier length and within the 128-char ceiling.
    /// Throws ``PreludeAuthError/generic(code:message:)`` on the
    /// near-impossible CSPRNG failure rather than crashing the host.
    static func generateCodeVerifier() throws -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else {
            throw PreludeAuthError.generic(
                code: "pkce_random_failed",
                message: "SecRandomCopyBytes failed: \(status)"
            )
        }
        return Data(bytes).base64URLEncodedString()
    }

    /// S256 transform per RFC 7636 §4.2: SHA-256 of the verifier's
    /// ASCII bytes, base64url-encoded.
    static func codeChallenge(for verifier: String) -> String {
        Data.sha256Base64URL(verifier)
    }
}
