import Foundation

enum DPoPProofError: Error {
    case publicKeyExportFailed
    case invalidPublicKeyRepresentation
    case signingFailed(underlying: Error?)
    case derSignatureMalformed
    case jsonEncodingFailed(Error)
}

/// Builds DPoP JWT proofs (RFC 9449). Injectable so
/// ``DPoPInterceptor`` can be unit-tested in isolation.
protocol DPoPProofBuilder: Sendable {
    func create(
        key: DPoPKey,
        method: String,
        url: URL,
        nonce: String?,
        jti: String?,
        now: Date,
        clockSkewSec: TimeInterval
    ) throws -> String
}

/// Production ``DPoPProofBuilder``. Stateless; safe to share.
struct DefaultDPoPProofBuilder: DPoPProofBuilder {
    /// ``clockSkewSec`` is `serverTime - localTime`. Applied to
    /// ``iat`` so the claim lands in the server's frame when the
    /// device clock has drifted. Default `0` keeps existing call
    /// sites compiling.
    func create(
        key: DPoPKey,
        method: String,
        url: URL,
        nonce: String? = nil,
        jti: String? = nil,
        now: Date = Date(),
        clockSkewSec: TimeInterval = 0
    ) throws -> String {
        let jwk = try key.exportPublicJWK()
        let header: [String: Any] = [
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": jwk,
        ]

        var payload: [String: Any] = [
            "jti": jti ?? UUID().uuidString.lowercased(),
            "htm": method,
            "htu": url.absoluteString,
            "iat": Int(now.addingTimeInterval(clockSkewSec).timeIntervalSince1970),
        ]
        if let nonce {
            payload["nonce"] = nonce
        }

        let encodedHeader = try Self.jsonData(header).base64URLEncodedString()
        let encodedPayload = try Self.jsonData(payload).base64URLEncodedString()
        let signingInput = "\(encodedHeader).\(encodedPayload)"
        let signature = try key.signES256(Data(signingInput.utf8))
        return "\(signingInput).\(signature.base64URLEncodedString())"
    }

    /// Deterministic JSON bytes (sorted keys) so signatures are
    /// reproducible.
    private static func jsonData(_ object: [String: Any]) throws -> Data {
        do {
            return try JSONSerialization.data(
                withJSONObject: object,
                options: [.sortedKeys, .withoutEscapingSlashes]
            )
        } catch {
            throw DPoPProofError.jsonEncodingFailed(error)
        }
    }
}
