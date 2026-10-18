import Foundation

/// Attaches a DPoP proof bound to a specific step-up challenge token.
///
/// The proof reuses the challenge's `jti` so the server can pin it to the
/// challenge, and carries no nonce. These requests are one-shot and never
/// retry, so the skew is *read* from the keystore, pre-corrected by the
/// regular ``DPoPInterceptor``'s own retry.
///
/// Uses ``DPoPKeyStore/get(domain:)`` rather than ``getOrCreate``: minting a
/// fresh keypair here would mismatch the fingerprint the challenge-issuing
/// session pinned server-side.
struct ChallengeDPoPInterceptor: Interceptor {
    let domain: String
    let keyStore: DPoPKeyStore
    let challengeToken: String

    func intercept(
        _ request: URLRequest,
        next: SendFunction
    ) async throws -> (Data, HTTPURLResponse) {
        guard let handle = try keyStore.get(domain: domain) else {
            return try await next(request)
        }

        guard let jti = try Self.decodeJTI(from: challengeToken) else {
            // Malformed or jti-less challenge token: let the server
            // reject with `invalid_challenge_token`.
            return try await next(request)
        }

        guard let htu = DPoPInterceptor.htuURL(for: request) else {
            throw PreludeAuthError.invalidConfiguration(
                "URLRequest is missing a URL; challenge DPoP proof requires one"
            )
        }

        let method = request.httpMethod ?? "GET"
        let skew = (try? keyStore.getClockSkew(domain: domain)) ?? 0
        let proof = try DefaultDPoPProofBuilder().create(
            key: handle,
            method: method,
            url: htu,
            nonce: nil,
            jti: jti,
            now: Date(),
            clockSkewSec: skew
        )

        var signed = request
        signed.setValue(proof, forHTTPHeaderField: HTTPHeader.dpop)

        return try await next(signed)
    }

    static func decodeJTI(from challengeToken: String) throws -> String? {
        let jwt = try JWT.decode(challengeToken)
        return jwt.claims.jti
    }
}
