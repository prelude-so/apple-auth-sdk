import Foundation

/// Attaches a DPoP proof bound to a specific step-up challenge token.
///
/// Differences from ``DPoPInterceptor``:
/// - The proof's `jti` is the challenge's `jti`, not a fresh UUID,
///   so the server can pin the proof to the challenge.
/// - No nonce: challenge-scoped requests are one-shot.
/// - No retry. The skew correction is *read* from the keystore so
///   one-shot proofs after the regular interceptor's first retry
///   are pre-corrected.
///
/// Uses ``DPoPKeyStore/get(domain:)`` (not ``getOrCreate``) — the
/// challenge-issuing session has already provisioned the keypair, so
/// minting a fresh one here would mismatch the fingerprint pinned
/// server-side. An empty keystore passes through unsigned and lets
/// the server's own error surface.
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
