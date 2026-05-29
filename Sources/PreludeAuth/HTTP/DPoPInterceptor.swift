import Foundation

/// Minimum |skew| (s) that warrants retrying with a corrected
/// `iat`. Below this, an ``invalid_dpop_proof`` is unlikely to be
/// caused by clock drift so we don't retry.
private let clockSkewRetryThresholdSec: TimeInterval = 1.0

/// Upper bound on the body size we attempt to decode as an API
/// error. Caps the cost of a misbehaving server returning a giant
/// non-JSON 4xx page. Mirrors the Android `MAX_PEEK_BYTES`.
private let maxErrorBodyBytes = 4 * 1024

/// Signs outgoing requests with a DPoP proof and retries once on
/// ``use_dpop_nonce`` or — when the device clock has drifted past
/// ``clockSkewRetryThresholdSec`` — on ``invalid_dpop_proof``. The
/// keypair is created lazily on first use.
struct DPoPInterceptor: Interceptor {
    let domain: String
    let keyStore: DPoPKeyStore
    let proofBuilder: DPoPProofBuilder

    init(
        domain: String,
        keyStore: DPoPKeyStore,
        proofBuilder: DPoPProofBuilder = DefaultDPoPProofBuilder()
    ) {
        self.domain = domain
        self.keyStore = keyStore
        self.proofBuilder = proofBuilder
    }

    func intercept(
        _ request: URLRequest,
        next: SendFunction
    ) async throws -> (Data, HTTPURLResponse) {
        let key = try keyStore.getOrCreate(domain: domain)
        let nonce = try keyStore.getNonce(domain: domain)
        let skew = (try? keyStore.getClockSkew(domain: domain)) ?? 0

        guard let htu = Self.htuURL(for: request) else {
            throw PreludeAuthError.invalidConfiguration(
                "URLRequest is missing a URL; DPoP proof requires one"
            )
        }
        let method = request.httpMethod ?? "GET"

        let proof = try sign(key: key, method: method, htu: htu, nonce: nonce, skew: skew)
        var initialRequest = request
        initialRequest.setValue(proof, forHTTPHeaderField: HTTPHeader.dpop)

        let (data, response) = try await next(initialRequest)
        // RFC 9449 §8: server SHOULD echo `DPoP-Nonce` on every
        // response. Harvest unconditionally up here so the retry
        // paths stay focused on their own concern (use_dpop_nonce
        // or clock skew) and read any rotated nonce from the store.
        let rotatedNonce = try harvestNonce(from: response)

        if !(200 ..< 300).contains(response.statusCode),
           data.count <= maxErrorBodyBytes,
           let apiError = try? JSONDecoder().decode(APIErrorJSON.self, from: data) {
            if apiError.code == "use_dpop_nonce" {
                return try await retryWithNonce(
                    request: request,
                    freshNonce: rotatedNonce,
                    key: key,
                    method: method,
                    htu: htu,
                    skew: skew,
                    next: next
                )
            }
            if apiError.code == "invalid_dpop_proof",
               let retry = try await retryWithCorrectedSkew(
                   request: request,
                   response: response,
                   key: key,
                   method: method,
                   htu: htu,
                   next: next
               ) {
                return retry
            }
        }

        return (data, response)
    }

    private func retryWithNonce(
        request: URLRequest,
        freshNonce: String?,
        key: DPoPKey,
        method: String,
        htu: URL,
        skew: TimeInterval,
        next: SendFunction
    ) async throws -> (Data, HTTPURLResponse) {
        guard let freshNonce else {
            throw PreludeAuthError.generic(
                code: "missing_dpop_nonce",
                message: "Server requested a DPoP nonce but did not provide one"
            )
        }
        let retryProof = try sign(key: key, method: method, htu: htu, nonce: freshNonce, skew: skew)
        let (retryData, retryResponse) = try await sendSigned(request, proof: retryProof, next: next)
        try harvestNonce(from: retryResponse)
        return (retryData, retryResponse)
    }

    /// Returns `nil` when the server didn't supply a parseable
    /// `Date:` header, or the computed skew is below the retry
    /// threshold. A sub-threshold result still *clears* any
    /// persisted skew so a stale correction (e.g. from before a
    /// device-clock re-sync) can't keep poisoning future
    /// requests. Caller falls through to the normal error path.
    private func retryWithCorrectedSkew(
        request: URLRequest,
        response: HTTPURLResponse,
        key: DPoPKey,
        method: String,
        htu: URL,
        next: SendFunction
    ) async throws -> (Data, HTTPURLResponse)? {
        guard let newSkew = Self.serverSkewSec(from: response) else {
            return nil
        }
        guard abs(newSkew) >= clockSkewRetryThresholdSec else {
            try keyStore.deleteClockSkew(domain: domain)
            return nil
        }
        // Persisted skew is sticky until the next
        // `invalid_dpop_proof` either resets or clears it. After
        // a device-clock re-sync the first request burns one
        // server rejection to self-heal — acceptable in exchange
        // for not invalidating skew on every refresh.
        try keyStore.setClockSkew(domain: domain, skew: newSkew)
        let nonce = try keyStore.getNonce(domain: domain)
        let retryProof = try sign(key: key, method: method, htu: htu, nonce: nonce, skew: newSkew)
        let (retryData, retryResponse) = try await sendSigned(request, proof: retryProof, next: next)
        try harvestNonce(from: retryResponse)
        return (retryData, retryResponse)
    }

    private func sign(
        key: DPoPKey, method: String, htu: URL, nonce: String?, skew: TimeInterval
    ) throws -> String {
        try proofBuilder.create(
            key: key,
            method: method,
            url: htu,
            nonce: nonce,
            jti: nil,
            now: Date(),
            clockSkewSec: skew
        )
    }

    private func sendSigned(
        _ request: URLRequest, proof: String, next: SendFunction
    ) async throws -> (Data, HTTPURLResponse) {
        var signed = request
        signed.setValue(proof, forHTTPHeaderField: HTTPHeader.dpop)
        return try await next(signed)
    }

    /// `serverTime - localTime` derived from the response `Date:`
    /// header. `nil` when missing or unparseable, so callers don't
    /// retry on garbage.
    static func serverSkewSec(from response: HTTPURLResponse) -> TimeInterval? {
        guard let dateString = response.value(forHTTPHeaderField: HTTPHeader.date),
              let serverDate = HTTPDate.parse(dateString) else {
            return nil
        }
        return serverDate.timeIntervalSinceNow
    }

    /// Thin alias kept so existing tests and ``Client+Logout`` /
    /// ``ChallengeDPoPInterceptor`` callers don't churn. The shape
    /// helper lives in ``DPoPHtu``.
    static func htuURL(for request: URLRequest) -> URL? {
        DPoPHtu.url(for: request)
    }

    /// Persist a rotated `DPoP-Nonce` if present and return it.
    @discardableResult
    private func harvestNonce(from response: HTTPURLResponse) throws -> String? {
        guard let nonce = response.value(forHTTPHeaderField: HTTPHeader.dpopNonce),
              !nonce.isEmpty else {
            return nil
        }
        try keyStore.setNonce(domain: domain, nonce: nonce)
        return nonce
    }
}
