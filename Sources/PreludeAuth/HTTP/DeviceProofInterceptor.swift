import Foundation

/// Adds the `Prelude-Device-Proof` header. Place it outside the DPoP
/// interceptor so a DPoP retry resends the same device proof.
struct DeviceProofInterceptor: Interceptor {
    enum Mode {
        /// On `invalid_device_proof`, retries without the proof, so an SDK
        /// bug never blocks a sign-in.
        case login
        /// No retry: the server requires the proof.
        case stepUp
    }

    let mode: Mode
    let domain: String
    let keyStore: DPoPKeyStore
    let deviceKeyStore: DeviceKeyStore
    let challengeToken: String

    func intercept(
        _ request: URLRequest,
        next: SendFunction
    ) async throws -> (Data, HTTPURLResponse) {
        // At step-up the server refuses a request without a proof, so a
        // Keychain error is thrown instead.
        let proof: String?
        do {
            proof = try makeProof(for: request)
        } catch {
            guard mode == .login else { throw error }
            proof = nil
        }
        guard let proof else {
            return try await next(request)
        }

        var signed = request
        signed.setValue(proof, forHTTPHeaderField: HTTPHeader.deviceProof)
        let (data, response) = try await next(signed)

        if mode == .login,
           response.statusCode == 400,
           APIErrorJSON.decode(data, response: response)?.code == "invalid_device_proof" {
            return try await next(request)
        }
        return (data, response)
    }

    private func makeProof(for request: URLRequest) throws -> String? {
        let dpopKey = mode == .login ? try keyStore.getOrCreate(domain: domain) : try keyStore.get(domain: domain)
        guard let dpopKey, let url = DPoPHtu.url(for: request) else {
            return nil
        }
        return try DeviceProof.create(
            deviceKey: deviceKeyStore.getOrCreate(),
            storage: deviceKeyStore.storage,
            dpopKey: dpopKey,
            method: request.httpMethod ?? "POST",
            url: url,
            challengeToken: challengeToken
        )
    }
}
