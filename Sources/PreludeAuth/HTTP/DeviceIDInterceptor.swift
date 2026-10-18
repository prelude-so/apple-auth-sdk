import Foundation

/// Stamps the persisted device id from ``DeviceIDStore`` onto every request
/// as ``HTTPHeader/deviceID``. Best-effort: a store fault (e.g. a Keychain
/// error) must never fail the chain, so the request proceeds unstamped.
struct DeviceIDInterceptor: Interceptor {
    let domain: String
    let store: DeviceIDStore

    func intercept(
        _ request: URLRequest,
        next: SendFunction
    ) async throws -> (Data, HTTPURLResponse) {
        var mutated = request
        if let deviceID = try? store.getOrCreate(domain: domain) {
            mutated.setValue(deviceID, forHTTPHeaderField: HTTPHeader.deviceID)
        }
        return try await next(mutated)
    }
}
