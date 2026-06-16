import Foundation

/// Stamps the persisted device id from ``DeviceIDStore`` onto every
/// request as ``HTTPHeader/deviceID``. The store handles lazy
/// creation and concurrent-caller convergence.
///
/// Best-effort: if the store throws (e.g. a Keychain fault) the
/// request proceeds without the header — a missing device id must
/// never fail the chain.
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
