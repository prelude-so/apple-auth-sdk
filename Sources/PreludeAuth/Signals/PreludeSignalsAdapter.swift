import Foundation

// The signals SDK is the module `Prelude` in its 0.x line and
// `PreludeSignals` in its 1.x line. Wrappers that compile both source
// trees into one module import neither.
#if canImport(Prelude)
    import Prelude
#elseif canImport(PreludeSignals)
    import PreludeSignals
#endif

/// ``PreludeSignalsDispatcher`` backed by the Prelude Apple SDK.
///
/// The SDK key is `sdkKey` when it is not blank, else the
/// ``infoPlistKey`` entry of the main bundle's `Info.plist`. With no
/// key in either place the adapter is a no-op: ``dispatch()`` returns
/// `nil` and logins carry no `dispatch_id`.
///
/// `timeout` bounds each request and the whole dispatch.
///
/// ``PreludeAuthClient`` builds one of these by itself when it gets no
/// dispatcher, so most apps only add the `Info.plist` entry.
///
/// `@unchecked Sendable`: the upstream `Prelude` and `Configuration`
/// types are value-type structs without shared mutable state.
public struct PreludeSignalsAdapter: PreludeSignalsDispatcher, @unchecked Sendable {
    /// `Info.plist` entry read for the SDK key.
    public static let infoPlistKey = "PreludeSDKKey"

    private let prelude: Prelude?
    private let timeout: TimeInterval

    public init(
        sdkKey: String? = nil,
        timeout: TimeInterval = 5.0
    ) {
        let resolved = pickSignalsSDKKey(explicit: sdkKey) {
            Bundle.main.object(forInfoDictionaryKey: Self.infoPlistKey) as? String
        }
        prelude = resolved.map { Prelude(Configuration(sdkKey: $0, timeout: timeout)) }
        self.timeout = max(0, timeout)
    }

    public func dispatch() async throws -> String? {
        guard let prelude else { return nil }
        // The signals SDK retries each request and does not stop on
        // cancellation, so the time limit races the dispatch.
        let limit = UInt64(timeout * 1_000_000_000)
        return try await withCheckedThrowingContinuation { continuation in
            let race = DispatchRace(continuation)
            Task {
                do {
                    try await race.finish(.success(prelude.dispatchSignals()))
                } catch {
                    race.finish(.failure(error))
                }
            }
            Task {
                try? await Task.sleep(nanoseconds: limit)
                race.finish(.success(nil))
            }
        }
    }
}

/// Resumes the continuation with the first result only.
private final class DispatchRace: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<String?, Error>?

    init(_ continuation: CheckedContinuation<String?, Error>) {
        self.continuation = continuation
    }

    func finish(_ result: Result<String?, Error>) {
        lock.lock()
        let pending = continuation
        continuation = nil
        lock.unlock()
        pending?.resume(with: result)
    }
}

/// The explicit key when it is not blank, else the `Info.plist` key, else `nil`.
func pickSignalsSDKKey(explicit: String?, infoPlist: () -> String?) -> String? {
    func nonBlank(_ value: String?) -> String? {
        guard let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines),
              !trimmed.isEmpty else { return nil }
        return trimmed
    }
    return nonBlank(explicit) ?? nonBlank(infoPlist())
}
