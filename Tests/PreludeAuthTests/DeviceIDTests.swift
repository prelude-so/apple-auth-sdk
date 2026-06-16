import Foundation
@testable import PreludeAuth
import Security
import XCTest

/// `X-Device-Id` is attached to every session request and the
/// underlying id is stable across calls — the value is generated
/// once per domain and persisted in the Keychain.
final class DeviceIDTests: XCTestCase {
    private var domain: String!
    private var baseURL: URL!
    private var clock: NowProvider!

    override func setUp() {
        super.setUp()
        domain = "deviceid-test-\(UUID().uuidString.lowercased()).example"
        baseURL = URL(string: "https://\(domain!)")!
        clock = { Date(timeIntervalSince1970: 1_000_000) }
    }

    func test_deviceIDHeader_isAttachedAndStableAcrossRequests() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        fixture.http.install(path: "/v1/session/otp", response: .noContent)

        for _ in 0 ..< 2 {
            try await fixture.client.startOTPLogin(
                StartOTPLoginOptions(
                    identifier: PreludeIdentifier(type: .emailAddress, value: "alice@example.com")
                )
            )
        }

        let headers = fixture.http.requests(forPath: "/v1/session/otp")
            .compactMap { $0.value(forHTTPHeaderField: HTTPHeader.deviceID) }
        XCTAssertEqual(headers.count, 2, "every request must carry X-Device-Id")
        XCTAssertEqual(headers[0], headers[1], "device id must be stable across requests")
        XCTAssertNotNil(UUID(uuidString: headers[0]), "device id must be a UUID")
    }

    /// Device id is best-effort — if the store throws (e.g. a
    /// Keychain fault) the request must still go out, just without
    /// `X-Device-Id`; it must never fail the chain.
    func test_deviceIDHeader_isOmittedNotFatal_whenStoreFails() async throws {
        let fixture = try Fixture.make(
            domain: domain,
            baseURL: baseURL,
            clock: clock,
            backend: DeviceIDFailingKeychainBackend()
        )
        fixture.http.install(path: "/v1/session/otp", response: .noContent)

        try await fixture.client.startOTPLogin(
            StartOTPLoginOptions(
                identifier: PreludeIdentifier(type: .emailAddress, value: "alice@example.com")
            )
        )

        let requests = fixture.http.requests(forPath: "/v1/session/otp")
        XCTAssertEqual(requests.count, 1, "request must still be sent")
        XCTAssertNil(
            requests.first?.value(forHTTPHeaderField: HTTPHeader.deviceID),
            "header must be omitted, not fatal"
        )
    }

    func test_deviceIDStore_getOrCreate_isIdempotent() throws {
        let backend = InMemoryKeychainBackend()
        let store = DeviceIDStore(keychain: backend)
        let first = try store.getOrCreate(domain: domain)
        let second = try store.getOrCreate(domain: domain)
        XCTAssertEqual(first, second)
        XCTAssertNotNil(UUID(uuidString: first))
    }

    /// Parallel first-time callers must converge on a single id —
    /// the in-process lock plus the duplicate-item fallback keep
    /// the get-then-add window race-free.
    func test_deviceIDStore_concurrentGetOrCreate_convergesOnOneID() async throws {
        let backend = InMemoryKeychainBackend()
        let store = DeviceIDStore(keychain: backend)
        let domain = try XCTUnwrap(domain)

        let ids = await withTaskGroup(of: String.self) { group in
            for _ in 0 ..< 16 {
                group.addTask { (try? store.getOrCreate(domain: domain)) ?? "" }
            }
            var out: [String] = []
            for await id in group {
                out.append(id)
            }
            return out
        }

        XCTAssertEqual(Set(ids).count, 1, "all callers must observe one id; got \(Set(ids))")
        XCTAssertFalse(ids.first?.isEmpty ?? true)
    }

    /// A racing peer (another process sharing the Keychain) lands a
    /// write between our `get` and `add`. Our `add` returns
    /// `errSecDuplicateItem` and we recover by re-reading.
    func test_deviceIDStore_getOrCreate_recoversFromDuplicateItem() throws {
        let racingValue = UUID().uuidString.lowercased()
        let backend = RacingKeychainBackend(racingValue: racingValue)
        let store = DeviceIDStore(keychain: backend)

        XCTAssertEqual(try store.getOrCreate(domain: domain), racingValue)
        XCTAssertEqual(backend.addCalls, 1, "add must have been attempted")
    }
}

/// Simulates a peer writing between our `get` (sees nothing) and
/// our `add` (returns `errSecDuplicateItem`). The recovery re-read
/// then returns the peer's value.
private final class RacingKeychainBackend: KeychainBackend, @unchecked Sendable {
    private let racingValue: String
    private let lock = NSLock()
    private(set) var addCalls = 0
    private var addAttempted = false

    init(racingValue: String) {
        self.racingValue = racingValue
    }

    func copyMatching(_: [String: Any]) throws -> CFTypeRef? {
        lock.lock(); defer { lock.unlock() }
        // First read (pre-race) sees nothing; later reads (post-add)
        // see the racing peer's value.
        if !addAttempted {
            return nil
        }
        return Data(racingValue.utf8) as NSData as CFTypeRef
    }

    func add(_: [String: Any]) -> OSStatus {
        lock.lock(); defer { lock.unlock() }
        addCalls += 1
        addAttempted = true
        return errSecDuplicateItem
    }

    func update(_: [String: Any], attributesToUpdate _: [String: Any]) -> OSStatus {
        errSecUnimplemented
    }

    func delete(_: [String: Any]) -> OSStatus {
        errSecSuccess
    }

    func createRandomKey(_: [String: Any]) throws -> SecKey {
        throw DPoPKeyStoreError.keychainFailure(errSecUnimplemented)
    }
}

/// Delegates to an inner in-memory backend but fails any
/// generic-password operation scoped to the device-id service —
/// the other stores (DPoP keys, tokens) keep working so the
/// request itself can proceed.
private final class DeviceIDFailingKeychainBackend: KeychainBackend, @unchecked Sendable {
    private static let deviceIDService = "so.prelude.auth.device_id"
    private let inner = InMemoryKeychainBackend()

    func copyMatching(_ query: [String: Any]) throws -> CFTypeRef? {
        if query[kSecAttrService as String] as? String == Self.deviceIDService {
            throw DPoPKeyStoreError.keychainFailure(errSecIO)
        }
        return try inner.copyMatching(query)
    }

    func add(_ attributes: [String: Any]) -> OSStatus {
        if attributes[kSecAttrService as String] as? String == Self.deviceIDService {
            return errSecIO
        }
        return inner.add(attributes)
    }

    func update(_ query: [String: Any], attributesToUpdate: [String: Any]) -> OSStatus {
        inner.update(query, attributesToUpdate: attributesToUpdate)
    }

    func delete(_ query: [String: Any]) -> OSStatus {
        inner.delete(query)
    }

    func createRandomKey(_ attributes: [String: Any]) throws -> SecKey {
        try inner.createRandomKey(attributes)
    }
}
