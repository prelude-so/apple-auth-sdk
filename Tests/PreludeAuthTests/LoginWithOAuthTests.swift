import Foundation
@testable import PreludeAuth
@testable import PreludeAuthSocial
import XCTest

/// Resolves immediately with a canned callback URL, recording the
/// arguments it was called with.
private final class FakePresenter: WebAuthPresenting, @unchecked Sendable {
    let callback: Result<URL, Error>
    private(set) var receivedURL: URL?
    private(set) var receivedScheme: String?
    private(set) var receivedEphemeral = false

    init(callback: Result<URL, Error>) {
        self.callback = callback
    }

    func authenticate(
        url: URL,
        callbackScheme: String,
        prefersEphemeralSession: Bool
    ) async throws -> URL {
        receivedURL = url
        receivedScheme = callbackScheme
        receivedEphemeral = prefersEphemeralSession
        return try callback.get()
    }
}

/// Suspends inside `authenticate` until released, to hold the login
/// gate open deterministically.
private actor BlockingPresenter: WebAuthPresenting {
    private let callbackURL: URL
    private var entered: CheckedContinuation<Void, Never>?
    private var proceed: CheckedContinuation<Void, Never>?
    private var hasEntered = false

    init(callbackURL: URL) {
        self.callbackURL = callbackURL
    }

    func waitUntilEntered() async {
        if hasEntered {
            return
        }
        await withCheckedContinuation { entered = $0 }
    }

    func release() {
        proceed?.resume()
        proceed = nil
    }

    func authenticate(
        url _: URL,
        callbackScheme _: String,
        prefersEphemeralSession _: Bool
    ) async throws -> URL {
        hasEntered = true
        entered?.resume()
        entered = nil
        await withCheckedContinuation { proceed = $0 }
        return callbackURL
    }
}

final class LoginWithOAuthTests: XCTestCase {
    private var domain: String!
    private var baseURL: URL!
    private var clock: NowProvider!

    override func setUp() {
        super.setUp()
        domain = "social-test-\(UUID().uuidString.lowercased()).example"
        baseURL = URL(string: "https://\(domain!)")!
        clock = { Date(timeIntervalSince1970: 1_000_000) }
    }

    private let accessJWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEifQ.sig"

    private func makeLoginToken() throws -> String {
        let data = try JSONSerialization.data(withJSONObject: ["sub": "user-1"])
        let b64 = data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return "eyJhbGciOiJIUzI1NiJ9.\(b64).sig"
    }

    private func installHappyPath(_ fixture: Fixture) {
        fixture.http.install(
            path: "/v1/session/login/oauth/google/authorize",
            response: .json(["authorization_url": "https://provider.example/auth"])
        )
        fixture.http.install(
            path: "/v1/session/login/finalize",
            response: .json([
                "access_token": accessJWT,
                "expires_at": Int(clock().timeIntervalSince1970) + 3600,
            ])
        )
    }

    func test_loginWithOAuth_endToEnd() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        let token = try makeLoginToken()
        installHappyPath(fixture)
        let presenter = try FakePresenter(
            callback: .success(XCTUnwrap(URL(string: "demo://oauth?challenge_token=\(token)")))
        )

        let result = try await fixture.client.loginWithOAuth(
            OAuthLoginOptions(
                provider: .google,
                redirectURI: XCTUnwrap(URL(string: "demo://oauth")),
                prefersEphemeralSession: true
            ),
            presenter: presenter
        )

        guard case let .loggedIn(user) = result else {
            XCTFail("expected loggedIn")
            return
        }
        XCTAssertEqual(user.profile.userID, "user-1")
        XCTAssertEqual(presenter.receivedURL?.absoluteString, "https://provider.example/auth")
        XCTAssertEqual(presenter.receivedScheme, "demo")
        XCTAssertEqual(presenter.receivedEphemeral, true)
    }

    func test_loginWithOAuth_httpsRedirectURI_throwsWithoutNetworkCall() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        let presenter = FakePresenter(callback: .failure(PreludeAuthError.cancelled))

        do {
            _ = try await fixture.client.loginWithOAuth(
                OAuthLoginOptions(provider: .google, redirectURI: XCTUnwrap(URL(string: "https://example.com/cb"))),
                presenter: presenter
            )
            XCTFail("expected invalidConfiguration")
        } catch PreludeAuthError.invalidConfiguration {
            // expected
        }
        XCTAssertEqual(
            fixture.http.requestCount(forPath: "/v1/session/login/oauth/google/authorize"), 0
        )
    }

    func test_loginWithOAuth_userCancel_surfacesCancelled_andReleasesGate() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        let token = try makeLoginToken()
        installHappyPath(fixture)

        do {
            _ = try await fixture.client.loginWithOAuth(
                OAuthLoginOptions(provider: .google, redirectURI: XCTUnwrap(URL(string: "demo://oauth"))),
                presenter: FakePresenter(callback: .failure(PreludeAuthError.cancelled))
            )
            XCTFail("expected cancelled")
        } catch PreludeAuthError.cancelled {
            // expected
        }

        // Gate must be free again after the failure.
        let result = try await fixture.client.loginWithOAuth(
            OAuthLoginOptions(provider: .google, redirectURI: XCTUnwrap(URL(string: "demo://oauth"))),
            presenter: FakePresenter(
                callback: .success(XCTUnwrap(URL(string: "demo://oauth?challenge_token=\(token)")))
            )
        )
        guard case .loggedIn = result else {
            XCTFail("expected loggedIn after gate release")
            return
        }
    }

    func test_loginWithOAuth_concurrentLogin_throwsConflict() async throws {
        let fixture = try Fixture.make(domain: domain, baseURL: baseURL, clock: clock)
        let token = try makeLoginToken()
        installHappyPath(fixture)
        let blocking = try BlockingPresenter(
            callbackURL: XCTUnwrap(URL(string: "demo://oauth?challenge_token=\(token)"))
        )

        let first = Task {
            try await fixture.client.loginWithOAuth(
                OAuthLoginOptions(provider: .google, redirectURI: URL(string: "demo://oauth")!),
                presenter: blocking
            )
        }
        await blocking.waitUntilEntered()

        do {
            _ = try await fixture.client.loginWithOAuth(
                OAuthLoginOptions(provider: .google, redirectURI: XCTUnwrap(URL(string: "demo://oauth"))),
                presenter: FakePresenter(callback: .failure(PreludeAuthError.cancelled))
            )
            XCTFail("expected conflict")
        } catch PreludeAuthError.conflict {
            // expected
        }

        await blocking.release()
        let result = try await first.value
        guard case .loggedIn = result else {
            XCTFail("expected first login to complete")
            return
        }
    }
}
