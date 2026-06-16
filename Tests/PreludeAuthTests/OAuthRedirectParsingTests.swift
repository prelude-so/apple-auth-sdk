import Foundation
@testable import PreludeAuth
@testable import PreludeAuthSocial
import XCTest

final class OAuthRedirectParsingTests: XCTestCase {
    func test_parse_challengeToken() throws {
        let url = try XCTUnwrap(URL(string: "demo://oauth?challenge_token=challenge-abc"))
        XCTAssertEqual(OAuthRedirect.parse(url), .challenge(token: "challenge-abc"))
    }

    func test_parse_ignoresStatusParameter() throws {
        let url = try XCTUnwrap(URL(string: "demo://oauth?challenge_token=t1&status=otp_required"))
        XCTAssertEqual(OAuthRedirect.parse(url), .challenge(token: "t1"))
    }

    func test_parse_serverErrorWinsOverToken() throws {
        let url = try XCTUnwrap(URL(string: "demo://oauth?error=server_error&challenge_token=t1"))
        guard case let .failure(code, _) = OAuthRedirect.parse(url) else {
            XCTFail("expected failure")
            return
        }
        XCTAssertEqual(code, "server_error")
    }

    func test_parse_missingToken() throws {
        let url = try XCTUnwrap(URL(string: "demo://oauth"))
        guard case let .failure(code, _) = OAuthRedirect.parse(url) else {
            XCTFail("expected failure")
            return
        }
        XCTAssertEqual(code, "missing_challenge_token")
    }

    func test_errorMapping() throws {
        func error(for code: String) throws -> PreludeAuthError? {
            let url = try XCTUnwrap(URL(string: "demo://oauth?error=\(code)&error_description=msg"))
            return OAuthRedirect.parse(url).error
        }

        // Unknown codes round-trip through `.generic`, preserving the code.
        guard case let .generic(failedCode, _) = try error(for: "authentication_failed") else {
            XCTFail("expected generic")
            return
        }
        XCTAssertEqual(failedCode, "authentication_failed")

        guard case let .generic(newCode, _) = try error(for: "something_new") else {
            XCTFail("expected generic")
            return
        }
        XCTAssertEqual(newCode, "something_new")

        // Known codes map to typed cases.
        guard case .conflict = try error(for: "email_already_in_use") else {
            XCTFail("expected conflict")
            return
        }
        guard case .internalServerError = try error(for: "server_error") else {
            XCTFail("expected internalServerError")
            return
        }

        let missing = try XCTUnwrap(URL(string: "demo://oauth"))
        guard case .missingChallengeToken = OAuthRedirect.parse(missing).error else {
            XCTFail("expected missingChallengeToken")
            return
        }
    }

    func test_challenge_hasNoError() throws {
        let url = try XCTUnwrap(URL(string: "demo://oauth?challenge_token=t1"))
        XCTAssertNil(OAuthRedirect.parse(url).error)
    }
}
