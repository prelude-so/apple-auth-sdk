import Foundation

/// HTTP header names used by the SDK.
enum HTTPHeader {
    static let accept = "Accept"
    static let authorization = "Authorization"
    static let contentType = "Content-Type"
    static let date = "Date"
    static let host = "Host"
    static let userAgent = "User-Agent"

    static let dpop = "DPoP"
    static let dpopNonce = "DPoP-Nonce"

    static let deviceID = "X-Device-Id"
    static let refreshToken = "X-Refresh-Token"
    static let refreshTokenExpiresAt = "X-Refresh-Token-Expires-At"
}
