import Foundation

enum DeviceProof {
    static func create(
        deviceKey: DPoPKey,
        storage: DeviceKeyStorage,
        dpopKey: DPoPKey,
        method: String,
        url: URL,
        challengeToken: String
    ) throws -> String {
        try JWS.compactES256(
            header: [
                "typ": "device-proof+jwt",
                "alg": "ES256",
                "jwk": deviceKey.exportPublicJWK(),
            ],
            payload: [
                "htm": method,
                "htu": url.absoluteString,
                "cth": Data.sha256Base64URL(challengeToken),
                "jkt": thumbprint(of: dpopKey.exportPublicJWK()),
                "key_storage": storage.rawValue,
            ],
            key: deviceKey
        )
    }

    /// RFC 7638 JWK thumbprint.
    static func thumbprint(of jwk: [String: String]) throws -> String {
        guard let crv = jwk["crv"], let kty = jwk["kty"], let xCoord = jwk["x"], let yCoord = jwk["y"] else {
            throw DPoPProofError.invalidPublicKeyRepresentation
        }
        let canonical = try JWS.jsonData(["crv": crv, "kty": kty, "x": xCoord, "y": yCoord])
        return canonical.sha256Base64URLEncodedString()
    }
}
