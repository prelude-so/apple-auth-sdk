import Foundation

// MARK: - Passkey management

extension PreludeAuthClient.Impl {
    func listPasskeys() async throws -> [PasskeyCredential] {
        let request = buildRequest(path: "me/passkeys", method: "GET")
        let (body, _) = try await httpClient.sendJSON(
            request,
            interceptors: [autoRefreshInterceptor],
            as: PasskeyListResponse.self
        )
        return (body.credentials ?? []).map(PasskeyCredential.init)
    }

    func renamePasskey(_ credentialID: String, nickname: String) async throws {
        guard !credentialID.isEmpty else {
            throw PreludeAuthError.invalidConfiguration("renamePasskey requires a non-empty credential id")
        }
        var request = buildRequest(path: "me/passkeys/\(credentialID)", method: "PATCH")
        request.httpBody = try JSONEncoder().encode(PasskeyRenameBody(nickname: nickname))
        try await httpClient.sendExpectingNoBody(request, interceptors: [autoRefreshInterceptor])
    }

    func deletePasskey(_ credentialID: String) async throws {
        guard !credentialID.isEmpty else {
            throw PreludeAuthError.invalidConfiguration("deletePasskey requires a non-empty credential id")
        }
        let request = buildRequest(path: "me/passkeys/\(credentialID)", method: "DELETE")
        try await httpClient.sendExpectingNoBody(request, interceptors: [autoRefreshInterceptor])

        // Removing the last passkey may flip the has_passkey claim.
        try await refreshAfterPasskeyMutation()
    }

    /// Force the next access token to reflect a changed
    /// `has_passkey` claim.
    func refreshAfterPasskeyMutation() async throws {
        try await invalidateSession()
        _ = try await refresh()
    }
}
