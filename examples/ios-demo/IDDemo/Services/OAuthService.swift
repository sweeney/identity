import Foundation

enum OAuthService {

    // MARK: - Errors

    enum OAuthError: LocalizedError {
        case invalidResponse
        case httpError(Int)
        case decodingError

        var errorDescription: String? {
            switch self {
            case .invalidResponse:
                return "Invalid response from server."
            case .httpError(let statusCode):
                return "HTTP error \(statusCode)."
            case .decodingError:
                return "Failed to decode server response."
            }
        }
    }

    // MARK: - Public Methods

    static func exchangeCode(code: String, codeVerifier: String) async throws -> TokenResponse {
        let url = URL(string: Constants.OAuth.baseURL + Constants.OAuth.tokenEndpoint)!

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")

        let params: [(String, String)] = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", Constants.OAuth.redirectURI),
            ("client_id", Constants.OAuth.clientID),
            ("code_verifier", codeVerifier)
        ]
        request.httpBody = formEncode(params)

        let (data, response) = try await URLSession.shared.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw OAuthError.invalidResponse
        }
        guard (200...299).contains(httpResponse.statusCode) else {
            throw OAuthError.httpError(httpResponse.statusCode)
        }

        do {
            return try JSONDecoder().decode(TokenResponse.self, from: data)
        } catch {
            throw OAuthError.decodingError
        }
    }

    static func refreshToken(_ refreshToken: String) async throws -> TokenResponse {
        let url = URL(string: Constants.OAuth.baseURL + Constants.OAuth.tokenEndpoint)!

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")

        let params: [(String, String)] = [
            ("grant_type", "refresh_token"),
            ("refresh_token", refreshToken),
            ("client_id", Constants.OAuth.clientID)
        ]
        request.httpBody = formEncode(params)

        let (data, response) = try await URLSession.shared.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw OAuthError.invalidResponse
        }
        guard (200...299).contains(httpResponse.statusCode) else {
            throw OAuthError.httpError(httpResponse.statusCode)
        }

        do {
            return try JSONDecoder().decode(TokenResponse.self, from: data)
        } catch {
            throw OAuthError.decodingError
        }
    }

    static func fetchProfile(accessToken: String) async throws -> UserProfile {
        let url = URL(string: Constants.OAuth.baseURL + Constants.OAuth.profileEndpoint)!

        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")

        let (data, response) = try await URLSession.shared.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw OAuthError.invalidResponse
        }
        guard (200...299).contains(httpResponse.statusCode) else {
            throw OAuthError.httpError(httpResponse.statusCode)
        }

        do {
            return try JSONDecoder().decode(UserProfile.self, from: data)
        } catch {
            throw OAuthError.decodingError
        }
    }

    static func logout(accessToken: String?, refreshToken: String?) async throws {
        let url = URL(string: Constants.OAuth.baseURL + Constants.OAuth.logoutEndpoint)!

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        if let accessToken {
            request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        }

        if let refreshToken {
            request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
            let params: [(String, String)] = [
                ("refresh_token", refreshToken)
            ]
            request.httpBody = formEncode(params)
        }

        let (_, response) = try await URLSession.shared.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw OAuthError.invalidResponse
        }
        guard (200...299).contains(httpResponse.statusCode) else {
            throw OAuthError.httpError(httpResponse.statusCode)
        }
    }

    // MARK: - Private Helpers

    private static func formEncode(_ params: [(String, String)]) -> Data {
        let allowedCharacters = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-._~"))
        let encoded = params.map { key, value in
            let encodedKey = key.addingPercentEncoding(withAllowedCharacters: allowedCharacters) ?? key
            let encodedValue = value.addingPercentEncoding(withAllowedCharacters: allowedCharacters) ?? value
            return "\(encodedKey)=\(encodedValue)"
        }.joined(separator: "&")
        return Data(encoded.utf8)
    }
}
