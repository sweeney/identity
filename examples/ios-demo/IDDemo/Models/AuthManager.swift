import SwiftUI
import AuthenticationServices

@Observable
@MainActor
final class AuthManager {

    // MARK: - Public Properties

    var isAuthenticated: Bool = false
    var userProfile: UserProfile? = nil
    var isLoading: Bool = false
    var error: String? = nil

    // In-memory only, never persisted
    var accessToken: String? = nil
    var tokenExpiresAt: Date? = nil

    // MARK: - Private Properties

    private var refreshTask: Task<Void, Never>? = nil
    private var authSession: ASWebAuthenticationSession? = nil
    private var contextProvider: PresentationContextProvider? = nil

    // MARK: - Init

    init() {
        if KeychainService.readRefreshToken() != nil {
            isLoading = true
            Task {
                await performRefresh()
                isLoading = false
            }
        }
    }

    // MARK: - Public Methods

    func login() async {
        isLoading = true
        error = nil

        do {
            let pkce = PKCEGenerator.generate()

            var components = URLComponents(string: Constants.OAuth.baseURL + Constants.OAuth.authorizeEndpoint)!
            components.queryItems = [
                URLQueryItem(name: "response_type", value: "code"),
                URLQueryItem(name: "client_id", value: Constants.OAuth.clientID),
                URLQueryItem(name: "redirect_uri", value: Constants.OAuth.redirectURI),
                URLQueryItem(name: "code_challenge", value: pkce.challenge),
                URLQueryItem(name: "code_challenge_method", value: "S256"),
                URLQueryItem(name: "scope", value: "openid profile"),
            ]

            guard let authorizeURL = components.url else {
                throw URLError(.badURL)
            }

            let callbackURL: URL = try await withCheckedThrowingContinuation { continuation in
                let session = ASWebAuthenticationSession(
                    url: authorizeURL,
                    callbackURLScheme: Constants.OAuth.callbackScheme
                ) { [weak self] url, error in
                    self?.authSession = nil
                    self?.contextProvider = nil
                    if let error {
                        continuation.resume(throwing: error)
                    } else if let url {
                        continuation.resume(returning: url)
                    } else {
                        continuation.resume(throwing: URLError(.badServerResponse))
                    }
                }

                session.prefersEphemeralWebBrowserSession = true

                self.contextProvider = PresentationContextProvider()
                session.presentationContextProvider = self.contextProvider
                self.authSession = session

                session.start()
            }

            guard let components = URLComponents(url: callbackURL, resolvingAgainstBaseURL: false),
                  let code = components.queryItems?.first(where: { $0.name == "code" })?.value else {
                throw URLError(.badServerResponse)
            }

            let tokenResponse = try await OAuthService.exchangeCode(code: code, codeVerifier: pkce.verifier)
            handleTokenResponse(tokenResponse)
            try await fetchProfile()

            isLoading = false
        } catch {
            self.error = error.localizedDescription
            isLoading = false
        }
    }

    func refresh() async {
        if let existingTask = refreshTask {
            await existingTask.value
            return
        }

        let task = Task {
            await performRefresh()
        }
        refreshTask = task
        await task.value
        refreshTask = nil
    }

    func logout() async {
        try? await OAuthService.logout(
            accessToken: accessToken,
            refreshToken: KeychainService.readRefreshToken()
        )
        KeychainService.deleteRefreshToken()
        isAuthenticated = false
        accessToken = nil
        userProfile = nil
        tokenExpiresAt = nil
        error = nil
    }

    func fetchProfile() async throws {
        guard let accessToken else { return }
        userProfile = try await OAuthService.fetchProfile(accessToken: accessToken)
    }

    // MARK: - Private Methods

    private func performRefresh() async {
        guard let refreshToken = KeychainService.readRefreshToken() else {
            forceLogout()
            return
        }

        do {
            let tokenResponse = try await OAuthService.refreshToken(refreshToken)
            handleTokenResponse(tokenResponse)
        } catch {
            forceLogout()
        }
    }

    private func handleTokenResponse(_ response: TokenResponse) {
        accessToken = response.accessToken
        tokenExpiresAt = Date().addingTimeInterval(TimeInterval(response.expiresIn))
        if let newRefreshToken = response.refreshToken {
            KeychainService.saveRefreshToken(newRefreshToken)
        }
        isAuthenticated = true
    }

    private func forceLogout() {
        KeychainService.deleteRefreshToken()
        isAuthenticated = false
        accessToken = nil
        userProfile = nil
        tokenExpiresAt = nil
        error = "Session expired. Please sign in again."
    }
}

// MARK: - Presentation Context Provider

private class PresentationContextProvider: NSObject, ASWebAuthenticationPresentationContextProviding {
    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        guard let scene = UIApplication.shared.connectedScenes
            .compactMap({ $0 as? UIWindowScene })
            .first,
              let window = scene.windows.first(where: { $0.isKeyWindow }) else {
            return ASPresentationAnchor()
        }
        return window
    }
}
