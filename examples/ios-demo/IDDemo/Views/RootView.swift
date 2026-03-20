import SwiftUI

struct RootView: View {
    @Environment(AuthManager.self) private var authManager

    var body: some View {
        ZStack {
            if authManager.isAuthenticated {
                TabView {
                    ProfileView()
                        .tabItem {
                            Label("Profile", systemImage: "person.circle")
                        }
                    TokenInspectorView()
                        .tabItem {
                            Label("Token", systemImage: "key")
                        }
                }
            } else {
                LoginView()
            }

            if authManager.isLoading {
                Color.black.opacity(0.3)
                    .ignoresSafeArea()
                ProgressView()
                    .scaleEffect(1.5)
                    .tint(.white)
            }
        }
        .animation(.default, value: authManager.isAuthenticated)
    }
}
