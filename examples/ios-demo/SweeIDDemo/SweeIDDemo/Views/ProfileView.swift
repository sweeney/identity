import SwiftUI

struct ProfileView: View {
    @Environment(AuthManager.self) private var authManager

    var body: some View {
        NavigationStack {
            Group {
                if let profile = authManager.userProfile {
                    List {
                        Section("Account") {
                            row("Username", profile.username)
                            row("Role", profile.role.rawValue.capitalized)
                            row("Status", profile.isActive ? "Active" : "Inactive")
                        }
                        Section("Details") {
                            row("User ID", profile.id.uuidString)
                        }
                    }
                    .refreshable {
                        try? await authManager.fetchProfile()
                    }
                } else {
                    ContentUnavailableView("No Profile",
                        systemImage: "person.slash",
                        description: Text("Pull to refresh or sign in again."))
                }
            }
            .navigationTitle("Profile")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Sign Out", systemImage: "rectangle.portrait.and.arrow.right") {
                        Task { await authManager.logout() }
                    }
                }
            }
        }
    }

    private func row(_ label: String, _ value: String) -> some View {
        LabeledContent(label, value: value)
    }
}
