import SwiftUI

struct TokenInspectorView: View {
    @Environment(AuthManager.self) private var authManager

    var body: some View {
        NavigationStack {
            List {
                if let token = authManager.accessToken,
                   let decoded = JWTDecoder.decode(token) {

                    Section("Token Expiry") {
                        TimelineView(.periodic(from: .now, by: 1)) { context in
                            if let expiresAt = authManager.tokenExpiresAt {
                                let remaining = expiresAt.timeIntervalSince(context.date)
                                HStack {
                                    Text("Expires in")
                                    Spacer()
                                    Text(formatRemaining(remaining))
                                        .monospacedDigit()
                                        .foregroundStyle(expiryColor(remaining))
                                        .fontWeight(.semibold)
                                }
                            }
                        }
                    }

                    Section("Claims") {
                        ForEach(decoded.claims, id: \.0) { key, value in
                            LabeledContent(key, value: value)
                                .font(.caption)
                        }
                    }

                    Section {
                        DisclosureGroup("Raw JWT") {
                            Text(token)
                                .font(.system(.caption2, design: .monospaced))
                                .textSelection(.enabled)
                            Button("Copy to Clipboard") {
                                UIPasteboard.general.string = token
                            }
                            .font(.caption)
                        }
                    }
                } else {
                    ContentUnavailableView("No Token",
                        systemImage: "key.slash",
                        description: Text("Sign in to inspect tokens."))
                }
            }
            .navigationTitle("Token Inspector")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Refresh", systemImage: "arrow.clockwise") {
                        Task { await authManager.refresh() }
                    }
                }
            }
        }
    }

    private func formatRemaining(_ seconds: TimeInterval) -> String {
        if seconds <= 0 { return "Expired" }
        let m = Int(seconds) / 60
        let s = Int(seconds) % 60
        return String(format: "%d:%02d", m, s)
    }

    private func expiryColor(_ seconds: TimeInterval) -> Color {
        if seconds > 300 { return .green }
        if seconds > 60 { return .yellow }
        return .red
    }
}
