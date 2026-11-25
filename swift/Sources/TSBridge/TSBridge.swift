import Foundation
import tsbridge

// A thin, string-safe wrapper over the C ABI.
//
// The C API hands out `char *` that this side must free. Doing that by hand at
// every call site is how a 50 Hz poll loop turns into a leak, so every accessor
// here is the *only* place a returned string is touched: read, decode, free in
// a `defer`. Nothing above this file ever sees an `UnsafeMutablePointer`.

/// The version this wrapper was written against. Compared with the loaded
/// library at init; a mismatch means the shell and the binary came from
/// different builds, which produces confusing half-working behaviour.
public let tsbridgeAbiVersion: UInt32 = 8

public enum BridgeError: Error, CustomStringConvertible {
    case abiMismatch(expected: UInt32, got: UInt32)
    case createFailed(String)
    case command(String)

    public var description: String {
        switch self {
        case let .abiMismatch(expected, got):
            return "TSBridge ABI mismatch: built for \(expected), library is \(got)"
        case let .createFailed(detail):
            return "TSBridge: could not open a session: \(detail)"
        case let .command(detail):
            return detail
        }
    }
}

/// Both handles come from the same library, so both check the same contract.
private func requireABI() throws {
    let loaded = tsbridge_abi_version()
    guard loaded == tsbridgeAbiVersion else {
        throw BridgeError.abiMismatch(expected: tsbridgeAbiVersion, got: loaded)
    }
}

/// One `tsbridge_exec` call, with the returned string freed in a `defer`.
private func runCommand(on handle: OpaquePointer?, _ name: String, _ args: [String: Any]) throws {
    guard let handle else { throw BridgeError.command("the session is closed") }
    let argsData = try JSONSerialization.data(withJSONObject: args)
    let argsJSON = String(decoding: argsData, as: UTF8.self)

    let result: String = name.withCString { namePtr in
        argsJSON.withCString { argsPtr in
            guard let raw = tsbridge_exec(handle, namePtr, argsPtr) else {
                return "the library returned no result"
            }
            defer { tsbridge_string_free(raw) }
            return String(cString: raw)
        }
    }
    if !result.isEmpty { throw BridgeError.command(result) }
}

/// The JSON config accepted by `tsbridge_create`.
///
/// Field names match the C side one-for-one, so a config written here is the
/// same document the header documents.
public struct BridgeConfig: Encodable, Sendable {
    public var address: String
    public var identity: String?
    public var nickname: String
    public var password: String?
    public var channel: String?
    public var channelPassword: String?
    /// The client version number to announce (`3.6.3`). Paired with `platform`;
    /// resolved to the full signed tuple. Absent means `3.6.3`.
    public var version: String?
    /// The platform to announce with the version (`Windows`, `OS X`, `Linux`, …).
    /// Absent means `Windows`.
    public var platform: String?
    /// A privilege key to redeem on first connect; single-use.
    public var token: String?

    public init(
        address: String,
        nickname: String,
        identity: String? = nil,
        password: String? = nil,
        channel: String? = nil,
        channelPassword: String? = nil,
        version: String? = nil,
        platform: String? = nil,
        token: String? = nil
    ) {
        self.address = address
        self.nickname = nickname
        self.identity = identity
        self.password = password
        self.channel = channel
        self.channelPassword = channelPassword
        self.version = version
        self.platform = platform
        self.token = token
    }
}

/// The JSON config accepted by `tsbridge_create_account`.
///
/// Every path is optional and none is probed. `credentialFile` is what makes
/// "stay signed in" work: a successful login writes the accepted credential
/// hash and the account key there (never the password), and `logOut()` deletes
/// it. `baselineFile` is where `sync_merge` records what both sides last agreed
/// on.
public struct AccountConfig: Encodable, Sendable {
    public var legacyDb: String?
    public var backupDir: String?
    public var credentialFile: String?
    public var rememberLogin: Bool
    public var baselineFile: String?

    public init(
        credentialFile: String? = nil,
        baselineFile: String? = nil,
        backupDir: String? = nil,
        legacyDb: String? = nil,
        rememberLogin: Bool = true
    ) {
        self.credentialFile = credentialFile
        self.baselineFile = baselineFile
        self.backupDir = backupDir
        self.legacyDb = legacyDb
        self.rememberLogin = rememberLogin
    }
}

/// One session. `deinit` frees the handle, so dropping the last reference is
/// enough to close the connection.
///
/// Not marked `Sendable`: the handle may not be destroyed while another thread
/// is inside a call on it. Poll from one thread (see `SessionModel`), or pass
/// access through your own queue.
public final class Bridge {
    private var handle: OpaquePointer?

    public init(config: BridgeConfig) throws {
        self.handle = try Bridge.open(config: config, account: nil)
    }

    /// Connects while carrying the signed-in account's myTeamSpeak proof.
    ///
    /// The account is only read during this initializer; the connection keeps
    /// what it needs, so the account handle may be released afterwards. An
    /// account that is not signed in connects normally, without the badge.
    public init(config: BridgeConfig, account: AccountBridge) throws {
        self.handle = try Bridge.open(config: config, account: account.rawHandle)
    }

    private static func open(config: BridgeConfig, account: OpaquePointer?) throws -> OpaquePointer {
        try requireABI()

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        // One conversion to a C string: the create calls read a NUL-terminated
        // buffer, and keeping the buffer alive only for that call is what
        // `withCString` guarantees.
        let json = String(decoding: try encoder.encode(config), as: UTF8.self)
        let raw = json.withCString { jsonPtr -> OpaquePointer? in
            if let account {
                return tsbridge_create_with_account(account, jsonPtr)
            }
            return tsbridge_create(jsonPtr)
        }
        guard let raw else {
            throw BridgeError.createFailed("the library rejected the config")
        }
        return raw
    }

    deinit {
        if let handle {
            // No `tsbridge_disconnect` here: the session may already be closed,
            // and destroy performs the clean shutdown itself.
            tsbridge_destroy(handle)
        }
    }

    public var isConnected: Bool {
        guard let handle else { return false }
        return tsbridge_is_connected(handle)
    }

    /// Library and protocol versions, for an About box or a crash report.
    public static func info() -> [String: Any] {
        guard let raw = tsbridge_info_json() else { return [:] }
        defer { tsbridge_string_free(raw) }
        let text = String(cString: raw)
        return (try? JSONSerialization.jsonObject(with: Data(text.utf8))) as? [String: Any] ?? [:]
    }

    /// The whole server state. An unchanged revision returns the identical
    /// string, so decoding can be skipped by comparing `rev` first.
    public func snapshotJSON() -> String? {
        guard let handle, let raw = tsbridge_snapshot_json(handle) else { return nil }
        defer { tsbridge_string_free(raw) }
        return String(cString: raw)
    }

    /// Drains queued events. Returns `[]` when nothing happened.
    public func pollEvents() -> [[String: Any]] {
        guard let handle, let raw = tsbridge_poll_events_json(handle) else { return [] }
        defer { tsbridge_string_free(raw) }
        let text = String(cString: raw)
        guard let data = try? JSONSerialization.jsonObject(with: Data(text.utf8)) else {
            return []
        }
        return data as? [[String: Any]] ?? []
    }

    /// Runs one command. Throws with the library's own message on rejection.
    public func exec(_ name: String, _ args: [String: Any] = [:]) throws {
        try runCommand(on: handle, name, args)
    }

    /// Sends a clean goodbye; the handle stays readable until `deinit`.
    public func disconnect() {
        guard let handle else { return }
        tsbridge_disconnect(handle)
    }

    /// The identity to persist. Nil until the worker thread has built one, which
    /// happens shortly after `init` returns.
    ///
    /// Store it in the Keychain and pass it back as `BridgeConfig.identity`, or
    /// the server registers this user as a new person on every launch.
    public func identity() -> String? {
        guard let handle, let raw = tsbridge_identity(handle) else { return nil }
        defer { tsbridge_string_free(raw) }
        return String(cString: raw)
    }

    // -- voice ---------------------------------------------------------------
    // Raw PCM16, 48 kHz mono, one frame = 960 samples. These are the only calls
    // that do not go through JSON.

    /// Queues captured samples. Returns how many the library took.
    @discardableResult
    public func audioWrite(_ samples: [Int16]) -> Int {
        guard let handle, !samples.isEmpty else { return 0 }
        return samples.withUnsafeBufferPointer { buffer in
            tsbridge_audio_write(handle, buffer.baseAddress, buffer.count)
        }
    }

    /// Fills `frame` with decoded samples and returns how many are valid.
    /// Zero means "nothing was received"; repeat your previous frame or play
    /// silence.
    @discardableResult
    public func audioRead(into frame: inout [Int16]) -> Int {
        guard let handle, !frame.isEmpty else { return 0 }
        return frame.withUnsafeMutableBufferPointer { buffer in
            tsbridge_audio_read(handle, buffer.baseAddress, buffer.count)
        }
    }

    public func audioReset() {
        guard let handle else { return }
        tsbridge_audio_reset(handle)
    }
}

/// An account-only session: sign in, read bookmarks and back them up with no
/// server connection.
///
/// It is also what a connection needs in order to announce the myTeamSpeak ID:
/// pass it to `Bridge(config:account:)`. The account handle and the connection
/// are independent, so signing out does not drop a live call.
///
/// Not marked `Sendable`, for the same reason as `Bridge`.
public final class AccountBridge {
    private var handle: OpaquePointer?

    public init(config: AccountConfig = AccountConfig()) throws {
        try requireABI()
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let json = String(decoding: try encoder.encode(config), as: UTF8.self)
        guard let raw = json.withCString({ tsbridge_create_account($0) }) else {
            throw BridgeError.createFailed("the library rejected the account config")
        }
        self.handle = raw
    }

    deinit {
        if let handle {
            tsbridge_destroy(handle)
        }
    }

    fileprivate var rawHandle: OpaquePointer? { handle }

    /// The whole state, including the `account` object with bookmarks.
    public func snapshotJSON() -> String? {
        guard let handle, let raw = tsbridge_snapshot_json(handle) else { return nil }
        defer { tsbridge_string_free(raw) }
        return String(cString: raw)
    }

    /// Drains queued events, including one `account_status` per command.
    public func pollEvents() -> [[String: Any]] {
        guard let handle, let raw = tsbridge_poll_events_json(handle) else { return [] }
        defer { tsbridge_string_free(raw) }
        let text = String(cString: raw)
        guard let data = try? JSONSerialization.jsonObject(with: Data(text.utf8)) else {
            return []
        }
        return data as? [[String: Any]] ?? []
    }

    /// Runs one account command. The call returns when the command is accepted;
    /// the result arrives through `pollEvents()` and `snapshotJSON()`.
    public func exec(_ name: String, _ args: [String: Any] = [:]) throws {
        try runCommand(on: handle, name, args)
    }

    /// A failed login is thrown synchronously only for bad arguments; a rejected
    /// credential arrives as an `account_status` event later.
    public func logIn(email: String, password: String, otp: String? = nil) throws {
        var args: [String: Any] = ["email": email, "password": password]
        if let otp, !otp.isEmpty {
            args["otp"] = otp
        }
        try exec("account_login", args)
    }

    public func logOut() throws {
        try exec("account_logout")
    }

    /// Re-reads `/me` and the item list.
    public func refresh() throws {
        try exec("account_refresh", ["revealSecrets": false])
    }

    /// Reads the bookmarks with passwords as presence only. Ask for
    /// `["revealSecrets": true]` explicitly if you must display a value.
    public func listBookmarks() throws {
        try exec("sync_list", ["revealSecrets": false])
    }

    /// Writes a backup to the configured `backupDir` (or the per-user default).
    public func backup() throws {
        try exec("sync_backup")
    }
}
