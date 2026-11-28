package dev.litespeak

import dev.litespeak.core.ServerConfig
import dev.litespeak.model.ChatMessage
import dev.litespeak.model.ChatScope
import dev.litespeak.model.ServerState
import dev.litespeak.model.Transfer
import dev.litespeak.model.User

enum class SessionStatus { Idle, Connecting, Online, Disconnected, Failed }

enum class SessionTab { Channels, Chat, Files }

/**
 * The bottom navigation destinations.
 *
 * Home and Settings exist with or without a connection; the three session
 * tabs only mean anything once a server is joined, and show a "connect first"
 * state otherwise.
 */
enum class NavTab(val label: String) {
    Home("首页"),
    Channels("频道"),
    Chat("聊天"),
    Files("文件"),
    Settings("设置"),
}

data class SessionUiState(
    val status: SessionStatus = SessionStatus.Idle,
    val config: ServerConfig? = null,
    val state: ServerState = ServerState(),
    val tab: SessionTab = SessionTab.Channels,
    val messages: List<ChatMessage> = emptyList(),
    val transfers: List<Transfer> = emptyList(),
    val scope: ChatScope = ChatScope.Channel,
    val peer: User? = null,
    val filesChannelId: Long? = null,
    val filesLoading: Boolean = false,
    val unreadChannel: Int = 0,
    val unreadServer: Int = 0,
    val unreadPrivate: Map<Int, Int> = emptyMap(),
    val log: List<String> = emptyList(),
    val lastError: String? = null,
    /** Why the connection failed, in the core's vocabulary (`client_version`, …). */
    val failureKind: String = "",
    val toast: String? = null,
    val micEnabled: Boolean = true,
    val speakerEnabled: Boolean = true,
) {
    val isOnline: Boolean get() = status == SessionStatus.Online
    val unreadTotal: Int get() = unreadChannel + unreadServer + unreadPrivate.values.sum()
}
