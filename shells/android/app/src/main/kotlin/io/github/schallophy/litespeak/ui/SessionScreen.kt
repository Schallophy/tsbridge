package io.github.schallophy.litespeak.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.schallophy.litespeak.SessionStatus
import io.github.schallophy.litespeak.SessionViewModel
import io.github.schallophy.litespeak.model.Channel
import io.github.schallophy.litespeak.model.PermissionTarget
import io.github.schallophy.litespeak.model.User
import io.github.schallophy.litespeak.ui.components.ExitGlyph
import io.github.schallophy.litespeak.ui.components.StatusDot
import io.github.schallophy.litespeak.ui.sheets.ChannelSettingsSheet
import io.github.schallophy.litespeak.ui.sheets.GroupTargetPickerSheet
import io.github.schallophy.litespeak.ui.sheets.PermissionSheet
import io.github.schallophy.litespeak.ui.sheets.ServerSettingsSheet
import io.github.schallophy.litespeak.ui.sheets.UserSheet
import io.github.schallophy.litespeak.ui.sheets.WhisperSheet

/**
 * The session content: the server header and the active tab's content.
 *
 * The tab selection and the microphone bar live outside this screen — the
 * bottom navigation replaces the old in-screen pill tabs, and the mic bar is
 * composed by the app shell above the bottom nav. What remains here is what
 * only the session itself owns: the server header and the three tab contents.
 */
@Composable
fun SessionScreen(
    vm: SessionViewModel,
    onLeave: () -> Unit,
    onOpenSettings: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val ui by vm.ui.collectAsStateWithLifecycle()
    val permissions by vm.permissions.collectAsStateWithLifecycle()
    var sheetUser by remember { mutableStateOf<User?>(null) }
    var whisperOpen by remember { mutableStateOf(false) }
    var serverSettingsOpen by remember { mutableStateOf(false) }
    var editChannel by remember { mutableStateOf<Channel?>(null) }
    var permissionTarget by remember { mutableStateOf<PermissionTarget?>(null) }
    var groupPickerOpen by remember { mutableStateOf(false) }

    // The server never reports our own voice, so the core derives this from the
    // capture path (gain, silence gate and a tail). The local meter is only for
    // the level ring around the button.
    val ownTalking = ui.state.ownTalking

    Column(modifier = modifier.fillMaxSize()) {
        ServerHeader(
            title = ui.state.server.name.ifEmpty { ui.config?.address.orEmpty() },
            subtitle = statusLine(ui.status, ui.state.server.clientsOnline, ui.state.server.maxClients),
            connected = ui.status == SessionStatus.Online,
            onDisconnect = vm::disconnect,
            onWhisper = { whisperOpen = true },
            onServerSettings = { serverSettingsOpen = true },
        )

        Box(modifier = Modifier.weight(1f)) {
            when (ui.tab) {
                io.github.schallophy.litespeak.SessionTab.Channels -> ChannelsTab(
                    ui = ui,
                    ownTalking = ownTalking,
                    onJoinChannel = vm::joinChannel,
                    onSelectUser = { sheetUser = it },
                    onEditChannel = { editChannel = it },
                )

                io.github.schallophy.litespeak.SessionTab.Chat -> ChatTab(
                    ui = ui,
                    onScope = vm::selectScope,
                    onSend = vm::sendMessage,
                )

                io.github.schallophy.litespeak.SessionTab.Files -> FilesTab(
                    ui = ui,
                    onRefresh = vm::refreshFiles,
                    onDownload = vm::downloadFile,
                    onUpload = { uri: android.net.Uri -> ui.filesChannelId?.let { vm.uploadFile(uri, it) } },
                )
            }

            // Overlay, not an inline row: a failure banner that pushes the list
            // down as it appears is exactly the kind of layout jump that reads
            // as broken. It floats over the top of the content instead.
            if (ui.status == SessionStatus.Failed) {
                Box(modifier = Modifier.align(Alignment.TopCenter)) {
                    ConnectErrorBanner(
                        message = ui.lastError?.takeIf { it.isNotBlank() }
                            ?: "请检查服务器地址和网络",
                        // A refused client version cannot be fixed by retrying:
                        // the same value would be announced again. The banner
                        // offers the setting instead of a button that cannot work.
                        versionRejected = ui.failureKind == "client_version",
                        onRetry = vm::reconnect,
                        onEdit = onLeave,
                        onOpenSettings = onOpenSettings,
                    )
                }
            }
        }
    }

    sheetUser?.let { user ->
        UserSheet(
            user = user,
            ownClientId = ui.state.ownClientId,
            onDismiss = { sheetUser = null },
            onPrivate = {
                vm.openPrivateChat(user)
                sheetUser = null
            },
            onPoke = { message ->
                vm.poke(user, message)
                sheetUser = null
            },
            initialVolume = vm.userVolume(user),
            onVolume = { volume -> vm.setUserVolume(user, volume) },
            whispering = vm.isWhisperingTo(user),
            onWhisper = { enabled -> vm.setWhisperTo(user, enabled) },
            onPermissions = {
                permissionTarget = PermissionTarget(
                    kind = "client",
                    id = user.databaseId,
                    title = "客户端权限 · ${user.nickname}",
                )
                sheetUser = null
            },
            onChannelPermissions = {
                permissionTarget = PermissionTarget(
                    kind = "channel_client",
                    id = user.databaseId,
                    title = "频道内权限 · ${user.nickname}",
                    secondaryId = user.channelId,
                )
                sheetUser = null
            },
        )
    }

    if (whisperOpen) {
        WhisperSheet(
            ui = ui,
            onDismiss = { whisperOpen = false },
            onApply = { clients, channels, groups ->
                vm.setWhisperTargets(clients, channels, groups)
            },
        )
    }

    if (serverSettingsOpen) {
        ServerSettingsSheet(
            server = ui.state.server,
            onDismiss = { serverSettingsOpen = false },
            onGroupPermissions = {
                serverSettingsOpen = false
                groupPickerOpen = true
            },
            onApply = { name, welcome, maxClients, password, hostMessage, hostBanner, level ->
                vm.editServer(
                    name = name,
                    welcomeMessage = welcome,
                    maxClients = maxClients,
                    password = password,
                    hostMessage = hostMessage,
                    hostBannerUrl = hostBanner,
                    neededSecurityLevel = level,
                )
            },
        )
    }

    if (groupPickerOpen) {
        GroupTargetPickerSheet(
            ui = ui,
            onDismiss = { groupPickerOpen = false },
            onPick = { target ->
                groupPickerOpen = false
                permissionTarget = target
            },
        )
    }

    permissionTarget?.let { target ->
        PermissionSheet(
            target = target,
            state = permissions,
            onDismiss = { permissionTarget = null },
            onLoad = vm::loadPermissions,
            onAdd = { picked, name, value -> vm.addPermission(picked, name, value) },
            onDelete = { picked, name -> vm.deletePermission(picked, name) },
        )
    }

    editChannel?.let { channel ->
        ChannelSettingsSheet(
            channel = channel,
            onDismiss = { editChannel = null },
            onPermissions = {
                permissionTarget = PermissionTarget(
                    kind = "channel",
                    id = channel.id,
                    title = "频道权限 · ${channel.name}",
                )
                editChannel = null
            },
            onApply = { name, topic, maxClients, maxFamily, neededTalk, codec, quality, latency, deleteDelay, isDefault, isPermanent, isSemiPermanent, password ->
                vm.editChannel(
                    channelId = channel.id,
                    name = name,
                    topic = topic,
                    maxClients = maxClients,
                    maxFamilyClients = maxFamily,
                    neededTalkPower = neededTalk,
                    codec = codec,
                    codecQuality = quality,
                    codecLatencyFactor = latency,
                    deleteDelay = deleteDelay,
                    isDefault = isDefault,
                    isPermanent = isPermanent,
                    isSemiPermanent = isSemiPermanent,
                    password = password,
                )
            },
        )
    }
}

/**
 * Why the connection failed, in full, right where the user is looking.
 *
 * The header only has room for "连接失败", but the interesting part is *why*:
 * a wrong server password, an unreachable host and a refused identity all look
 * identical from the outside, and guessing means editing settings blindly.
 */
@Composable
private fun ConnectErrorBanner(
    message: String,
    versionRejected: Boolean,
    onRetry: () -> Unit,
    onEdit: () -> Unit,
    onOpenSettings: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 14.dp, vertical = 6.dp)
            .clip(RoundedCornerShape(14.dp))
            .background(MaterialTheme.colorScheme.errorContainer)
            .padding(start = 14.dp, end = 14.dp, top = 12.dp, bottom = 6.dp),
    ) {
        Text(
            text = message,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onErrorContainer,
        )
        Row(
            horizontalArrangement = Arrangement.End,
            modifier = Modifier.fillMaxWidth(),
        ) {
            androidx.compose.material3.TextButton(onClick = onEdit) { Text("修改设置") }
            if (versionRejected) {
                androidx.compose.material3.TextButton(onClick = onOpenSettings) { Text("换版本") }
            } else {
                androidx.compose.material3.TextButton(onClick = onRetry) { Text("重试") }
            }
        }
    }
}

private fun statusLine(status: SessionStatus, online: Int, max: Int): String = when (status) {
    SessionStatus.Connecting -> "连接中…"
    SessionStatus.Online -> if (max > 0) "$online / $max 在线" else "$online 在线"
    SessionStatus.Disconnected -> "已断开"
    SessionStatus.Failed -> "连接失败"
    SessionStatus.Idle -> ""
}

@Composable
private fun ServerHeader(
    title: String,
    subtitle: String,
    connected: Boolean,
    onDisconnect: () -> Unit,
    onWhisper: () -> Unit,
    onServerSettings: () -> Unit,
) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .padding(start = 18.dp, end = 6.dp, top = 6.dp),
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleLarge,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                StatusDot(
                    color = if (connected) Color(0xFF3FB950) else MaterialTheme.colorScheme.error,
                )
                Text(
                    text = subtitle,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        IconButton(onClick = onServerSettings) {
            Icon(
                imageVector = Icons.Default.Settings,
                contentDescription = "服务器设置",
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(22.dp),
            )
        }
        // Whisper is a first-class voice mode in the official client; the
        // target picker is one tap from the header rather than a settings page.
        IconButton(onClick = onWhisper) {
            Text(
                "密聊",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        // The desktop client buries disconnect in a menu; on a phone that is
        // one tap too many for the action you reach for when things go wrong.
        // One tap, straight out — same as TS6 Droid CN.
        IconButton(onClick = onDisconnect) {
            ExitGlyph(
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(22.dp),
            )
        }
    }
}
