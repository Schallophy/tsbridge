//! The command protocol between the host UI and the connection thread.
//!
//! Everything the UI can *do* arrives through one entry point ([`parse`]) as a
//! name plus a JSON object. That is deliberately a single entry point: the FFI
//! surface stays the same size no matter how many features exist, and adding one
//! is a match arm here plus a caller in each shell — no new symbol, no
//! regenerated headers, no chance of the two sides disagreeing about arity.

use serde_json::Value;

use crate::handle::{Command, TextTarget};

/// Parses one command. Errors are user-facing strings: they end up in the log
/// right next to the button that caused them.
pub fn parse(name: &str, args: &str) -> Result<Command, String> {
    let json: Value = if args.trim().is_empty() {
        Value::Null
    } else {
        serde_json::from_str(args).map_err(|e| format!("bad arguments: {e}"))?
    };

    match name {
        "disconnect" => Ok(Command::Disconnect),

        "send_text" => Ok(Command::SendText {
            target: match str_field(&json, "target")? {
                "server" => TextTarget::Server,
                "channel" => TextTarget::Channel,
                "client" => TextTarget::Client(int_field(&json, "clientId")?),
                other => return Err(format!("unknown message target: {other}")),
            },
            message: str_field(&json, "message")?.to_string(),
        }),

        "poke" => Ok(Command::Poke {
            client_id: int_field(&json, "clientId")?,
            message: str_field(&json, "message")?.to_string(),
        }),

        "join_channel" => Ok(Command::JoinChannel {
            channel_id: long_field(&json, "channelId")?,
            password: optional_str(&json, "password"),
        }),

        "set_input_muted" => Ok(Command::SetInputMuted(bool_field(&json, "muted")?)),
        "set_output_muted" => Ok(Command::SetOutputMuted(bool_field(&json, "muted")?)),

        "set_away" => Ok(Command::SetAway {
            away: bool_field(&json, "away")?,
            message: optional_str(&json, "message"),
        }),

        "set_nickname" => Ok(Command::SetNickname(
            str_field(&json, "nickname")?.to_string(),
        )),

        "list_files" => Ok(Command::ListFiles {
            channel_id: long_field(&json, "channelId")?,
            path: normalize_path(&optional_str(&json, "path").unwrap_or_else(|| "/".to_string())),
            password: optional_str(&json, "password"),
        }),

        "download" => Ok(Command::Download {
            channel_id: long_field(&json, "channelId")?,
            path: normalize_path(str_field(&json, "path")?),
            local: str_field(&json, "local")?.to_string(),
            password: optional_str(&json, "password"),
        }),

        "upload" => Ok(Command::Upload {
            channel_id: long_field(&json, "channelId")?,
            path: normalize_path(str_field(&json, "path")?),
            local: str_field(&json, "local")?.to_string(),
            password: optional_str(&json, "password"),
            overwrite: json
                .get("overwrite")
                .and_then(Value::as_bool)
                .unwrap_or(true),
        }),

        "audio_enabled" => Ok(Command::SetAudioEnabled(bool_field(&json, "enabled")?)),

        "set_mic_gain" => Ok(Command::SetMicGain(f32_field(&json, "gain")?)),
        "set_user_volume" => Ok(Command::SetUserVolume {
            client_id: int_field(&json, "clientId")?,
            volume: f32_field(&json, "volume")?,
        }),
        "kick_client" => Ok(Command::KickClient {
            client_id: int_field(&json, "clientId")?,
            reason: u8_field(&json, "reason").unwrap_or(5),
            message: optional_str(&json, "message"),
        }),

        "move_client" => Ok(Command::MoveClient {
            client_id: int_field(&json, "clientId")?,
            channel_id: long_field(&json, "channelId")?,
            password: optional_str(&json, "password"),
        }),

        "ban_add" => Ok(Command::BanAdd {
            uid: optional_str(&json, "uid"),
            ip: optional_str(&json, "ip"),
            name: optional_str(&json, "name"),
            seconds: json.get("seconds").and_then(Value::as_u64).unwrap_or(0),
            reason: optional_str(&json, "reason"),
        }),

        "ban_delete" => Ok(Command::BanDelete {
            ban_id: json.get("banId").and_then(Value::as_i64).unwrap_or(0),
        }),

        "ban_list" => Ok(Command::BanList),

        "channel_create" => Ok(Command::ChannelCreate {
            parent_id: json.get("parentId").and_then(Value::as_i64),
            name: str_field(&json, "name")?.to_string(),
            topic: optional_str(&json, "topic"),
            description: optional_str(&json, "description"),
            password: optional_str(&json, "password"),
            max_clients: json
                .get("maxClients")
                .and_then(Value::as_i64)
                .map(|v| v as i32),
            order: json.get("order").and_then(Value::as_i64),
        }),

        "channel_edit" => Ok(Command::ChannelEdit {
            channel_id: long_field(&json, "channelId")?,
            name: optional_str(&json, "name"),
            topic: optional_str(&json, "topic"),
            description: optional_str(&json, "description"),
            max_clients: json
                .get("maxClients")
                .and_then(Value::as_i64)
                .map(|v| v as i32),
        }),

        "channel_delete" => Ok(Command::ChannelDelete {
            channel_id: long_field(&json, "channelId")?,
            force: json.get("force").and_then(Value::as_bool).unwrap_or(false),
        }),

        "channel_subscribe" => Ok(Command::ChannelSubscribe {
            channel_id: long_field(&json, "channelId")?,
            subscribed: bool_field(&json, "subscribed")?,
        }),

        "complain_add" => Ok(Command::ComplainAdd {
            client_db_id: long_field(&json, "clientDbId")?,
            message: str_field(&json, "message")?.to_string(),
        }),

        "complain_delete" => Ok(Command::ComplainDelete {
            client_db_id: json.get("clientDbId").and_then(Value::as_i64).unwrap_or(0),
            message: optional_str(&json, "message"),
        }),

        "privilege_key_create" => Ok(Command::PrivilegeKeyCreate {
            group_id: long_field(&json, "groupId")?,
            channel_id: json.get("channelId").and_then(Value::as_i64).unwrap_or(0),
            description: optional_str(&json, "description"),
        }),

        "privilege_key_use" => Ok(Command::PrivilegeKeyUse {
            key: str_field(&json, "key")?.to_string(),
        }),

        "privilege_key_list" => Ok(Command::PrivilegeKeyList),

        "set_client_channel_group" => Ok(Command::SetClientChannelGroup {
            client_db_id: long_field(&json, "clientDbId")?,
            channel_id: long_field(&json, "channelId")?,
            group_id: long_field(&json, "groupId")?,
        }),

        "offline_message_list" => Ok(Command::OfflineMessageList),

        "offline_message_get" => Ok(Command::OfflineMessageGet {
            message_id: long_field(&json, "messageId")?,
        }),

        "offline_message_delete" => Ok(Command::OfflineMessageDelete {
            message_id: json.get("messageId").and_then(Value::as_i64).unwrap_or(0),
        }),

        "offline_message_send" => Ok(Command::OfflineMessageSend {
            uid: str_field(&json, "uid")?.to_string(),
            subject: str_field(&json, "subject")?.to_string(),
            message: str_field(&json, "message")?.to_string(),
        }),

        "server_variables" => Ok(Command::ServerVariables),

        "client_variables" => Ok(Command::ClientVariables {
            client_id: int_field(&json, "clientId")?,
        }),

        "temp_password_add" => Ok(Command::TempPasswordAdd {
            password: str_field(&json, "password")?.to_string(),
            description: optional_str(&json, "description").unwrap_or_default(),
            seconds: json.get("seconds").and_then(Value::as_u64).unwrap_or(0),
            channel_id: json.get("channelId").and_then(Value::as_i64).unwrap_or(0),
            channel_password: optional_str(&json, "channelPassword").unwrap_or_default(),
        }),

        "temp_password_delete" => Ok(Command::TempPasswordDelete {
            password: str_field(&json, "password")?.to_string(),
        }),

        "temp_password_list" => Ok(Command::TempPasswordList),

        "client_permission_list" => Ok(Command::ClientPermissionList {
            client_db_id: long_field(&json, "clientDbId")?,
        }),

        "channel_permission_list" => Ok(Command::ChannelPermissionList {
            channel_id: long_field(&json, "channelId")?,
        }),

        "client_edit" => Ok(Command::ClientEdit {
            client_id: int_field(&json, "clientId")?,
            description: optional_str(&json, "description"),
            talk_power_granted: json.get("talkPowerGranted").and_then(Value::as_bool),
        }),

        "client_update" => Ok(Command::ClientUpdate {
            channel_commander: json.get("channelCommander").and_then(Value::as_bool),
            recording: json.get("recording").and_then(Value::as_bool),
            phonetic_name: optional_str(&json, "phoneticName"),
            input_hardware_enabled: json.get("inputHardwareEnabled").and_then(Value::as_bool),
            output_hardware_enabled: json.get("outputHardwareEnabled").and_then(Value::as_bool),
            avatar_hash: optional_str(&json, "avatarHash"),
        }),

        "talk_power_request" => Ok(Command::TalkPowerRequest {
            message: optional_str(&json, "message"),
        }),

        "server_edit" => Ok(Command::ServerEdit {
            name: optional_str(&json, "name"),
            welcome_message: optional_str(&json, "welcomeMessage"),
            max_clients: json
                .get("maxClients")
                .and_then(Value::as_i64)
                .map(|v| v as i32),
        }),

        "notify_register" => Ok(Command::NotifyRegister {
            channel_id: json.get("channelId").and_then(Value::as_i64).unwrap_or(0),
            subscribed: bool_field(&json, "subscribed")?,
        }),

        "delete_file" => Ok(Command::DeleteFile {
            channel_id: long_field(&json, "channelId")?,
            path: normalize_path(str_field(&json, "path")?),
            password: optional_str(&json, "password"),
        }),

        "rename_file" => Ok(Command::RenameFile {
            channel_id: long_field(&json, "channelId")?,
            path: normalize_path(str_field(&json, "path")?),
            new_name: str_field(&json, "newName")?.to_string(),
            target_channel_id: json.get("targetChannelId").and_then(Value::as_i64),
            target_password: optional_str(&json, "targetPassword"),
            password: optional_str(&json, "password"),
        }),

        "create_directory" => Ok(Command::CreateDirectory {
            channel_id: long_field(&json, "channelId")?,
            path: normalize_path(str_field(&json, "path")?),
            password: optional_str(&json, "password"),
        }),

        "server_group_create" => Ok(Command::ServerGroupCreate {
            name: str_field(&json, "name")?.to_string(),
            group_type: u8_field(&json, "type"),
        }),

        "server_group_delete" => Ok(Command::ServerGroupDelete {
            group_id: long_field(&json, "groupId")?,
            force: json.get("force").and_then(Value::as_bool).unwrap_or(false),
        }),

        "server_group_rename" => Ok(Command::ServerGroupRename {
            group_id: long_field(&json, "groupId")?,
            name: str_field(&json, "name")?.to_string(),
        }),

        "server_group_add_client" => Ok(Command::ServerGroupAddClient {
            group_id: long_field(&json, "groupId")?,
            client_db_id: long_field(&json, "clientDbId")?,
        }),

        "server_group_del_client" => Ok(Command::ServerGroupDelClient {
            group_id: long_field(&json, "groupId")?,
            client_db_id: long_field(&json, "clientDbId")?,
        }),

        "channel_group_create" => Ok(Command::ChannelGroupCreate {
            name: str_field(&json, "name")?.to_string(),
            group_type: u8_field(&json, "type"),
        }),

        "channel_group_delete" => Ok(Command::ChannelGroupDelete {
            group_id: long_field(&json, "groupId")?,
            force: json.get("force").and_then(Value::as_bool).unwrap_or(false),
        }),

        "channel_group_rename" => Ok(Command::ChannelGroupRename {
            group_id: long_field(&json, "groupId")?,
            name: str_field(&json, "name")?.to_string(),
        }),

        "channel_client_add_perm" => Ok(Command::ChannelClientAddPerm {
            channel_id: long_field(&json, "channelId")?,
            client_db_id: long_field(&json, "clientDbId")?,
            permission_id: json.get("permissionId").and_then(Value::as_i64),
            permission_name: optional_str(&json, "permissionName"),
            value: int_field(&json, "value")?,
        }),

        "channel_client_del_perm" => Ok(Command::ChannelClientDelPerm {
            channel_id: long_field(&json, "channelId")?,
            client_db_id: long_field(&json, "clientDbId")?,
            permission_id: json.get("permissionId").and_then(Value::as_i64),
            permission_name: optional_str(&json, "permissionName"),
        }),

        "client_db_list" => Ok(Command::ClientDbList {
            offset: json.get("offset").and_then(Value::as_i64),
            limit: json.get("limit").and_then(Value::as_i64),
        }),

        "client_db_find" => Ok(Command::ClientDbFind {
            pattern: str_field(&json, "pattern")?.to_string(),
        }),

        "client_db_info" => Ok(Command::ClientDbInfo {
            client_db_id: long_field(&json, "clientDbId")?,
        }),

        "offline_message_flag" => Ok(Command::OfflineMessageFlag {
            message_id: long_field(&json, "messageId")?,
            read: bool_field(&json, "read")?,
        }),

        "server_group_add_perm" => Ok(Command::ServerGroupAddPerm {
            group_id: long_field(&json, "groupId")?,
            permission_id: json.get("permissionId").and_then(Value::as_i64),
            permission_name: optional_str(&json, "permissionName"),
            value: int_field(&json, "value")?,
            negated: json
                .get("negated")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            skip: json.get("skip").and_then(Value::as_bool).unwrap_or(false),
        }),

        "server_group_del_perm" => Ok(Command::ServerGroupDelPerm {
            group_id: long_field(&json, "groupId")?,
            permission_id: json.get("permissionId").and_then(Value::as_i64),
            permission_name: optional_str(&json, "permissionName"),
        }),

        "channel_group_add_perm" => Ok(Command::ChannelGroupAddPerm {
            group_id: long_field(&json, "groupId")?,
            permission_id: json.get("permissionId").and_then(Value::as_i64),
            permission_name: optional_str(&json, "permissionName"),
            value: int_field(&json, "value")?,
        }),

        "channel_group_del_perm" => Ok(Command::ChannelGroupDelPerm {
            group_id: long_field(&json, "groupId")?,
            permission_id: json.get("permissionId").and_then(Value::as_i64),
            permission_name: optional_str(&json, "permissionName"),
        }),

        "channel_add_perm" => Ok(Command::ChannelAddPerm {
            channel_id: long_field(&json, "channelId")?,
            permission_id: json.get("permissionId").and_then(Value::as_i64),
            permission_name: optional_str(&json, "permissionName"),
            value: int_field(&json, "value")?,
        }),

        "channel_del_perm" => Ok(Command::ChannelDelPerm {
            channel_id: long_field(&json, "channelId")?,
            permission_id: json.get("permissionId").and_then(Value::as_i64),
            permission_name: optional_str(&json, "permissionName"),
        }),

        "client_db_delete" => Ok(Command::ClientDbDelete {
            client_db_id: long_field(&json, "clientDbId")?,
        }),

        "global_message" => Ok(Command::GlobalMessage {
            message: str_field(&json, "message")?.to_string(),
        }),

        "plugin_command" => Ok(Command::PluginInvoke {
            name: str_field(&json, "name")?.to_string(),
            data: optional_str(&json, "data").unwrap_or_default(),
            target: optional_str(&json, "target").unwrap_or_else(|| "channel".to_string()),
            client_id: json
                .get("clientId")
                .and_then(Value::as_i64)
                .map(|v| v as i32),
        }),

        "record_start" => Ok(Command::RecordStart {
            path: str_field(&json, "path")?.to_string(),
        }),

        "record_stop" => Ok(Command::RecordStop),

        "client_set_server_query_login" => Ok(Command::ClientSetServerQueryLogin {
            login_name: str_field(&json, "loginName")?.to_string(),
            password: optional_str(&json, "password"),
            client_db_id: json.get("clientDbId").and_then(Value::as_i64),
        }),

        "log_add" => Ok(Command::LogAdd {
            level: optional_str(&json, "level").unwrap_or_else(|| "info".to_string()),
            message: str_field(&json, "message")?.to_string(),
        }),

        "client_find" => Ok(Command::ClientFind {
            pattern: str_field(&json, "pattern")?.to_string(),
        }),

        "perm_get" => Ok(Command::PermGet {
            permission_id: long_field(&json, "permissionId")?,
        }),

        "server_info" => Ok(Command::ServerInfo),

        "server_snapshot_create" => Ok(Command::ServerSnapshotCreate),

        "server_snapshot_deploy" => Ok(Command::ServerSnapshotDeploy {
            snapshot: str_field(&json, "snapshot")?.to_string(),
        }),

        "server_create" => Ok(Command::ServerCreate {
            name: str_field(&json, "name")?.to_string(),
        }),

        "server_delete" => Ok(Command::ServerDelete {
            server_id: long_field(&json, "serverId")?,
        }),

        "server_start" => Ok(Command::ServerStart {
            server_id: long_field(&json, "serverId")?,
        }),

        "server_stop" => Ok(Command::ServerStop {
            server_id: long_field(&json, "serverId")?,
            reason: optional_str(&json, "reason"),
        }),

        "server_process_stop" => Ok(Command::ServerProcessStop {
            reason: optional_str(&json, "reason"),
        }),

        "instance_edit" => Ok(Command::InstanceEdit),

        "channel_subscribe_all" => Ok(Command::ChannelSubscribeAll),

        "channel_unsubscribe_all" => Ok(Command::ChannelUnsubscribeAll),

        "client_db_edit" => Ok(Command::ClientDbEdit {
            client_db_id: long_field(&json, "clientDbId")?,
        }),

        "ban_client" => Ok(Command::BanClient {
            client_id: int_field(&json, "clientId")?,
            seconds: json
                .get("seconds")
                .and_then(Value::as_i64)
                .filter(|v| *v > 0),
            reason: optional_str(&json, "reason"),
        }),

        "channel_description" => Ok(Command::ChannelDescription {
            channel_id: long_field(&json, "channelId")?,
        }),

        "channel_list" => Ok(Command::ChannelList),

        "client_db_id_from_uid" => Ok(Command::ClientDbIdFromUid {
            uid: str_field(&json, "uid")?.to_string(),
        }),

        "perm_overview" => Ok(Command::PermOverview {
            channel_id: long_field(&json, "channelId")?,
            client_db_id: long_field(&json, "clientDbId")?,
            permission_id: json.get("permissionId").and_then(Value::as_i64),
            permission_name: optional_str(&json, "permissionName"),
        }),

        "client_info" => Ok(Command::ClientInfo {
            client_id: int_field(&json, "clientId")?,
        }),

        "channel_info" => Ok(Command::ChannelInfo {
            channel_id: long_field(&json, "channelId")?,
        }),

        "channel_find" => Ok(Command::ChannelFind {
            pattern: str_field(&json, "pattern")?.to_string(),
        }),

        "client_list" => Ok(Command::ClientList),

        "server_list" => Ok(Command::ServerList),

        "who_am_i" => Ok(Command::WhoAmI),

        "version" => Ok(Command::Version),

        "host_info" => Ok(Command::HostInfo),

        "instance_info" => Ok(Command::InstanceInfo),

        "binding_list" => Ok(Command::BindingList {
            subsystem: optional_str(&json, "subsystem"),
        }),

        "perm_id_by_name" => Ok(Command::PermIdByName {
            permission_name: str_field(&json, "permissionName")?.to_string(),
        }),

        "perm_reset" => Ok(Command::PermReset),

        "server_id_by_port" => Ok(Command::ServerIdByPort {
            port: int_field(&json, "port")?,
        }),

        "channel_move" => Ok(Command::ChannelMove {
            channel_id: long_field(&json, "channelId")?,
            parent_id: long_field(&json, "parentId")?,
            order: json.get("order").and_then(Value::as_i64),
        }),

        "server_group_copy" => Ok(Command::ServerGroupCopy {
            source_group_id: long_field(&json, "sourceGroupId")?,
            target_group_id: json
                .get("targetGroupId")
                .and_then(Value::as_i64)
                .unwrap_or(0),
            name: optional_str(&json, "name").unwrap_or_default(),
            query: json.get("query").and_then(Value::as_bool).unwrap_or(false),
        }),

        "channel_group_copy" => Ok(Command::ChannelGroupCopy {
            source_group_id: long_field(&json, "sourceGroupId")?,
            target_group_id: json
                .get("targetGroupId")
                .and_then(Value::as_i64)
                .unwrap_or(0),
            name: optional_str(&json, "name").unwrap_or_default(),
            query: json.get("query").and_then(Value::as_bool).unwrap_or(false),
        }),

        "server_group_auto_add_perm" => Ok(Command::ServerGroupAutoAddPerm {
            query: json.get("query").and_then(Value::as_bool).unwrap_or(false),
            permission_id: json.get("permissionId").and_then(Value::as_i64),
            permission_name: optional_str(&json, "permissionName"),
            value: int_field(&json, "value")?,
            negated: json
                .get("negated")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            skip: json.get("skip").and_then(Value::as_bool).unwrap_or(false),
        }),

        "server_group_auto_del_perm" => Ok(Command::ServerGroupAutoDelPerm {
            query: json.get("query").and_then(Value::as_bool).unwrap_or(false),
            permission_id: json.get("permissionId").and_then(Value::as_i64),
            permission_name: optional_str(&json, "permissionName"),
        }),

        "client_add_perm" => Ok(Command::ClientAddPerm {
            client_db_id: long_field(&json, "clientDbId")?,
            permission_id: json.get("permissionId").and_then(Value::as_i64),
            permission_name: optional_str(&json, "permissionName"),
            value: int_field(&json, "value")?,
            skip: json.get("skip").and_then(Value::as_bool).unwrap_or(false),
        }),

        "client_del_perm" => Ok(Command::ClientDelPerm {
            client_db_id: long_field(&json, "clientDbId")?,
            permission_id: json.get("permissionId").and_then(Value::as_i64),
            permission_name: optional_str(&json, "permissionName"),
        }),

        "custom_set" => Ok(Command::CustomSet {
            client_db_id: long_field(&json, "clientDbId")?,
            ident: str_field(&json, "ident")?.to_string(),
            value: str_field(&json, "value")?.to_string(),
        }),

        "custom_delete" => Ok(Command::CustomDelete {
            client_db_id: long_field(&json, "clientDbId")?,
            ident: str_field(&json, "ident")?.to_string(),
        }),

        "token_use" => Ok(Command::TokenUse {
            token: str_field(&json, "token")?.to_string(),
        }),

        "privilege_key_delete" => Ok(Command::PrivilegeKeyDelete {
            key: str_field(&json, "key")?.to_string(),
        }),

        "server_group_client_list" => Ok(Command::ServerGroupClientList {
            group_id: long_field(&json, "groupId")?,
        }),

        "server_group_perm_list" => Ok(Command::ServerGroupPermList {
            group_id: long_field(&json, "groupId")?,
        }),

        "channel_group_client_list" => Ok(Command::ChannelGroupClientList {
            channel_id: json.get("channelId").and_then(Value::as_i64),
            client_db_id: json.get("clientDbId").and_then(Value::as_i64),
            group_id: json.get("groupId").and_then(Value::as_i64),
        }),

        "channel_group_perm_list" => Ok(Command::ChannelGroupPermList {
            group_id: long_field(&json, "groupId")?,
        }),

        "channel_client_perm_list" => Ok(Command::ChannelClientPermList {
            channel_id: long_field(&json, "channelId")?,
            client_db_id: long_field(&json, "clientDbId")?,
        }),

        "server_groups_by_client" => Ok(Command::ServerGroupsByClient {
            client_db_id: long_field(&json, "clientDbId")?,
        }),

        "client_ids" => Ok(Command::ClientIds {
            uid: str_field(&json, "uid")?.to_string(),
        }),

        "client_name_from_db_id" => Ok(Command::ClientNameFromDbId {
            client_db_id: long_field(&json, "clientDbId")?,
        }),

        "client_name_from_uid" => Ok(Command::ClientNameFromUid {
            uid: str_field(&json, "uid")?.to_string(),
        }),

        "client_uid_from_clid" => Ok(Command::ClientUidFromClid {
            client_id: int_field(&json, "clientId")?,
        }),

        "client_connection_info" => Ok(Command::ClientConnectionInfo {
            client_id: int_field(&json, "clientId")?,
        }),

        "server_connection_info" => Ok(Command::ServerConnectionInfo),

        "file_info" => Ok(Command::FileInfo {
            channel_id: long_field(&json, "channelId")?,
            path: normalize_path(str_field(&json, "path")?),
            password: optional_str(&json, "password"),
        }),

        "perm_find" => Ok(Command::PermFind {
            permission_id: json.get("permissionId").and_then(Value::as_i64),
            permission_name: optional_str(&json, "permissionName"),
        }),

        "perm_list" => Ok(Command::PermList),

        "log_view" => Ok(Command::LogView {
            lines: json.get("lines").and_then(Value::as_i64),
            reverse: json.get("reverse").and_then(Value::as_bool),
            instance_log: json.get("instanceLog").and_then(Value::as_bool),
            offset: json.get("offset").and_then(Value::as_i64),
        }),

        "token_add" => Ok(Command::TokenAdd {
            group_id: long_field(&json, "groupId")?,
            channel_id: json.get("channelId").and_then(Value::as_i64).unwrap_or(0),
            description: optional_str(&json, "description"),
        }),

        "token_list" => Ok(Command::TokenList),

        "token_delete" => Ok(Command::TokenDelete {
            token: str_field(&json, "token")?.to_string(),
        }),

        "complain_list" => Ok(Command::ComplainList {
            client_db_id: json.get("clientDbId").and_then(Value::as_i64),
        }),

        "client_chat_close" => Ok(Command::ClientChatClose {
            client_id: int_field(&json, "clientId")?,
        }),

        "filetransfer_list" => Ok(Command::FiletransferList),

        "stop_filetransfer" => Ok(Command::StopFiletransfer {
            server_id: long_field(&json, "serverId")?,
            delete: json.get("delete").and_then(Value::as_bool).unwrap_or(false),
        }),

        "fetch_icon" => Ok(Command::FetchIcon {
            icon_id: long_field(&json, "iconId")?,
        }),

        "set_whisper_targets" => Ok(Command::SetWhisperTargets {
            clients: u16_array(&json, "clients")?,
            channels: u64_array(&json, "channels")?,
            groups: whisper_groups(&json)?,
        }),

        other => Err(format!("unknown command: {other}")),
    }
}

fn str_field<'a>(json: &'a Value, key: &str) -> Result<&'a str, String> {
    json.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing string field `{key}`"))
}

fn optional_str(json: &Value, key: &str) -> Option<String> {
    json.get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn u8_field(json: &Value, key: &str) -> Option<u8> {
    json.get(key).and_then(Value::as_u64).map(|v| v as u8)
}

fn int_field(json: &Value, key: &str) -> Result<i32, String> {
    json.get(key)
        .and_then(Value::as_i64)
        .map(|value| value as i32)
        .ok_or_else(|| format!("missing integer field `{key}`"))
}

fn long_field(json: &Value, key: &str) -> Result<i64, String> {
    json.get(key)
        .and_then(Value::as_i64)
        .ok_or_else(|| format!("missing integer field `{key}`"))
}

fn bool_field(json: &Value, key: &str) -> Result<bool, String> {
    json.get(key)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("missing boolean field `{key}`"))
}

/// TeamSpeak file paths are always absolute. Accepting `name` as well as
/// `/name` keeps every shell from having to remember the leading slash.
fn normalize_path(path: &str) -> String {
    if path.is_empty() {
        "/".to_string()
    } else if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

fn f32_field(json: &Value, key: &str) -> Result<f32, String> {
    json.get(key)
        .and_then(Value::as_f64)
        .map(|value| value as f32)
        .ok_or_else(|| format!("missing number field `{key}`"))
}

fn u16_array(json: &Value, key: &str) -> Result<Vec<u16>, String> {
    let Some(value) = json.get(key) else {
        return Ok(Vec::new());
    };
    let items = value
        .as_array()
        .ok_or_else(|| format!("`{key}` must be an array"))?;
    items
        .iter()
        .map(|item| {
            item.as_u64()
                .and_then(|id| u16::try_from(id).ok())
                .ok_or_else(|| format!("`{key}` contains a non-client id"))
        })
        .collect()
}

fn u64_array(json: &Value, key: &str) -> Result<Vec<u64>, String> {
    let Some(value) = json.get(key) else {
        return Ok(Vec::new());
    };
    let items = value
        .as_array()
        .ok_or_else(|| format!("`{key}` must be an array"))?;
    items
        .iter()
        .map(|item| {
            item.as_u64()
                .ok_or_else(|| format!("`{key}` contains a non-integer id"))
        })
        .collect()
}

/// Group whisper targets use the new-protocol packet. Names are resolved here
/// so every shell sends the same protocol numbers.
fn whisper_groups(json: &Value) -> Result<Vec<(u8, u8, u64)>, String> {
    let Some(value) = json.get("groups") else {
        return Ok(Vec::new());
    };
    let items = value
        .as_array()
        .ok_or_else(|| "`groups` must be an array".to_string())?;
    items
        .iter()
        .map(|group| {
            let kind = match str_field(group, "type")? {
                "server_group" => 0,
                "channel_group" => 1,
                "channel_commander" => 2,
                "all_clients" => 3,
                other => return Err(format!("unknown whisper group type: {other}")),
            };
            let target = match group
                .get("target")
                .and_then(Value::as_str)
                .unwrap_or("all_channels")
            {
                "all_channels" => 0,
                "current_channel" => 1,
                "parent_channel" => 2,
                "all_parent_channel" => 3,
                "channel_family" => 4,
                "complete_channel_family" => 5,
                "subchannels" => 6,
                other => return Err(format!("unknown whisper target: {other}")),
            };
            let id = group.get("id").and_then(Value::as_u64).unwrap_or(0);
            Ok((kind, target, id))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_paths_get_a_leading_slash() {
        let command = parse("list_files", r#"{"channelId":1,"path":"docs"}"#).unwrap();
        match command {
            Command::ListFiles { path, .. } => assert_eq!(path, "/docs"),
            other => panic!("unexpected command: {other:?}"),
        }
    }

    /// Every command the protocol documents has to be reachable by name.
    ///
    /// The list is the contract with the shells: a name that parses here is one
    /// a shell can call, and a name that stops parsing breaks a button silently.
    #[test]
    fn every_documented_command_parses() {
        let cases: &[(&str, &str)] = &[
            ("disconnect", ""),
            ("send_text", r#"{"target":"server","message":"hi"}"#),
            ("poke", r#"{"clientId":1,"message":"hi"}"#),
            ("join_channel", r#"{"channelId":1}"#),
            ("set_input_muted", r#"{"muted":true}"#),
            ("set_output_muted", r#"{"muted":true}"#),
            ("set_away", r#"{"away":true}"#),
            ("set_nickname", r#"{"nickname":"x"}"#),
            ("list_files", r#"{"channelId":1}"#),
            (
                "download",
                r#"{"channelId":1,"path":"/a","local":"/tmp/a"}"#,
            ),
            ("upload", r#"{"channelId":1,"path":"/a","local":"/tmp/a"}"#),
            ("audio_enabled", r#"{"enabled":true}"#),
            ("set_mic_gain", r#"{"gain":1.0}"#),
            ("set_user_volume", r#"{"clientId":1,"volume":1.0}"#),
            ("set_whisper_targets", r#"{"clients":[],"channels":[]}"#),
            ("kick_client", r#"{"clientId":1,"reason":5}"#),
            ("move_client", r#"{"clientId":1,"channelId":2}"#),
            ("ban_add", r#"{"name":"x","seconds":60}"#),
            ("ban_delete", r#"{"banId":3}"#),
            ("ban_list", ""),
            ("channel_create", r#"{"name":"x"}"#),
            ("channel_edit", r#"{"channelId":1,"name":"y"}"#),
            ("channel_delete", r#"{"channelId":1,"force":true}"#),
            ("channel_subscribe", r#"{"channelId":1,"subscribed":true}"#),
            ("complain_add", r#"{"clientDbId":1,"message":"x"}"#),
            ("complain_delete", r#"{"clientDbId":1}"#),
            ("privilege_key_create", r#"{"groupId":6}"#),
            ("privilege_key_use", r#"{"key":"abc"}"#),
            ("privilege_key_list", ""),
            (
                "set_client_channel_group",
                r#"{"clientDbId":1,"channelId":2,"groupId":3}"#,
            ),
            ("offline_message_list", ""),
            ("offline_message_get", r#"{"messageId":1}"#),
            ("offline_message_delete", r#"{"messageId":1}"#),
            (
                "offline_message_send",
                r#"{"uid":"abc","subject":"s","message":"m"}"#,
            ),
            ("server_variables", ""),
            ("client_variables", r#"{"clientId":1}"#),
            ("temp_password_add", r#"{"password":"p"}"#),
            ("temp_password_delete", r#"{"password":"p"}"#),
            ("temp_password_list", ""),
            ("client_permission_list", r#"{"clientDbId":1}"#),
            ("channel_permission_list", r#"{"channelId":1}"#),
            ("client_edit", r#"{"clientId":1,"description":"d"}"#),
            ("client_update", r#"{"recording":true}"#),
            ("talk_power_request", r#"{"message":"m"}"#),
            ("server_edit", r#"{"name":"n"}"#),
            ("notify_register", r#"{"subscribed":true}"#),
            ("delete_file", r#"{"channelId":1,"path":"/a"}"#),
            (
                "rename_file",
                r#"{"channelId":1,"path":"/a","newName":"b"}"#,
            ),
            ("create_directory", r#"{"channelId":1,"path":"/d"}"#),
            ("server_group_create", r#"{"name":"g"}"#),
            ("server_group_delete", r#"{"groupId":1}"#),
            ("server_group_rename", r#"{"groupId":1,"name":"g"}"#),
            ("server_group_add_client", r#"{"groupId":1,"clientDbId":2}"#),
            ("server_group_del_client", r#"{"groupId":1,"clientDbId":2}"#),
            ("channel_group_create", r#"{"name":"g"}"#),
            ("channel_group_delete", r#"{"groupId":1}"#),
            ("channel_group_rename", r#"{"groupId":1,"name":"g"}"#),
            (
                "channel_client_add_perm",
                r#"{"channelId":1,"clientDbId":2,"permissionName":"p","value":1}"#,
            ),
            (
                "channel_client_del_perm",
                r#"{"channelId":1,"clientDbId":2,"permissionId":3}"#,
            ),
            ("client_db_list", r#"{"offset":0,"limit":50}"#),
            ("client_db_find", r#"{"pattern":"x"}"#),
            ("client_db_info", r#"{"clientDbId":1}"#),
            ("offline_message_flag", r#"{"messageId":1,"read":true}"#),
            (
                "server_group_add_perm",
                r#"{"groupId":1,"permissionName":"p","value":1}"#,
            ),
            (
                "server_group_del_perm",
                r#"{"groupId":1,"permissionName":"p"}"#,
            ),
            (
                "channel_group_add_perm",
                r#"{"groupId":1,"permissionName":"p","value":1}"#,
            ),
            (
                "channel_group_del_perm",
                r#"{"groupId":1,"permissionName":"p"}"#,
            ),
            (
                "channel_add_perm",
                r#"{"channelId":1,"permissionName":"p","value":1}"#,
            ),
            (
                "channel_del_perm",
                r#"{"channelId":1,"permissionName":"p"}"#,
            ),
            ("client_db_delete", r#"{"clientDbId":1}"#),
            ("global_message", r#"{"message":"m"}"#),
            ("plugin_command", r#"{"name":"n"}"#),
            ("record_start", r#"{"path":"/tmp/a.wav"}"#),
            ("record_stop", ""),
            (
                "client_set_server_query_login",
                r#"{"loginName":"q","password":"p"}"#,
            ),
            ("log_add", r#"{"message":"m"}"#),
            ("client_find", r#"{"pattern":"x"}"#),
            ("perm_get", r#"{"permissionId":1}"#),
            ("server_info", ""),
            ("server_snapshot_create", ""),
            ("server_snapshot_deploy", r#"{"snapshot":"abc"}"#),
            ("server_create", r#"{"name":"s"}"#),
            ("server_delete", r#"{"serverId":1}"#),
            ("server_start", r#"{"serverId":1}"#),
            ("server_stop", r#"{"serverId":1}"#),
            ("server_process_stop", ""),
            ("instance_edit", ""),
            ("channel_subscribe_all", ""),
            ("channel_unsubscribe_all", ""),
            ("client_db_edit", r#"{"clientDbId":1}"#),
            ("ban_client", r#"{"clientId":1}"#),
            ("channel_description", r#"{"channelId":1}"#),
            ("channel_list", ""),
            ("client_db_id_from_uid", r#"{"uid":"abc="}"#),
            ("perm_overview", r#"{"channelId":1,"clientDbId":2}"#),
            ("client_info", r#"{"clientId":1}"#),
            ("channel_info", r#"{"channelId":1}"#),
            ("channel_find", r#"{"pattern":"x"}"#),
            ("client_list", ""),
            ("server_list", ""),
            ("who_am_i", ""),
            ("version", ""),
            ("host_info", ""),
            ("instance_info", ""),
            ("binding_list", ""),
            ("perm_id_by_name", r#"{"permissionName":"p"}"#),
            ("perm_reset", ""),
            ("server_id_by_port", r#"{"port":9987}"#),
            ("channel_move", r#"{"channelId":1,"parentId":0}"#),
            ("server_group_copy", r#"{"sourceGroupId":1,"name":"g"}"#),
            ("channel_group_copy", r#"{"sourceGroupId":1,"name":"g"}"#),
            (
                "server_group_auto_add_perm",
                r#"{"permissionName":"p","value":1}"#,
            ),
            ("server_group_auto_del_perm", r#"{"permissionName":"p"}"#),
            (
                "client_add_perm",
                r#"{"clientDbId":1,"permissionName":"p","value":1}"#,
            ),
            (
                "client_del_perm",
                r#"{"clientDbId":1,"permissionName":"p"}"#,
            ),
            ("custom_set", r#"{"clientDbId":1,"ident":"i","value":"v"}"#),
            ("custom_delete", r#"{"clientDbId":1,"ident":"i"}"#),
            ("token_use", r#"{"token":"abc"}"#),
            ("privilege_key_delete", r#"{"key":"abc"}"#),
            ("server_group_client_list", r#"{"groupId":1}"#),
            ("server_group_perm_list", r#"{"groupId":1}"#),
            ("channel_group_client_list", r#"{"groupId":1}"#),
            ("channel_group_perm_list", r#"{"groupId":1}"#),
            (
                "channel_client_perm_list",
                r#"{"channelId":1,"clientDbId":2}"#,
            ),
            ("server_groups_by_client", r#"{"clientDbId":1}"#),
            ("client_ids", r#"{"uid":"abc="}"#),
            ("client_name_from_db_id", r#"{"clientDbId":1}"#),
            ("client_name_from_uid", r#"{"uid":"abc="}"#),
            ("client_uid_from_clid", r#"{"clientId":1}"#),
            ("client_connection_info", r#"{"clientId":1}"#),
            ("server_connection_info", ""),
            ("file_info", r#"{"channelId":1,"path":"/a"}"#),
            ("perm_find", r#"{"permissionName":"p"}"#),
            ("perm_list", ""),
            ("log_view", r#"{"lines":10}"#),
            ("token_add", r#"{"groupId":1}"#),
            ("token_list", ""),
            ("token_delete", r#"{"token":"abc"}"#),
            ("complain_list", ""),
            ("client_chat_close", r#"{"clientId":1}"#),
            ("filetransfer_list", ""),
            ("stop_filetransfer", r#"{"serverId":1,"delete":true}"#),
            ("fetch_icon", r#"{"iconId":5}"#),
        ];
        for (name, args) in cases {
            parse(name, args).unwrap_or_else(|e| panic!("{name} did not parse: {e}"));
        }
    }

    #[test]
    fn a_ban_without_an_identifier_is_refused_by_the_connection_not_the_parser() {
        // Parsing accepts it: "no identifier" is a semantic error the connection
        // thread reports, because only it knows whether the shell meant to ban
        // by uid, address or name.
        let command = parse("ban_add", r#"{"seconds":60}"#).unwrap();
        match command {
            Command::BanAdd { uid, ip, name, .. } => {
                assert!(uid.is_none() && ip.is_none() && name.is_none());
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn an_unknown_command_is_an_error_with_its_name() {
        let error = parse("no_such_command", "").unwrap_err();
        assert!(error.contains("no_such_command"), "{error}");
    }

    #[test]
    fn kick_reason_defaults_to_a_server_kick() {
        let command = parse("kick_client", r#"{"clientId":1}"#).unwrap();
        match command {
            Command::KickClient { reason, .. } => assert_eq!(reason, 5),
            other => panic!("unexpected command: {other:?}"),
        }
    }
}
