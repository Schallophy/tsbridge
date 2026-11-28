package io.github.schallophy.litespeak

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.graphics.drawable.Icon
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Binder
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import io.github.schallophy.litespeak.data.ServerStore
import io.github.schallophy.litespeak.data.Settings

/**
 * Hosts the session so it outlives the Activity.
 *
 * The connection, audio and the per-session state live in [SessionController],
 * which this service owns. The UI binds here and reads through the controller;
 * a rotation, backgrounding or the screen turning off does not touch any of it,
 * because none of it belongs to a screen.
 *
 * The service is a foreground service for exactly as long as a session exists:
 * Android only keeps a microphone alive in the background for a foreground
 * service of type `microphone`, and only such a service is exempt from the
 * process freeze that would otherwise stop the audio tick on a locked screen.
 */
class SessionService : Service() {

    private val binder = LocalBinder()
    private lateinit var settings: Settings

    /** The live session, or null before the first connect and after the last leave. */
    var controller: SessionController? = null
        private set

    inner class LocalBinder : Binder() {
        /** The service itself, so a bound client can reach [controller]. */
        fun service(): SessionService = this@SessionService
    }

    override fun onBind(intent: Intent?): IBinder = binder

    override fun onCreate() {
        super.onCreate()
        settings = Settings(this)
        createChannel()
    }

    /**
     * Starts the session for a connection, or returns the running one.
     *
     * Called by the UI on the main thread. The controller is created here rather
     * than in the Activity so its lifetime is the service's, not the screen's.
     */
    fun session(): SessionController {
        controller?.let { return it }
        val app = application as LiteSpeakApp
        val created = SessionController(
            app,
            Settings(this),
            ServerStore(this),
            app.account,
        )
        created.onSessionEnded = { endSession() }
        created.onStateChanged = { refreshNotification() }
        controller = created
        return created
    }

    /**
     * Ends the session and stops the service.
     *
     * The controller's own shutdown stops audio, the wake lock and the native
     * client; the service then has nothing to host, so it stops rather than
     * lingering as an empty process.
     */
    fun endSession() {
        controller?.let {
            it.onSessionEnded = null
            it.onStateChanged = null
            it.shutdown()
        }
        controller = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        controller?.let {
            it.onSessionEnded = null
            it.onStateChanged = null
            it.shutdown()
        }
        controller = null
        super.onDestroy()
    }

    /**
     * The app was swiped off the recent-tasks list.
     *
     * With "keep in background" on, the session keeps running and the
     * notification is the way back. Off, the swipe ends the call — the same as
     * closing any other app.
     */
    override fun onTaskRemoved(rootIntent: Intent?) {
        if (!settings.keepInBackground) {
            controller?.leave()
            endSession()
        }
        super.onTaskRemoved(rootIntent)
    }

    // ── foreground notification ───────────────────────────────────────────

    private fun createChannel() {
        val manager = getSystemService(NotificationManager::class.java)
        // The old channel was IMPORTANCE_LOW, and importance cannot be raised in
        // place. A notification whose controls must be reachable from the lock
        // screen ranks above "quiet", but it stays silent: the clock updates it
        // every 20 ms and must never buzz.
        manager.deleteNotificationChannel(LEGACY_CHANNEL_ID)
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.notif_channel),
            NotificationManager.IMPORTANCE_HIGH,
        ).apply {
            description = getString(R.string.notif_channel_description)
            setShowBadge(false)
            setSound(null, null)
            enableVibration(false)
            lockscreenVisibility = Notification.VISIBILITY_PUBLIC
        }
        manager.createNotificationChannel(channel)
    }

    private fun buildNotification(): Notification {
        val ui = controller?.ui?.value
        val title = when (ui?.status) {
            SessionStatus.Online -> ui.state.server.name.ifEmpty {
                ui.config?.address ?: getString(R.string.notif_call)
            }
            SessionStatus.Connecting -> getString(R.string.notif_connecting)
            SessionStatus.Failed -> getString(R.string.notif_failed)
            SessionStatus.Disconnected -> getString(R.string.notif_disconnected)
            else -> ui?.config?.address ?: getString(R.string.notif_call)
        }
        val subtitle = when {
            ui == null -> getString(R.string.notif_connecting)
            !ui.state.inputHardwareEnabled -> getString(R.string.notif_mic_device_off)
            !ui.micEnabled -> getString(R.string.notif_mic_muted)
            ui.state.away -> ui.state.awayMessage.ifEmpty { getString(R.string.notif_away) }
            else -> getString(R.string.notif_mic_on)
        }

        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )

        // MIUI/HyperOS drops notifications that carry a custom content view:
        // the notification is posted, ranked first, and then never rendered.
        // Compact MediaStyle actions are the platform's own answer for controls
        // that have to survive a collapsed shade and a lock screen, and MIUI
        // renders those.
        //
        // The platform builder rather than NotificationCompat: the compact style
        // is `Notification.MediaStyle`, and the compat builder only accepts its
        // own style type. minSdk is 26, so every setter here exists directly.
        val builder = Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.icon_capture)
            .setContentTitle(title)
            .setContentText(subtitle)
            .setContentIntent(open)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setShowWhen(false)
            .setVisibility(Notification.VISIBILITY_PUBLIC)
            .setCategory(Notification.CATEGORY_CALL)
            .setStyle(Notification.MediaStyle().setShowActionsInCompactView(0, 1, 2))
            .addAction(
                action(micIcon(ui), if (ui?.micEnabled != false) {
                    getString(R.string.notif_mic_on)
                } else {
                    getString(R.string.notif_mic_muted)
                }, ACTION_MIC),
            )
            .addAction(action(speakerIcon(ui), getString(R.string.notif_speaker), ACTION_SPEAKER))
            .addAction(
                action(R.drawable.ic_logout, getString(R.string.notif_hangup), ACTION_DISCONNECT),
            )

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            builder.setForegroundServiceBehavior(Notification.FOREGROUND_SERVICE_IMMEDIATE)
        }
        return builder.build()
    }

    private fun micIcon(ui: SessionUiState?): Int = when {
        ui == null || !ui.state.inputHardwareEnabled -> R.drawable.icon_hardware_input_muted
        !ui.micEnabled -> R.drawable.icon_input_muted
        else -> R.drawable.icon_capture
    }

    private fun speakerIcon(ui: SessionUiState?): Int = when {
        ui == null || !ui.state.outputHardwareEnabled -> R.drawable.icon_hardware_output_muted
        !ui.speakerEnabled -> R.drawable.icon_output_muted
        else -> R.drawable.icon_volume
    }

    private fun action(icon: Int, label: String, name: String): Notification.Action {
        val intent = Intent(this, SessionService::class.java).setAction(name)
        val pending = PendingIntent.getService(
            this,
            name.hashCode(),
            intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return Notification.Action.Builder(
            Icon.createWithResource(this, icon),
            label,
            pending,
        ).build()
    }

    private fun refreshNotification() {
        if (controller == null) return
        getSystemService(NotificationManager::class.java)
            .notify(NOTIFICATION_ID, buildNotification())
    }

    private fun startInForeground() {
        val notification = buildNotification()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE or
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PLAYBACK,
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // A started (not just bound) foreground service has to call
        // startForeground promptly or the system kills it.
        startInForeground()

        when (intent?.action) {
            ACTION_MIC -> controller?.toggleMic()
            ACTION_SPEAKER -> controller?.toggleSpeaker()
            ACTION_DISCONNECT -> {
                controller?.leave()
                endSession()
            }
        }
        return START_NOT_STICKY
    }

    private companion object {
        const val CHANNEL_ID = "session-v3"
        const val LEGACY_CHANNEL_ID = "session"
        const val NOTIFICATION_ID = 1
        const val ACTION_MIC = "io.github.schallophy.litespeak.MIC"
        const val ACTION_SPEAKER = "io.github.schallophy.litespeak.SPEAKER"
        const val ACTION_DISCONNECT = "io.github.schallophy.litespeak.DISCONNECT"
    }
}
