package it.netknights.piauthenticator;

import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.media.RingtoneManager;
import android.net.Uri;
import android.support.v4.app.NotificationCompat;
import android.support.v4.app.NotificationManagerCompat;
import android.util.Log;

import com.google.firebase.messaging.FirebaseMessagingService;
import com.google.firebase.messaging.RemoteMessage;

import java.util.Map;

import static android.support.v4.app.NotificationCompat.PRIORITY_DEFAULT;
import static android.support.v4.app.NotificationCompat.PRIORITY_HIGH;
import static android.support.v4.app.NotificationCompat.PRIORITY_MAX;
import static it.netknights.piauthenticator.AppConstants.*;
import static it.netknights.piauthenticator.Util.logprint;

public class FCMReceiverService extends FirebaseMessagingService {

    String question, nonce, serial, signature;

    @Override
    public void onMessageReceived(RemoteMessage message) {
        // get the key-value pairs
        Map<String, String> map = message.getData();
        logprint("FCM message received: " + message.toString());
        if (map.containsKey(NOTIFICATION_TEXT)) {
            question = map.get(NOTIFICATION_TEXT);
        } else {
            // TODO default question?
        }
        if (map.containsKey(NONCE)) {
            nonce = map.get(NONCE);
        } else {
            // TODO no nonce in push
        }
        if (map.containsKey(SERIAL)) {
            serial = map.get(SERIAL);
        } else {
            // TODO no serial in push
        }
        if (map.containsKey(SIGNATURE)) {
            signature = map.get(SIGNATURE);
        } else {
            // TODO reject request?
        }

        sendNotification(message.getData().toString(), question);
    }

    @Override
    public void onNewToken(String s) {
        super.onNewToken(s);
        Log.e("NEW TOKEN", s);
    }

    private void sendNotification(String data, String message) {
        Intent intent = new Intent(this, PushAuthService.class);
        intent.putExtra(DATA, data);
        PendingIntent pendingIntent = PendingIntent.getService(this, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT);

        // TODO indicate verification from within app?

        NotificationCompat.Action action = new NotificationCompat.Action.Builder(0, "Allow", pendingIntent).build();

        NotificationCompat.Builder mBuilder = new NotificationCompat.Builder(this,
                NOTIFICATION_CHANNEL_ID)    // Android 8 uses notification channels
                .setSmallIcon(R.drawable.ic_edit)
                .setContentTitle("privacyIDEA Authentication")
                .setContentText(message)
                .setPriority(NotificationCompat.PRIORITY_MAX)          // 7.1 and lower
                .addAction(action)
                .setStyle(new NotificationCompat.BigTextStyle()
                        .bigText("BIG TEXT"))
                .setAutoCancel(true)                  // dont remove the notification after tabbing it
                .setWhen(0);
        //.setContentIntent(pendingIntent)

        NotificationManagerCompat notificationManager = NotificationManagerCompat.from(this);
        if (notificationManager != null) {
            notificationManager.notify(0, mBuilder.build());
        }

    }
}