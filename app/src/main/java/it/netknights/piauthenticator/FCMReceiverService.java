package it.netknights.piauthenticator;

import android.app.PendingIntent;
import android.content.Intent;
import android.support.v4.app.NotificationCompat;
import android.support.v4.app.NotificationManagerCompat;
import android.util.Log;

import com.google.firebase.messaging.FirebaseMessagingService;
import com.google.firebase.messaging.RemoteMessage;

import java.util.Map;

import static it.netknights.piauthenticator.AppConstants.*;
import static it.netknights.piauthenticator.Util.logprint;

public class FCMReceiverService extends FirebaseMessagingService {

    String question, nonce, serial, signature, title, url;

    @Override
    public void onMessageReceived(RemoteMessage message) {
        // get the key-value pairs
        Map<String, String> map = message.getData();
        logprint("FCM message received: " + message.getData().toString());
        if (map.containsKey(QUESTION)) {
            question = map.get(QUESTION);
        }
        if (map.containsKey(NONCE)) {
            nonce = map.get(NONCE);
        }
        if (map.containsKey(SERIAL)) {
            serial = map.get(SERIAL);
        }
        if (map.containsKey(TITLE)) {
            title = map.get(TITLE);
        }
        if (map.containsKey(AUTHENTICATION_URL)) {
            url = map.get(AUTHENTICATION_URL);
        }
        if (map.containsKey(SIGNATURE)) {
            signature = map.get(SIGNATURE);
        }

        // Start the service with the data from the push when the button in the notification is pressed
        Intent service_intent = new Intent(this, PushAuthService.class);
        service_intent.putExtra(SERIAL, serial)
                .putExtra(NONCE, nonce)
                .putExtra(TITLE, title)
                .putExtra(AUTHENTICATION_URL, url)
                .putExtra(SIGNATURE, signature)
                .putExtra(QUESTION, question);

        PendingIntent pService_intent = PendingIntent.getService(this, 0, service_intent, PendingIntent.FLAG_UPDATE_CURRENT);
        NotificationCompat.Action action = new NotificationCompat.Action.Builder(0, "Allow", pService_intent).build();

        Intent activity_intent = new Intent(this, MainActivity.class);
        activity_intent.putExtra(SERIAL, serial)
                .putExtra(NONCE, nonce)
                .putExtra(TITLE, title)
                .putExtra(AUTHENTICATION_URL, url)
                .putExtra(SIGNATURE, signature)
                .putExtra(QUESTION, question);

        PendingIntent pActivity_intent = PendingIntent.getActivity(this, 0, activity_intent, PendingIntent.FLAG_UPDATE_CURRENT);

        // TODO indicate verification from within app?

        NotificationCompat.Builder mBuilder = new NotificationCompat.Builder(this,
                NOTIFICATION_CHANNEL_ID)                                // Android 8+ uses notification channels
                .setSmallIcon(R.drawable.ic_add_white_24dp)
                .setContentTitle(title)
                .setContentText(question)
                .setPriority(NotificationCompat.PRIORITY_MAX)          // 7.1 and lower
                .addAction(action)                                     // Add the allow Button
                .setAutoCancel(true)                                   // Remove the notification after tabbing it
                .setWhen(0)
                .setContentIntent(pActivity_intent);                   // Intent for opening activity with the request

        NotificationManagerCompat notificationManager = NotificationManagerCompat.from(this);
        notificationManager.notify(NOTIFICATION_ID, mBuilder.build());
    }

    @Override
    public void onNewToken(String s) {
        super.onNewToken(s);
        Log.e("NEW TOKEN", s);
    }

}