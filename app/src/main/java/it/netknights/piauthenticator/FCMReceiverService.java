package it.netknights.piauthenticator;

import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.media.RingtoneManager;
import android.net.Uri;
import android.support.v4.app.NotificationCompat;
import android.util.Log;

import com.google.firebase.messaging.FirebaseMessagingService;
import com.google.firebase.messaging.RemoteMessage;

import java.util.Map;

import static android.support.v4.app.NotificationCompat.PRIORITY_DEFAULT;
import static it.netknights.piauthenticator.AppConstants.*;

public class FCMReceiverService extends FirebaseMessagingService {

    String question, nonce, serial, signature;

    @Override
    public void onMessageReceived(RemoteMessage message) {


        Log.e("MESSAGE", message.getData().toString());

        // get the key-value pairs
        Map<String,String> map = message.getData();

        if(map.containsKey(NOTIFICATION_TEXT)) {
            question = map.get(NOTIFICATION_TEXT);
        } else {
            // TODO default question?
        }
        if(map.containsKey(NONCE)) {
            nonce = map.get(NONCE);
        } else {
            // TODO no nonce in push
        }
        if(map.containsKey(SERIAL)){
            serial = map.get(SERIAL);
        } else {
            // TODO no serial in push
        }
        if(map.containsKey(SIGNATURE)){
            signature = map.get(SIGNATURE);
        } else {
            // TODO reject request?
        }

        // if(!verifySignature(signature, token)){
            // return
        // }
        sendNotification(question, serial, nonce);
    }

    @Override
    public void onNewToken(String s) {
        super.onNewToken(s);
        Log.e("NEW TOKEN", s);
    }

    private void sendNotification(String message, String serial, String nonce) {
        Intent intent = new Intent(this, MainActivity.class);
        intent.putExtra("serial", serial);
        intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);
        PendingIntent pendingIntent = PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_ONE_SHOT);


        Intent intent2 = new Intent(this, MainActivity.class);
        intent2.putExtra(SERIAL, serial)
        .putExtra("message", message)
        .putExtra(NONCE, nonce);
        PendingIntent pendingIntent2 = PendingIntent.getActivity(this, 0, intent2, PendingIntent.FLAG_ONE_SHOT);



        // TODO indicate verification from within app?
        Uri soundUri= RingtoneManager.getDefaultUri(RingtoneManager.TYPE_NOTIFICATION);

        NotificationCompat.Builder mBuilder = new NotificationCompat.Builder(this,
                NOTIFICATION_CHANNEL_ID)    // Android 8 uses notification channels
                .setSmallIcon(R.mipmap.ic_launcher)
                .setContentTitle("privacyIDEA Authentication")      // TODO extract from push
                .setContentText(message)
                .setAutoCancel(false)                   // dont remove the notification after tabbing it
                .setSound(soundUri)
                .setPriority(PRIORITY_DEFAULT)          // 7.1 and lower
                .setContentIntent(pendingIntent)
                .addAction(R.drawable.ic_info_black_24dp, "blaaa", pendingIntent2);

        NotificationManager notificationManager =
                (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);

        if (notificationManager != null) {
            notificationManager.notify(0, mBuilder.build());
        }
    }

}