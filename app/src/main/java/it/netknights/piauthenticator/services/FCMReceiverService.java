/*
  privacyIDEA Authenticator

  Authors: Nils Behlen <nils.behlen@netknights.it>

  Copyright (c) 2017-2019 NetKnights GmbH

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

package it.netknights.piauthenticator.services;

import android.app.Notification;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.os.Build;

import com.google.firebase.messaging.FirebaseMessagingService;
import com.google.firebase.messaging.RemoteMessage;

import java.util.Map;
import java.util.Random;

import androidx.annotation.Nullable;
import androidx.core.app.NotificationCompat;
import androidx.core.app.NotificationManagerCompat;

import it.netknights.piauthenticator.R;
import it.netknights.piauthenticator.viewcontroller.MainActivity;

import static it.netknights.piauthenticator.utils.AppConstants.INTENT_FILTER;
import static it.netknights.piauthenticator.utils.AppConstants.NONCE;
import static it.netknights.piauthenticator.utils.AppConstants.NOTIFICATION_CHANNEL_ID;
import static it.netknights.piauthenticator.utils.AppConstants.NOTIFICATION_ID;
import static it.netknights.piauthenticator.utils.AppConstants.QUESTION;
import static it.netknights.piauthenticator.utils.AppConstants.SERIAL;
import static it.netknights.piauthenticator.utils.AppConstants.SIGNATURE;
import static it.netknights.piauthenticator.utils.AppConstants.SSL_VERIFY;
import static it.netknights.piauthenticator.utils.AppConstants.TITLE;
import static it.netknights.piauthenticator.utils.AppConstants.URL;
import static it.netknights.piauthenticator.utils.Util.logprint;

public class FCMReceiverService extends FirebaseMessagingService {

    String question, nonce, serial, signature, title, url;
    boolean sslVerify = true;

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
        if (map.containsKey(URL)) {
            url = map.get(URL);
        }
        if (map.containsKey(SIGNATURE)) {
            signature = map.get(SIGNATURE);
        }
        if (map.containsKey(SSL_VERIFY)) {
            if (Integer.parseInt(map.get(SSL_VERIFY)) < 1) {
                sslVerify = false;
            }
        }

        // Generate a random notification ID
        Random random = new Random();
        int notificationID = random.nextInt(9999 - 1000) + 1000;

        // Build an intent which will update the running app
        Intent update_intent = new Intent(INTENT_FILTER);
        update_intent = packIntent(update_intent, notificationID);
        sendBroadcast(update_intent);

        // Start the service with the data from the push when the button in the notification is pressed
        Intent service_intent = new Intent(this, PushAuthService.class);
        service_intent = packIntent(service_intent, notificationID);

        // Or start the Activity with the same data if the notification is pressed
        Intent activity_intent = new Intent(this, MainActivity.class);
        activity_intent = packIntent(activity_intent, notificationID);

        Notification notification = buildNotificationFromPush(getApplicationContext(), notificationID, service_intent,
                activity_intent, title, question, "Token: " + activity_intent.getStringExtra(SERIAL), getApplicationContext().getString(R.string.Allow));
        if (notification != null) {
            NotificationManagerCompat.from(this).notify(notificationID, notification);
        }
    }

    /**
     * Build the default notification for a Push Authentication Request.
     * Showing the title, question, an optional subtext and a button.
     * Pressing the button will the start the sepcified service.
     * The intents for the activity and the service need to be filled beforehand.
     *
     * @param context           app context
     * @param notificationID    notification ID
     * @param service_intent    intent to start the service with, getService will be called on this
     * @param activity_intent   intent to start the activity with, getActivity will be called on this
     * @param title             notification title
     * @param contextText       notification text
     * @param subText           notification subtext, optional
     * @param buttonText        button text
     * @return                  notification
     */
    static Notification buildNotificationFromPush(Context context, int notificationID, Intent service_intent, Intent activity_intent,
                                                  String title, String contextText, @Nullable String subText, String buttonText) {
        if (context == null || service_intent.getExtras() == null || activity_intent.getExtras() == null) {
            logprint("Building default notification failed - missing parameters");
            return null;
        }

        // Build the PendingIntents with the random notificationID as request code so multiple PendingIntents can live simultaneously
        PendingIntent pActivity_intent = PendingIntent.getActivity(context, notificationID, activity_intent, PendingIntent.FLAG_UPDATE_CURRENT);
        PendingIntent pService_intent = PendingIntent.getService(context, notificationID, service_intent, PendingIntent.FLAG_UPDATE_CURRENT);

        NotificationCompat.Action action = new NotificationCompat.Action.Builder(0, buttonText, pService_intent).build();

        NotificationCompat.Builder mBuilder = new NotificationCompat.Builder(context,
                NOTIFICATION_CHANNEL_ID)                                // Android 8+ uses notification channels
                .setSmallIcon(R.drawable.ic_pi_notification)
                .setContentTitle(title)
                .setContentText(contextText)
                .setPriority(NotificationCompat.PRIORITY_MAX)          // 7.1 and lower
                .addAction(action)                                     // Add the allow Button
                .setAutoCancel(true)                                   // Remove the notification after tabbing it
                .setWhen(0)
                .setContentIntent(pActivity_intent);                   // Intent for opening activity with the request

        if (subText != null) {
            mBuilder.setSubText(subText);
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            mBuilder.setColor(context.getResources().getColor(R.color.PIBLUE, null));
        }
        return mBuilder.build();
    }

    /**
     * Add the data from the FCM Message to the intent.
     *
     * @param intent intent to add data to
     * @return the intent
     */
    Intent packIntent(Intent intent, int notificationID) {
        intent.putExtra(SERIAL, serial)
                .putExtra(NONCE, nonce)
                .putExtra(TITLE, title)
                .putExtra(URL, url)
                .putExtra(SIGNATURE, signature)
                .putExtra(QUESTION, question)
                .putExtra(SSL_VERIFY, sslVerify)
                .putExtra(NOTIFICATION_ID, notificationID);
        return intent;
    }

    @Override
    public void onNewToken(String s) {
        super.onNewToken(s);
        logprint("New Token in FCMReceiver: " + s);
    }

}