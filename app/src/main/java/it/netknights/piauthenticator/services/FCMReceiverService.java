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

import android.app.PendingIntent;
import android.content.Intent;
import android.os.Build;

import com.google.firebase.messaging.FirebaseMessagingService;
import com.google.firebase.messaging.RemoteMessage;

import java.util.Map;
import java.util.Random;

import androidx.core.app.NotificationCompat;
import androidx.core.app.NotificationManagerCompat;

import it.netknights.piauthenticator.R;
import it.netknights.piauthenticator.viewcontroller.MainActivity;

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

        // Start the service with the data from the push when the button in the notification is pressed
        Intent service_intent = new Intent(this, PushAuthService.class);
        service_intent = packIntent(service_intent, notificationID);

        // Or start the Activity with the same data if the notification is pressed
        Intent activity_intent = new Intent(this, MainActivity.class);
        activity_intent = packIntent(activity_intent, notificationID);

        // Build the PendingIntents with the random notificationID as request code so multiple PendingIntents can live simultaneously
        PendingIntent pActivity_intent = PendingIntent.getActivity(this, notificationID, activity_intent, PendingIntent.FLAG_UPDATE_CURRENT);
        PendingIntent pService_intent = PendingIntent.getService(this, notificationID, service_intent, PendingIntent.FLAG_UPDATE_CURRENT);


        NotificationCompat.Action action = new NotificationCompat.Action.Builder(0, "Allow", pService_intent).build();

        NotificationCompat.Builder mBuilder = new NotificationCompat.Builder(this,
                NOTIFICATION_CHANNEL_ID)                                // Android 8+ uses notification channels
                .setSmallIcon(R.drawable.ic_pi_notification)
                .setContentTitle(title)
                .setContentText(question)
                .setSubText("Token: " + serial)                        // TODO Maybe add a service name field?
                .setPriority(NotificationCompat.PRIORITY_MAX)          // 7.1 and lower
                .addAction(action)                                     // Add the allow Button
                .setAutoCancel(true)                                   // Remove the notification after tabbing it
                .setWhen(0)
                .setContentIntent(pActivity_intent);                   // Intent for opening activity with the request

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            mBuilder.setColor(getResources().getColor(R.color.PIBLUE, null));
        }

        NotificationManagerCompat notificationManager = NotificationManagerCompat.from(this);
        notificationManager.notify(notificationID, mBuilder.build());
        logprint("Notification sent with id: " + notificationID);
        logprint("Service data: " + service_intent.getExtras().toString());
        logprint("Activity data: " + activity_intent.getExtras().toString());
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