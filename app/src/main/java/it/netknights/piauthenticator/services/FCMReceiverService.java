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

import android.app.ActivityManager;
import android.app.Notification;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.os.Build;

import androidx.annotation.Nullable;
import androidx.core.app.NotificationCompat;
import androidx.core.app.NotificationManagerCompat;

import com.google.firebase.messaging.FirebaseMessagingService;
import com.google.firebase.messaging.RemoteMessage;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;

import it.netknights.piauthenticator.R;
import it.netknights.piauthenticator.model.PushAuthRequest;
import it.netknights.piauthenticator.model.Token;
import it.netknights.piauthenticator.utils.SecretKeyWrapper;
import it.netknights.piauthenticator.utils.Util;
import it.netknights.piauthenticator.viewcontroller.MainActivity;

import static it.netknights.piauthenticator.utils.AppConstants.CHANNEL_ID_HIGH_PRIO;
import static it.netknights.piauthenticator.utils.AppConstants.CHANNEL_ID_LOW_PRIO;
import static it.netknights.piauthenticator.utils.AppConstants.INTENT_FILTER;
import static it.netknights.piauthenticator.utils.AppConstants.NONCE;
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
            try {
                if (Integer.parseInt(map.get(SSL_VERIFY)) < 1) {
                    sslVerify = false;
                }
            } catch (NullPointerException | NumberFormatException e) {
                sslVerify = true;
            }
        }
        // Generate a random notification ID
        Random random = new Random();
        int notificationID = random.nextInt(9999 - 1000) + 1000;

        PushAuthRequest req = new PushAuthRequest(nonce, url, serial, question, title, signature, notificationID, sslVerify);

        // check if the token was deleted from within the app,
        // if that is the case do not show any notification for it
        // if the token is found, append the request so it will be loaded when loading the app, if closed before
        try {
            Util util = new Util(new SecretKeyWrapper(this.getApplicationContext()),
                    this.getFilesDir().getAbsolutePath());
            boolean tokenExists = false;
            ArrayList<Token> tokens = util.loadTokens();
            for (Token t : tokens) {
                if (t.getSerial().equals(serial)) {
                    t.addPushAuthRequest(req);
                    tokenExists = true;
                    break;
                }
            }
            if (!tokenExists) {
                return;
            }
            util.saveTokens(tokens);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

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
            //if (!appInForeground(getApplicationContext())) {
            NotificationManagerCompat.from(this).notify(notificationID, notification);
            //}
        }
    }

    private static boolean appInForeground(Context context) {
        ActivityManager activityManager = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
        List<ActivityManager.RunningAppProcessInfo> runningAppProcesses = activityManager.getRunningAppProcesses();
        if (runningAppProcesses == null) {
            return false;
        }

        for (ActivityManager.RunningAppProcessInfo runningAppProcess : runningAppProcesses) {
            if (runningAppProcess.processName.equals(context.getPackageName()) &&
                    runningAppProcess.importance == ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND) {
                return true;
            }
        }
        return false;
    }

    /**
     * Build the default notification for a Push Authentication Request.
     * Showing the title, question, an optional subtext and a button.
     * Pressing the button will the start the sepcified service.
     * The intents for the activity and the service need to be filled beforehand.
     *
     * @param context         app context
     * @param notificationID  notification ID
     * @param service_intent  intent to start the service with, getService will be called on this
     * @param activity_intent intent to start the activity with, getActivity will be called on this
     * @param title           notification title
     * @param contextText     notification text
     * @param subText         notification subtext, optional
     * @param buttonText      button text
     * @return notification
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

        // If the app is already in foreground, add the notification with low priority so it does not pop up
        boolean isAppInForeground = appInForeground(context);
        String channelID = isAppInForeground ? CHANNEL_ID_LOW_PRIO : CHANNEL_ID_HIGH_PRIO;
        int priority = isAppInForeground ? NotificationCompat.PRIORITY_LOW : NotificationCompat.PRIORITY_MAX;

        NotificationCompat.Builder mBuilder = new NotificationCompat.Builder(context, channelID) // Android 8+ uses notification channels
                .setSmallIcon(R.drawable.ic_pi_notification)
                .setContentTitle(title)
                .setContentText(contextText)
                .setPriority(priority)                                  // 7.1 and lower
                .addAction(action)                                     // Add the allow Button
                .setAutoCancel(true)                                   // Remove the notification after tabbing it
                .setWhen(0)
                .setContentIntent(pActivity_intent)                    // Intent for opening activity with the request
                .setDefaults(Notification.DEFAULT_SOUND);              // Play a sound/vibrate for push auth

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