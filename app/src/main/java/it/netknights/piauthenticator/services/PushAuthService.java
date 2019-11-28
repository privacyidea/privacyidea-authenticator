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
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.AsyncTask;
import android.os.Build;
import android.os.IBinder;
import android.widget.Toast;

import androidx.annotation.Nullable;
import androidx.core.app.NotificationCompat;
import androidx.core.app.NotificationManagerCompat;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;

import it.netknights.piauthenticator.R;
import it.netknights.piauthenticator.interfaces.PushAuthCallbackInterface;
import it.netknights.piauthenticator.model.PushAuthRequest;
import it.netknights.piauthenticator.model.Token;
import it.netknights.piauthenticator.tasks.PushAuthTask;
import it.netknights.piauthenticator.utils.SecretKeyWrapper;
import it.netknights.piauthenticator.utils.Util;
import it.netknights.piauthenticator.viewcontroller.MainActivity;

import static it.netknights.piauthenticator.utils.AppConstants.CHANNEL_ID_HIGH_PRIO;
import static it.netknights.piauthenticator.utils.AppConstants.INTENT_FILTER;
import static it.netknights.piauthenticator.utils.AppConstants.NONCE;
import static it.netknights.piauthenticator.utils.AppConstants.NOTIFICATION_ID;
import static it.netknights.piauthenticator.utils.AppConstants.QUESTION;
import static it.netknights.piauthenticator.utils.AppConstants.SERIAL;
import static it.netknights.piauthenticator.utils.AppConstants.SIGNATURE;
import static it.netknights.piauthenticator.utils.AppConstants.SSL_VERIFY;
import static it.netknights.piauthenticator.utils.AppConstants.STATUS_ENDPOINT_SSL_ERROR;
import static it.netknights.piauthenticator.utils.AppConstants.STATUS_ENDPOINT_UNKNOWN_HOST;
import static it.netknights.piauthenticator.utils.AppConstants.TITLE;
import static it.netknights.piauthenticator.utils.AppConstants.URL;
import static it.netknights.piauthenticator.utils.Util.logprint;

public class PushAuthService extends Service implements PushAuthCallbackInterface {

    private PushAuthRequest req;
    private Util util;
    private ArrayList<Token> tokenlist;
    private AsyncTask<Void, Integer, Boolean> pushAuthTask;
    private Token token;
    private Intent reuseIntent;
    private String failureReason;

    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        super.onStartCommand(intent, flags, startId);
        logprint("AuthService started");
        if (intent == null) {
            logprint("intent is null, returning");
            return Service.START_STICKY;
        }

        // Cancel
        if (intent.hasExtra("ACTION")) {
            cancelRunningAuthentication(intent);
            return Service.START_STICKY;
        }

        // Authentication
        reuseIntent = intent;
        int notificationID = intent.getIntExtra(NOTIFICATION_ID, 654321);
        NotificationManagerCompat.from(this).cancel(notificationID);

        String serial = intent.getStringExtra(SERIAL);
        String nonce = intent.getStringExtra(NONCE);
        String title = intent.getStringExtra(TITLE);
        String url = intent.getStringExtra(URL);
        String signature = intent.getStringExtra(SIGNATURE);
        String question = intent.getStringExtra(QUESTION);
        boolean sslVerify = intent.getBooleanExtra(SSL_VERIFY, true);

        token = null;
        PrivateKey appPrivateKey = null;
        PublicKey publicKey = null;
        try {
            SecretKeyWrapper skw = new SecretKeyWrapper(getApplicationContext());
            appPrivateKey = skw.getPrivateKeyFor(serial);
            util = new Util(skw, getApplicationContext().getFilesDir().getAbsolutePath());
            publicKey = util.getPIPubkey(serial);

            // Load the token (App is not necessarily running)
            tokenlist = util.loadTokens();
            for (Token t : tokenlist) {
                if (t.getSerial().equals(serial)) {
                    token = t;
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
        if (appPrivateKey == null) {
            logprint("PushAuthService: appPrivateKey is null, Authentication is not started.");
            return Service.START_NOT_STICKY;    // Restart the Service in case of being killed, but don't redeliver the intent
        }
        if (publicKey == null) {
            logprint("PushAuthService: appPrivateKey is null, Authentication is not started.");
            return Service.START_NOT_STICKY;
        }
        if (token == null) {
            logprint("PushAuthService: Token is null, Authentication is not started.");
            return Service.START_NOT_STICKY;
        }

        // Add the pendingAuth to the token
        req = new PushAuthRequest(nonce, url, serial, question, title, signature, notificationID, sslVerify);
        token.addPushAuthRequest(req);
        saveIfAppNotRunning();

        // start the authentication
        pushAuthTask = new PushAuthTask(token, req, publicKey, appPrivateKey, this);
        pushAuthTask.execute();
        showRunningAuthNotification();
        broadcastAuthenitcationStarted();
        return Service.START_NOT_STICKY;
    }

    private void cancelRunningAuthentication(Intent intent) {
        // Just cancel the running task, the authentication request was saved before starting and can be repeated
        if (pushAuthTask != null) {
            logprint("Cancelling authentication");
            pushAuthTask.cancel(true);
            // Close the notification
            NotificationManagerCompat.from(this).cancel(intent.getIntExtra(NOTIFICATION_ID, 654321));
        }
    }

    private void showRunningAuthNotification() {
        if (!isRunningInBackground()) {
            return;
        }
        // Show a notification that the Authentication is running (in background) and add the possibility to cancel it
        Intent cancel_intent = new Intent(this, PushAuthService.class);
        cancel_intent.putExtra("ACTION", "cancel");
        cancel_intent.putExtra(NOTIFICATION_ID, req.getNotificationID());
        cancel_intent.putExtra(SIGNATURE, req.getSignature());

        PendingIntent pCancel_intent = PendingIntent.getService(this, req.getNotificationID(), cancel_intent, PendingIntent.FLAG_UPDATE_CURRENT);
        NotificationCompat.Action action = new NotificationCompat.Action.Builder(0, "Cancel", pCancel_intent).build();

        NotificationCompat.Builder mBuilder = new NotificationCompat.Builder(this,
                CHANNEL_ID_HIGH_PRIO)                                // Android 8+ uses notification channels
                .setSmallIcon(R.drawable.ic_pi_notification)
                .setContentTitle(getApplicationContext().getString(R.string.PushtokenAuthenticating))
                .setContentText(getString(R.string.NotificationWithToken) + token.getLabel())
                .setPriority(NotificationCompat.PRIORITY_MAX)           // 7.1 and lower
                .addAction(action)                                      // Add the allow Button
                .setAutoCancel(true)                                    // Remove the notification after tabbing it
                .setWhen(0)
                .setContentIntent(pCancel_intent);                      // Intent for opening activity with the request

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            mBuilder.setColor(getResources().getColor(R.color.PIBLUE, null));
        }
        NotificationManagerCompat notificationManager = NotificationManagerCompat.from(this);
        notificationManager.notify(req.getNotificationID(), mBuilder.build());
    }

    @Override
    public void authenticationFinished(boolean success, Token token) {
        broadcastAuthenticationFinished(success);
        if (success) {
            Toast.makeText(getApplicationContext(), R.string.AuthenticationSuccessful, Toast.LENGTH_LONG).show();
            // In case of success, remove the pendingAuth from the token (the one the auth was started with)
            // If the app is running broadcast the result, otherwise edit and save the token here
            //if (isRunningInBackground()) {
            token.getPendingAuths().remove(req);
            if (util != null) {
                util.saveTokens(tokenlist);
            }
            // Close the notification that the authentication is running
            NotificationManagerCompat.from(this).cancel(req.getNotificationID());
            //} else {
            //}
        } else {
            Toast.makeText(getApplicationContext(), R.string.AuthenticationFailed, Toast.LENGTH_LONG).show();
            // If failed save the request so it can be retried from within the app
            saveIfAppNotRunning();

            // TODO rebuild original notification?
            rebuildNotificationWithErrorReason(failureReason);
        }
    }

    /**
     * Build a modified authentication notification including the reason the last authentication did not work.
     *
     * @param reason reason
     */
    private void rebuildNotificationWithErrorReason(String reason) {
        // The reuseIntent is for the Service, so the extras need to be copied to an intent for the Activity
        Intent activity_intent = new Intent(this, MainActivity.class);
        activity_intent.putExtras(reuseIntent);

        int notificationID = reuseIntent.getIntExtra(NOTIFICATION_ID, 654321);
        String title = reuseIntent.getStringExtra(TITLE);
        String question = reuseIntent.getStringExtra(QUESTION);

        // Alter the notification: Title = subtext, Question = title and reason = text
        Notification notification = FCMReceiverService.buildNotificationFromPush(getApplicationContext(),
                notificationID, reuseIntent, activity_intent, question, reason, title,
                getApplicationContext().getString(R.string.retry_authentication));
        if (notification != null) {
            NotificationManagerCompat.from(this).notify(notificationID, notification);
        }
    }

    @Override
    public void handleAuthError(int statusCode, Token token) {
        switch (statusCode) {
            case STATUS_ENDPOINT_UNKNOWN_HOST: {
                // TODO just fail the authentication?
                failureReason = getApplicationContext().getString(R.string.ERR_SERVER_UNREACHABLE);
                authenticationFinished(false, this.token);
                break;
            }
            case STATUS_ENDPOINT_SSL_ERROR: {
                failureReason = getApplicationContext().getString(R.string.SSLHandshakeFailed);
                authenticationFinished(false, this.token);
                break;
            }
            default:
                break;
        }
    }

    private void saveIfAppNotRunning() {
        //if (isRunningInBackground()) {
        if (util != null) {
            util.saveTokens(tokenlist);
        }
        //}
    }

    // Send broadcast in case app is running and the notification button was clicked
    private void broadcastAuthenticationFinished(boolean success) {
        Intent intent = new Intent(INTENT_FILTER);
        // Use notificationID and signature to identify (just has to be removed)
        intent.putExtra(SERIAL, token.getSerial());
        intent.putExtra("finished", req.getNotificationID());
        intent.putExtra("success", success);
        intent.putExtra(SIGNATURE, req.getSignature());
        sendBroadcast(intent);
    }

    private void broadcastAuthenitcationStarted() {
        Intent intent = new Intent(INTENT_FILTER);
        // Use notificationID and signature to identify (just has to be removed)
        intent.putExtra("running", req.getNotificationID());
        intent.putExtra(SERIAL, token.getSerial());
        intent.putExtra(SIGNATURE, req.getSignature());
        sendBroadcast(intent);
    }

    public boolean isRunningInBackground() {
        Context context = getApplicationContext();
        ActivityManager am = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
        List<ActivityManager.RunningAppProcessInfo> runningProcesses = am.getRunningAppProcesses();
        for (ActivityManager.RunningAppProcessInfo processInfo : runningProcesses) {
            if (processInfo.importance == ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND) {
                for (String activeProcess : processInfo.pkgList) {
                    if (activeProcess.equals(context.getPackageName())) {
                        return false;
                    }
                }
            }
        }
        return true;
    }
}
