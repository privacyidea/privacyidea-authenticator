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

package it.netknights.piauthenticator;

import android.app.Service;
import android.content.Intent;
import android.os.AsyncTask;
import android.os.IBinder;
import android.support.annotation.Nullable;
import android.support.v4.app.NotificationManagerCompat;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import static it.netknights.piauthenticator.AppConstants.AUTHENTICATION_URL;
import static it.netknights.piauthenticator.AppConstants.NONCE;
import static it.netknights.piauthenticator.AppConstants.NOTIFICATION_ID;
import static it.netknights.piauthenticator.AppConstants.QUESTION;
import static it.netknights.piauthenticator.AppConstants.SERIAL;
import static it.netknights.piauthenticator.AppConstants.SIGNATURE;
import static it.netknights.piauthenticator.AppConstants.SSL_VERIFY;
import static it.netknights.piauthenticator.AppConstants.TITLE;
import static it.netknights.piauthenticator.Util.logprint;

public class PushAuthService extends Service {
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
        NotificationManagerCompat.from(this).cancel(NOTIFICATION_ID);
        String serial = intent.getStringExtra(SERIAL);
        String nonce = intent.getStringExtra(NONCE);
        String title = intent.getStringExtra(TITLE);
        String url = intent.getStringExtra(AUTHENTICATION_URL);
        String signature = intent.getStringExtra(SIGNATURE);
        String question = intent.getStringExtra(QUESTION);
        boolean sslVerify = intent.getBooleanExtra(SSL_VERIFY, true);
        PrivateKey appPrivateKey = null;
        try {
            appPrivateKey = new SecretKeyWrapper(getApplicationContext()).getPrivateKeyFor(serial);
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
            return Service.START_STICKY;    // Restart the Service in case of being killed, but don't redeliver the intent
        }
        Util util = new Util();
        AsyncTask<Void, Integer, Boolean> pushAuth = new PushAuthTask(
                new PushAuthRequest(nonce, url, serial, question, title, signature, sslVerify),
                util.getPIPubkey(getBaseContext().getFilesDir().getAbsolutePath(), serial), appPrivateKey);
        pushAuth.execute();
        //return Service.START_REDELIVER_INTENT;
        return Service.START_STICKY;
    }
}
