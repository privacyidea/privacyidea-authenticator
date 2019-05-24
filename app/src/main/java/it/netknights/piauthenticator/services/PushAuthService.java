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

import android.app.Service;
import android.content.Intent;
import android.os.AsyncTask;
import android.os.IBinder;
import android.widget.Toast;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.ArrayList;

import androidx.annotation.Nullable;
import androidx.core.app.NotificationManagerCompat;

import it.netknights.piauthenticator.R;
import it.netknights.piauthenticator.interfaces.PushAuthCallbackInterface;
import it.netknights.piauthenticator.model.Token;
import it.netknights.piauthenticator.utils.SecretKeyWrapper;
import it.netknights.piauthenticator.utils.Util;
import it.netknights.piauthenticator.model.PushAuthRequest;
import it.netknights.piauthenticator.tasks.PushAuthTask;

import static it.netknights.piauthenticator.utils.AppConstants.NONCE;
import static it.netknights.piauthenticator.utils.AppConstants.NOTIFICATION_ID;
import static it.netknights.piauthenticator.utils.AppConstants.QUESTION;
import static it.netknights.piauthenticator.utils.AppConstants.SERIAL;
import static it.netknights.piauthenticator.utils.AppConstants.SIGNATURE;
import static it.netknights.piauthenticator.utils.AppConstants.SSL_VERIFY;
import static it.netknights.piauthenticator.utils.AppConstants.TITLE;
import static it.netknights.piauthenticator.utils.AppConstants.URL;
import static it.netknights.piauthenticator.utils.Util.logprint;

public class PushAuthService extends Service implements PushAuthCallbackInterface {

    private PushAuthRequest req;

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
        logprint(intent.getExtras().toString());

        int notificationID = intent.getIntExtra(NOTIFICATION_ID, 654321);
        NotificationManagerCompat.from(this).cancel(notificationID);

        String serial = intent.getStringExtra(SERIAL);
        String nonce = intent.getStringExtra(NONCE);
        String title = intent.getStringExtra(TITLE);
        String url = intent.getStringExtra(URL);
        String signature = intent.getStringExtra(SIGNATURE);
        String question = intent.getStringExtra(QUESTION);
        boolean sslVerify = intent.getBooleanExtra(SSL_VERIFY, true);

        Token token = null;
        PrivateKey appPrivateKey = null;
        PublicKey publicKey = null;
        try {
            SecretKeyWrapper skw = new SecretKeyWrapper(getApplicationContext());
            appPrivateKey = skw.getPrivateKeyFor(serial);
            Util util = new Util(skw, getApplicationContext().getFilesDir().getAbsolutePath());
            publicKey = util.getPIPubkey(serial);

            // Load the token (App is not necessarily running)
            ArrayList<Token> list = util.loadTokens();
            for (Token t : list) {
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
        token.getPendingAuths().add(req);

        // start the authentication
        AsyncTask<Void, Integer, Boolean> pushAuth = new PushAuthTask(token, req, publicKey, appPrivateKey, this);
        pushAuth.execute();
        return Service.START_NOT_STICKY;
    }

    @Override
    public void authenticationFinished(boolean success, Token token) {
        if (success) {
            Toast.makeText(getApplicationContext(), R.string.AuthenticationSuccessful, Toast.LENGTH_SHORT).show();
            // In case of success, remove the pendingAuth from the token (the one the auth was started with)
            token.getPendingAuths().remove(req);
        } else {
            Toast.makeText(getApplicationContext(), R.string.AuthenticationFailed, Toast.LENGTH_SHORT).show();
        }
    }
}
