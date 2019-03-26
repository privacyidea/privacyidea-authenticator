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

import android.os.AsyncTask;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.Date;

import javax.net.ssl.HttpsURLConnection;

import it.netknights.piauthenticator.Interfaces.PresenterTaskInterface;

import static it.netknights.piauthenticator.AppConstants.CONNECT_TIMEOUT;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_DONE;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_KEY_RECEIVED;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_MALFORMED_JSON;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_MALFORMED_URL;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_REGISTRATION_TIME_EXPIRED;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_RESPONSE_NOT_OK;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_STEP_1;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_STEP_2;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_STEP_3;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_UNKNOWN_HOST;
import static it.netknights.piauthenticator.AppConstants.READ_TIMEOUT;
import static it.netknights.piauthenticator.AppConstants.RESPONSE_DETAIL;
import static it.netknights.piauthenticator.AppConstants.RESPONSE_PUBLIC_KEY;
import static it.netknights.piauthenticator.Util.logprint;

public class PushRolloutTask extends AsyncTask<Void, Integer, Boolean> {

    private String serial;
    private String rollout_url;
    private Token token;
    private PresenterTaskInterface presenterTaskInterface;
    private String in_key;

    PushRolloutTask(Token t, PresenterTaskInterface presenterTaskInterface) {
        this.token = t;
        this.serial = t.getSerial();
        this.rollout_url = t.rollout_url;
        this.presenterTaskInterface = presenterTaskInterface;
    }

    @Override
    protected void onPreExecute() {
        super.onPreExecute();
        logprint("Starting push rollout...");
        logprint("rollout url: " + rollout_url);
    }

    @Override
    protected Boolean doInBackground(Void... voids) {
        publishProgress(PRO_STATUS_STEP_1);
        // Verify the tokens register ttl
        Date now = new Date();
        if (now.after(token.rollout_expiration)) {
            publishProgress(PRO_STATUS_REGISTRATION_TIME_EXPIRED);
            return false;
        }

        // 1. Generate a new keypair (RSA 4096bit), the private key is stored with the serial as alias
        PublicKey pubkey = presenterTaskInterface.generatePublicKeyFor(serial);

        // Get the Firebase token
        String fb_token = presenterTaskInterface.getFirebaseToken();
        logprint("Token: " + fb_token);

        // 2. Send the pubkey and the firebase token to the rollout URL
        publishProgress(PRO_STATUS_STEP_2);

        logprint("Setting up connection");


        // Connection setup
        URL url = null;
        try {
            url = new URL(this.rollout_url);
        } catch (MalformedURLException e) {
            publishProgress(PRO_STATUS_MALFORMED_URL);
            e.printStackTrace();
            return false;
        }
        HttpsURLConnection con;
        try {
            con = (HttpsURLConnection) url.openConnection();
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
        con.setDoOutput(true);
        con.setDoInput(true);
        try {
            con.setRequestMethod("POST");
        } catch (ProtocolException e) {
            e.printStackTrace();
        }
        con.setReadTimeout(READ_TIMEOUT);
        con.setConnectTimeout(CONNECT_TIMEOUT);

        if (!token.sslVerify) {
            con = Util.turnOffSSLVerification(con);
        }
        logprint("Sending...");
        // Send the pubkey and firebase token
        OutputStream os = null;
        try {
            os = con.getOutputStream();
        } catch (IOException e) {
            e.printStackTrace();
            publishProgress(PRO_STATUS_UNKNOWN_HOST);
            return false;
        }

        BufferedWriter writer;
        writer = new BufferedWriter(new OutputStreamWriter(os, StandardCharsets.UTF_8));
        String key = null;
        if (pubkey != null) {
            key = new Util().encodeBase64(pubkey.getEncoded());
        }
        logprint("Enrollment cred: " + token.enrollment_credential);
        logprint("Serial: " + serial);
        logprint("Token: " + fb_token);
        logprint("pubkey: " + key);
        try {
            writer.write("enrollment_credential=" + token.enrollment_credential);
            writer.write("&serial=" + serial);
            writer.write("&fbtoken=" + fb_token);
            writer.write("&pubkey=" + key);
            writer.flush();
            writer.close();
            os.close();
            con.connect();
        } catch (IOException e) {
            e.printStackTrace();
        }

        // 3. Save the pubkey from the response
        publishProgress(PRO_STATUS_STEP_3);
        logprint("Getting response...");
        // Get the response
        int responsecode = 0;
        try {
            responsecode = con.getResponseCode();
        } catch (IOException e) {
            e.printStackTrace();
        }
        logprint("response code: " + responsecode);
        BufferedReader br = null;
        String line;
        StringBuilder response = new StringBuilder();
        try {
            br = new BufferedReader(new InputStreamReader(con.getInputStream()));
            while ((line = br.readLine()) != null) {
                response.append(line);
            }
            logprint("response: " + response.toString());
        } catch (IOException e) {
            e.printStackTrace();
        }

        if (responsecode == 200) {
            if (!response.toString().equals("")) {
                try {
                    JSONObject resp = new JSONObject(response.toString());
                    JSONObject detail = resp.getJSONObject(RESPONSE_DETAIL);
                    in_key = detail.getString(RESPONSE_PUBLIC_KEY);
                    logprint("in_key:" + in_key);
                    publishProgress(PRO_STATUS_DONE);
                    publishProgress(PRO_STATUS_KEY_RECEIVED);
                } catch (JSONException e) {
                    logprint("Malformed JSON in response");
                    publishProgress(PRO_STATUS_MALFORMED_JSON);
                    e.printStackTrace();
                }
            }
        } else {
            publishProgress(PRO_STATUS_RESPONSE_NOT_OK);
        }
        // TODO other response codes
        con.disconnect();
        return true;
    }

    @Override
    protected void onProgressUpdate(Integer... values) {
        super.onProgressUpdate(values);
        // Pass the statusCode to the presenter. This must be done via this method
        // because onProgressUpdate runs on the main thread.
        if (values[0] == PRO_STATUS_KEY_RECEIVED) {
            presenterTaskInterface.receivePublicKey(in_key, token);
        } else {
            presenterTaskInterface.updateTaskStatus(values[0], token);
        }
    }

    @Override
    protected void onPostExecute(Boolean aBoolean) {
        super.onPostExecute(aBoolean);
    }
}
