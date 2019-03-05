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
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;

import static it.netknights.piauthenticator.AppConstants.CONNECT_TIMEOUT;
import static it.netknights.piauthenticator.AppConstants.PA_INVALID_SIGNATURE;
import static it.netknights.piauthenticator.AppConstants.PA_SIGNING_FAILURE;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_MALFORMED_URL;
import static it.netknights.piauthenticator.AppConstants.READ_TIMEOUT;
import static it.netknights.piauthenticator.Util.logprint;

public class PushAuthTask extends AsyncTask<Void, Integer, Boolean> {

    private String nonce, endpoint_url, serial, question, title, signature;
    private PublicKey piPublicKey;
    private PrivateKey appPrivateKey;

    PushAuthTask(PushAuthRequest pushAuthRequest,
                 PublicKey piPublicKey, PrivateKey appPrivateKey) {
        this.nonce = pushAuthRequest.nonce;
        this.endpoint_url = pushAuthRequest.url;
        this.serial = pushAuthRequest.serial;
        this.question = pushAuthRequest.question;
        this.title = pushAuthRequest.title;
        this.signature = pushAuthRequest.signature;
        this.appPrivateKey = appPrivateKey;
        this.piPublicKey = piPublicKey;
    }

    @Override
    protected void onPreExecute() {
        super.onPreExecute();
        logprint("Push authentication starting...");
        logprint("Authentication url:" + endpoint_url);
    }

    @Override
    protected Boolean doInBackground(Void... voids) {
        // 0. Split data
        // TODO convert key-value pairs to the map that was signed in the server
        // TODO how does the payload look like?
        StringBuilder sb = new StringBuilder();
        sb.append(nonce).append("|").append(endpoint_url).append("|").append(serial).append("|").append(question)
                .append("|").append(title);
        String toVerify = sb.toString();

        // 1. Verify the signature

        boolean validSignature = false;
        try {
            validSignature = SecretKeyWrapper.verifySignature(piPublicKey, signature, toVerify);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }

        if (!validSignature) {
            logprint("INVALID SIGNATURE");
            publishProgress(PA_INVALID_SIGNATURE);
            return false;
        }

        // 2. Sign the nonce
        String signature_to_send = null;
        String toSign = nonce + "|" + serial;
        try {
            signature_to_send = SecretKeyWrapper.sign(appPrivateKey, toSign);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }

        if (signature_to_send == null) {
            publishProgress(PA_SIGNING_FAILURE);
            return false;
        }

        // 3. Send the nonce to the server
        logprint("Setting up connection");
        // Connection setup
        URL url;
        try {
            url = new URL(endpoint_url);
        } catch (MalformedURLException e) {
            publishProgress(PRO_STATUS_MALFORMED_URL);
            e.printStackTrace();
            return false;
        }
        HttpURLConnection con;
        try {
            con = (HttpURLConnection) url.openConnection();
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
        logprint("Sending...");
        // Send the pubkey and firebase token
        OutputStream os = null;
        try {
            os = con.getOutputStream();
        } catch (IOException e) {
            e.printStackTrace();
        }
        BufferedWriter writer = null;
        writer = new BufferedWriter(new OutputStreamWriter(os, StandardCharsets.UTF_8));
        logprint("Nonce: " + nonce);
        logprint("Signature: " + signature_to_send);
        logprint("Serial: " + serial);
        try {
            writer.write("nonce=" + nonce);
            writer.write("&serial=" + serial);
            writer.write("&signature=" + signature_to_send);
            writer.flush();
            writer.close();
            os.close();
            con.connect();
        } catch (IOException e) {
            e.printStackTrace();
        }
        logprint("Getting Response...");
        // Get the response
        int responsecode = 0;
        try {
            responsecode = con.getResponseCode();
        } catch (IOException e) {
            e.printStackTrace();
        }
        logprint("responsecode:" + responsecode);

        BufferedReader br = null;
        String line;
        StringBuffer response = new StringBuffer();
        try {
            br = new BufferedReader(new InputStreamReader(con.getInputStream()));
            while ((line = br.readLine()) != null) {
                response.append(line);
            }
            logprint("response: " + response.toString());
            // TODO format response
        } catch (IOException e) {
            e.printStackTrace();
        }

        if (responsecode == 200) {
            if (!response.equals("")) {
                try {
                    JSONObject jso = new JSONObject(response.toString());
                    JSONObject result = jso.getJSONObject("result");
                    boolean success = result.getBoolean("value");
                    if (success)
                        logprint("authentication successful");
                } catch (JSONException e) {
                    e.printStackTrace();
                }
            }
        }
        // TODO other response codes
        con.disconnect();
        return true;
    }

    @Override
    protected void onProgressUpdate(Integer... values) {
        super.onProgressUpdate(values);
    }
}
