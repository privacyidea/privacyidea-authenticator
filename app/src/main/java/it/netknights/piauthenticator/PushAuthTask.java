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

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.LinkedHashMap;
import java.util.Map;

import static it.netknights.piauthenticator.AppConstants.NONCE;
import static it.netknights.piauthenticator.AppConstants.PA_AUTHENTICATION_FINISHED;
import static it.netknights.piauthenticator.AppConstants.PA_INVALID_SIGNATURE;
import static it.netknights.piauthenticator.AppConstants.PA_SIGNING_FAILURE;
import static it.netknights.piauthenticator.AppConstants.RESPONSE_RESULT;
import static it.netknights.piauthenticator.AppConstants.RESPONSE_VALUE;
import static it.netknights.piauthenticator.AppConstants.SERIAL;
import static it.netknights.piauthenticator.AppConstants.SIGNATURE;
import static it.netknights.piauthenticator.Util.logprint;

public class PushAuthTask extends AsyncTask<Void, Integer, Boolean> implements Interfaces.EndpointCallback {

    private String nonce, endpoint_url, serial, question, title, signature;
    private PublicKey piPublicKey;
    private PrivateKey appPrivateKey;
    private boolean sslVerify;
    private Interfaces.PushAuthCallbackInterface pushAuthCallbackInterface;
    private boolean success;

    PushAuthTask(PushAuthRequest pushAuthRequest,
                 PublicKey piPublicKey, PrivateKey appPrivateKey, Interfaces.PushAuthCallbackInterface pushAuthCallbackInterface) {
        this.nonce = pushAuthRequest.nonce;
        this.endpoint_url = pushAuthRequest.url;
        this.serial = pushAuthRequest.serial;
        this.question = pushAuthRequest.question;
        this.title = pushAuthRequest.title;
        this.signature = pushAuthRequest.signature;
        this.appPrivateKey = appPrivateKey;
        this.piPublicKey = piPublicKey;
        this.sslVerify = pushAuthRequest.sslVerify;
        this.pushAuthCallbackInterface = pushAuthCallbackInterface;
    }

    @Override
    protected void onPreExecute() {
        super.onPreExecute();
        logprint("Push authentication starting...");
    }

    @Override
    protected Boolean doInBackground(Void... voids) {
        // 0. Split data
        // TODO convert key-value pairs to the map that was signed in the server
        // TODO how does the payload look like?
        String strSSLVerify = sslVerify ? "1" : "0";

        String toVerify = nonce + "|" + endpoint_url + "|" + serial + "|" + question +
                "|" + title + "|" + strSSLVerify;

        // 1. Verify the signature
        boolean validSignature = false;
        try {
            validSignature = Util.verifySignature(piPublicKey, signature, toVerify);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }

        if (!validSignature) {
            logprint("Signature invalid.");
            publishProgress(PA_INVALID_SIGNATURE);
            return false;
        } else {
            logprint("Signature valid.");
        }

        // 2. Sign the nonce
        String signature_to_send = null;
        String toSign = nonce + "|" + serial;
        try {
            signature_to_send = Util.sign(appPrivateKey, toSign);
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

        // 3. Assemble the data and send it to the endpoint
        Map<String, String> map = new LinkedHashMap<>();
        map.put(NONCE, nonce);
        map.put(SERIAL, serial);
        map.put(SIGNATURE, signature_to_send);

        Endpoint endpoint = new Endpoint(sslVerify, endpoint_url, map, this);
        endpoint.connect();
        return true;
    }

    @Override
    protected void onProgressUpdate(Integer... values) {
        super.onProgressUpdate(values);

        switch (values[0]) {
            case PA_INVALID_SIGNATURE:
                break;
            case PA_SIGNING_FAILURE:
                break;
            case PA_AUTHENTICATION_FINISHED:
                if (success) {
                    logprint("authentication successful :)");
                    pushAuthCallbackInterface.authenticationFinished(true);
                } else {
                    logprint("authentication failed :(");
                    pushAuthCallbackInterface.authenticationFinished(false);
                }
            default:
                break;
        }

    }

    @Override
    public void updateStatus(int statusCode) {

    }

    @Override
    public void responseReceived(String response, int responseCode) {
        if (responseCode == 200) {
            if (!response.equals("")) {
                try {
                    JSONObject jso = new JSONObject(response);
                    JSONObject result = jso.getJSONObject(RESPONSE_RESULT);
                    success = result.getBoolean(RESPONSE_VALUE);
                    publishProgress(PA_AUTHENTICATION_FINISHED);
                } catch (JSONException e) {
                    e.printStackTrace();
                }
            }
        }
    }
}
