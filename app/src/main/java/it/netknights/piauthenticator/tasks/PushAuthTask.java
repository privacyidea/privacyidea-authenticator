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

package it.netknights.piauthenticator.tasks;

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

import it.netknights.piauthenticator.interfaces.EndpointCallback;
import it.netknights.piauthenticator.interfaces.PushAuthCallbackInterface;
import it.netknights.piauthenticator.model.Token;
import it.netknights.piauthenticator.utils.Endpoint;
import it.netknights.piauthenticator.utils.Util;
import it.netknights.piauthenticator.model.PushAuthRequest;

import static it.netknights.piauthenticator.utils.AppConstants.NONCE;
import static it.netknights.piauthenticator.utils.AppConstants.PA_AUTHENTICATION_FINISHED;
import static it.netknights.piauthenticator.utils.AppConstants.PA_INVALID_SIGNATURE;
import static it.netknights.piauthenticator.utils.AppConstants.PA_SIGNING_FAILURE;
import static it.netknights.piauthenticator.utils.AppConstants.RESPONSE_RESULT;
import static it.netknights.piauthenticator.utils.AppConstants.RESPONSE_VALUE;
import static it.netknights.piauthenticator.utils.AppConstants.SERIAL;
import static it.netknights.piauthenticator.utils.AppConstants.SIGNATURE;
import static it.netknights.piauthenticator.utils.AppConstants.STATUS_ENDPOINT_UNKNOWN_HOST;
import static it.netknights.piauthenticator.utils.Util.logprint;

public class PushAuthTask extends AsyncTask<Void, Integer, Boolean> implements EndpointCallback {

    private String nonce, endpoint_url, serial, question, title, signature;
    private PublicKey piPublicKey;
    private PrivateKey appPrivateKey;
    private boolean sslVerify;
    private PushAuthCallbackInterface pushAuthCallbackInterface;
    private boolean success;
    private Token token;

    public PushAuthTask(Token token, PushAuthRequest pushAuthRequest,
                        PublicKey piPublicKey, PrivateKey appPrivateKey, PushAuthCallbackInterface pushAuthCallbackInterface) {
        this.nonce = pushAuthRequest.getNonce();
        this.endpoint_url = pushAuthRequest.getUrl();
        this.serial = pushAuthRequest.getSerial();
        this.question = pushAuthRequest.getQuestion();
        this.title = pushAuthRequest.getTitle();
        this.signature = pushAuthRequest.getSignature();
        this.appPrivateKey = appPrivateKey;
        this.piPublicKey = piPublicKey;
        this.sslVerify = pushAuthRequest.isSslVerify();
        this.pushAuthCallbackInterface = pushAuthCallbackInterface;
        this.token = token;
    }

    @Override
    protected void onPreExecute() {
        super.onPreExecute();
        logprint("Push authentication starting...");
    }

    @Override
    protected Boolean doInBackground(Void... voids) {
        // 0. Split data
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

    // Progress from THIS task and statusCodes from Endpoint
    @Override
    protected void onProgressUpdate(Integer... values) {
        super.onProgressUpdate(values);
        int code = values[0];
        switch (code) {
            case PA_INVALID_SIGNATURE:
                break;
            case PA_SIGNING_FAILURE:
                break;
            case PA_AUTHENTICATION_FINISHED:
                if (success) {
                    logprint("authentication successful :)");
                    pushAuthCallbackInterface.authenticationFinished(true, token);
                } else {
                    logprint("authentication failed :(");
                    pushAuthCallbackInterface.authenticationFinished(false, token);
                }
                break;
            default: {
                pushAuthCallbackInterface.handleError(code, token);
                break;
            }
        }
    }

    @Override
    public void updateStatus(int statusCode) {
        // Status Codes from the Endpoint are directed to onProgressUpdate to run on UI Thread
        logprint("Statuscode in PushAuthTask from Endpoint: " + statusCode);
        publishProgress(statusCode);
    }

    // Successful request callback from Endpoint
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