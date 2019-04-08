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

import java.security.PublicKey;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

import it.netknights.piauthenticator.Interfaces.PresenterTaskInterface;

import static it.netknights.piauthenticator.AppConstants.ENROLLMENT_CRED;
import static it.netknights.piauthenticator.AppConstants.FB_TOKEN;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_DONE;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_KEY_RECEIVED;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_MALFORMED_JSON;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_REGISTRATION_TIME_EXPIRED;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_RESPONSE_NOT_OK;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_STEP_1;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_STEP_2;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_STEP_3;
import static it.netknights.piauthenticator.AppConstants.PUBKEY;
import static it.netknights.piauthenticator.AppConstants.RESPONSE_DETAIL;
import static it.netknights.piauthenticator.AppConstants.RESPONSE_PUBLIC_KEY;
import static it.netknights.piauthenticator.AppConstants.SERIAL;
import static it.netknights.piauthenticator.AppConstants.STATUS_ENDPOINT_ERROR;
import static it.netknights.piauthenticator.AppConstants.STATUS_ENDPOINT_MALFORMED_URL;
import static it.netknights.piauthenticator.AppConstants.STATUS_ENDPOINT_SENDING_COMPLETE;
import static it.netknights.piauthenticator.AppConstants.STATUS_ENDPOINT_UNKNOWN_HOST;
import static it.netknights.piauthenticator.Util.logprint;

public class PushRolloutTask extends AsyncTask<Void, Integer, Boolean> implements Interfaces.EndpointCallback {

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

        String key = null;
        if (pubkey != null) {
            key = new Util().encodeBase64(pubkey.getEncoded());
        }

        // assemble the data to send
        Map<String, String> map = new LinkedHashMap<>();
        map.put(ENROLLMENT_CRED, token.enrollment_credential);
        map.put(SERIAL, token.getSerial());
        map.put(FB_TOKEN, fb_token);
        if (key == null) return false;
        map.put(PUBKEY, key);

        Endpoint endpoint = new Endpoint(token.sslVerify, token.rollout_url, map, this);
        endpoint.connect();
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


    @Override
    public void updateStatus(int statusCode) {
        switch (statusCode) {
            case STATUS_ENDPOINT_SENDING_COMPLETE:
                publishProgress(PRO_STATUS_STEP_3);
                break;
            case STATUS_ENDPOINT_MALFORMED_URL:
                publishProgress(STATUS_ENDPOINT_MALFORMED_URL);
                break;
            case STATUS_ENDPOINT_UNKNOWN_HOST:
                publishProgress(STATUS_ENDPOINT_UNKNOWN_HOST);
                break;
            case STATUS_ENDPOINT_ERROR:
                publishProgress(STATUS_ENDPOINT_ERROR);
                break;
            default:
                break;
        }
    }

    @Override
    public void responseReceived(String response, int responseCode) {
        // Parsing the JSON here
        if (responseCode == 200) {
            if (!response.equals("")) {
                try {
                    JSONObject resp = new JSONObject(response);
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
            logprint("response not ok");
            publishProgress(PRO_STATUS_RESPONSE_NOT_OK);
        }
    }
}
