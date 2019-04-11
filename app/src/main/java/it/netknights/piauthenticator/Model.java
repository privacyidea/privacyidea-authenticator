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

import java.util.ArrayList;
import java.util.Date;

import static it.netknights.piauthenticator.AppConstants.PUSH;

class Model {
    ArrayList<Token> tokens;
    ArrayList<PushAuthRequest> pushAuthRequests;
    Token currentSelection;

    Model() {
        this.tokens = new ArrayList<>();
        this.pushAuthRequests = new ArrayList<>();
    }

    Model(ArrayList<Token> tokenlist, ArrayList<PushAuthRequest> pushAuthRequests) {
        if (tokenlist == null) {
            this.tokens = new ArrayList<>();
        } else {
            this.tokens = tokenlist;
        }
        if (pushAuthRequests == null) {
            this.pushAuthRequests = new ArrayList<>();
        } else {
            this.pushAuthRequests = pushAuthRequests;
        }
    }

    void setCurrentSelection(int position) {
        if (position == -1) this.currentSelection = null;
        else
            this.currentSelection = tokens.get(position);
    }

    /**
     * Checks for Pushtoken whose rollout time has expired.
     *
     * @return String with the expired tokens serials or null if there are none
     */
    String checkForExpiredTokens() {
        ArrayList<Token> upForDeletion = new ArrayList<>();
        Date now = new Date();
        for (Token t : tokens) {
            if (t.getType().equals(PUSH)) {
                if (!t.rollout_finished && t.rollout_expiration.before(now)) {
                    upForDeletion.add(t);
                }
            }
        }

        if (!upForDeletion.isEmpty()) {
            StringBuilder sb = new StringBuilder();
            for (Token t : upForDeletion) {
                sb.append(t.getSerial()).append("\n");
                tokens.remove(t);
            }
            return sb.toString();
        } else {
            return null;
        }
    }

    boolean hasPushToken() {
        for (Token t:tokens) {
            if(t.getType().equals(PUSH)){
                return true;
            }
        }
        return false;
    }
}

class FirebaseInitConfig {
    String projID;
    String appID;
    String api_key;
    String projNumber;

    FirebaseInitConfig(String projID, String appID, String api_key, String projNumber) {
        this.projID = projID;
        this.appID = appID;
        this.api_key = api_key;
        this.projNumber = projNumber;
    }
}

class PushAuthRequest {
    String nonce, url, serial, question, title, signature;
    boolean sslVerify;

    PushAuthRequest(String nonce, String url, String serial, String question, String title, String signature, boolean sslVerify) {
        this.nonce = nonce;
        this.url = url;
        this.serial = serial;
        this.question = question;
        this.title = title;
        this.signature = signature;
        this.sslVerify = sslVerify;
    }
}

class ScanResult {
    // BASE
    String type, serial, label;

    // NORMAL TOKEN
    String secret, algorithm = "sha1";              // Default
    int digits = 6, period = 30, counter = 1;       // Defaults
    boolean pin = false, persistent = false, taptoshow = false;

    // TWO STEP TOKEN (addition)
    boolean do2Step = false;
    int phonepartlength = 10;                       // in bytes
    int iterations = 10000;
    int output_size = 160;                          // in bits

    // PUSH TOKEN
    String rollout_url, enrollment_credential;
    int ttl = 10;                                   // 10 Minutes is the default
    FirebaseInitConfig firebaseInitConfig;
    int push_version = 1;
    boolean sslverify = true;

    ScanResult(String type, String serial) {
        this.type = type;
        this.serial = serial;
    }
}
