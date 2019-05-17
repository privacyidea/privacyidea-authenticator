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

package it.netknights.piauthenticator.model;

import java.util.ArrayList;
import java.util.Date;

import static it.netknights.piauthenticator.utils.AppConstants.PUSH;

public class Model {
    private ArrayList<Token> tokens;
    private Token currentSelection;
    private ArrayList<PushAuthRequest> pushAuthRequests;

    public Model() {
        this.tokens = new ArrayList<>();
        this.pushAuthRequests = new ArrayList<>();
    }

    public Model(ArrayList<Token> tokenlist, ArrayList<PushAuthRequest> pushAuthRequests) {
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

    public void setCurrentSelection(int position) {
        if (position == -1) this.currentSelection = null;
        else
            this.currentSelection = tokens.get(position);
    }

    /**
     * Checks for Pushtoken whose rollout time has expired.
     *
     * @return String with the expired tokens serials or null if there are none
     */
    public String checkForExpiredTokens() {
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

    public boolean hasPushToken() {
        for (Token t : tokens) {
            if (t.getType().equals(PUSH)) {
                return true;
            }
        }
        return false;
    }

    public ArrayList<PushAuthRequest> getPushAuthRequests() {
        return pushAuthRequests;
    }

    public Token getCurrentSelection() {
        return currentSelection;
    }

    public ArrayList<Token> getTokens() {
        return tokens;
    }
}
