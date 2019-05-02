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

import java.security.PublicKey;
import java.util.Map;

class Interfaces {

    interface TokenListViewInterface {
        void updateProgressbars(int progress);

        void notifyChange();

        void removeProgressbar(int position);
    }

    interface MainActivityInterface {
        void makeAlertDialog(String title, String message);

        void makeAlertDialog(int titleID, String message);

        void makeAlertDialog(int titleID, int messageID);

        void makeToast(String message);

        void makeToast(int resID);

        void setStatusDialogText(String text);

        void setStatusDialogText(int id);

        void cancelStatusDialog();

        void getFirebaseTokenForPushRollout(Token token);

        void firebaseInit(FirebaseInitConfig firebaseInitConfig);

        void removeFirebase();

        void startTimer();

        void stopTimer();

        void resumeTimer();

        SecretKeyWrapper getWrapper();

        PublicKey generatePublicKeyFor(String alias);

        String getStringResource(int id);
    }

    interface PresenterInterface {
        void init();

        void scanQRfinished(ScanResult result);

        void addTokenFromIntent(String type, byte[] secret, String serial, int digits, String algorithm, String period, boolean withPIN);

        void addPushAuthRequest(PushAuthRequest request);

        void onResume();

        void onPause();

        void onStop();

        void setCurrentSelection(int position);

        void saveTokenlist();

        boolean isCurrentSelectionWithPin();

        boolean isCurrentSelectionPersistent();

        boolean isCurrentSelectionLocked();

        void removeCurrentSelection();

        String getCurrentSelectionLabel();

        String getCurrentSelectionOTP();

        Token getCurrentSelection();

        void setCurrentSelectionLabel(String label);

        void changeCurrentSelectionPIN(int pin);

        Token getTokenAtPosition(int position);

        int getTokenCount();

        void addTokenAt(int position, Token token);

        void addToken(Token token);

        Token removeTokenAtPosition(int position);

        Map<String, String> getPushAuthRequestInfo(Token token);

        void startPushAuthForPosition(int position);

        void startPushRolloutForPosition(int position);

        void increaseHOTPCounter(Token token);

        boolean checkPIN(String input, Token token);

        void setPIN(String input, Token token);

        void timerProgress(int progress);

        void firebaseTokenReceived(String fbtoken, Token token);
    }

    interface PresenterTaskInterface {
        void updateTaskStatus(int statusCode, Token token);

        void makeAlertDialog(String title, String message);

        PublicKey generatePublicKeyFor(String serial);

        void receivePublicKey(String key, Token token);
    }

    interface PresenterUtilInterface {
        SecretKeyWrapper getWrapper();
    }

    interface EndpointCallback {
        void updateStatus(int statusCode);
        void responseReceived(String response, int responseCode);
    }

    interface PushAuthCallbackInterface {
        void authenticationFinished(boolean success);
    }
}
