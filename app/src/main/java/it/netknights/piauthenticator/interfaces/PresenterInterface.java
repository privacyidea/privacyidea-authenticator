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

package it.netknights.piauthenticator.interfaces;

import it.netknights.piauthenticator.model.PushAuthRequest;
import it.netknights.piauthenticator.model.ScanResult;
import it.netknights.piauthenticator.model.Token;

public interface PresenterInterface {
    /**
     * Initialization which is called directly after instantiation in OnCreate of the Activity.
     */
    void init();

    void scanQRfinished(ScanResult result);

    void addTokenFromIntent(String type, byte[] secret, String serial, int digits, String algorithm, String period, boolean withPIN);

    void cancelAuthentication(Token token);

    /**
     * Add a Push Authentication Request to the corresponding Token.
     * Finds the token by serial and includes a check for duplicates.
     *
     * @param request request that should be added
     */
    void addPushAuthRequest(PushAuthRequest request);

    /**
     * Passing the Lifecycle event, so the presenter can act on it.
     */
    void onResume();

    /**
     * Passing the Lifecycle event, so the presenter can act on it.
     */
    void onPause();

    /**
     * Passing the Lifecycle event, so the presenter can act on it.
     */
    void onStop();

    /**
     * Set the currently selected token to the given position in the list. Actions selected in ActionMode will be done with this token.
     *
     * @param position index position in the list
     */
    void setCurrentSelection(int position);

    void saveTokenlist();

    boolean isCurrentSelectionWithPin();

    boolean isCurrentSelectionPersistent();

    boolean isCurrentSelectionLocked();

    void removeCurrentSelection();

    void removeCurrentAuthRequest(Token token);

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

    void startPushAuthentication(Token token);

    void startPushRolloutForPosition(int position);

    void increaseHOTPCounter(Token token);

    boolean checkPIN(String input, Token token);

    void setPIN(String input, Token token);

    void timerProgress(int progress);

    void firebaseTokenReceived(String fbtoken, Token token);

    /**
     * Remove the Push Authentication Request, because it was finished by the Service while the App was running.
     * The Request is identified by the notificationID and signature.
     *
     * @param notificationID the ID of the notification
     * @param signature      the signature of the Request
     */
    void pushAuthFinishedFor(String serial, int notificationID, String signature, boolean success);

    /**
     * Indicates that a broadcast from the PushAuthService was received to change the state of a token to "authenticating" and updating the UI
     *
     * @param serial         serial of the token
     * @param notificationID notificationID of the notification
     * @param signature      signature of the PushAuthRequest
     */
    void pushAuthStartedFor(String serial, int notificationID, String signature);
}