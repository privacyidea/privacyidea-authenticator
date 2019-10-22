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

import android.content.DialogInterface;

import java.security.PublicKey;

import it.netknights.piauthenticator.model.FirebaseInitConfig;
import it.netknights.piauthenticator.model.Token;
import it.netknights.piauthenticator.utils.SecretKeyWrapper;

public interface MainActivityInterface {
    void makeAlertDialog(String title, String message, String positiveBtnText, boolean cancelable,
                         DialogInterface.OnClickListener positiveBtnListener);

    void makeAlertDialog(int titleID, int messageID, int positiveBtnTextID, boolean cancelable,
                         DialogInterface.OnClickListener positiveBtnListener);

    void makeAlertDialog(String title, String message);

    void makeAlertDialog(int titleID, String message);

    void makeAlertDialog(int titleID, int messageID);

    void makeDeviceNotSupportedDialog();

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

    void cancelNotification(int notificationID);
}
