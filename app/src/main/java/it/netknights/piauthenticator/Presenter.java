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

import android.content.Context;
import android.content.Intent;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.Handler;
import android.widget.Toast;

import org.json.JSONObject;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;

import static it.netknights.piauthenticator.AppConstants.ALGORITHM;
import static it.netknights.piauthenticator.AppConstants.API_KEY;
import static it.netknights.piauthenticator.AppConstants.APP_ID;
import static it.netknights.piauthenticator.AppConstants.DIGITS;
import static it.netknights.piauthenticator.AppConstants.FB_CONFIG_FILE;
import static it.netknights.piauthenticator.AppConstants.KEYFILE;
import static it.netknights.piauthenticator.AppConstants.LABEL;
import static it.netknights.piauthenticator.AppConstants.PERIOD;
import static it.netknights.piauthenticator.AppConstants.PROJECT_ID;
import static it.netknights.piauthenticator.AppConstants.PROJECT_NUMBER;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_BAD_BASE64;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_DONE;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_MALFORMED_JSON;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_MALFORMED_URL;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_REGISTRATION_TIME_EXPIRED;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_RESPONSE_NO_KEY;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_STEP_1;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_STEP_2;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_STEP_3;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_UNKNOWN_HOST;
import static it.netknights.piauthenticator.AppConstants.PUSH;
import static it.netknights.piauthenticator.AppConstants.QUESTION;
import static it.netknights.piauthenticator.AppConstants.SECRET;
import static it.netknights.piauthenticator.AppConstants.STATUS_INIT_FIREBASE;
import static it.netknights.piauthenticator.AppConstants.STATUS_INIT_FIREBASE_DONE;
import static it.netknights.piauthenticator.AppConstants.STATUS_STANDARD_ROLLOUT_DONE;
import static it.netknights.piauthenticator.AppConstants.STATUS_TWO_STEP_ROLLOUT;
import static it.netknights.piauthenticator.AppConstants.STATUS_TWO_STEP_ROLLOUT_DONE;
import static it.netknights.piauthenticator.AppConstants.TITLE;
import static it.netknights.piauthenticator.AppConstants.TOTP;
import static it.netknights.piauthenticator.AppConstants.TYPE;
import static it.netknights.piauthenticator.AppConstants.WITHPIN;
import static it.netknights.piauthenticator.Interfaces.*;
import static it.netknights.piauthenticator.OTPGenerator.generate;
import static it.netknights.piauthenticator.OTPGenerator.hashPIN;
import static it.netknights.piauthenticator.Util.logprint;
import static it.netknights.piauthenticator.Util.readFile;

public class Presenter implements PresenterInterface, PresenterTaskInterface, PresenterUtilInterface {

    private TokenListViewInterface tokenListInterface;
    private MainActivityInterface mainActivityInterface;
    private Handler handler;
    private Runnable timer;
    private Model model;
    private Util util;

    @Override
    public void init() {
        // Logic of onCreate
        util = new Util(this);
        model = new Model(Util.loadTokens(mainActivityInterface.getContext()));

        initFirebase();
        startTimerThread();
        refreshOTPs();

        String expired = model.checkForExpiredTokens();
        if (expired != null) {
            mainActivityInterface.makeAlertDialog("Token expired!", expired);
        }
    }

    @Override
    public void scanQRfinished(String result) {
        AsyncTask<String, Integer, Boolean> tokenCreation = new TokenCreationTask(this);
        tokenCreation.execute(result);
    }

    @Override
    public void addTokenFromBundle(Intent data) {
        // Push tokens cannot be created manually so this is simplified
        String type = data.getStringExtra(TYPE);
        // Secret decoding is done in EnterDetailActivity
        byte[] secret = data.getByteArrayExtra(SECRET);
        String label = data.getStringExtra(LABEL);
        int digits = data.getIntExtra(DIGITS, 6);
        String algorithm = data.getStringExtra(ALGORITHM);
        Token tmp = new Token(secret, label, label, type, digits);

        if (type.equals(TOTP)) {
            int period = data.getIntExtra(PERIOD, 30);
            tmp.setPeriod(period);
        }
        if (algorithm != null) {
            tmp.setAlgorithm(algorithm);
        }
        if (data.getBooleanExtra(WITHPIN, false)) {
            tmp.setWithPIN(true);
        }
        tmp.setCurrentOTP(generate(tmp));
        model.tokens.add(tmp);
        saveTokenlist();
        tokenListInterface.notifyChange();
        mainActivityInterface.makeToast("Token added:" + label);
    }

    @Override
    public void addPushAuthRequest(String nonce, String url, String serial, String question, String title, String signature) {
        model.pushAuthRequests.add(new PushAuthRequest(nonce, url, serial, question, title, signature));
    }

    @Override
    public void onResume() {
        refreshAllTOTP();
        handler.post(timer);
    }

    @Override
    public void onPause() {
        handler.removeCallbacks(timer);
    }

    @Override
    public void onStop() {
        saveTokenlist();
    }

    @Override
    public void printKeystore() {
        try {
            SecretKeyWrapper.printKeystore();
            this.util.printPubkeys(model.tokens);
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void saveTokenlist() {

    }

    @Override
    public void setCurrentSelection(int position) {
        model.setCurrentSelection(position);
    }

    @Override
    public boolean isCurrentSelectionWithPin() {
        if (model.currentSelection == null) return false;
        return model.currentSelection.isWithPIN();
    }

    @Override
    public boolean isCurrentSelectionPersistent() {
        if (model.currentSelection == null) return false;
        return model.currentSelection.isPersistent();
    }

    @Override
    public boolean isCurrentSelectionLocked() {
        if (model.currentSelection == null) return false;
        return model.currentSelection.isLocked();
    }

    @Override
    public void removeCurrentSelection() {
        // callback from ActionMode delete
        if (model.currentSelection == null) return;
        this.removeToken(model.currentSelection);
    }

    @Override
    public String getCurrentSelectionLabel() {
        if (model.currentSelection == null) return null;
        return model.currentSelection.getLabel();
    }

    @Override
    public String getCurrentSelectionOTP() {
        if (model.currentSelection == null) return null;
        return model.currentSelection.getCurrentOTP();
    }

    @Override
    public Token getCurrentSelection() {
        return model.currentSelection;
    }

    @Override
    public void setCurrentSelectionLabel(String label) {
        if (model.currentSelection == null) return;
        model.currentSelection.setLabel(label);
    }

    @Override
    public void changeCurrentSelectionPIN(int pin) {
        if (model.currentSelection == null) return;
        String hashedPIN = OTPGenerator.hashPIN(pin, model.currentSelection);
        model.currentSelection.setPin(hashedPIN);
        tokenListInterface.notifyChange();
        saveTokenlist();
    }

    @Override
    public Token getTokenAtPosition(int position) {
        return model.tokens.get(position);
    }

    @Override
    public int getTokenCount() {
        if (model.tokens == null) return 0;
        return model.tokens.size();
    }

    @Override
    public void addTokenAt(int position, Token token) {
        model.tokens.add(position, token);
    }

    @Override
    public Token removeTokenAtPosition(int position) {
        return model.tokens.remove(position);
    }

    /**
     * Check if a token has pending PushAuthRequests
     *
     * @param position position to check for
     * @return Map with keys "title" and "message" if there is a PushAuthRequest, null if there is none
     */
    @Override
    public Map<String, String> getPushAuthRequestInfo(int position) {
        Token t = model.tokens.get(position);
        if (!t.getType().equals(PUSH)) return null;

        String t_serial = t.getSerial();
        for (PushAuthRequest req : model.pushAuthRequests) {
            if (req.serial.equals(t_serial)) {
                Map<String, String> map = new HashMap<>();
                map.put(TITLE, req.title);
                map.put(QUESTION, req.question);
                return map;
            }
        }
        return null;
    }

    @Override
    public void startPushAuthForPosition(int position) {
        // onclick from token in list
        Token t = model.tokens.get(position);
        if (!t.getType().equals(PUSH)) return;
        PushAuthRequest req = null;
        String t_serial = t.getSerial();
        for (PushAuthRequest request : model.pushAuthRequests) {
            if (request.serial.equals(t_serial)) {
                req = request;
            }
        }
        if (req == null) return; // none found
        try {
            PrivateKey appPrivateKey = SecretKeyWrapper.getPrivateKeyFor(t_serial);
            PublicKey piPublicKey = Util.getPIPubkey(mainActivityInterface.getContext(), req.serial);
            if (appPrivateKey != null && piPublicKey != null) {
                new PushAuthTask(req, piPublicKey, appPrivateKey).execute();
                model.pushAuthRequests.remove(req);
                tokenListInterface.notifyChange();
            }
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void startPushRolloutForPosition(int position) {
        AsyncTask<Void, Integer, Boolean> pushrollout = new PushRolloutTask(model.tokens.get(position), this);
        pushrollout.execute();
    }

    @Override
    public void increaseHOTPCounter(Token token) {
        token.setCounter((token.getCounter() + 1));
        token.setCurrentOTP(OTPGenerator.generate(token));
        tokenListInterface.notifyChange();
    }

    @Override
    public boolean checkPIN(String input, Token token) {
        return hashPIN(Integer.parseInt(input), token).equals(token.getPin());
    }

    @Override
    public void setPIN(String input, Token token) {
        token.setPin(hashPIN(Integer.parseInt(input), token));
        token.setLocked(false);
        tokenListInterface.notifyChange();
    }

    private void startTimerThread() {
        handler = new Handler();
        timer = new Runnable() {
            @Override
            public void run() {
                int progress = (int) (System.currentTimeMillis() / 1000) % 60;
                tokenListInterface.updateProgressbars(progress);
                // refresh OTP values only around the periods
                if (progress < 3 || progress > 27 && progress < 33 || progress > 57) {
                    refreshAllTOTP();
                }
                handler.postDelayed(this, 1000);
            }
        };
        handler.post(timer);
        handler.removeCallbacks(timer);
    }

    /**
     * Remove a token from the list. This includes Pub/Priv Keys for Pushtoken
     *
     * @param currToken the token to remove
     */
    private void removeToken(Token currToken) {
        if (currToken.getType().equals(PUSH)) {
            util.removePubkeyFor(currToken.getSerial());
            try {
                SecretKeyWrapper.removePrivateKeyFor(currToken.getSerial());
            } catch (CertificateException | NoSuchAlgorithmException | KeyStoreException | IOException e) {
                e.printStackTrace();
            }
        }
        int position = model.tokens.indexOf(currToken);
        tokenListInterface.removeProgressbar(position);

        if (model.tokens.size() >= position && position >= 0 && !model.tokens.isEmpty()) {
            model.tokens.remove(position);
        }
        tokenListInterface.notifyChange();
        mainActivityInterface.makeToast(R.string.toast_token_removed);
        saveTokenlist();
    }

    private void refreshOTPs() {
        for (int i = 0; i < model.tokens.size(); i++) {
            if (!model.tokens.get(i).getType().equals(PUSH)) {
                model.tokens.get(i).setCurrentOTP(OTPGenerator.generate(model.tokens.get(i)));
            }
        }
        tokenListInterface.notifyChange();
    }

    private void refreshAllTOTP() {
        for (int i = 0; i < model.tokens.size(); i++) {
            if (model.tokens.get(i).getType().equals(TOTP)) {
                model.tokens.get(i).setCurrentOTP(OTPGenerator.generate(model.tokens.get(i)));
            }
        }
        tokenListInterface.notifyChange();
    }

    void setMainActivityInterface(MainActivityInterface mainActivityInterface) {
        this.mainActivityInterface = mainActivityInterface;
    }

    void setTokenListInterface(TokenListViewInterface tokenListInterface) {
        this.tokenListInterface = tokenListInterface;
    }

    @Override
    public Context getContext() {
        return mainActivityInterface.getContext();
    }

    @Override
    public void doTwoStepRollout(Token token, int phonepartlength, int iterations, int output_size) {
        new TwoStepRolloutTask(token, phonepartlength, iterations, output_size, this).execute();
    }

    @Override
    public void doFirebaseInit(FirebaseInitConfig firebaseInitConfig) {
        util.storeFirebaseConfig(firebaseInitConfig);
        new FirebaseInitTask(firebaseInitConfig, this).execute();
    }

    @Override
    public void doPushRollout(Token token) {
        new PushRolloutTask(token, this).execute();
    }

    private void rolloutFinished(Token token) {
        if (token == null) return;
        if (!token.getType().equals(PUSH)) {
            token.setCurrentOTP(generate(token));
        }
        model.tokens.add(token);
        tokenListInterface.notifyChange();
    }

    @Override
    public String getFirebaseToken() {
        return mainActivityInterface.getFirebaseToken();
    }

    @Override
    public PublicKey generatePublicKeyFor(String serial) {
        PublicKey pubkey = null;
        try {
            pubkey = SecretKeyWrapper.generateKeyPair(serial, getContext());
        } catch (KeyStoreException | UnrecoverableEntryException | InvalidAlgorithmParameterException | NoSuchProviderException
                | IOException | NoSuchAlgorithmException |
                CertificateException e) {
            e.printStackTrace();
        }
        if (pubkey == null) {
            logprint("Generated PublicKey for " + serial + " is null.");
        }
        return pubkey;
    }

    /**
     * Store the received key with the serial as alias. If there is an error when storing the key,
     * the rollout will be marked as unfinished and can be repeated.
     *
     * @param key   the received key as raw String
     * @param token token to save the key for
     */
    @Override
    public void receivePublicKey(String key, Token token) {
        try {
            Util.storePIPubkey(key, token.getSerial(), getContext());
        } catch (GeneralSecurityException e) {
            // TODO response is not a key -> callback error
            // this means the "key" field was empty or the DECODED data is not a key
            updateTaskStatus(PRO_STATUS_RESPONSE_NO_KEY, token);
            token.rollout_finished = false;
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (IllegalArgumentException e) {
            logprint("BAD BASE64");
            e.printStackTrace();
            updateTaskStatus(PRO_STATUS_BAD_BASE64, token);
        }
    }

    private void initFirebase() {
        FirebaseInitConfig firebaseInitConfig = util.loadFirebaseConfig();
        if (firebaseInitConfig == null) return;
        new FirebaseInitTask(firebaseInitConfig, this).execute();
    }

    /**
     * Updates the UI according to the statusCode. This includes opening/closing dialogs and chosing the dialog type.
     *
     * @param statusCode statusCode
     */
    @Override
    public void updateTaskStatus(int statusCode, Token token) {
        switch (statusCode) {
            //----------- STANDARD ROLLOUT -----------
            case STATUS_STANDARD_ROLLOUT_DONE:
                rolloutFinished(token);
                break;
            //----------- INIT FIREBASE -----------
            case STATUS_INIT_FIREBASE:
                mainActivityInterface.setStatusDialogText(getContext().getString(R.string.InitFirebaseStatus));
                break;
            case STATUS_INIT_FIREBASE_DONE:
                mainActivityInterface.cancelStatusDialog();
                break;
            //----------- TWO STEP ROLLOUT -----------
            case STATUS_TWO_STEP_ROLLOUT:
                mainActivityInterface.setStatusDialogText("Please wait while the secret is generated.");
                break;
            case STATUS_TWO_STEP_ROLLOUT_DONE:
                rolloutFinished(token);
                mainActivityInterface.cancelStatusDialog();
                break;
            //----------- PUSH ROLLOUT -----------
            case PRO_STATUS_STEP_1:
                mainActivityInterface.setStatusDialogText(getContext().getString(R.string.PushRolloutStep1Status));
                break;
            case PRO_STATUS_STEP_2:
                mainActivityInterface.setStatusDialogText(getContext().getString(R.string.PushRolloutStep2Status));
                break;
            case PRO_STATUS_STEP_3:
                mainActivityInterface.setStatusDialogText(getContext().getString(R.string.PushRolloutStep3Status));
                break;
            case PRO_STATUS_DONE:
                token.rollout_finished = true;
                rolloutFinished(token);
                mainActivityInterface.cancelStatusDialog();
                break;
            //----------- PUSH ROLLOUT ERRORS-----------
            case PRO_STATUS_BAD_BASE64:
                token.rollout_finished = false;
                mainActivityInterface.cancelStatusDialog();
                mainActivityInterface.makeAlertDialog("Error", "The key from the server was not in the correct format.");
                break;
            case PRO_STATUS_MALFORMED_JSON:
                token.rollout_finished = false;
                mainActivityInterface.cancelStatusDialog();
                mainActivityInterface.makeAlertDialog("Error", "The response could not be parsed.");
                break;
            case PRO_STATUS_RESPONSE_NO_KEY:
                token.rollout_finished = false;
                mainActivityInterface.cancelStatusDialog();
                mainActivityInterface.makeAlertDialog("Error", "The response does not contain a key.");
                break;
            case PRO_STATUS_REGISTRATION_TIME_EXPIRED:
                mainActivityInterface.cancelStatusDialog();
                mainActivityInterface.makeAlertDialog("Error", "Registration time expired.");
                break;
            case PRO_STATUS_MALFORMED_URL:
                mainActivityInterface.cancelStatusDialog();
                mainActivityInterface.makeAlertDialog("Error", "Rollout URL is invalid.");
                break;
            case PRO_STATUS_UNKNOWN_HOST:
                token.rollout_finished = false;
                mainActivityInterface.cancelStatusDialog();
                mainActivityInterface.makeAlertDialog("Error", "Rollout URL cannot be resolved.");
                break;

            default:
                logprint("Unknown statusCode in updateTaskStatus: " + statusCode);
                break;
        }
    }

    @Override
    public void makeAlertDialog(String title, String message) {
        mainActivityInterface.makeAlertDialog(title, message);
    }

}
