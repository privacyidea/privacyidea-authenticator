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

import org.apache.commons.codec.binary.Base32;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;

import static it.netknights.piauthenticator.AppConstants.HOTP;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_BAD_BASE64;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_DONE;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_MALFORMED_JSON;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_REGISTRATION_TIME_EXPIRED;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_RESPONSE_NOT_OK;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_RESPONSE_NO_KEY;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_STEP_1;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_STEP_2;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_STEP_3;
import static it.netknights.piauthenticator.AppConstants.PUSH;
import static it.netknights.piauthenticator.AppConstants.QUESTION;
import static it.netknights.piauthenticator.AppConstants.STATUS_ENDPOINT_ERROR;
import static it.netknights.piauthenticator.AppConstants.STATUS_ENDPOINT_MALFORMED_URL;
import static it.netknights.piauthenticator.AppConstants.STATUS_ENDPOINT_UNKNOWN_HOST;
import static it.netknights.piauthenticator.AppConstants.STATUS_INIT_FIREBASE;
import static it.netknights.piauthenticator.AppConstants.STATUS_INIT_FIREBASE_DONE;
import static it.netknights.piauthenticator.AppConstants.STATUS_STANDARD_ROLLOUT_DONE;
import static it.netknights.piauthenticator.AppConstants.STATUS_TWO_STEP_ROLLOUT;
import static it.netknights.piauthenticator.AppConstants.STATUS_TWO_STEP_ROLLOUT_DONE;
import static it.netknights.piauthenticator.AppConstants.TITLE;
import static it.netknights.piauthenticator.AppConstants.TOTP;
import static it.netknights.piauthenticator.Interfaces.MainActivityInterface;
import static it.netknights.piauthenticator.Interfaces.PresenterInterface;
import static it.netknights.piauthenticator.Interfaces.PresenterTaskInterface;
import static it.netknights.piauthenticator.Interfaces.PresenterUtilInterface;
import static it.netknights.piauthenticator.Interfaces.TokenListViewInterface;
import static it.netknights.piauthenticator.OTPGenerator.generate;
import static it.netknights.piauthenticator.OTPGenerator.hashPIN;
import static it.netknights.piauthenticator.Util.logprint;

public class Presenter implements PresenterInterface, PresenterTaskInterface, PresenterUtilInterface, Interfaces.PushAuthCallbackInterface {

    private TokenListViewInterface tokenListInterface;
    private MainActivityInterface mainActivityInterface;
    private Model model;
    private Util util;

    Presenter(TokenListViewInterface tokenListViewInterface, MainActivityInterface mainActivityInterface, Util util) {
        this.tokenListInterface = tokenListViewInterface;
        this.mainActivityInterface = mainActivityInterface;
        this.util = util;
    }

    @Override
    public void init() {
        // Logic of onCreate
        if (model == null) {
            model = new Model(util.loadTokens(), new ArrayList<>());
        }
        FirebaseInitConfig firebaseInitConfig = util.loadFirebaseConfig();
        if (firebaseInitConfig != null) {
            mainActivityInterface.firebaseInit(firebaseInitConfig);
        }

        mainActivityInterface.startTimer();
        refreshOTPs();

        String expired = model.checkForExpiredTokens();
        if (expired != null) {
            mainActivityInterface.makeAlertDialog(R.string.TokenExpiredTitle, expired.trim());
            tokenListInterface.notifyChange();
        }
    }

    @Override
    public void scanQRfinished(ScanResult result) {
        Token token;
        switch (result.type) {
            case PUSH: {
                // Check the push push_version first
                // The current setup is v1
                if (result.push_version > 1) {
                    // Higher than v1 is currently not supported
                    mainActivityInterface.makeAlertDialog(R.string.IncompatiblePushVersion,
                            R.string.IncompatiblePushVersionMessage);
                    return;
                }

                token = new Token(result.serial, result.label);
                if (result.firebaseInitConfig != null) {
                    util.storeFirebaseConfig(result.firebaseInitConfig);
                    mainActivityInterface.firebaseInit(result.firebaseInitConfig);
                }
                if (!result.sslverify) {
                    token.sslVerify = false;
                }
                token.rollout_finished = false;
                Calendar now = Calendar.getInstance();
                now.add(Calendar.MINUTE, result.ttl);
                token.rollout_expiration = now.getTime();
                token.rollout_url = result.rollout_url;
                token.enrollment_credential = result.enrollment_credential;
                preparePushRollout(token);
                break;
            }
            case HOTP:
            case TOTP: {
                if (result.secret == null) return;
                token = new Token(new Base32().decode(result.secret), result.serial, result.label, result.type, result.digits);
                token.setCounter(result.counter);
                token.setPeriod(result.period);
                token.setAlgorithm(result.algorithm);
                token.setWithPIN(result.pin);
                token.setPersistent(result.persistent);
                token.setWithTapToShow(result.taptoshow);
                if (result.do2Step) {
                    doTwoStepRollout(token, result.phonepartlength, result.iterations, result.output_size);
                } else {
                    rolloutFinished(token);
                }
                break;
            }
            default:
                break;
        }
    }

    void setModel(Model model) {
        this.model = model;
    }

    @Override
    public void addTokenFromIntent(String type, byte[] secret, String serial, int digits, String algorithm, String period, boolean withPIN) {
        // Push tokens cannot be created manually so this is simplified
        // serial = label on creation, the label can be edited afterwards
        Token token = new Token(secret, serial, serial, type, digits);

        if (type.equals(TOTP)) {
            token.setPeriod(Integer.parseInt(period));
        }
        if (algorithm != null) {
            token.setAlgorithm(algorithm);
        }
        if (withPIN) {
            token.setWithPIN(true);
        }
        rolloutFinished(token);
        mainActivityInterface.makeToast(mainActivityInterface.getStringResource(R.string.TokenAddedToast) + serial);
    }

    @Override
    public void addPushAuthRequest(PushAuthRequest request) {
        // Requests for token that are not enrolled yet are not allowed
        for (Token token : model.tokens) {
            if (token.getSerial().equals(request.serial)) {
                if (!token.rollout_finished) {
                    return;
                } else {
                    logprint("Push Auth Request for " + request.serial + " added.");
                    model.pushAuthRequests.add(request);
                }
            }
        }
    }

    @Override
    public void onResume() {
        refreshOTPs();
        mainActivityInterface.resumeTimer();
    }

    @Override
    public void onPause() {
        mainActivityInterface.stopTimer();
    }

    @Override
    public void onStop() {
        saveTokenlist();
    }

    @Override
    public void saveTokenlist() {
        util.saveTokens(model.tokens);
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
    public void addToken(Token token) {
        if (!token.getType().equals(PUSH)) {
            if (token.getCurrentOTP() == null) {
                token.setCurrentOTP(generate(token));
            }
        }
        model.tokens.add(token);
    }

    @Override
    //This is only used for swapping when changing position in the list
    public Token removeTokenAtPosition(int position) {
        return model.tokens.remove(position);
    }

    /**
     * Remove a token from the list. This includes Pub/Priv Keys for Pushtoken
     *
     * @param currToken the token to remove
     */
    protected void removeToken(Token currToken) {
        if (currToken == null) return;

        int position = model.tokens.indexOf(currToken);
        tokenListInterface.removeProgressbar(position);

        if (model.tokens.size() >= position && position >= 0 && !model.tokens.isEmpty()) {
            model.tokens.remove(position);
        }

        if (currToken.getType().equals(PUSH)) {
            util.removePubkeyFor(currToken.getSerial());
            getWrapper().removePrivateKeyFor(currToken.getSerial());
            // if the removed token was the last push token, remove the firebase config
            if(!model.hasPushToken()){
                util.removeFirebaseConfig();
                mainActivityInterface.removeFirebase();
            }
        }

        tokenListInterface.notifyChange();
        mainActivityInterface.makeToast(R.string.toast_token_removed);
        saveTokenlist();
    }

    /**
     * Check if a token has pending PushAuthRequests
     *
     * @param token token to check for
     * @return Map with keys "title" and "message" if there is a PushAuthRequest, null if there is none
     */
    @Override
    public Map<String, String> getPushAuthRequestInfo(Token token) {
        if (!token.getType().equals(PUSH)) return null;
        String t_serial = token.getSerial();
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
            PrivateKey appPrivateKey = getWrapper().getPrivateKeyFor(t_serial);
            PublicKey piPublicKey = util.getPIPubkey(req.serial);
            if (appPrivateKey != null && piPublicKey != null) {
                new PushAuthTask(req, piPublicKey, appPrivateKey, this).execute();
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
        // This method is called from the Tokenlistadapter when the Rollout is retried,
        // the adapter has only the position of the row
        preparePushRollout(model.tokens.get(position));
    }

    private void preparePushRollout(Token token) {
        // Start getting the Firebase Token from InstanceID
        // When finished there will be call to firebaseTokenReceived to start the Rollout
        mainActivityInterface.getFirebaseTokenForPushRollout(token);
    }

    @Override
    public void firebaseTokenReceived(String fbtoken, Token token) {
        // Called when InstanceID in MainActivity finished getting the Token
        // Now the Rollout can be started
        new PushRolloutTask(token, fbtoken,this).execute();
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

    @Override
    public void timerProgress(int progress) {
        tokenListInterface.updateProgressbars(progress);
        // refresh OTP values only around the periods
        if (progress < 3 || progress > 27 && progress < 33 || progress > 57) {
            refreshOTPs();
        }
    }

    private void refreshOTPs() {
        for (int i = 0; i < model.tokens.size(); i++) {
            if (!model.tokens.get(i).getType().equals(PUSH)) {
                model.tokens.get(i).setCurrentOTP(OTPGenerator.generate(model.tokens.get(i)));
            }
        }
        tokenListInterface.notifyChange();
    }

    private void doTwoStepRollout(Token token, int phonepartlength, int iterations, int output_size) {
        new TwoStepRolloutTask(token, phonepartlength, iterations, output_size, this).execute();
    }

    private void rolloutFinished(Token token) {
        if (token == null) return;
        if (!token.getType().equals(PUSH)) {
            token.setCurrentOTP(generate(token));
        } else {
            // Do not add token twice
            for (Token t : model.tokens) {
                if (t.getSerial().equals(token.getSerial()) && t.getType().equals(PUSH)) {
                    saveTokenlist();
                    tokenListInterface.notifyChange();
                    return;
                }
            }
        }
        model.tokens.add(token);
        saveTokenlist();
        tokenListInterface.notifyChange();
    }

    @Override
    public PublicKey generatePublicKeyFor(String serial) {
        return mainActivityInterface.generatePublicKeyFor(serial);
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
            util.storePIPubkey(key, token.getSerial());
        } catch (GeneralSecurityException e) {
            // this means the "key" field was empty or the DECODED data is not a key
            updateTaskStatus(PRO_STATUS_RESPONSE_NO_KEY, token);
            e.printStackTrace();
        } catch (IllegalArgumentException e) {
            e.printStackTrace();
            updateTaskStatus(PRO_STATUS_BAD_BASE64, token);
        }
    }

    /**
     * Updates the UI according to the statusCode. This includes opening/closing dialogs and choosing the dialog type.
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
                mainActivityInterface.setStatusDialogText(R.string.InitFirebaseStatus);
                break;
            case STATUS_INIT_FIREBASE_DONE:
                mainActivityInterface.cancelStatusDialog();
                break;
            //----------- TWO STEP ROLLOUT -----------
            case STATUS_TWO_STEP_ROLLOUT:
                mainActivityInterface.setStatusDialogText(R.string.WaitWhileSecretIsGenerated);
                break;
            case STATUS_TWO_STEP_ROLLOUT_DONE:
                rolloutFinished(token);
                mainActivityInterface.cancelStatusDialog();
                break;
            //----------- PUSH ROLLOUT -----------
            case PRO_STATUS_STEP_1:
                mainActivityInterface.setStatusDialogText(R.string.PushRolloutStep1Status);
                break;
            case PRO_STATUS_STEP_2:
                mainActivityInterface.setStatusDialogText(R.string.PushRolloutStep2Status);
                break;
            case PRO_STATUS_STEP_3:
                mainActivityInterface.setStatusDialogText(R.string.PushRolloutStep3Status);
                break;
            case PRO_STATUS_DONE:
                token.rollout_finished = true;
                rolloutFinished(token);
                mainActivityInterface.cancelStatusDialog();
                break;
            //----------- PUSH ROLLOUT ERRORS-----------
            case PRO_STATUS_BAD_BASE64:
                token.rollout_finished = false;
                rolloutFinished(token);
                mainActivityInterface.makeAlertDialog(R.string.Error, R.string.KeyFromServerWrongFormat);
                break;
            case PRO_STATUS_MALFORMED_JSON:
                token.rollout_finished = false;
                rolloutFinished(token);
                mainActivityInterface.makeAlertDialog(R.string.Error, R.string.ResponseNotParsed);
                break;
            case PRO_STATUS_RESPONSE_NO_KEY:
                token.rollout_finished = false;
                rolloutFinished(token);
                mainActivityInterface.makeAlertDialog((R.string.Error), (R.string.ResponseNoKey));
                break;
            case PRO_STATUS_REGISTRATION_TIME_EXPIRED:
                mainActivityInterface.makeAlertDialog(R.string.Error, R.string.RegistrationTimeExpired);
                removeToken(token);
                break;
            case STATUS_ENDPOINT_MALFORMED_URL:
                mainActivityInterface.makeAlertDialog(R.string.Error, R.string.RolloutURLinvalid);
                break;
            case STATUS_ENDPOINT_UNKNOWN_HOST:
                token.rollout_finished = false;
                rolloutFinished(token);
                mainActivityInterface.makeAlertDialog(R.string.Error, R.string.RolloutURLNotResolved);
                break;
            case PRO_STATUS_RESPONSE_NOT_OK:
            case STATUS_ENDPOINT_ERROR:
                token.rollout_finished = false;
                rolloutFinished(token);
                mainActivityInterface.makeAlertDialog(R.string.Error, R.string.ServerResponseNotOk);
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

    @Override
    public SecretKeyWrapper getWrapper() {
        return mainActivityInterface.getWrapper();
    }

    @Override
    public void authenticationFinished(boolean success) {
        if (success) {
            mainActivityInterface.makeToast(R.string.AuthenticationSuccessful);
        } else {
            mainActivityInterface.makeToast(R.string.AuthenticationFailed);
        }
    }
}
