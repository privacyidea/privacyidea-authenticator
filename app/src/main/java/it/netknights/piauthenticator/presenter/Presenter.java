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

package it.netknights.piauthenticator.presenter;

import android.util.Pair;

import org.apache.commons.codec.binary.Base32;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;

import it.netknights.piauthenticator.R;
import it.netknights.piauthenticator.interfaces.MainActivityInterface;
import it.netknights.piauthenticator.interfaces.PresenterInterface;
import it.netknights.piauthenticator.interfaces.PresenterTaskInterface;
import it.netknights.piauthenticator.interfaces.PresenterUtilInterface;
import it.netknights.piauthenticator.interfaces.PushAuthCallbackInterface;
import it.netknights.piauthenticator.interfaces.TokenListViewInterface;
import it.netknights.piauthenticator.model.FirebaseInitConfig;
import it.netknights.piauthenticator.model.Model;
import it.netknights.piauthenticator.model.PushAuthRequest;
import it.netknights.piauthenticator.model.ScanResult;
import it.netknights.piauthenticator.model.Token;
import it.netknights.piauthenticator.tasks.PushAuthTask;
import it.netknights.piauthenticator.tasks.PushRolloutTask;
import it.netknights.piauthenticator.tasks.TwoStepRolloutTask;
import it.netknights.piauthenticator.utils.SecretKeyWrapper;
import it.netknights.piauthenticator.utils.Util;

import static it.netknights.piauthenticator.utils.AppConstants.HOTP;
import static it.netknights.piauthenticator.utils.AppConstants.PRO_STATUS_BAD_BASE64;
import static it.netknights.piauthenticator.utils.AppConstants.PRO_STATUS_DONE;
import static it.netknights.piauthenticator.utils.AppConstants.PRO_STATUS_MALFORMED_JSON;
import static it.netknights.piauthenticator.utils.AppConstants.PRO_STATUS_REGISTRATION_TIME_EXPIRED;
import static it.netknights.piauthenticator.utils.AppConstants.PRO_STATUS_RESPONSE_NOT_OK;
import static it.netknights.piauthenticator.utils.AppConstants.PRO_STATUS_RESPONSE_NO_KEY;
import static it.netknights.piauthenticator.utils.AppConstants.PRO_STATUS_STEP_1;
import static it.netknights.piauthenticator.utils.AppConstants.PRO_STATUS_STEP_2;
import static it.netknights.piauthenticator.utils.AppConstants.PRO_STATUS_STEP_3;
import static it.netknights.piauthenticator.utils.AppConstants.PUSH;
import static it.netknights.piauthenticator.utils.AppConstants.State.*;
import static it.netknights.piauthenticator.utils.AppConstants.STATUS_ENDPOINT_ERROR;
import static it.netknights.piauthenticator.utils.AppConstants.STATUS_ENDPOINT_MALFORMED_URL;
import static it.netknights.piauthenticator.utils.AppConstants.STATUS_ENDPOINT_SSL_ERROR;
import static it.netknights.piauthenticator.utils.AppConstants.STATUS_ENDPOINT_UNKNOWN_HOST;
import static it.netknights.piauthenticator.utils.AppConstants.STATUS_INIT_FIREBASE;
import static it.netknights.piauthenticator.utils.AppConstants.STATUS_INIT_FIREBASE_DONE;
import static it.netknights.piauthenticator.utils.AppConstants.STATUS_STANDARD_ROLLOUT_DONE;
import static it.netknights.piauthenticator.utils.AppConstants.STATUS_TWO_STEP_ROLLOUT;
import static it.netknights.piauthenticator.utils.AppConstants.STATUS_TWO_STEP_ROLLOUT_DONE;
import static it.netknights.piauthenticator.utils.AppConstants.TOTP;
import static it.netknights.piauthenticator.utils.OTPGenerator.generate;
import static it.netknights.piauthenticator.utils.OTPGenerator.hashPIN;
import static it.netknights.piauthenticator.utils.Util.logprint;

public class Presenter implements PresenterInterface, PresenterTaskInterface, PresenterUtilInterface, PushAuthCallbackInterface {

    private TokenListViewInterface tokenListInterface;
    private MainActivityInterface mainActivityInterface;
    private Model model;
    private Util util;

    private ArrayList<Pair<Token, PushAuthTask>> runningAuthentications = new ArrayList<>();
    private ArrayList<Pair<Token, PushAuthRequest>> toDelete = new ArrayList<>();

    public Presenter(TokenListViewInterface tokenListViewInterface, MainActivityInterface mainActivityInterface, Util util) {
        this.tokenListInterface = tokenListViewInterface;
        this.mainActivityInterface = mainActivityInterface;
        this.util = util;
    }

    @Override
    public void init() {
        // Logic of onCreate
        if (model == null) {
            model = new Model(util.loadTokens());
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
        checkForExpiredAuths();
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
                    try {
                        mainActivityInterface.firebaseInit(result.firebaseInitConfig);
                        util.storeFirebaseConfig(result.firebaseInitConfig);
                    } catch (InvalidKeyException e) {
                        e.printStackTrace();
                    } catch (IllegalArgumentException e) {
                        // mainActivityInterface.firebaseInit() will throw this exception if it
                        // least one of the parameters is empty; we do not want to add a Token then,
                        // as it will be broken too
                        mainActivityInterface.makeAlertDialog(R.string.firebase_config_broken_title,
                                R.string.firebase_config_broken);
                        return;
                    }
                }
                token.sslVerify = result.sslverify;
                token.state = UNFINISHED;
                Calendar now = Calendar.getInstance();
                now.add(Calendar.MINUTE, result.ttl);
                token.rollout_expiration = now.getTime();
                token.rollout_url = result.rollout_url;
                token.enrollment_credential = result.enrollment_credential;
                addToken(token);
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

    public void setModel(Model model) {
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
    public void cancelAuthentication(Token token) {
        // Reset the token's state and cancel the task
        token.state = FINISHED;
        deleteRunningAuthenticationFor(token);
        tokenListInterface.notifyChange();
    }

    @Override
    public void addPushAuthRequest(PushAuthRequest request) {
        // Requests for token that are not enrolled yet are not allowed
        for (Token token : model.getTokens()) {
            if (token.getSerial().equals(request.getSerial())) {
                if (token.state.equals(UNFINISHED)) {
                    return;
                } else {
                    logprint("Push Auth Request for " + request.getSerial() + " added.");
                    if (token.addPushAuthRequest(request))
                        tokenListInterface.notifyChange();
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
        util.saveTokens(model.getTokens());
    }

    public void checkKeyStoreIsWorking() {
        try {
            util.saveToFile("test", new byte[]{});
        } catch (InvalidKeyException e) {
            mainActivityInterface.makeDeviceNotSupportedDialog();
        }
    }

    @Override
    public void setCurrentSelection(int position) {
        model.setCurrentSelection(position);
    }

    @Override
    public boolean isCurrentSelectionWithPin() {
        if (model.getCurrentSelection() == null) return false;
        return model.getCurrentSelection().isWithPIN();
    }

    @Override
    public boolean isCurrentSelectionPersistent() {
        if (model.getCurrentSelection() == null) return false;
        return model.getCurrentSelection().isPersistent();
    }

    @Override
    public boolean isCurrentSelectionLocked() {
        if (model.getCurrentSelection() == null) return false;
        return model.getCurrentSelection().isLocked();
    }

    @Override
    public void removeCurrentSelection() {
        // callback from ActionMode delete
        if (model.getCurrentSelection() == null) return;
        this.removeToken(model.getCurrentSelection());
    }

    @Override
    public String getCurrentSelectionLabel() {
        if (model.getCurrentSelection() == null) return null;
        return model.getCurrentSelection().getLabel();
    }

    @Override
    public String getCurrentSelectionOTP() {
        if (model.getCurrentSelection() == null) return null;
        return model.getCurrentSelection().getCurrentOTP();
    }

    @Override
    public Token getCurrentSelection() {
        return model.getCurrentSelection();
    }

    @Override
    public void setCurrentSelectionLabel(String label) {
        if (model.getCurrentSelection() == null) return;
        model.getCurrentSelection().setLabel(label);
    }

    @Override
    public void changeCurrentSelectionPIN(int pin) {
        if (model.getCurrentSelection() == null) return;
        String hashedPIN = hashPIN(pin, model.getCurrentSelection());
        model.getCurrentSelection().setPin(hashedPIN);
        tokenListInterface.notifyChange();
        saveTokenlist();
    }

    @Override
    public Token getTokenAtPosition(int position) {
        return model.getTokens().get(position);
    }

    @Override
    public int getTokenCount() {
        if (model.getTokens() == null) return 0;
        return model.getTokens().size();
    }

    @Override
    public void addTokenAt(int position, Token token) {
        model.getTokens().add(position, token);
    }

    @Override
    public void addToken(Token token) {
        if (!token.getType().equals(PUSH)) {
            if (token.getCurrentOTP() == null) {
                token.setCurrentOTP(generate(token));
            }
        }
        model.getTokens().add(token);
    }

    @Override
    public Token removeTokenAtPosition(int position) {
        return model.getTokens().remove(position);
    }

    /**
     * Remove a token from the list. This includes public and private keys for Pushtoken
     *
     * @param currToken the token to remove
     */
    public void removeToken(Token currToken) {
        if (currToken == null) return;

        int position = model.getTokens().indexOf(currToken);
        tokenListInterface.removeProgressbar(position);

        if (model.getTokens().size() >= position && position >= 0 && !model.getTokens().isEmpty()) {
            model.getTokens().remove(position);
        }

        if (currToken.getType().equals(PUSH)) {
            util.removePubkeyFor(currToken.getSerial());
            getWrapper().removePrivateKeyFor(currToken.getSerial());
            // if the removed token was the last push token, remove the firebase config
            if (!model.hasPushToken()) {
                util.removeFirebaseConfig();
                mainActivityInterface.removeFirebase();
                mainActivityInterface.makeToast(R.string.ResetFirebaseInfoMsg);
            }
        }

        tokenListInterface.notifyChange();
        mainActivityInterface.makeToast(R.string.toast_token_removed);
        saveTokenlist();
    }

    @Override
    public void startPushAuthentication(Token token) {
        // onclick from token in list
        if (!token.getType().equals(PUSH)) return;
        // Always the first pendingAuth
        PushAuthRequest req = token.getPendingAuths().get(0);
        if (req == null || !req.getSerial().equals(token.getSerial()))
            return;
        if (req.getExpiration().compareTo(new Date()) < 1) {
            // Expired
            token.getPendingAuths().remove(req);
            tokenListInterface.notifyChange();
            return;
        }
        try {
            PrivateKey appPrivateKey = getWrapper().getPrivateKeyFor(req.getSerial());
            PublicKey piPublicKey = util.getPIPubkey(req.getSerial());
            if (appPrivateKey != null && piPublicKey != null) {
                token.state = AUTHENTICATING;
                PushAuthTask task = new PushAuthTask(token, req, piPublicKey, appPrivateKey, this);
                runningAuthentications.add(new Pair<>(token, task));
                task.execute();
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
        preparePushRollout(model.getTokens().get(position));
    }

    /**
     * Sets the token in RollingOut state and gets the Firebase Token.
     * After getting the FB Token the rollout is started by a callback.
     * This ensures the FB Token is present.
     *
     * @param token token to start the rollout for
     */
    private void preparePushRollout(Token token) {
        token.state = ROLLING_OUT;
        tokenListInterface.notifyChange();

        // Start getting the Firebase Token from InstanceID
        // When finished there will be call to firebaseTokenReceived to start the Rollout
        mainActivityInterface.getFirebaseTokenForPushRollout(token);
    }

    @Override
    public void firebaseTokenReceived(String fbtoken, Token token) {
        // Called when InstanceID in MainActivity finished getting the Token
        // Now the Rollout can be started
        new PushRolloutTask(token, fbtoken, this).execute();
    }

    @Override
    public void removePushAuthFor(int notificationID, String signature) {
        boolean changed = false;
        for (Token token : model.getTokens()) {
            for (PushAuthRequest req : token.getPendingAuths()) {
                if (req.getSignature().equals(signature) && req.getNotificationID() == notificationID) {
                    logprint("Removing PushAuthReq");
                    token.getPendingAuths().remove(req);
                    changed = true;
                }
            }
        }
        if (changed) {
            tokenListInterface.notifyChange();
        }
    }

    @Override
    public void increaseHOTPCounter(Token token) {
        token.setCounter((token.getCounter() + 1));
        token.setCurrentOTP(generate(token));
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
        // Check for expired pendingAuths every 30s
        if (progress == 30 || progress == 0) {
        }
        checkForExpiredAuths();
    }

    private void checkForExpiredAuths() {
        for (Token token : model.getTokens()) {
            if (token.getType().equals(PUSH)) {
                for (PushAuthRequest req : token.getPendingAuths()) {
                    if (new Date().after(req.getExpiration())) {
                        // Expired
                        toDelete.add(new Pair<>(token, req));
                    }
                }
            }
        }
        for (Pair<Token, PushAuthRequest> pair : toDelete) {
            pair.first.getPendingAuths().remove(pair.second);
            mainActivityInterface.cancelNotification(pair.second.getNotificationID());
        }
        if (!toDelete.isEmpty()) {
            tokenListInterface.notifyChange();
            toDelete.clear();
        }
    }

    private void refreshOTPs() {
        for (int i = 0; i < model.getTokens().size(); i++) {
            if (!model.getTokens().get(i).getType().equals(PUSH)) {
                model.getTokens().get(i).setCurrentOTP(generate(model.getTokens().get(i)));
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
            for (Token t : model.getTokens()) {
                if (t.getSerial().equals(token.getSerial()) && t.getType().equals(PUSH)) {
                    saveTokenlist();
                    tokenListInterface.notifyChange();
                    return;
                }
            }
        }
        model.getTokens().add(token);
        saveTokenlist();
        tokenListInterface.notifyChange();
    }

    @Override
    public PublicKey generatePublicKeyFor(String serial) {
        return mainActivityInterface.generatePublicKeyFor(serial);
    }

    /**
     * Store the received key with the serial as alias. If there is an error when storing the key,
     * the Token state will stay marked as unfinished and can be repeated.
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
                //mainActivityInterface.setStatusDialogText(R.string.InitFirebaseStatus);
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
                //mainActivityInterface.setStatusDialogText(R.string.PushRolloutStep1Status);
                break;
            case PRO_STATUS_STEP_2:
                //mainActivityInterface.setStatusDialogText(R.string.PushRolloutStep2Status);
                break;
            case PRO_STATUS_STEP_3:
                //mainActivityInterface.setStatusDialogText(R.string.PushRolloutStep3Status);
                break;
            case PRO_STATUS_DONE:
                token.state = FINISHED;
                rolloutFinished(token);
                mainActivityInterface.cancelStatusDialog();
                break;
            //----------- PUSH ROLLOUT ERRORS -----------
            case PRO_STATUS_BAD_BASE64:
                token.state = UNFINISHED;
                rolloutFinished(token);
                mainActivityInterface.makeAlertDialog(R.string.Error, R.string.KeyFromServerWrongFormat);
                break;
            case PRO_STATUS_MALFORMED_JSON:
                token.state = UNFINISHED;
                rolloutFinished(token);
                mainActivityInterface.makeAlertDialog(R.string.Error, R.string.ResponseNotParsed);
                break;
            case PRO_STATUS_RESPONSE_NO_KEY:
                token.state = UNFINISHED;
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
                token.state = UNFINISHED;
                rolloutFinished(token);
                mainActivityInterface.makeAlertDialog(R.string.Error, R.string.RolloutURLNotResolved);
                break;
            case PRO_STATUS_RESPONSE_NOT_OK:
            case STATUS_ENDPOINT_ERROR:
                token.state = UNFINISHED;
                rolloutFinished(token);
                mainActivityInterface.makeAlertDialog(R.string.Error, R.string.ServerResponseNotOk);
                break;
            case STATUS_ENDPOINT_SSL_ERROR:
                token.state = UNFINISHED;
                rolloutFinished(token);
                mainActivityInterface.makeAlertDialog(R.string.Error, R.string.SSLHandshakeFailed);
                break;
            default:
                logprint("Unknown statusCode in updateTaskStatus: " + statusCode);
                break;
        }
        tokenListInterface.notifyChange();
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
    public void authenticationFinished(boolean success, Token token) {
        if (success) {
            mainActivityInterface.makeToast(R.string.AuthenticationSuccessful);
            // Remove the notification if still present
            mainActivityInterface.cancelNotification(token.getPendingAuths().get(0).getNotificationID());
            // In case of success, remove the pendingAuth from the token (always the first from within the App)
            token.getPendingAuths().remove(0);
            token.state = FINISHED;
            tokenListInterface.notifyChange();
        } else {
            mainActivityInterface.makeToast(R.string.AuthenticationFailed);
        }
        // Regardless of success, remove the token from runningAuthentications
        deleteRunningAuthenticationFor(token);
    }

    /**
     * Cancel the running Authentication Task and remove the pair from the runningAuthentications List
     *
     * @param token token of the pair
     */
    private void deleteRunningAuthenticationFor(Token token) {
        Pair<Token, PushAuthTask> toDelete = null;
        for (Pair<Token, PushAuthTask> pair :
                runningAuthentications) {
            if (pair.first.getSerial().equals(token.getSerial())) {
                toDelete = pair;
            }
        }
        if (toDelete != null) {
            toDelete.second.cancel(true);
            runningAuthentications.remove(toDelete);
        }
        token.state = FINISHED;
    }

    @Override
    public void handleError(int statusCode, Token token) {
        switch (statusCode) {
            case STATUS_ENDPOINT_UNKNOWN_HOST: {
                // Network unreachable
                cancelAuthentication(token);
                mainActivityInterface.makeToast(R.string.ERR_SERVER_UNREACHABLE);
                break;
            }
            case STATUS_ENDPOINT_SSL_ERROR: {
                cancelAuthentication(token);
                mainActivityInterface.makeToast(R.string.SSLHandshakeFailed);
                break;
            }
            default:
                logprint("No handling for errorcode " + statusCode + " in presenter.");
                break;
        }
    }
}