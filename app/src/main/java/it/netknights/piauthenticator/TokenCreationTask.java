package it.netknights.piauthenticator;

import android.net.Uri;
import android.os.AsyncTask;

import org.apache.commons.codec.binary.Base32;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Calendar;

import static it.netknights.piauthenticator.AppConstants.ALGORITHM;
import static it.netknights.piauthenticator.AppConstants.API_KEY;
import static it.netknights.piauthenticator.AppConstants.APP_ID;
import static it.netknights.piauthenticator.AppConstants.COUNTER;
import static it.netknights.piauthenticator.AppConstants.DIGITS;
import static it.netknights.piauthenticator.AppConstants.ENROLLMENT_CRED;
import static it.netknights.piauthenticator.AppConstants.HMACSHA1;
import static it.netknights.piauthenticator.AppConstants.HMACSHA256;
import static it.netknights.piauthenticator.AppConstants.HMACSHA512;
import static it.netknights.piauthenticator.AppConstants.HOTP;
import static it.netknights.piauthenticator.AppConstants.ISSUER;
import static it.netknights.piauthenticator.AppConstants.PERIOD;
import static it.netknights.piauthenticator.AppConstants.PERSISTENT;
import static it.netknights.piauthenticator.AppConstants.PIN;
import static it.netknights.piauthenticator.AppConstants.PROJECT_ID;
import static it.netknights.piauthenticator.AppConstants.PROJECT_NUMBER;
import static it.netknights.piauthenticator.AppConstants.PUSH;
import static it.netknights.piauthenticator.AppConstants.ROLLOUT_URL;
import static it.netknights.piauthenticator.AppConstants.SECRET;
import static it.netknights.piauthenticator.AppConstants.STATUS_DO_2STEP_ROLLOUT;
import static it.netknights.piauthenticator.AppConstants.STATUS_DO_FIREBASE_INIT;
import static it.netknights.piauthenticator.AppConstants.STATUS_DO_PUSH_ROLLOUT;
import static it.netknights.piauthenticator.AppConstants.STATUS_TOKEN_CREATION_FINISHED_OK;
import static it.netknights.piauthenticator.AppConstants.TAPTOSHOW;
import static it.netknights.piauthenticator.AppConstants.TOTP;
import static it.netknights.piauthenticator.AppConstants.TTL;
import static it.netknights.piauthenticator.AppConstants.TWOSTEP_DIFFICULTY;
import static it.netknights.piauthenticator.AppConstants.TWOSTEP_OUTPUT;
import static it.netknights.piauthenticator.AppConstants.TWOSTEP_SALT;
import static it.netknights.piauthenticator.Util.logprint;

public class TokenCreationTask extends AsyncTask<String, Integer, Boolean> {

    private ActivityInterface activityInterface;
    private AsyncTask<Void, Integer, Boolean> pushrollout;
    private AsyncTask<Void, Integer, Boolean> firebaseInit;
    private AsyncTask<Void, Void, Boolean> twoStepRollout;
    Util util;
    private Token toAdd;

    TokenCreationTask(ActivityInterface activityInterface, Util util) {
        this.activityInterface = activityInterface;
        this.util = util;
    }

    @Override
    protected void onPreExecute() {
        super.onPreExecute();
        logprint("Starting token creation...");
    }

    @Override
    protected Boolean doInBackground(String... strings) {
        if (strings[0] == null) {
            return false;
        }
        String content = strings[0];
        logprint("QR CONTENT: " + content);
        content = content.replaceFirst("otpauth", "http");
        Uri uri = Uri.parse(content);
        URL url = null;
        try {
            url = new URL(content);
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }

        if (!url.getProtocol().equals("http")) {
            try {
                throw new Exception("Invalid Protocol");
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        if (!url.getHost().equals(TOTP)) {
            if (!url.getHost().equals(HOTP)) {
                if (!url.getHost().equals(PUSH)) {
                    try {
                        throw new Exception("No TOTP, HOTP or Push Token");
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }
        }
        // TOKEN TYPE
        String type = url.getHost();

        // LABEL, SERIAL
        String label = uri.getPath().substring(1);

        String serial = label;
        String issuer = uri.getQueryParameter(ISSUER);
        if (issuer != null && !label.startsWith(issuer)) {
            label = issuer + ": " + label;
        }

        // --------------------- PUSH ---------------------
        // https://github.com/privacyidea/privacyidea/wiki/concept:-PushToken
        // if its a push token, it is returned early and the push-rollout (+firebase init) is initiated
        if (type.equals(PUSH)) {

            // Check for FirebaseInit info
            if (uri.getQueryParameter(PROJECT_ID) != null) {
                String projID = uri.getQueryParameter(PROJECT_ID);
                String appID = uri.getQueryParameter(APP_ID);
                String api_key = uri.getQueryParameter(API_KEY);
                String projNumber = uri.getQueryParameter(PROJECT_NUMBER);
                logprint("projID: " + projID);
                logprint("appID: " + appID);
                logprint("API Key: " + api_key);
                logprint("Proj Number: " + projNumber);
                util.storeFirebaseConfig(projID, appID, api_key, projNumber);
                firebaseInit = new FirebaseInitTask(projID, appID, api_key, projNumber, activityInterface);
                publishProgress(STATUS_DO_FIREBASE_INIT);
            }

            Token token = new Token(serial, label);
            token.rollout_url = uri.getQueryParameter(ROLLOUT_URL);
            token.rollout_finished = false;

            // Add the TTL to the token
            int ttl = 10;   // default
            if (uri.getQueryParameter(TTL) != null) {
                ttl = Integer.parseInt(uri.getQueryParameter(TTL));
            }
            Calendar now = Calendar.getInstance();
            now.add(Calendar.MINUTE, ttl);
            token.rollout_expiration = now.getTime();

            if(uri.getQueryParameter(ENROLLMENT_CRED)!= null){
                token.enrollment_credential = uri.getQueryParameter(ENROLLMENT_CRED);
            }

            pushrollout = new PushRolloutTask(token, activityInterface);

            publishProgress(STATUS_DO_PUSH_ROLLOUT);
            cancel(true);
        }
        // --------------------- END PUSH ---------------------
        // SECRET
        String secret_string = uri.getQueryParameter(SECRET);
        byte[] secret = new Base32().decode(secret_string.toUpperCase());

        // DIGITS
        int digits = 6;
        if (uri.getQueryParameter(DIGITS) != null) {
            digits = Integer.parseInt(uri.getQueryParameter(DIGITS));
        }

        // CREATE BASE TOKEN (HOTP/TOTP)
        Token tmp = new Token(secret, serial, label, type, digits);

        // ADD ADDITIONAL INFORMATION TO IT
        if (type.equals(TOTP)) {
            if (uri.getQueryParameter(PERIOD) != null) {
                tmp.setPeriod(Integer.parseInt(uri.getQueryParameter(PERIOD)));
            } else {
                tmp.setPeriod(30);
            }
        }
        if (type.equals(HOTP)) {
            if (uri.getQueryParameter(COUNTER) != null) {
                tmp.setCounter(Integer.parseInt(uri.getQueryParameter(COUNTER)));
            } else {
                tmp.setCounter(1);
            }
        }
        if (uri.getQueryParameter(ALGORITHM) != null) {
            tmp.setAlgorithm(uri.getQueryParameter(ALGORITHM).toUpperCase());
        }
        if (uri.getBooleanQueryParameter(PIN, false)) {
            tmp.setWithPIN(true);
            tmp.setLocked(true);
        }
        if (uri.getBooleanQueryParameter(PERSISTENT, false)) {
            tmp.setUndeletable(true);
        }
        // tap to show is currently not used
        if (uri.getBooleanQueryParameter(TAPTOSHOW, false)) {
            tmp.setWithTapToShow(true);
        }

        // --------------------- 2 STEP ---------------------
        // if at least one parameter for 2step is set do 2step init
        if (uri.getQueryParameter(TWOSTEP_SALT) != null ||
                uri.getQueryParameter(TWOSTEP_DIFFICULTY) != null ||
                uri.getQueryParameter(TWOSTEP_OUTPUT) != null) {

            int phonepartlength = 10; // default value
            if (uri.getQueryParameter(TWOSTEP_SALT) != null) {
                phonepartlength = Integer.parseInt(uri.getQueryParameter(TWOSTEP_SALT));
            }
            int iterations = 10000;
            if (uri.getQueryParameter(TWOSTEP_DIFFICULTY) != null) {
                iterations = Integer.parseInt(uri.getQueryParameter(TWOSTEP_DIFFICULTY));
            }
            // comes in bytes, needs to be converted to bit as parameter for PBKDF2
            int output_size = 160;

            if (uri.getQueryParameter(TWOSTEP_OUTPUT) != null) {
                output_size = Integer.parseInt(uri.getQueryParameter(TWOSTEP_OUTPUT)) * 8;
            } else {
                // if the output size is not specified, it is derived from the OTP algorithm
                // Check here for HMACSHA... because when setting the tokens algorithm above,
                // it is converted to the Hmac
                if (tmp.getAlgorithm().equals(HMACSHA1)) {
                    // do nothing default is already 20bytes = 160bit
                } else if (tmp.getAlgorithm().equals(HMACSHA256)) {
                    output_size = 256;
                } else if (tmp.getAlgorithm().equals(HMACSHA512)) {
                    output_size = 512;
                }
            }
            twoStepRollout = new TwoStepRolloutTask(tmp, phonepartlength, iterations, output_size, activityInterface);
            publishProgress(STATUS_DO_2STEP_ROLLOUT);
            cancel(true);
            //return do2StepInit(tmp, phonepartlength, iterations, output_size);
        }
        toAdd = tmp;
        publishProgress(STATUS_TOKEN_CREATION_FINISHED_OK);
        return true;
    }

    @Override
    protected void onProgressUpdate(Integer... values) {
        super.onProgressUpdate(values);

        switch (values[0]) {
            case STATUS_DO_2STEP_ROLLOUT: {
                if (twoStepRollout != null) {
                    twoStepRollout.execute();
                }
                break;
            }
            case STATUS_DO_FIREBASE_INIT: {
                if (firebaseInit != null) {
                    firebaseInit.execute();
                }
                break;
            }
            case STATUS_DO_PUSH_ROLLOUT: {
                if (pushrollout != null) {
                    pushrollout.execute();
                }
                break;
            }
            case STATUS_TOKEN_CREATION_FINISHED_OK: {
                if (toAdd != null) {
                    activityInterface.addToken(toAdd);
                }
                break;
            }
            default: break;
        }
    }

    @Override
    protected void onPostExecute(Boolean aBoolean) {
        super.onPostExecute(aBoolean);
        logprint("TOKEN CREATION ENDING");
        activityInterface.update();
    }

    @Override
    protected void onCancelled() {
        super.onCancelled();
        logprint("TOKEN CREATION ENDING");
    }
}
