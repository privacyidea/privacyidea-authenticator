package it.netknights.piauthenticator;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.os.AsyncTask;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.TextView;

import com.google.android.gms.tasks.OnSuccessListener;
import com.google.firebase.iid.FirebaseInstanceId;
import com.google.firebase.iid.InstanceIdResult;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.lang.ref.WeakReference;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;

import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_RESPONSE_NO_KEY;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_STEP_1;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_STEP_2;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_STEP_3;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_DONE;
import static it.netknights.piauthenticator.Util.logprint;

public class PushRollout extends AsyncTask<Void, Integer, Boolean> {

    private String serial, rollout_url, fb_token;
    private Token token;
    private final WeakReference<Activity> mActivity;
    private AlertDialog rollout_status_dialog;

    PushRollout(Token t, Activity myActivity) {
        this.token = t;
        this.serial = t.getSerial();
        this.rollout_url = t.rollout_url;
        this.mActivity = new WeakReference<>(myActivity);
    }

    @Override
    protected void onPreExecute() {
        super.onPreExecute();
        logprint("STARTING LOADING SCREEN");
        //update_delegate.startLoadingScreen();

        View view_pro_progress = mActivity.get().getLayoutInflater().inflate(R.layout.pushrollout_loading, null);


        AlertDialog.Builder dialog_builder = new AlertDialog.Builder(mActivity.get());
        dialog_builder.setView(view_pro_progress);
        dialog_builder.setCancelable(false);
        rollout_status_dialog = dialog_builder.show();
        logprint("LOADING SCREEN END");
    }

    @Override
    protected Boolean doInBackground(Void... voids) {
        publishProgress(PRO_STATUS_STEP_1);
        // Verify the tokens register ttl
        Date now = new Date();
        if (now.after(token.rollout_expiration)) {
            // TODO callback -> time expired
            publishProgress();
            return false;
        }

        logprint("PUSH ROLLOUT STARTED");
        // 1. Generate a new keypair (RSA 4096bit), the private key is stored with the serial as alias
        PublicKey pubkey = null;
        try {
            pubkey = SecretKeyWrapper.generateKeyPair(serial, mActivity.get().getBaseContext());
        } catch (KeyStoreException | UnrecoverableEntryException | InvalidAlgorithmParameterException | NoSuchProviderException
                | IOException | NoSuchAlgorithmException |
                CertificateException e) {
            e.printStackTrace();
        }
        if (pubkey == null) {
            // error -> return?
            logprint("PUBKEY IS NULL!!!");
        }

        // Get the Firebase fb_token
        logprint("GETTING FIREBASE TOKEN");
        FirebaseInstanceId.getInstance().getInstanceId().addOnSuccessListener(mActivity.get(), new OnSuccessListener<InstanceIdResult>() {
            @Override
            public void onSuccess(InstanceIdResult instanceIdResult) {
                fb_token = instanceIdResult.getToken();
            }
        });
        if (fb_token != null) {
            logprint("TOKEN: " + fb_token);
        }

        // 2. Send the pubkey and the firebase token to the rollout URL
        publishProgress(PRO_STATUS_STEP_2);
        if (rollout_url == null) {
            // error -> return?
        }
        try {
            logprint("SETTING UP CONNECTION");
            // Connection setup
            URL url = new URL(this.rollout_url);
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setDoOutput(true);
            con.setDoInput(true);
            con.setRequestMethod("POST");
//            con.setReadTimeout(READ_TIMEOUT);
//            con.setConnectTimeout(CONNECT_TIMEOUT);
            logprint("TRYING TO SENT");
            // Send the pubkey and firebase token
            OutputStream os = con.getOutputStream();
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(os, "UTF-8"));
            String key = null;
            if (pubkey != null) {
                key = Base64.encodeToString(pubkey.getEncoded(), Base64.DEFAULT);
                byte[] kb = pubkey.getEncoded();
                logprint("key byte count: " + kb.length);
            }
            /*logprint("URL: " + rollout_url);
            logprint("Serial: " + serial);
            logprint("Token: " + fb_token);
            logprint("Pubkey: " + key);
            logprint("Pubkey format: " + pubkey.getFormat()); */
            writer.write("serial=" + serial);
            writer.write("&otpkey=" + fb_token);
            writer.write("&pubkey=" + key);

            writer.flush();
            writer.close();
            os.close();
            con.connect();

            // 3. Save the pubkey from the response
            publishProgress(PRO_STATUS_STEP_3);
            logprint("GETTING RESPONSE");
            // Get the response
            int responsecode = con.getResponseCode();
            Log.e("repsonse code: ", responsecode + "");

            InputStream is = con.getInputStream();
            BufferedReader br = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8));
            String response = "";
            while (br.readLine() != null) {
                response += br.readLine();
            }
            Log.e("response: ", response);
            // TODO format response
            if (responsecode == 200) {
                if (!response.equals("")) {
                    try {
                        Util.storePIPubkey(response, serial, mActivity.get().getBaseContext());
                        token.rollout_finished = true;
                        publishProgress(PRO_STATUS_DONE);

                    } catch (GeneralSecurityException e) {
                        // TODO response is not a key -> callback error
                        publishProgress(PRO_STATUS_RESPONSE_NO_KEY);
                        token.rollout_finished = false;
                        e.printStackTrace();
                    }
                }
            }
            // TODO other response codes
        } catch (IOException e) {
            e.printStackTrace();
        }
        return true;
    }

    @Override
    protected void onProgressUpdate(Integer... values) {
        super.onProgressUpdate(values);
        TextView tv_pro_status;

        if (rollout_status_dialog == null) {
            logprint("cant find status dialog");
            return;
        } else {
            tv_pro_status = rollout_status_dialog.findViewById(R.id.pro_status);
        }
        if (tv_pro_status == null) {
            logprint("cant find status text view");
            return;
        }

        switch (values[0]) {
            case PRO_STATUS_STEP_1: {
                tv_pro_status.setText("(1/3) Preparing registration data");
                break;
            }
            case PRO_STATUS_STEP_2: {
                tv_pro_status.setText("(2/3) Sending data to server");
                break;
            }
            case PRO_STATUS_STEP_3: {
                tv_pro_status.setText("(3/3) Processing data from server");
                break;
            }
            case PRO_STATUS_DONE: {
                rollout_status_dialog.cancel();
                logprint("ROLLOUT FINISHED - CLOSING DIALOG");
                break;
            }
            case PRO_STATUS_RESPONSE_NO_KEY: {
                logprint("ROLLOUT RESPONSE DID NOT CONTAIN A VALID KEY");
                rollout_status_dialog.cancel();
                showFailureDialog("Reponse did not contain key");
            }
            default:
                break;
        }
    }

    private void showFailureDialog(String message) {
        AlertDialog.Builder builder = new AlertDialog.Builder(mActivity.get());
        builder.setTitle("Rollout failed");
        builder.setMessage(message);
        builder.setCancelable(false);
        builder.setPositiveButton("OK", new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                dialog.cancel();
            }
        });
        builder.show();
    }

    @Override
    protected void onPostExecute(Boolean aBoolean) {
        super.onPostExecute(aBoolean);
    }
}
