package it.netknights.piauthenticator;

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

import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Date;

import static it.netknights.piauthenticator.AppConstants.CONNECT_TIMEOUT;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_BAD_BASE64;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_DONE;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_MALFORMED_URL;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_REGISTRATION_TIME_EXPIRED;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_RESPONSE_NO_KEY;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_STEP_1;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_STEP_2;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_STEP_3;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_UNKNOWN_HOST;
import static it.netknights.piauthenticator.AppConstants.READ_TIMEOUT;
import static it.netknights.piauthenticator.Util.logprint;

public class PushRolloutTask extends AsyncTask<Void, Integer, Boolean> {

    private String serial, rollout_url, fb_token;
    private Token token;
    private AlertDialog rollout_status_dialog;
    private ActivityInterface activityInterface;

    PushRolloutTask(Token t, ActivityInterface activityInterface) {
        this.token = t;
        this.serial = t.getSerial();
        this.rollout_url = t.rollout_url;
        this.activityInterface = activityInterface;
    }

    @Override
    protected void onPreExecute() {
        super.onPreExecute();
        logprint("Starting push rollout...");
        logprint("rollout url: " + rollout_url);
        View view_pro_progress = activityInterface.getPresentActivity().getLayoutInflater().inflate(R.layout.pushrollout_loading, null);
        AlertDialog.Builder dialog_builder = new AlertDialog.Builder(activityInterface.getPresentActivity());
        dialog_builder.setView(view_pro_progress);
        dialog_builder.setCancelable(false);
        rollout_status_dialog = dialog_builder.show();
    }

    @Override
    protected Boolean doInBackground(Void... voids) {
        publishProgress(PRO_STATUS_STEP_1);
        // Verify the tokens register ttl
        Date now = new Date();
        if (now.after(token.rollout_expiration)) {
            // TODO callback -> time expired
            publishProgress(PRO_STATUS_REGISTRATION_TIME_EXPIRED);
            return false;
        }

        // 1. Generate a new keypair (RSA 4096bit), the private key is stored with the serial as alias
        PublicKey pubkey = null;
        try {
            pubkey = SecretKeyWrapper.generateKeyPair(serial, activityInterface.getPresentActivity().getBaseContext());
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
        FirebaseInstanceId.getInstance().getInstanceId().addOnSuccessListener(activityInterface.getPresentActivity(), new OnSuccessListener<InstanceIdResult>() {
            @Override
            public void onSuccess(InstanceIdResult instanceIdResult) {
                fb_token = instanceIdResult.getToken();
            }
        });
        logprint("TOKEN: " + fb_token);

        // 2. Send the pubkey and the firebase token to the rollout URL
        publishProgress(PRO_STATUS_STEP_2);

        logprint("SETTING UP CONNECTION");
        // Connection setup
        URL url = null;
        try {
            url = new URL(this.rollout_url);
        } catch (MalformedURLException e) {
            publishProgress(PRO_STATUS_MALFORMED_URL);
            e.printStackTrace();
            return false;
        }
        HttpURLConnection con = null;
        try {
            con = (HttpURLConnection) url.openConnection();
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
        con.setDoOutput(true);
        con.setDoInput(true);
        try {
            con.setRequestMethod("POST");
        } catch (ProtocolException e) {
            e.printStackTrace();
        }
        con.setReadTimeout(READ_TIMEOUT);
        con.setConnectTimeout(CONNECT_TIMEOUT);
        logprint("TRYING TO SENT");
        // Send the pubkey and firebase token
        OutputStream os = null;
        try {
            os = con.getOutputStream();
        } catch (IOException e) {
            e.printStackTrace();
            publishProgress(PRO_STATUS_UNKNOWN_HOST);
            return false;
        }

        BufferedWriter writer;
        assert os != null;
        writer = new BufferedWriter(new OutputStreamWriter(os, StandardCharsets.UTF_8));
        String key = null;
        if (pubkey != null) {
            key = Base64.encodeToString(pubkey.getEncoded(), Base64.DEFAULT);
        }
            /*logprint("URL: " + rollout_url);
            logprint("Serial: " + serial);
            logprint("Token: " + fb_token);
            logprint("Pubkey format: " + pubkey.getFormat()); */
        logprint("pubkey: " + key);
        try {
            writer.write("enrollment_credential=" + token.enrollment_credential);
            writer.write("&serial=" + serial);
            writer.write("&fbtoken=" + fb_token);
            writer.write("&pubkey=" + key);
            writer.flush();
            writer.close();
            os.close();
            con.connect();
        } catch (IOException e) {
            e.printStackTrace();
        }

        // 3. Save the pubkey from the response
        publishProgress(PRO_STATUS_STEP_3);
        logprint("GETTING RESPONSE");
        // Get the response
        int responsecode = 0;
        try {
            responsecode = con.getResponseCode();
        } catch (IOException e) {
            e.printStackTrace();
        }
        Log.e("repsonse code: ", responsecode + "");

        BufferedReader br = null;
        String line;
        StringBuffer response = new StringBuffer();
        try {
            br = new BufferedReader(new InputStreamReader(con.getInputStream()));
            while ((line = br.readLine()) != null) {
                response.append(line);
            }
            Log.e("response: ", response.toString());
            // TODO format response
        } catch (IOException e) {
            e.printStackTrace();
        }

        if (responsecode == 200) {
            if (!response.equals("")) {
                try {
                    JSONObject resp = new JSONObject(response.toString());
                    JSONObject detail = resp.getJSONObject("detail");
                    String in_key = detail.getString("public_key");
                    logprint("in_key:" + in_key);
                    Util.storePIPubkey(in_key, serial, activityInterface.getPresentActivity().getBaseContext());
                    token.rollout_finished = true;
                    publishProgress(PRO_STATUS_DONE);

                } catch (GeneralSecurityException e) {
                    // TODO response is not a key -> callback error
                    // this means the "key" field was empty or the DECODED data is not a key
                    publishProgress(PRO_STATUS_RESPONSE_NO_KEY);
                    token.rollout_finished = false;
                    e.printStackTrace();
                } catch (JSONException e) {
                    logprint("MALFORMED JSON");
                    // TODO malformed response
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (IllegalArgumentException e) {
                    logprint("BAD BASE64");
                    e.printStackTrace();
                    publishProgress(PRO_STATUS_BAD_BASE64);
                }
            }
        }
        // TODO other response codes
        con.disconnect();

        return true;
    }

    @Override
    protected void onProgressUpdate(Integer... values) {
        super.onProgressUpdate(values);
        TextView tv_pro_status;

        if (rollout_status_dialog == null) {
            logprint("cannot find status dialog");
            return;
        } else {
            tv_pro_status = rollout_status_dialog.findViewById(R.id.tv_status);
        }
        if (tv_pro_status == null) {
            logprint("cannot find status text view");
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
                MainActivity main = (MainActivity) activityInterface.getPresentActivity();
                main.tokenlistadapter.notifyDataSetChanged();
                main.saveTokenlist();
                logprint("ROLLOUT FINISHED - CLOSING DIALOG");
                break;
            }
            case PRO_STATUS_RESPONSE_NO_KEY: {
                logprint("ROLLOUT RESPONSE DID NOT CONTAIN A VALID KEY");
                rollout_status_dialog.cancel();
                showFailureDialog("Reponse did not contain key");
                break;
            }
            case PRO_STATUS_REGISTRATION_TIME_EXPIRED: {
                logprint("REGISTRATION TIME EXPIRED");
                rollout_status_dialog.cancel();
                showFailureDialog("Registration time expired! \nToken will be removed.");
                MainActivity main = (MainActivity) activityInterface.getPresentActivity();
                main.removeToken(token);
                break;
            }
            case PRO_STATUS_MALFORMED_URL: {
                logprint("URL MALFORMED");
                rollout_status_dialog.cancel();
                showFailureDialog("Rollout URL is invalid:\n" + rollout_url + "\nToken will be removed.");
                MainActivity main = (MainActivity) activityInterface.getPresentActivity();
                main.removeToken(token);
                break;
            }
            case PRO_STATUS_BAD_BASE64: {
                logprint("KEY NOT IN BASE64 FORMAT");
                rollout_status_dialog.cancel();
                showFailureDialog("The key from the server was not in the correct format!");
                break;
            }
            case PRO_STATUS_UNKNOWN_HOST: {
                logprint("UNKNOWN HOST");
                rollout_status_dialog.cancel();
                showFailureDialog("The rollout URL:\n"
                        + rollout_url
                        + "\ncannot be resolved!");
                break;
            }
            default:
                break;
        }
    }

    private void showFailureDialog(String message) {
        AlertDialog.Builder builder = new AlertDialog.Builder(activityInterface.getPresentActivity());
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
        activityInterface.addToken(token);
    }
}
