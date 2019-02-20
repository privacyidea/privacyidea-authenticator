package it.netknights.piauthenticator;

import android.os.AsyncTask;
import android.util.Base64;

import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Map;

import static it.netknights.piauthenticator.AppConstants.AUTHENTICATION_ENDPOINT_URL;
import static it.netknights.piauthenticator.AppConstants.CONNECT_TIMEOUT;
import static it.netknights.piauthenticator.AppConstants.NONCE;
import static it.netknights.piauthenticator.AppConstants.PA_INVALID_SIGNATURE;
import static it.netknights.piauthenticator.AppConstants.PA_SIGNING_FAILURE;
import static it.netknights.piauthenticator.AppConstants.PRO_STATUS_MALFORMED_URL;
import static it.netknights.piauthenticator.AppConstants.READ_TIMEOUT;
import static it.netknights.piauthenticator.AppConstants.SERIAL;
import static it.netknights.piauthenticator.AppConstants.SIGNATURE;
import static it.netknights.piauthenticator.Util.logprint;

public class PushAuthTask extends AsyncTask<Void, Integer, Boolean> {

    private String data;
    private ActivityInterface activityInterface;

    PushAuthTask(String data, ActivityInterface activityInterface) {
        this.data = data;
        this.activityInterface = activityInterface;
    }

    PushAuthTask(String data) {
        this.data = data;
    }

    @Override
    protected void onPreExecute() {
        super.onPreExecute();
        logprint("Push authentication starting...");
    }

    @Override
    protected Boolean doInBackground(Void... voids) {
        // 0. Split data
        Map<String, String> map = Util.convert(data);
        String serial = map.get(SERIAL);
        String nonce = map.get(NONCE);
        String signature = map.get(SIGNATURE);
        String auth_endpoint_url = map.get(AUTHENTICATION_ENDPOINT_URL);
        map.remove(SIGNATURE);
        logprint("map to verify signature for: " + map.toString());
        // 1. Verify the signature
        // TODO how does the payload look like?
        boolean validSignature = false;
        try {
            validSignature = Util.verifySignature(serial, signature, map.toString(), activityInterface.getPresentActivity());
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }

        if (!validSignature) {
            logprint("INVALID SIGNATURE");
            publishProgress(PA_INVALID_SIGNATURE);
            return false;
        }

        // 2. Sign the nonce
        String signature_to_send = null;
        try {
            signature_to_send = SecretKeyWrapper.sign(serial, nonce);
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }

        if (signature_to_send == null) {
            publishProgress(PA_SIGNING_FAILURE);
            return false;
        }

        // 3. Send the nonce to the server
        logprint("SETTING UP CONNECTION");
        // Connection setup
        URL url;
        try {
            url = new URL(auth_endpoint_url);
        } catch (MalformedURLException e) {
            publishProgress(PRO_STATUS_MALFORMED_URL);
            e.printStackTrace();
            return false;
        }
        HttpURLConnection con;
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
        logprint("TRYING TO SENT THE NONCE");
        // Send the pubkey and firebase token
        OutputStream os = null;
        try {
            os = con.getOutputStream();
        } catch (IOException e) {
            e.printStackTrace();
        }
        BufferedWriter writer = null;
        try {
            writer = new BufferedWriter(new OutputStreamWriter(os, "UTF-8"));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        logprint("NONCE TO SEND: " + nonce);
        logprint("SIGNATURE TO SEND: " + signature_to_send);
        try {
            writer.write("nonce=" + nonce);
            writer.write("signature=" + signature_to_send);
            writer.flush();
            writer.close();
            os.close();
            con.connect();
        } catch (IOException e) {
            e.printStackTrace();
        }


        return true;
    }

    @Override
    protected void onProgressUpdate(Integer... values) {
        super.onProgressUpdate(values);
    }
}
