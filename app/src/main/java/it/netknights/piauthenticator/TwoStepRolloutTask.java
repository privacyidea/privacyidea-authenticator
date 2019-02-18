package it.netknights.piauthenticator;

import android.app.AlertDialog;
import android.app.ProgressDialog;
import android.content.DialogInterface;
import android.os.AsyncTask;

import org.apache.commons.codec.binary.Base32;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import static it.netknights.piauthenticator.Util.byteArrayToHexString;
import static it.netknights.piauthenticator.Util.logprint;

public class TwoStepRolloutTask extends AsyncTask<Void, Void, Boolean> {

    private final Token token;
    private ProgressDialog pd;
    private int iterations;
    private int output_size_bit;
    byte[] phonepartBytes;
    ActivityInterface activityInterface;

    TwoStepRolloutTask(Token t, int phonepartlength, int iterations, int output_size, ActivityInterface activityInterface) {
        this.token = t;
        this.iterations = iterations;
        this.output_size_bit = output_size;
        this.phonepartBytes = new byte[phonepartlength];
        this.activityInterface = activityInterface;
    }

    @Override
    protected void onPreExecute() {
        super.onPreExecute();
        logprint("Starting 2step rollout...");
        pd = new ProgressDialog(activityInterface.getPresentActivity());
        pd.setMessage("Please wait while the secret is generated");
        pd.setProgressStyle(ProgressDialog.STYLE_SPINNER);
        pd.setCancelable(false);
        pd.setIndeterminate(true);
        pd.show();
    }

    @Override
    protected Boolean doInBackground(Void... params) {
        // 1. Generate random bytes for the phonepartBytes
        SecureRandom sr = new SecureRandom(); //Seeded by PRNGFixes
        sr.nextBytes(phonepartBytes);

        String server_secret_hex = byteArrayToHexString(token.getSecret());
        char[] ch = server_secret_hex.toCharArray();
        byte[] completesecretBytes = new byte[(output_size_bit / 8)];
        // 2. PBKDF2 with the specified parameters
        try {
            completesecretBytes = OTPGenerator.generatePBKDFKey(ch, phonepartBytes, iterations, output_size_bit);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        token.setSecret(completesecretBytes);
        return true;
    }

    @Override
    protected void onPostExecute(final Boolean success) {
        // 4. Display the phone-part of the secret and first OTP to verify
        pd.dismiss();
        AlertDialog.Builder builder = new AlertDialog.Builder(activityInterface.getPresentActivity());
        builder.setCancelable(false);
        builder.setPositiveButton("Ok", new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                dialog.cancel();
            }
        });
        builder.setTitle("Phonepart");
        builder.setMessage(buildResultMessage());
        final AlertDialog alert = builder.create();
        MainActivity.changeDialogFontColor(alert);
        alert.show();
        logprint("2step rollout finished.");
        activityInterface.addToken(token);
    }

    private String buildResultMessage() {
            /* 3. Build the result to show to the user
            We use the first 4 characters of the sha1 hash of the client(phone) part as checksum.
            client_part being the binary random value, that the client(phone) generated:
            b32encode( sha1(client_part)[0:3] + client_part)*/
        String result;
        byte[] digest = new byte[20];
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            digest = md.digest(phonepartBytes);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        byte[] checksumBytes = new byte[4];
        System.arraycopy(digest, 0, checksumBytes, 0, 4);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            outputStream.write(checksumBytes);
            outputStream.write(phonepartBytes);
        } catch (IOException e) {
            e.printStackTrace();
        }

        byte completeOutputBytes[] = outputStream.toByteArray();
        result = insertPeriodically(new Base32().encodeAsString(completeOutputBytes), " ", 4);
        result = result.replaceAll("=", "");
        return result;
    }

    String insertPeriodically(String text, String insert, int period) {
        StringBuilder builder = new StringBuilder(text.length() + insert.length() * (text.length() / period) + 1);
        int index = 0;
        String prefix = "";
        while (index < text.length()) {
            builder.append(prefix);
            prefix = insert;
            builder.append(text.substring(index,
                    Math.min(index + period, text.length())));
            index += period;
        }
        return builder.toString();
    }
}
