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

package it.netknights.piauthenticator.tasks;

import android.os.AsyncTask;

import org.apache.commons.codec.binary.Base32;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import it.netknights.piauthenticator.interfaces.PresenterTaskInterface;
import it.netknights.piauthenticator.model.Token;
import it.netknights.piauthenticator.utils.OTPGenerator;
import it.netknights.piauthenticator.utils.Util;

import static it.netknights.piauthenticator.utils.AppConstants.STATUS_TWO_STEP_ROLLOUT;
import static it.netknights.piauthenticator.utils.AppConstants.STATUS_TWO_STEP_ROLLOUT_DONE;
import static it.netknights.piauthenticator.utils.Util.byteArrayToHexString;
import static it.netknights.piauthenticator.utils.Util.logprint;

public class TwoStepRolloutTask extends AsyncTask<Void, Void, Boolean> {

    private final Token token;
    private int iterations;
    private int output_size_bit;
    private byte[] phonepartBytes;
    private PresenterTaskInterface presenterTaskInterface;

    public TwoStepRolloutTask(Token t, int phonepartlength, int iterations, int output_size, PresenterTaskInterface presenterTaskInterface) {
        this.token = t;
        this.iterations = iterations;
        this.output_size_bit = output_size;
        this.phonepartBytes = new byte[phonepartlength];
        this.presenterTaskInterface = presenterTaskInterface;
    }

    @Override
    protected void onPreExecute() {
        super.onPreExecute();
        logprint("Starting 2step rollout...");
        presenterTaskInterface.updateTaskStatus(STATUS_TWO_STEP_ROLLOUT, token);
    }

    @Override
    protected Boolean doInBackground(Void... params) {
        // 1. Generate random bytes for the phonepartBytes
        SecureRandom sr = new SecureRandom();
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

    private String buildResultMessage() {
        /* 3. Build the result to show to the user
            We use the first 4 characters of the sha1 hash of the client(phone) part as checksum.
            client_part being the binary random value, that the client(phone) generated:
            b32encode(sha1(client_part)[0:3] + client_part)*/
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
        result = Util.insertPeriodically(new Base32().encodeAsString(completeOutputBytes), 4);
        result = result.replaceAll("=", "");
        return result;
    }

    @Override
    protected void onPostExecute(final Boolean success) {
        // 4. Display the phone-part of the secret and first OTP to verify
        presenterTaskInterface.updateTaskStatus(STATUS_TWO_STEP_ROLLOUT_DONE, token);
        presenterTaskInterface.makeAlertDialog("Phone secret", buildResultMessage());
        logprint("2step rollout finished.");
    }
}
