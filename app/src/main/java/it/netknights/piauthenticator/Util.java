/*
 * Part of this code like writeFile and readFile is based on the
 * Android Open Source Project
 *
 * Copyright (C) 2013 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */


package it.netknights.piauthenticator;

import android.content.Context;
import android.util.Base64;
import android.util.Log;

import org.apache.commons.codec.binary.Base32;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;

import static it.netknights.piauthenticator.AppConstants.ALGORITHM;
import static it.netknights.piauthenticator.AppConstants.API_KEY;
import static it.netknights.piauthenticator.AppConstants.APP_ID;
import static it.netknights.piauthenticator.AppConstants.COUNTER;
import static it.netknights.piauthenticator.AppConstants.DATAFILE;
import static it.netknights.piauthenticator.AppConstants.DIGITS;
import static it.netknights.piauthenticator.AppConstants.FB_CONFIG_FILE;
import static it.netknights.piauthenticator.AppConstants.HOTP;
import static it.netknights.piauthenticator.AppConstants.KEYFILE;
import static it.netknights.piauthenticator.AppConstants.LABEL;
import static it.netknights.piauthenticator.AppConstants.PERIOD;
import static it.netknights.piauthenticator.AppConstants.PERSISTENT;
import static it.netknights.piauthenticator.AppConstants.PIN;
import static it.netknights.piauthenticator.AppConstants.PROJECT_ID;
import static it.netknights.piauthenticator.AppConstants.PROJECT_NUMBER;
import static it.netknights.piauthenticator.AppConstants.PUBKEYFILE;
import static it.netknights.piauthenticator.AppConstants.PUSH;
import static it.netknights.piauthenticator.AppConstants.ROLLOUT_EXPIRATION;
import static it.netknights.piauthenticator.AppConstants.ROLLOUT_FINISHED;
import static it.netknights.piauthenticator.AppConstants.ROLLOUT_URL;
import static it.netknights.piauthenticator.AppConstants.SECRET;
import static it.netknights.piauthenticator.AppConstants.SERIAL;
import static it.netknights.piauthenticator.AppConstants.TAPTOSHOW;
import static it.netknights.piauthenticator.AppConstants.TOTP;
import static it.netknights.piauthenticator.AppConstants.TYPE;
import static it.netknights.piauthenticator.AppConstants.WITHPIN;

public class Util {

    private ActivityInterface activityInterface;

    Util(ActivityInterface activityInterface) {
        this.activityInterface = activityInterface;
    }


    /**
     * This Method loads the encrypted saved tokens, in the progress the Secret Key is unwrapped
     * and used to decrypt the saved tokens
     *
     * @param context is needed to get the FilesDir
     * @return An ArrayList of Tokens
     */
    static ArrayList<Token> loadTokens(Context context) {
        ArrayList<Token> tokens = new ArrayList<>();

        try {
            byte[] data = readFile(new File(context.getFilesDir() + "/" + DATAFILE));
            SecretKey key = EncryptionHelper.getSecretKey(context, new File(context.getFilesDir() + "/" + KEYFILE));
            data = EncryptionHelper.decrypt(key, data);

            JSONArray a = new JSONArray(new String(data));
            for (int i = 0; i < a.length(); i++) {
                tokens.add(makeTokenFromJSON(a.getJSONObject(i)));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return tokens;
    }

    /**
     * Encrpyt and save the ArrayList of tokens with a Secret Key, which is wrapped by a Public Key
     * that is stored in the Keystore
     *
     * @param context Needed to get the FilesDir
     * @param tokens  ArrayList of tokens to save
     */
    static void saveTokens(Context context, ArrayList<Token> tokens) {
        JSONArray tmp = new JSONArray();
        if (tokens == null) {
            return;
        }
        for (Token t : tokens) {
            try {
                tmp.put(makeJSONfromToken(t));
            } catch (JSONException e) {
                e.printStackTrace();
            }
        }
        try {
            byte[] data = tmp.toString().getBytes();
            SecretKey key = EncryptionHelper.getSecretKey(context, new File(context.getFilesDir() + "/" + KEYFILE));
            data = EncryptionHelper.encrypt(key, data);
            writeFile(new File(context.getFilesDir() + "/" + DATAFILE), data);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static Token makeTokenFromJSON(JSONObject o) throws JSONException {
        //Log.d("LOAD TOKEN FROM: ", o.toString());

        // when no serial is found (for "old" data) it is set to the label
        String serial;
        try {
            serial = o.getString(SERIAL);
        } catch (JSONException e) {
            serial = o.getString(SERIAL);
        }
        // when loading "old" data the type is still a string so we convert it here
        String type = o.getString(TYPE);;

        String label = o.getString(LABEL);

        if (type.equals(PUSH)) {
            Token t = new Token(serial, label);
            t.rollout_finished = o.getBoolean(ROLLOUT_FINISHED);
            // TODO add exp date / url
            t.rollout_url = o.getString(ROLLOUT_URL);
            try {
                t.rollout_expiration = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").parse(o.getString(ROLLOUT_EXPIRATION));
            } catch (ParseException e) {
                e.printStackTrace();
            }
            return t;
        }

        Token tmp = new Token(new Base32().decode(o.getString(SECRET)), serial, label,
                type, o.getInt(DIGITS));

        tmp.setAlgorithm(o.getString(ALGORITHM));
        if (o.getString(TYPE).equals(HOTP)) {
            tmp.setCounter(o.getInt(COUNTER));
        }
        if (o.getString(TYPE).equals(TOTP)) {
            tmp.setPeriod(o.getInt(PERIOD));
        }
        if (o.optBoolean(WITHPIN, false)) {
            tmp.setWithPIN(true);
            tmp.setPin(o.getString(PIN));
            tmp.setLocked(true);
        }
        if (o.optBoolean(TAPTOSHOW, false)) {
            tmp.setWithTapToShow(true);
        }
        if (o.optBoolean(PERSISTENT)) {
            tmp.setUndeletable(true);
        }

        return tmp;
    }

    private static JSONObject makeJSONfromToken(Token t) throws JSONException {
        //logprint("saving tokens");
        JSONObject o = new JSONObject();

        o.put(SERIAL, t.getSerial());
        o.put(LABEL, t.getLabel());
        o.put(TYPE, t.getType());

        if (t.getType().equals(PUSH)) {
            o.put(ROLLOUT_FINISHED, t.rollout_finished);
            //TODO add exp date / url
            o.put(ROLLOUT_URL, t.rollout_url);
            o.put(ROLLOUT_EXPIRATION, new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(t.rollout_expiration));
            return o;
        }

        o.put(SECRET, new String(new Base32().encode(t.getSecret())));
        o.put(DIGITS, t.getDigits());
        o.put(ALGORITHM, t.getAlgorithm());

        if (t.getType().equals(HOTP)) {
            o.put(COUNTER, t.getCounter());
        }
        if (t.getType().equals(TOTP)) {
            o.put(PERIOD, t.getPeriod());
        }
        if (t.isWithPIN()) {
            o.put(WITHPIN, true);
            o.put(PIN, t.getPin());
        } else {
            o.put(WITHPIN, false);
        }
        if (t.isWithTapToShow()) {
            o.put(TAPTOSHOW, true);
        }
        if (t.isUndeletable()) {
            o.put(PERSISTENT, true);
        }
        logprint("SAVE TOKEN AS: " + o.toString());
        return o;
    }

    static void storePIPubkey(String key, String serial, Context context) throws GeneralSecurityException, IOException, IllegalArgumentException {
        byte[] keybytes = Base64.decode(key.getBytes(), Base64.DEFAULT);
       
        PublicKey pubkey = PKCS1ToSubjectPublicKeyInfo.decodePKCS1PublicKey(keybytes);

        // this code is expecting pkcs8
        /*X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keybytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey pubkey = kf.generatePublic(keySpec); */

        // encrypt
        SecretKey encryptionKey = EncryptionHelper.getSecretKey(context,
                new File(context.getFilesDir() + "/" + KEYFILE));

        byte[] dataToSave = EncryptionHelper.encrypt(encryptionKey, pubkey.getEncoded());
        // write to file
        writeFile(new File(context.getFilesDir() + "/" + serial + "_" + PUBKEYFILE), dataToSave);
    }

    static PublicKey getPIPubkey(Context context, String serial) {
        try {
            byte[] encryptedData = readFile(new File(context.getFilesDir() + "/" + serial + "_" + PUBKEYFILE));
            // decrypt
            SecretKey encryptionKey = EncryptionHelper.getSecretKey(context,
                    new File(context.getFilesDir() + "/" + KEYFILE));
            if (encryptedData == null) {
                return null;
            }
            byte[] keybytes = EncryptionHelper.decrypt(encryptionKey, encryptedData);
            // build pubkey
            X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(keybytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(X509publicKey);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    static Map<String, String> convert(String str) {
        str = str.replace(",", "");
        String[] tokens = str.split(" |=");
        Map<String, String> map = new HashMap<>();
        for (int i = 0; i < tokens.length - 1; ) map.put(tokens[i++], tokens[i++]);
        return map;
    }

    /**
     * Converts a byte array to a Hex String
     *
     * @param ba byte array to convert
     * @return the Hex as String
     */
    static String byteArrayToHexString(byte[] ba) {
        StringBuilder str = new StringBuilder();
        for (int i = 0; i < ba.length; i++)
            str.append(String.format("%02x", ba[i]));
        return str.toString();
    }

    /**
     * Converts a Hex string to a byte array
     *
     * @param hex: the Hex string to convert
     * @return a byte array
     */
    static byte[] hexStringToByteArray(String hex) {
        // Adding one byte to get the right conversion
        // Values starting with "0" can be converted
        byte[] bArray = new BigInteger("10" + hex, 16).toByteArray();

        // Copy all the REAL bytes, not the "first"
        byte[] ret = new byte[bArray.length - 1];
        for (int i = 0; i < ret.length; i++)
            ret[i] = bArray[i + 1];
        return ret;
    }

    static void writeFile(File file, byte[] data) throws IOException {
        try (OutputStream out = new FileOutputStream(file)) {
            out.write(data);
        }
    }

    static byte[] readFile(File file) throws IOException {
        try (InputStream in = new FileInputStream(file)) {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int count;
            while ((count = in.read(buffer)) != -1) {
                bytes.write(buffer, 0, count);
            }
            return bytes.toByteArray();
        } catch (FileNotFoundException e) {
            logprint("File: " + file.getAbsolutePath() + " not found");
            return null;
        }
    }

    public static void logprint(String msg) {
        if (msg == null)
            return;
        Log.e("PI-Authenticator", msg);
    }

    void printPubkeys(ArrayList<Token> tokenlist) {
        logprint("------ PUBKEYS (IN FILES) ------");
        PublicKey pub;
        for (Token t : tokenlist) {
            if (t.getType().equals(PUSH)) {
                pub = getPIPubkey(activityInterface.getPresentActivity().getBaseContext(), t.getSerial());
                if (pub != null)
                    logprint(t.getSerial() + " : " + pub.getFormat());
            }
        }
    }

    void removePubkeyFor(String serial) {
        File f = new File(activityInterface.getPresentActivity().getFilesDir() + "/" + serial + "_" + PUBKEYFILE);
        boolean res = false;
        if (f.exists()) {
            res = f.delete();
            if (res) {
                logprint("pubkey file of " + serial + " was found and deleted!");
            } else {
                logprint("pubkey file of " + serial + " was not deleted!");
            }
        } else {
            logprint("pubkey file of " + serial + " was not found!");
        }
    }

    void storeFirebaseConfig(String projID, String appID, String api_key, String projNumber) {
        logprint("Storing Firebase config...");
        JSONObject o = new JSONObject();
        try {
            o.put(PROJECT_ID, projID);
            o.put(APP_ID, appID);
            o.put(API_KEY, api_key);
            o.put(PROJECT_NUMBER, projNumber);
        } catch (JSONException e) {
            e.printStackTrace();
        }
        byte[] data = o.toString().getBytes();
        SecretKey key = null;
        try {
            key = EncryptionHelper.getSecretKey(activityInterface.getPresentActivity(),
                    new File(activityInterface.getPresentActivity().getFilesDir() + "/" + KEYFILE));
            data = EncryptionHelper.encrypt(key, data);
            writeFile(new File(activityInterface.getPresentActivity().getFilesDir() + "/" + FB_CONFIG_FILE), data);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        logprint("Firebase config stored.");
    }

    void initFirebase() {
        logprint("Loading Firebase config...");
        try {
            byte[] data = readFile(new File(activityInterface.getPresentActivity().getFilesDir() + "/" + FB_CONFIG_FILE));
            if (data == null) {
                logprint("Firebase config not found!");
                return;
            }

            SecretKey key = EncryptionHelper.getSecretKey(activityInterface.getPresentActivity(),
                    new File(activityInterface.getPresentActivity().getFilesDir() + "/" + KEYFILE));
            data = EncryptionHelper.decrypt(key, data);

            JSONObject o = new JSONObject(new String(data));
            String projID = o.getString(PROJECT_ID);
            String appID = o.getString(APP_ID);
            String api_key = o.getString(API_KEY);
            String projNumber = o.getString(PROJECT_NUMBER);

            if (projID == null || appID == null || api_key == null || projNumber == null) {
                logprint("Missing parameter from config!");
                return;
            }
            logprint("Firebase config loaded.");
            new FirebaseInitTask(projID, appID, api_key, projNumber, activityInterface).execute();


        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}