/*
 * Part of this code like writeFile and readFile is based on the
 * Android Open Source Project
 *
 * Copyright (C) 2013 The Android Open Source Project
 *
 * privacyIDEA Authenticator
 *
 * Authors: Nils Behlen <nils.behlen@netknights.it>
 * Copyright (c) 2017-2019 NetKnights GmbH
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

package it.netknights.piauthenticator.utils;

import android.util.Base64;
import android.util.Log;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

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
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import it.netknights.piauthenticator.model.FirebaseInitConfig;
import it.netknights.piauthenticator.model.PushAuthRequest;
import it.netknights.piauthenticator.model.Token;

import static it.netknights.piauthenticator.utils.AppConstants.ALGORITHM;
import static it.netknights.piauthenticator.utils.AppConstants.API_KEY;
import static it.netknights.piauthenticator.utils.AppConstants.APP_ID;
import static it.netknights.piauthenticator.utils.AppConstants.COUNTER;
import static it.netknights.piauthenticator.utils.AppConstants.CRYPT_ALGORITHM;
import static it.netknights.piauthenticator.utils.AppConstants.DATAFILE;
import static it.netknights.piauthenticator.utils.AppConstants.DIGITS;
import static it.netknights.piauthenticator.utils.AppConstants.ENROLLMENT_CRED;
import static it.netknights.piauthenticator.utils.AppConstants.FB_CONFIG_FILE;
import static it.netknights.piauthenticator.utils.AppConstants.HOTP;
import static it.netknights.piauthenticator.utils.AppConstants.IV_LENGTH;
import static it.netknights.piauthenticator.utils.AppConstants.KEYFILE;
import static it.netknights.piauthenticator.utils.AppConstants.KEY_LENGTH;
import static it.netknights.piauthenticator.utils.AppConstants.LABEL;
import static it.netknights.piauthenticator.utils.AppConstants.PENDING_AUTHS;
import static it.netknights.piauthenticator.utils.AppConstants.PERIOD;
import static it.netknights.piauthenticator.utils.AppConstants.PERSISTENT;
import static it.netknights.piauthenticator.utils.AppConstants.PIN;
import static it.netknights.piauthenticator.utils.AppConstants.PROJECT_ID;
import static it.netknights.piauthenticator.utils.AppConstants.PROJECT_NUMBER;
import static it.netknights.piauthenticator.utils.AppConstants.PUBKEYFILE;
import static it.netknights.piauthenticator.utils.AppConstants.PUSH;
import static it.netknights.piauthenticator.utils.AppConstants.ROLLOUT_EXPIRATION;
import static it.netknights.piauthenticator.utils.AppConstants.ROLLOUT_STATE;
import static it.netknights.piauthenticator.utils.AppConstants.SIGNING_ALGORITHM;
import static it.netknights.piauthenticator.utils.AppConstants.State;
import static it.netknights.piauthenticator.utils.AppConstants.State.AUTHENTICATING;
import static it.netknights.piauthenticator.utils.AppConstants.State.FINISHED;
import static it.netknights.piauthenticator.utils.AppConstants.State.UNFINISHED;
import static it.netknights.piauthenticator.utils.AppConstants.SECRET;
import static it.netknights.piauthenticator.utils.AppConstants.SERIAL;
import static it.netknights.piauthenticator.utils.AppConstants.SSL_VERIFY;
import static it.netknights.piauthenticator.utils.AppConstants.TAG;
import static it.netknights.piauthenticator.utils.AppConstants.TAPTOSHOW;
import static it.netknights.piauthenticator.utils.AppConstants.TOTP;
import static it.netknights.piauthenticator.utils.AppConstants.TYPE;
import static it.netknights.piauthenticator.utils.AppConstants.URL;
import static it.netknights.piauthenticator.utils.AppConstants.WITHPIN;

public class Util {

    private String baseFilePath;
    private SecretKeyWrapper secretKeyWrapper;

    public Util(SecretKeyWrapper secretKeyWrapper, String baseFilePath) {
        this.baseFilePath = baseFilePath;
        this.secretKeyWrapper = secretKeyWrapper;
    }

    public Util() {
    }

    /**
     * This Method loads the encrypted saved tokens, in the progress the Secret Key is unwrapped
     * and used to decrypt the saved tokens
     *
     * @return An ArrayList of Tokens
     */
    public ArrayList<Token> loadTokens() {
        ArrayList<Token> tokens = new ArrayList<>();
        try {
            byte[] data = loadDataFromFile(DATAFILE);
            if (data == null) {
                return null;
            }
            JSONArray a = new JSONArray(new String(data));
            for (int i = 0; i < a.length(); i++) {
                tokens.add(makeTokenFromJSON(a.getJSONObject(i)));
            }
        } catch (JSONException e) {
            e.printStackTrace();
        }
        return tokens;
    }

    /**
     * Encrpyt and save the ArrayList of tokens with a Secret Key, which is wrapped by a Public Key
     * that is stored in the Keystore
     *
     * @param tokens ArrayList of tokens to save
     */
    public void saveTokens(ArrayList<Token> tokens) {
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

        if (saveToFile(DATAFILE, tmp.toString().getBytes())) {
            logprint("Tokenlist saved.");
        }
    }

    private Token makeTokenFromJSON(JSONObject o) throws JSONException {
        //Log.d("LOAD TOKEN FROM: ", o.toString());

        // when no serial is found (for "old" data) it is set to the label
        String serial;
        String label = o.getString(LABEL);
        try {
            serial = o.getString(SERIAL);
        } catch (JSONException e) {
            serial = label;
        }
        String type = o.getString(TYPE);

        if (type.equals(PUSH)) {
            Token t = new Token(serial, label);
            t.state = State.valueOf(o.getString(ROLLOUT_STATE));
            if (t.state.equals(UNFINISHED)) {
                t.rollout_url = o.getString(URL);
                t.enrollment_credential = o.getString(ENROLLMENT_CRED);
                t.sslVerify = o.getBoolean(SSL_VERIFY);
                try {
                    t.rollout_expiration = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss")
                            .parse(o.getString(ROLLOUT_EXPIRATION));
                } catch (ParseException e) {
                    e.printStackTrace();
                }
            }
            // Check for pending Authentication Requests
            try {
                String pendingAuths = o.getString(PENDING_AUTHS);
                t.setPendingAuths(new Gson().fromJson(pendingAuths, new TypeToken<ArrayList<PushAuthRequest>>() {
                }.getType()));
            } catch (JSONException e) {
                // there were none and that's ok
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
            tmp.setPersistent(true);
        }

        return tmp;
    }

    private JSONObject makeJSONfromToken(Token t) throws JSONException {
        JSONObject o = new JSONObject();

        o.put(SERIAL, t.getSerial());
        o.put(LABEL, t.getLabel());
        o.put(TYPE, t.getType());

        if (t.getType().equals(PUSH)) {
            State state = t.state;
            if (state.equals(AUTHENTICATING)) {
                // Don't save authenticating state, has to be finished
                // Unfinished token cannot authenticate
                state = FINISHED;
            }
            o.put(ROLLOUT_STATE, state);
            // If the rollout is not finished yet, save the data necessary to complete it
            if (t.state.equals(UNFINISHED)) {
                o.put(URL, t.rollout_url);
                o.put(ROLLOUT_EXPIRATION, new SimpleDateFormat("yyyy-MM-dd HH:mm:ss")
                        .format(t.rollout_expiration));
                o.put(ENROLLMENT_CRED, t.enrollment_credential);
                o.put(SSL_VERIFY, t.sslVerify);
            }

            // Check for pending Authentication Requests
            if (!t.getPendingAuths().isEmpty()) {
                String pendingAuths = new Gson().toJson(t.getPendingAuths());
                o.put(PENDING_AUTHS, pendingAuths);
            }
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
        if (t.isPersistent()) {
            o.put(PERSISTENT, true);
        }
        return o;
    }

    public void storePIPubkey(String key, String serial) throws GeneralSecurityException, IllegalArgumentException {
        byte[] keybytes = decodeBase64(key);

        PublicKey pubkey = PKCS1ToSubjectPublicKeyInfo.decodePKCS1PublicKey(keybytes);
        if (saveToFile(serial + "_" + PUBKEYFILE, pubkey.getEncoded())) {
            logprint("pubkey for " + serial + " saved.");
        }

        // this code is expecting pkcs8
        /*X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keybytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey pubkey = kf.generatePublic(keySpec); */
    }

    public PublicKey getPIPubkey(String serial) {
        if (baseFilePath == null) return null;
        return getPIPubkey(baseFilePath, serial);
    }

    PublicKey getPIPubkey(String filepath, String serial) {
        try {
            byte[] keybytes = loadDataFromFile(serial + "_" + PUBKEYFILE, filepath);
            // build pubkey
            if (keybytes == null) return null;
            X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(keybytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(X509publicKey);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Load the data from an encrypted file. The baseFilePath of Util will be used if set.
     * baseFilePath + "/" + fileName
     *
     * @param fileName Name of the file to load
     * @return raw data as byte array, null if no baseFilePath is set or there is no file
     */
    private byte[] loadDataFromFile(String fileName) {
        if (baseFilePath == null) return null;
        return loadDataFromFile(fileName, baseFilePath);
    }

    /**
     * Load the data from an encrypted file, using the specified baseFilePath (from context).
     * baseFilePath + "/" + fileName
     *
     * @param fileName     Name of the file to load
     * @param baseFilePath baseFilePath of the Context
     * @return raw data as byte array, null if there is no file
     */
    private byte[] loadDataFromFile(String fileName, String baseFilePath) {
        try {
            byte[] encryptedData = readFile(new File(baseFilePath + "/" + fileName));
            // decrypt
            SecretKey encryptionKey = getSecretKey(new File(baseFilePath + "/" + KEYFILE));
            if (encryptedData == null) {
                return null;
            }
            return decrypt(encryptionKey, encryptedData);
        } catch (Exception e) {
            // combine exceptions here, nothing would be done anyway
            e.printStackTrace();
        }
        return null;
    }

    private void writeFile(File file, byte[] data) throws IOException {
        try (OutputStream out = new FileOutputStream(file)) {
            out.write(data);
        }
    }

    private byte[] readFile(File file) throws IOException {
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

    public void removePubkeyFor(String serial) {
        File f = new File(baseFilePath + "/" + serial + "_" + PUBKEYFILE);
        boolean res;
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

    public void storeFirebaseConfig(FirebaseInitConfig firebaseInitConfig) {
        logprint("Storing Firebase config...");
        JSONObject o = new JSONObject();
        try {
            o.put(PROJECT_ID, firebaseInitConfig.getProjID());
            o.put(APP_ID, firebaseInitConfig.getAppID());
            o.put(API_KEY, firebaseInitConfig.getApiKey());
            o.put(PROJECT_NUMBER, firebaseInitConfig.getProjNumber());
        } catch (JSONException e) {
            e.printStackTrace();
        }
        if (saveToFile(FB_CONFIG_FILE, o.toString().getBytes())) {
            logprint("Firebase config stored.");
        }
    }

    /**
     * @return FirebaseInitConfig object or null if there is no config / error
     */
    public FirebaseInitConfig loadFirebaseConfig() {
        logprint("Loading Firebase config...");
        try {
            byte[] data = loadDataFromFile(FB_CONFIG_FILE);
            if (data == null) {
                logprint("Firebase config not found!");
                return null;
            }

            JSONObject o = new JSONObject(new String(data));
            String projID = o.getString(PROJECT_ID);
            String appID = o.getString(APP_ID);
            String api_key = o.getString(API_KEY);
            String projNumber = o.getString(PROJECT_NUMBER);

            logprint("Firebase config loaded.");
            return new FirebaseInitConfig(projID, appID, api_key, projNumber);

        } catch (Exception e) {
            e.printStackTrace();
            logprint("Missing parameter from config!");
            return null;
        }
    }

    public void removeFirebaseConfig() {
        File f = new File(baseFilePath + "/" + FB_CONFIG_FILE);
        if (f.exists()) {
            if (f.delete()) {
                logprint("Firebase config removed.");
            }
        }
    }

    /**
     * Encrypt and save the given data in the specified file and baseFilePath.
     * baseFilePath + "/" + fileName
     *
     * @param fileName     Name of the file to save to
     * @param baseFilePath Path to the app's data storage
     * @param data         Data to save
     * @return true if successful, false if error
     */
    private boolean saveToFile(String fileName, String baseFilePath, byte[] data) {
        try {
            SecretKey key = getSecretKey(new File(baseFilePath + "/" + KEYFILE));
            data = encrypt(key, data);
            writeFile(new File(baseFilePath + "/" + fileName), data);
            return true;
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return false;
    }

    /**
     * Encrypt and save the given data in the specified file.
     * baseFilePath + "/" + fileName
     *
     * @param fileName Name of the file to save to
     * @param data     Data to save
     * @return true if successful, false if error
     */
    boolean saveToFile(String fileName, byte[] data) {
        if (baseFilePath == null) return false;
        return saveToFile(fileName, baseFilePath, data);
    }

    private static byte[] encrypt(SecretKey secretKey, GCMParameterSpec iv, byte[] plainText)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(CRYPT_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        return cipher.doFinal(plainText);
    }

    private static byte[] decrypt(SecretKey secretKey, GCMParameterSpec iv, byte[] cipherText)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(CRYPT_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
        return cipher.doFinal(cipherText);
    }

    static byte[] encrypt(SecretKey secretKey, byte[] plaintext)
            throws NoSuchPaddingException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException,
            IllegalBlockSizeException, InvalidAlgorithmParameterException {
        final byte[] iv = new byte[IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec params = new GCMParameterSpec(128, iv, 0, 12);
        byte[] cipherText = encrypt(secretKey, params, plaintext);
        byte[] combined = new byte[iv.length + cipherText.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(cipherText, 0, combined, iv.length, cipherText.length);
        return combined;
    }

    static byte[] decrypt(SecretKey secretKey, byte[] cipherText)
            throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException,
            BadPaddingException, InvalidAlgorithmParameterException {
        //byte[] iv = Arrays.copyOfRange(cipherText, 0, IV_LENGTH);
        GCMParameterSpec params = new GCMParameterSpec(128, cipherText, 0, 12);
        byte[] cipher = Arrays.copyOfRange(cipherText, IV_LENGTH, cipherText.length);
        return decrypt(secretKey, params, cipher);
    }

    /**
     * Load our symmetric secret key.
     * The symmetric secret key is stored securely on disk by wrapping
     * it with a public/private key pair, possibly backed by hardware.
     */
    public SecretKey getSecretKey(File keyFile)
            throws GeneralSecurityException, IOException {
        if (secretKeyWrapper == null) {
            throw new GeneralSecurityException("No SecretKeyWrapper available!");
        }
        // Generate secret key if none exists
        if (!keyFile.exists()) {
            final byte[] raw = new byte[KEY_LENGTH];
            new SecureRandom().nextBytes(raw);
            final SecretKey key = new SecretKeySpec(raw, "AES");
            final byte[] wrapped = secretKeyWrapper.wrap(key);
            writeFile(keyFile, wrapped);
        }
        // Even if we just generated the key, always read it back to ensure we
        // can read it successfully.
        final byte[] wrapped = readFile(keyFile);
        if (wrapped == null) return null;
        return secretKeyWrapper.unwrap(wrapped);
    }

    /**
     * @param privateKey privateKey to sign the message with
     * @param message    message to sign
     * @return Base32 formatted signature
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public static String sign(PrivateKey privateKey, String message) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        byte[] bMessage = message.getBytes(StandardCharsets.UTF_8);

        Signature s = Signature.getInstance(SIGNING_ALGORITHM);
        s.initSign(privateKey);
        s.update(bMessage);

        byte[] signature = s.sign();
        return new Base32().encodeAsString(signature);
    }

    /**
     * @param publicKey publicKey to verify the signature with
     * @param signature signature to verify, !!formatted in Base32!!
     * @param payload   payload that was signed
     * @return true if the signature is valid, false otherwise
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     */
    public static boolean verifySignature(PublicKey publicKey, String signature, String payload) throws InvalidKeyException,
            NoSuchAlgorithmException, SignatureException {
        if (!new Base32().isInAlphabet(signature)) {
            logprint("verifySignature: The given signature is not Base32 encoded!");
            return false;
        }

        byte[] message = payload.getBytes(StandardCharsets.UTF_8);
        byte[] bSignature = new Base32().decode(signature);
        Signature sig = Signature.getInstance(SIGNING_ALGORITHM);

        sig.initVerify(publicKey);
        sig.update(message);
        return sig.verify(bSignature);
    }

    public byte[] decodeBase64(String key) {
        return Base64.decode(key, Base64.DEFAULT);
    }

    public String encodeBase64(byte[] data) {
        return Base64.encodeToString(data, Base64.URL_SAFE);
    }

    /**
     * Converts a byte array to a Hex String
     *
     * @param ba byte array to convert
     * @return the Hex as String
     */
    public static String byteArrayToHexString(byte[] ba) {
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
    public static byte[] hexStringToByteArray(String hex) {
        // Adding one byte to get the right conversion
        // Values starting with "0" can be converted
        byte[] bArray = new BigInteger("10" + hex, 16).toByteArray();

        // Copy all the REAL bytes, not the "first"
        byte[] ret = new byte[bArray.length - 1];
        for (int i = 0; i < ret.length; i++)
            ret[i] = bArray[i + 1];
        return ret;
    }

    public static void logprint(String msg) {
        if (msg == null)
            return;
        Log.e(TAG, msg);
    }
}