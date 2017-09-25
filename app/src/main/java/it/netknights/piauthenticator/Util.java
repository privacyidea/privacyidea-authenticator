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
import android.net.Uri;
import android.os.Build;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.util.ArrayList;

import javax.crypto.SecretKey;

import static it.netknights.piauthenticator.Token.ALGORITHM;
import static it.netknights.piauthenticator.Token.COUNTER;
import static it.netknights.piauthenticator.Token.DIGITS;
import static it.netknights.piauthenticator.Token.HOTP;
import static it.netknights.piauthenticator.Token.ISSUER;
import static it.netknights.piauthenticator.Token.LABEL;
import static it.netknights.piauthenticator.Token.PERIOD;
import static it.netknights.piauthenticator.Token.SECRET;
import static it.netknights.piauthenticator.Token.TOTP;
import static it.netknights.piauthenticator.Token.TYPE;

public class Util {


    private static final String DATAFILE = "data.dat";
    private static final String KEYFILE = "key.key";

    /**
     * Creates a token with the parameters passed in KeyURI format
     *
     * @param content The URI String
     * @return Token Object
     * @throws Exception
     */
    public static Token makeTokenFromURI(String content) throws Exception {
        content = content.replaceFirst("otpauth", "http");
        Uri uri = Uri.parse(content);
        URL url = new URL(content);

        if (!url.getProtocol().equals("http")) {
            throw new Exception("Invalid Protocol");
        }
        if (!url.getHost().equals(TOTP)) {
            if (!url.getHost().equals(HOTP)) {
                throw new Exception("No TOTP or HOTP Token");
            }
        }

        String type = url.getHost();
        String secret = uri.getQueryParameter(SECRET);
        String label = uri.getPath().substring(1);
        String issuer = uri.getQueryParameter(ISSUER);
        if (issuer != null) {
            label = issuer + ": " + label;
        }
        int digits = Integer.parseInt(uri.getQueryParameter(DIGITS));
        //byte[] secretAsbytes = new Base32().decode(secret.toUpperCase());
        Token tmp = new Token(secret, label, type, digits);

        if (type.equals(TOTP)) {
            tmp.setPeriod(Integer.parseInt(uri.getQueryParameter(PERIOD)));
        }
        if (type.equals(HOTP)) {
            tmp.setCounter(Integer.parseInt(uri.getQueryParameter(COUNTER)));
        }
        if (uri.getQueryParameter(ALGORITHM) != null) {
            tmp.setAlgorithm("Hmac" + uri.getQueryParameter(ALGORITHM).toUpperCase());
        }
        boolean pinned = uri.getBooleanQueryParameter("pin", false);
        if (pinned) {
            tmp.setWithPIN(pinned);
            tmp.setLocked(pinned);
        }
        if (uri.getBooleanQueryParameter("2step", false)) {
            Token tmp2 = start2StepInit(tmp);
            return tmp2;
        }
        if (uri.getQueryParameter("maxnum") != null) {
            int maxnumber = Integer.parseInt(uri.getQueryParameter("maxnum"));
            MainActivity.restrictionIsSet(maxnumber);
        }
        if (uri.getBooleanQueryParameter("tapshow", false)) {
            tmp.setWithTapToShow(true);
        }

        return tmp;
    }

    private static Token start2StepInit(Token tmp) {
        // when this method is entered the tokens secret is not the full secret
        // and has to be combined with salt (generated on the phone). Also the salt has to
        // be entered in PI so both sides can derive the full secret
        return tmp;
    }

    /**
     * This Method loads the encrypted saved tokens, in the progress the Secret Key is unwrapped
     * and used to decrypt the saved tokens
     *
     * @param context is needed to get the FilesDir
     * @return An ArrayList of Tokens
     */
    public static ArrayList<Token> loadTokens(Context context) {
        ArrayList<Token> tokens = new ArrayList<>();

        try {
            byte[] data = readFile(new File(context.getFilesDir() + "/" + DATAFILE));
            //-------check if keystore is supported (API 18+)-------------------
            int currentApiVersion = android.os.Build.VERSION.SDK_INT;
            if (currentApiVersion >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
                SecretKey key = EncryptionHelper.loadOrGenerateKeys(context, new File(context.getFilesDir() + "/" + KEYFILE));
                data = EncryptionHelper.decrypt(key, data);
            }
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
     * Encrpyt and save the ArrayList of tokens with a Secret Key, which wrapped by a Public Key
     * that is stored in the Keystore
     *
     * @param context Needed to get the FilesDir
     * @param tokens  ArrayList of tokens to save
     */
    public static void saveTokens(Context context, ArrayList<Token> tokens) {
        JSONArray tmp = new JSONArray();
        for (Token t : tokens) {
            try {
                tmp.put(makeJSONfromToken(t));
            } catch (JSONException e) {
                e.printStackTrace();
            }
        }
        try {
            byte[] data = tmp.toString().getBytes();
            int currentApiVersion = android.os.Build.VERSION.SDK_INT;
            if (currentApiVersion >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
                SecretKey key = EncryptionHelper.loadOrGenerateKeys(context, new File(context.getFilesDir() + "/" + KEYFILE));
                data = EncryptionHelper.encrypt(key, data);
            }
            writeFile(new File(context.getFilesDir() + "/" + DATAFILE), data);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static Token makeTokenFromJSON(JSONObject o) throws JSONException {
        //Token tmp = new Token(new Base32().decode(o.getString(SECRET)), o.getString(LABEL), o.getString(TYPE), o.getInt(DIGITS));
        Token tmp = new Token(o.getString(SECRET), o.getString(LABEL), o.getString(TYPE), o.getInt(DIGITS));
        tmp.setAlgorithm(o.getString(ALGORITHM));
        if (o.getString(TYPE).equals(HOTP)) {
            tmp.setCounter(o.getInt(COUNTER));
        }
        if (o.getString(TYPE).equals(TOTP)) {
            tmp.setPeriod(o.getInt(PERIOD));
        }
        if (o.getBoolean("haspin")) {
            tmp.setWithPIN(true);
            tmp.setPin(o.getInt("pin"));
            tmp.setLocked(true);
        }
        if (o.getBoolean("hastap")) {
            tmp.setWithTapToShow(true);
        }
        return tmp;
    }

    public static JSONObject makeJSONfromToken(Token t) throws JSONException {
        JSONObject o = new JSONObject();
        //o.put(SECRET, new String(new Base32().encode(t.getSecret())));
        o.put(SECRET, t.getSecret());
        o.put(LABEL, t.getLabel());
        o.put(DIGITS, t.getDigits());
        o.put(ALGORITHM, t.getAlgorithm());
        o.put(TYPE, t.getType());
        if (t.getType().equals(HOTP)) {
            o.put(COUNTER, t.getCounter());
        }
        if (t.getType().equals(TOTP)) {
            o.put(PERIOD, t.getPeriod());
        }
        if (t.isWithPIN()) {
            o.put("haspin", true);
            o.put("pin", t.getPin());
        } else {
            o.put("haspin", false);
        }
        if (t.isWithTapToShow()) {
            o.put("hastap", true);
        }
        return o;
    }

    public static void writeFile(File file, byte[] data) throws IOException {
        final OutputStream out = new FileOutputStream(file);
        try {
            out.write(data);
        } finally {
            out.close();
        }
    }

    public static byte[] readFile(File file) throws IOException {
        final InputStream in = new FileInputStream(file);
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int count;
            while ((count = in.read(buffer)) != -1) {
                bytes.write(buffer, 0, count);
            }
            return bytes.toByteArray();
        } finally {
            in.close();
        }
    }
}
