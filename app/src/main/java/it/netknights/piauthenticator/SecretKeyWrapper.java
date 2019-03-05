/* Parts from The Android Open Source Project
 * Copyright (C) 2013 The Android Open Source Project
 *
 * privacyIDEA Authenticator
 *
 * Authors: Nils Behlen <nils.behlen@netknights.it>
 *
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
 */


package it.netknights.piauthenticator;

import android.annotation.SuppressLint;
import android.annotation.TargetApi;
import android.content.Context;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.support.annotation.RequiresApi;

import org.apache.commons.codec.binary.Base32;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Calendar;
import java.util.Enumeration;
import java.util.GregorianCalendar;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.security.auth.x500.X500Principal;

import static it.netknights.piauthenticator.Util.logprint;

/**
 * Wraps {@link SecretKey} instances using a public/private key pair stored in
 * the platform {@link KeyStore}. This allows us to protect symmetric keys with
 * hardware-backed crypto, if provided by the device.
 * <p>
 * See <a href="http://en.wikipedia.org/wiki/Key_Wrap">key wrapping</a> for more
 * details.
 * <p>
 * Not inherently thread safe.
 */
class SecretKeyWrapper {
    private final Cipher mCipher;
    private final KeyPair mPair;

    /**
     * Create a wrapper using the public/private key pair with the given alias.
     * If no pair with that alias exists, it will be generated.
     */
    @SuppressLint("GetInstance")
    SecretKeyWrapper(Context context, String alias)
            throws GeneralSecurityException, IOException {
        mCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        final KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);

        if (!keyStore.containsAlias(alias)) {
            generateKeyPair(context, alias);
        }

        // Even if we just generated the key, always read it back to ensure we
        // can read it successfully.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            //Following code is for API 28+
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);
            Certificate certificate = keyStore.getCertificate(alias);
            KeyStore.PrivateKeyEntry entry = new KeyStore.PrivateKeyEntry(privateKey, new Certificate[]{certificate});
            mPair = new KeyPair(entry.getCertificate().getPublicKey(), entry.getPrivateKey());
        } else {
            final KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, null);
            mPair = new KeyPair(entry.getCertificate().getPublicKey(), entry.getPrivateKey());
        }

        /*final PrivateKey privateKey = (PrivateKey) keyStore.getKey("alias", null);
        final PublicKey publicKey = privateKey != null ? keyStore.getCertificate("alias").getPublicKey() : null;
        mPair = new KeyPair(publicKey, privateKey);*/
    }

    @TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
    private static void generateKeyPair(Context context, String alias)
            throws GeneralSecurityException {
        final Calendar start = new GregorianCalendar();
        final Calendar end = new GregorianCalendar();
        end.add(Calendar.YEAR, 100);
        final KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
        final KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(context)
                .setAlias(alias)
                .setSubject(new X500Principal("CN=" + alias))
                .setSerialNumber(BigInteger.ONE)
                .setStartDate(start.getTime())
                .setEndDate(end.getTime())
                .build();
        gen.initialize(spec);
        gen.generateKeyPair();
    }

    /**
     * Wrap a {@link SecretKey} using the public key assigned to this wrapper.
     * Use {@link #unwrap(byte[])} to later recover the original
     * {@link SecretKey}.
     *
     * @return a wrapped version of the given {@link SecretKey} that can be
     * safely stored on untrusted storage.
     */
    byte[] wrap(SecretKey key) throws GeneralSecurityException {
        mCipher.init(Cipher.WRAP_MODE, mPair.getPublic());
        return mCipher.wrap(key);
    }

    /**
     * Unwrap a {@link SecretKey} using the private key assigned to this
     * wrapper.
     *
     * @param blob a wrapped {@link SecretKey} as previously returned by
     *             {@link #wrap(SecretKey)}.
     */
    SecretKey unwrap(byte[] blob) throws GeneralSecurityException {
        mCipher.init(Cipher.UNWRAP_MODE, mPair.getPrivate());

        return (SecretKey) mCipher.unwrap(blob, "AES", Cipher.SECRET_KEY);
    }

    /**
     * Generate a KeyPair and store it with the given alias in the KeyStore.
     * Return the PublicKey
     *
     * @param alias   the alias to store the key with
     * @param context needed for KeyPairGeneratorSpec
     * @return the PublicKey of the just generated KeyPair
     */
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    static PublicKey generateKeyPair(String alias, Context context) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException,
            NoSuchProviderException, InvalidAlgorithmParameterException, UnrecoverableEntryException {
        final KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        logprint("generateKeyPair for alias: " + alias);
        if (keyStore.containsAlias(alias)) {
            // TODO double entry -> overwrite?
        }
        final Calendar start = new GregorianCalendar();
        final Calendar end = new GregorianCalendar();
        end.add(Calendar.YEAR, 100);
        final KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
        final KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(context)
                .setAlias(alias)
                .setSubject(new X500Principal("CN=" + alias))
                .setSerialNumber(BigInteger.ONE)
                .setStartDate(start.getTime())
                .setEndDate(end.getTime())
                .setKeySize(4096)
                .build();
        gen.initialize(spec);
        gen.generateKeyPair();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            //Following code is for API 28+
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);
            Certificate certificate = keyStore.getCertificate(alias);
            return new KeyStore.PrivateKeyEntry(privateKey, new Certificate[]{certificate}).getCertificate().getPublicKey();
        } else {
            final KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, null);
            return entry.getCertificate().getPublicKey();
        }
    }

    /**
     * Load the PrivateKey for the given alias/serial
     *
     * @param alias the alias to load the key for
     * @return the PrivateKey
     */
    static PrivateKey getPrivateKeyFor(String alias) throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException, UnrecoverableEntryException {
        final KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        if (!keyStore.containsAlias(alias)) {
            // TODO key not found
            return null;
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            //Following code is for API 28+
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, null);
            Certificate certificate = keyStore.getCertificate(alias);
            return new KeyStore.PrivateKeyEntry(privateKey, new Certificate[]{certificate}).getPrivateKey();
        } else {
            final KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, null);
            return entry.getPrivateKey();
        }
    }

    static void printKeystore() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableEntryException {
        final KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        Enumeration<String> aliases = keyStore.aliases();
        String s;
        PrivateKey k;
        logprint("-------- KEYSTORE ELEMENTS (PrivKeys) --------");
        while (aliases.hasMoreElements()) {
            s = aliases.nextElement();
            k = getPrivateKeyFor(s);
            if (k != null) {
                logprint("" + s + " : " + k.toString());
            } else {
                logprint("" + s + " : NO KEY FOUND");
            }
        }
    }

    /**
     * Remove the privateKey from the Keystore for the given alias/serial
     *
     * @param alias                the serial is the alias of the privateKey in the Keystore
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws KeyStoreException
     */
    static void removePrivateKeyFor(String alias) throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {
        final KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        if (!keyStore.containsAlias(alias)) {
            logprint("key for alias " + alias + " was not found for deletion!");
            return;
        }
        keyStore.deleteEntry(alias);
        logprint("key for alias " + alias + " was deleted from keystore!");
    }

    /**
     *
     * @param privateKey    privateKey to sign the message with
     * @param message       message to sign
     * @return              Base32 formatted signature
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    static String sign(PrivateKey privateKey, String message) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        // TODO format of nonce??
        logprint("message to sign: " + message);
        byte[] bMessage = message.getBytes(StandardCharsets.UTF_8);

        Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign(privateKey);
        s.update(bMessage);

        byte[] signature = s.sign();
        // TODO format of signature
        return new Base32().encodeAsString(signature);
    }

    /**
     *
     * @param publicKey     publicKey to verify the signature with
     * @param signature     signature to verify, !!formatted in Base32!!
     * @param payload       payload that was signed
     * @return              true if the signature is valid, false otherwise
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     */
    static boolean verifySignature(PublicKey publicKey, String signature, String payload) throws InvalidKeyException,
            NoSuchAlgorithmException, SignatureException {
        logprint("signature to verify (b32): " + signature);
        logprint("message to verify signature for: " + payload);
        if(!new Base32().isInAlphabet(signature)){
            logprint("verifySignature: The given signature is not Base32 encoded!");
            return false;
        }

        byte[] message = payload.getBytes(StandardCharsets.UTF_8);
        byte[] bSignature = new Base32().decode(signature);
        Signature sig = Signature.getInstance("SHA256withRSA");

        sig.initVerify(publicKey);
        sig.update(message);
        return sig.verify(bSignature);
    }
}