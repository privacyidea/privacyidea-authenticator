package it.netknights.androidTest;

import android.content.Context;
import android.os.Build;
import android.support.test.InstrumentationRegistry;
import android.support.test.filters.LargeTest;
import android.support.test.runner.AndroidJUnit4;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import it.netknights.piauthenticator.EncryptionHelper;
import it.netknights.piauthenticator.MainActivity;
import it.netknights.piauthenticator.Token;
import it.netknights.piauthenticator.Util;

import static it.netknights.piauthenticator.OTPGenerator.generateHOTP;
import static it.netknights.piauthenticator.OTPGenerator.generatePBKDFKey;
import static it.netknights.piauthenticator.OTPGenerator.byteArrayToHexString;
import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertTrue;
import static junit.framework.Assert.fail;

@RunWith(AndroidJUnit4.class)
@LargeTest
public class InstrumentedTest {
    @Test
    public void testMakeTokenFromURI() throws Exception {
        Context context = InstrumentationRegistry.getTargetContext();
        //delete all files to simulate a fresh installation, especially the generation of a new keypair
        if (android.os.Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
            final KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            keyStore.deleteEntry("settings");

        }
        MainActivity utils = new MainActivity(); //TODO update this test
        assertTrue(new File(context.getFilesDir() + "/data.dat").delete());
        assertTrue(new File(context.getFilesDir() + "/key.key").delete());


        Token hotp = utils.makeTokenFromURI("otpauth://hotp" +
                "/OATH00014BE1?secret=2VKLHJMESGDZDXO7UO5GRH6T34CSYWYY&counter=1&digits=6&issuer=privacyIDEA");
        Token totp = utils.makeTokenFromURI("otpauth://totp" +
                "/TOTP00114F8F?secret=HI64N3EHBUWXWHJWAGLNYBHAXWPZMD3N&period=60&digits=6&issuer=privacyIDEA&algorithm=SHA256");

        assertEquals("privacyIDEA: OATH00014BE1", hotp.getLabel());
        assertEquals(6, hotp.getDigits());
        assertEquals("HmacSHA1", hotp.getAlgorithm());
        assertEquals(1, hotp.getCounter());
        assertEquals(0, hotp.getPeriod());
        assertEquals("hotp", hotp.getType());
        assertEquals("2VKLHJMESGDZDXO7UO5GRH6T34CSYWYY", hotp.getSecret());
        assertEquals("privacyIDEA: TOTP00114F8F", totp.getLabel());
        assertEquals(60, totp.getPeriod());
        assertEquals(0, totp.getCounter());
        assertEquals("HmacSHA256", totp.getAlgorithm());


        ArrayList<Token> ar = new ArrayList<>();
        ar.add(hotp);
        ar.add(totp);
        Util.saveTokens(context, ar);
        ArrayList<Token> loaded = Util.loadTokens(context);

        assertEquals("privacyIDEA: OATH00014BE1", loaded.get(0).getLabel());
        assertEquals(6, loaded.get(0).getDigits());
        assertEquals("HmacSHA1", loaded.get(0).getAlgorithm());
        assertEquals(1, loaded.get(0).getCounter());
        assertEquals(0, loaded.get(0).getPeriod());
        assertEquals("hotp", loaded.get(0).getType());
        assertEquals("2VKLHJMESGDZDXO7UO5GRH6T34CSYWYY", loaded.get(0).getSecret());

        assertEquals("privacyIDEA: TOTP00114F8F", loaded.get(1).getLabel());
        assertEquals(60, loaded.get(1).getPeriod());
        assertEquals(0, loaded.get(1).getCounter());
        assertEquals("HmacSHA256", loaded.get(1).getAlgorithm());
        assertEquals("HI64N3EHBUWXWHJWAGLNYBHAXWPZMD3N", loaded.get(1).getSecret());

        hotp.setCurrentOTP("523432");
        hotp.setType("totp");
        hotp.setLabel("test setlabel");
        String s = "Hallo test123";
        hotp.setSecret(s);
        assertEquals("523432", hotp.getCurrentOTP());
        assertEquals("totp", hotp.getType());
        assertEquals(s, hotp.getSecret());
        assertEquals("test setlabel", hotp.getLabel());

        //test the exceptions
        try {
            Token fail1 = utils.makeTokenFromURI("ftp://hotp" +
                    "/OATH00014BE1?secret=2VKLHJMESGDZDXO7UO5GRH6T34CSYWYY&counter=1&digits=6&issuer=privacyIDEA");
            fail("this should throw: invalid protocol");
        } catch (Exception e) {
            assertEquals("Invalid Protocol", e.getMessage());
        }
        try {
            Token fail2 = utils.makeTokenFromURI("otpauth://ptoh" +
                    "/OATH00014BE1?secret=2VKLHJMESGDZDXO7UO5GRH6T34CSYWYY&counter=1&digits=6&issuer=privacyIDEA");
            fail("this should throw: no totp/hotp");
        } catch (Exception e) {
            assertEquals("No TOTP or HOTP Token", e.getMessage());
        }
    }

    @Test
    public void testRWFile() throws IOException {
        File f = new File(InstrumentationRegistry.getTargetContext().getFilesDir() + "/test");
        String text = "testtext";
        Util.writeFile(f, text.getBytes());
        byte[] retrieved = Util.readFile(f);
        assertTrue(Arrays.equals(retrieved, text.getBytes()));
    }

    @Test
    public void testOTPGenerator() throws Exception {
        // Testvectors for TOTP are from https://tools.ietf.org/html/rfc6238#appendix-B

        String sha256 = "HmacSHA256";
        String sha512 = "HmacSHA512";
        String sha1 = "HmacSHA1";
        // The original seed is "12345678901234567890" as ASCII String
        // Seed as HEX for HMAC-SHA1 - 20 bytes
        String seed = "3132333435363738393031323334353637383930";
        // Seed as HEX for HMAC-SHA256 - 32 bytes
        String seed32 = "3132333435363738393031323334353637383930" +
                "313233343536373839303132";
        // Seed as HEX for HMAC-SHA512 - 64 bytes
        String seed64 = "3132333435363738393031323334353637383930" +
                "3132333435363738393031323334353637383930" +
                "3132333435363738393031323334353637383930" +
                "31323334";
        String digits = "8";

        long X = 30;    // The period: 30 seconds
        long testTime[] = {59L, 1111111109L, 1111111111L,
                1234567890L, 2000000000L, 20000000000L};

        long time0 = testTime[0] / X;
        String step0 = Long.toHexString(time0).toUpperCase();
        long time1 = testTime[1] / X;
        String step1 = Long.toHexString(time1).toUpperCase();
        long time2 = testTime[2] / X;
        String step2 = Long.toHexString(time2).toUpperCase();
        long time3 = testTime[3] / X;
        String step3 = Long.toHexString(time3).toUpperCase();
        long time4 = testTime[4] / X;
        String step4 = Long.toHexString(time4).toUpperCase();
        long time5 = testTime[5] / X;
        String step5 = Long.toHexString(time5).toUpperCase();

        assertEquals(94287082, generateHOTP(seed, step0, digits, sha1));
        assertEquals(46119246, generateHOTP(seed32, step0, digits, sha256));
        assertEquals(90693936, generateHOTP(seed64, step0, digits, sha512));
        assertEquals(7081804, generateHOTP(seed, step1, digits, sha1));
        assertEquals(68084774, generateHOTP(seed32, step1, digits, sha256));
        assertEquals(25091201, generateHOTP(seed64, step1, digits, sha512));
        assertEquals(14050471, generateHOTP(seed, step2, digits, sha1));
        assertEquals(67062674, generateHOTP(seed32, step2, digits, sha256));
        assertEquals(99943326, generateHOTP(seed64, step2, digits, sha512));
        assertEquals(89005924, generateHOTP(seed, step3, digits, sha1));
        assertEquals(91819424, generateHOTP(seed32, step3, digits, sha256));
        assertEquals(93441116, generateHOTP(seed64, step3, digits, sha512));
        assertEquals(69279037, generateHOTP(seed, step4, digits, sha1));
        assertEquals(90698825, generateHOTP(seed32, step4, digits, sha256));
        assertEquals(38618901, generateHOTP(seed64, step4, digits, sha512));
        assertEquals(65353130, generateHOTP(seed, step5, digits, sha1));
        assertEquals(77737706, generateHOTP(seed32, step5, digits, sha256));
        assertEquals(47863826, generateHOTP(seed64, step5, digits, sha512));
    }


    @Test
    public void testEncryptionHelper() throws NoSuchPaddingException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException,
            IllegalBlockSizeException, UnsupportedEncodingException, InvalidAlgorithmParameterException, DecoderException {

        // https://golang.org/src/crypto/cipher/gcm_test.go
        String[][] testCases = new String[][]{
                new String[]{"11754cd72aec309bf52f7687212e8957", "3c819d9a9bed087615030b65", "", "250327c674aaf477aef2675748cf6971"},
                new String[]{"ca47248ac0b6f8372a97ac43508308ed", "ffd2b598feabc9019262d2be", "", "60d20404af527d248d893ae495707d1a"},
                new String[]{"7fddb57453c241d03efbed3ac44e371c", "ee283a3fc75575e33efd4887", "d5de42b461646c255c87bd2962d3b9a2", "2ccda4a5415cb91e135c2a0f78c9b2fdb36d1df9b9d5e596f83e8b7f52971cb3"},
                new String[]{"ab72c77b97cb5fe9a382d9fe81ffdbed", "54cc7dc2c37ec006bcc6d1da", "007c5e5b3e59df24a7c355584fc1518d", "0e1bde206a07a9c2c1b65300f8c649972b4401346697138c7a4891ee59867d0c"},
                new String[]{"feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888", "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
                        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f59854d5c2af327cd64a62cf35abd2ba6fab4"},
        };
        for (String[] testCase : testCases) {

            SecretKeySpec k = new SecretKeySpec(new Hex().decode(testCase[0].getBytes()), "AES");
            IvParameterSpec iv = new IvParameterSpec(new Hex().decode(testCase[1].getBytes()));

            byte[] cipherTExt = EncryptionHelper.encrypt(k, iv, new Hex().decode(testCase[2].getBytes()));
            String cipher = new String(new Hex().encode(cipherTExt));

            assertEquals(cipher, testCase[3]);
            assertEquals(testCase[2], new String(new Hex().encode(EncryptionHelper.decrypt(k, iv, cipherTExt))));
        }
    }

    @Test
    public void testPBKDF2() throws InvalidKeySpecException, NoSuchAlgorithmException {
        // Testvectors are from https://www.rfc-editor.org/rfc/rfc6070.txt
        // 16Mio. iterations testvector is not used, takes forever
        // char[] pw , byte[] salt, int iterations, int length in bit

        char[] p = "password".toCharArray();
        byte[] s = new byte[0];
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
            s = "salt".getBytes(StandardCharsets.US_ASCII);
        }
        assertEquals("0c60c80f961f0e71f3a9b524af6012062fe037a6", byteArrayToHexString(generatePBKDFKey(p, s, 1, 160)));
        assertEquals("ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957", byteArrayToHexString(generatePBKDFKey(p, s, 2, 160)));
        assertEquals("4b007901b765489abead49d926f721d065a429c1", byteArrayToHexString(generatePBKDFKey(p, s, 4096, 160)));
        //assertEquals("eefe3d61cd4da4e4e9945b3d6ba2158c2634e984", byteArrayToHexString(generatePBKDFKey(p, s, 16777216, 160)));

        p = "passwordPASSWORDpassword".toCharArray();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
            s = "saltSALTsaltSALTsaltSALTsaltSALTsalt".getBytes(StandardCharsets.US_ASCII);
        }
        assertEquals("3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038", byteArrayToHexString(generatePBKDFKey(p, s, 4096, 200)));

        p = "pass\0word".toCharArray();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
            s = "sa\0lt".getBytes(StandardCharsets.US_ASCII);
        }
        assertEquals("56fa6aa75548099dcc37d7f03425e0c3", byteArrayToHexString(generatePBKDFKey(p, s, 4096, 128)));
    }



}
