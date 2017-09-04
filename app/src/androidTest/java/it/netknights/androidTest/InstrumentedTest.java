package it.netknights.androidTest;

import android.content.Context;
import android.os.Build;
import android.support.test.InstrumentationRegistry;
import android.support.test.filters.LargeTest;
import android.support.test.runner.AndroidJUnit4;
import android.test.InstrumentationTestCase;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Hex;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import it.netknights.piauthenticator.EncryptionHelper;
import it.netknights.piauthenticator.OTPGenerator;
import it.netknights.piauthenticator.Token;
import it.netknights.piauthenticator.Util;

import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertNotSame;
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
        assertTrue(new File(context.getFilesDir() + "/data.dat").delete());
        assertTrue(new File(context.getFilesDir() + "/key.key").delete());

        Token hotp = Util.makeTokenFromURI("otpauth://hotp" +
                "/OATH00014BE1?secret=2VKLHJMESGDZDXO7UO5GRH6T34CSYWYY&counter=1&digits=6&issuer=privacyIDEA");
        Token totp = Util.makeTokenFromURI("otpauth://totp" +
                "/TOTP00114F8F?secret=HI64N3EHBUWXWHJWAGLNYBHAXWPZMD3N&period=60&digits=6&issuer=privacyIDEA&algorithm=SHA256");

        assertEquals("privacyIDEA: OATH00014BE1", hotp.getLabel());
        assertEquals(6, hotp.getDigits());
        assertEquals("HmacSHA1", hotp.getAlgorithm());
        assertEquals(1, hotp.getCounter());
        assertEquals(0, hotp.getPeriod());
        assertEquals("hotp", hotp.getType());
        assertTrue(Arrays.equals(hotp.getSecret(), new Base32().decode("2VKLHJMESGDZDXO7UO5GRH6T34CSYWYY")));
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
        assertTrue(Arrays.equals(loaded.get(0).getSecret(), new Base32().decode("2VKLHJMESGDZDXO7UO5GRH6T34CSYWYY")));

        assertEquals("privacyIDEA: TOTP00114F8F", loaded.get(1).getLabel());
        assertEquals(60, loaded.get(1).getPeriod());
        assertEquals(0, loaded.get(1).getCounter());
        assertEquals("HmacSHA256", loaded.get(1).getAlgorithm());
        assertTrue(Arrays.equals(new Base32().decode("HI64N3EHBUWXWHJWAGLNYBHAXWPZMD3N"), loaded.get(1).getSecret()));

        hotp.setCurrentOTP("523432");
        hotp.setType("totp");
        hotp.setLabel("test setlabel");
        byte[] s = "Hallo test123".getBytes();
        hotp.setSecret(s);
        assertEquals("523432", hotp.getCurrentOTP());
        assertEquals("totp", hotp.getType());
        assertTrue(Arrays.equals(s, hotp.getSecret()));
        assertEquals("test setlabel", hotp.getLabel());

        //test the exceptions
        try {
            Token fail1 = Util.makeTokenFromURI("ftp://hotp" +
                    "/OATH00014BE1?secret=2VKLHJMESGDZDXO7UO5GRH6T34CSYWYY&counter=1&digits=6&issuer=privacyIDEA");
            fail("this should throw: invalid protocol");
        } catch (Exception e) {
            assertEquals("Invalid Protocol", e.getMessage());
        }
        try {
            Token fail2 = Util.makeTokenFromURI("otpauth://ptoh" +
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
        Token hotp = Util.makeTokenFromURI("otpauth://hotp" +
                "/OATH00014BE1?secret=2VKLHJMESGDZDXO7UO5GRH6T34CSYWYY&counter=1&digits=6&issuer=privacyIDEA");
        Token totp = Util.makeTokenFromURI("otpauth://totp" +
                "/TOTP00114F8F?secret=HI64N3EHBUWXWHJWAGLNYBHAXWPZMD3N&period=60&digits=6&issuer=privacyIDEA&algorithm=SHA256");
        assertEquals(OTPGenerator.generate(hotp), "034072");
        assertNotSame(OTPGenerator.generate(hotp), OTPGenerator.generate(totp));
    }

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
}
