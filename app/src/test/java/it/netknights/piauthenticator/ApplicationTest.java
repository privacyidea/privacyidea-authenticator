package it.netknights.piauthenticator;

import android.content.Context;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base32;
import org.junit.Assert;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.mockito.Mock;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.UndeclaredThrowableException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import static it.netknights.piauthenticator.OTPGenerator.byteArrayToHexString;
import static it.netknights.piauthenticator.OTPGenerator.generateHOTP;
import static it.netknights.piauthenticator.OTPGenerator.generatePBKDFKey;
import static it.netknights.piauthenticator.OTPGenerator.hexStringToByteArray;
import static junit.framework.Assert.assertEquals;
import static junit.framework.Assert.assertTrue;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class ApplicationTest {

    @Test
    public void testRWFile() throws IOException {
        File f = new File("test");
        String text = "testtext";
        Util.writeFile(f, text.getBytes());
        byte[] retrieved = Util.readFile(f);
        assertNotNull(retrieved);
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

        // additional OTPGenerator tests
        Token t = new Token("testsetestest".getBytes(),"label","totp",6);
        long time = (System.currentTimeMillis() / 1000);
        String otp1 = OTPGenerator.generate(t);
        String key = byteArrayToHexString(t.getSecret());
        String otp2 = String.valueOf(OTPGenerator.generateTOTP(key,time ,"6",30,t.getAlgorithm()));
        assertEquals(otp1,otp2);

        Token t2 = new Token("testsetestest".getBytes(),"label","hotp",6);
        String otp3 = OTPGenerator.generate(t2);
        assertEquals("922108", otp3);
    }

    @Test(expected = UndeclaredThrowableException.class)
    public void testGSE(){
        // combines NoSuchAlgorithmException, InvalidKeyException
        OTPGenerator.generateHOTP("","","6","");
    }

    @Test
    public void testEncryptionHelper() throws NoSuchPaddingException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException,
            IllegalBlockSizeException, IOException, InvalidAlgorithmParameterException, DecoderException {
        byte[] test_bytes = "testsetestset".getBytes();
        byte[] key_bytes = "keykeykeykeykeyk".getBytes();
        SecretKeySpec key = new SecretKeySpec(key_bytes, "AES");
        byte[] iv_bytes = new byte[12];
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(iv_bytes);
        GCMParameterSpec params = new GCMParameterSpec(128, iv_bytes, 0, 12);

        byte[] encrypted = EncryptionHelper.encrypt(key, test_bytes);
        byte[] decrypted = EncryptionHelper.decrypt(key, encrypted);

        Assert.assertArrayEquals(test_bytes, decrypted);
    }

    @Test
    public void testHashingPIN() {
        Token t = new Token("testsetestset".getBytes(), "test","hotp", 6);
        String hash = OTPGenerator.hashPIN(123454321, t);
        assertEquals("da99819a2c1eca77026056579ff46e864589fd5c85e6dc756e67412cd4617200ea43f35f667596dbcfb6754582d85b775cfa525c730f23188dd6e742d404cc84",hash);
    }

    @Test
    public void testPBKDF2() throws InvalidKeySpecException, NoSuchAlgorithmException {
        // Testvectors are from https://www.rfc-editor.org/rfc/rfc6070.txt
        // 16Mio. iterations testvector is not used, takes forever
        // char[] pw , byte[] salt, int iterations, int length in bit

        char[] p = "password".toCharArray();
        byte[] s = new byte[0];
        s = "salt".getBytes(StandardCharsets.US_ASCII);

        assertEquals("0c60c80f961f0e71f3a9b524af6012062fe037a6", byteArrayToHexString(generatePBKDFKey(p, s, 1, 160)));
        assertEquals("ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957", byteArrayToHexString(generatePBKDFKey(p, s, 2, 160)));
        assertEquals("4b007901b765489abead49d926f721d065a429c1", byteArrayToHexString(generatePBKDFKey(p, s, 4096, 160)));
        //assertEquals("eefe3d61cd4da4e4e9945b3d6ba2158c2634e984", byteArrayToHexString(generatePBKDFKey(p, s, 16777216, 160)));

        p = "passwordPASSWORDpassword".toCharArray();
        s = "saltSALTsaltSALTsaltSALTsaltSALTsalt".getBytes(StandardCharsets.US_ASCII);

        assertEquals("3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038", byteArrayToHexString(generatePBKDFKey(p, s, 4096, 200)));

        p = "pass\0word".toCharArray();
        s = "sa\0lt".getBytes(StandardCharsets.US_ASCII);

        assertEquals("56fa6aa75548099dcc37d7f03425e0c3", byteArrayToHexString(generatePBKDFKey(p, s, 4096, 128)));
    }

    @Test
    public void test2step() throws InvalidKeySpecException, NoSuchAlgorithmException {
        String server_secret = "3d228545e86d18d29affc4c52a427cb751c4aa15bbe2f9e91f0e116658d4bef6";
        String server_secret_b32 = new Base32().encodeAsString(hexStringToByteArray(server_secret));
        String client_secret_b32 = "OF3XYLDSPTMWK===";
        byte[] client_secret_bytes = new Base32().decode(client_secret_b32);

        char[] server_secret_chararray = server_secret.toCharArray();
        byte[] complete_secret_bytes = generatePBKDFKey(server_secret_chararray, client_secret_bytes, 10000, 32 * 8);
        byte[] digest = new byte[20];
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            digest = md.digest(client_secret_bytes);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        byte[] checksumBytes = new byte[4];
        System.arraycopy(digest, 0, checksumBytes, 0, 4);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try {
            outputStream.write(checksumBytes);
            outputStream.write(client_secret_bytes);
        } catch (IOException e) {
            e.printStackTrace();
        }
        byte complete_client_bytes[] = outputStream.toByteArray();
        String full_secret = byteArrayToHexString(complete_secret_bytes);
        int otp1 = OTPGenerator.generateHOTP(full_secret, "1", "6", "HmacSHA256");
        int otp2 = OTPGenerator.generateHOTP(full_secret, "2", "6", "HmacSHA256");
        int otp3 = OTPGenerator.generateHOTP(full_secret, "3", "6", "HmacSHA256");
    }


}