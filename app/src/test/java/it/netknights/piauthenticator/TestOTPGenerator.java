package it.netknights.piauthenticator;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import static it.netknights.piauthenticator.OTPGenerator.generateHOTP;
import static it.netknights.piauthenticator.OTPGenerator.generatePBKDFKey;
import static it.netknights.piauthenticator.OTPGenerator.generateTOTP;
import static it.netknights.piauthenticator.Util.byteArrayToHexString;
import static org.junit.Assert.assertEquals;

public class TestOTPGenerator {

    @Test
    public void testOTPGenerator() {
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

        // TOTP for once
        assertEquals(94287082, generateTOTP(seed, testTime[0], digits, 30, sha1));
        // Hash pin
        byte[] secret = "testtesttesttest".getBytes();
        Token t = new Token(secret, "serial", "test", "hotp", 6);
        assertEquals("4e25988118d7e38ef94c1f32d14d5de463f159fa34304bdc9acba6728a60b541cb948e75c75493705ee4e43e0d2d224f0f0fc0cd803bd707ba4b0acccf702ab7"
                , OTPGenerator.hashPIN(1234567890, t));

        // Generate for token
        assertEquals("766082", OTPGenerator.generate(t));  // HOTP
        secret = "edb642c8348a20b6c2a19a65cc71bc2eb4c2b8fc29c42a00c489e57f9b8ed73b".getBytes();
        Token t2 = new Token(secret, "serial", "test", "totp", 6); //TOTP
        assertEquals(generateTOTP(byteArrayToHexString(secret), (System.currentTimeMillis() / 1000), "6", 30, sha1),
                Integer.parseInt(OTPGenerator.generate(t2)));

        // Generating for Push token returns empty String
        Token pushy = new Token("serial", "label");
        assertEquals("", OTPGenerator.generate(pushy));
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
}
