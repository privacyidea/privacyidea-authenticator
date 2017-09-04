/*
  privacyIDEA Authenticator

  Authors: Nils Behlen <nils.behlen@netknights.it>

  Copyright (c) 2017 NetKnights GmbH

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

package it.netknights.piauthenticator;


import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import static it.netknights.piauthenticator.Token.HOTP;
import static it.netknights.piauthenticator.Token.TOTP;


public class OTPGenerator {

    private OTPGenerator() {
    }

    public static String generate(Token token) {
        if (token.getType().equals(TOTP)) {
            return String.format("%0" + token.getDigits() + "d", generateTOTP(token.getSecret(),
                    (System.currentTimeMillis() / 1000), token.getDigits(), token.getPeriod(), token.getAlgorithm()));
        }
        if (token.getType().equals(HOTP)) {
            return String.format("%0" + token.getDigits() + "d", generateHOTP(token.getSecret(), token.getCounter(),
                    token.getDigits(), token.getAlgorithm()));
        }
        //  return String.format("%06d", generate(secret, System.currentTimeMillis() / 1000, 6));
        return "";
    }

    /**
     * This method calculates the OTP value according to RFC 4226.
     *
     * @param key       The secret shared key, which is used for the HMAC-SHA1 algorithm
     * @param counter   The moving counter, either key presses or time steps
     * @param digits    The number of digits of the calculated OTP value. Would be usually either 6 or 8
     * @param algorithm The hashing algorithm, "HmacSHA1", "HmacSHA256", "HmacSHA512"
     * @return The OTP value for the HOTP Token
     */
    private static int generateHOTP(byte[] key
            , long counter, int digits, String algorithm) {
        int r = 0;
        try {
            byte[] data = new byte[8];
            long value = counter;
            for (int i = 8; i-- > 0; value >>>= 8) {
                data[i] = (byte) value;
            }
            SecretKeySpec signKey = new SecretKeySpec(key, algorithm);
            Mac mac = Mac.getInstance(algorithm);
            mac.init(signKey);
            byte[] hash = mac.doFinal(data);
            int offset = hash[20 - 1] & 0xF;
            long truncatedHash = 0;
            for (int i = 0; i < 4; ++i) {
                truncatedHash <<= 8;
                truncatedHash |= (hash[offset + i] & 0xFF);
            }
            truncatedHash &= 0x7FFFFFFF;
            truncatedHash %= Math.pow(10, digits);
            r = (int) truncatedHash;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return r;
    }

    /**
     * Calculate an OTP value by the OATH TOTP algorithm as defined in RFC 6238
     *
     * @param key The secret, shared key key
     * @param t The unix system time, seconds since 1.1.1970
     * @param digits The number of digits of the calculated OTP value. Would be usually either 6 or 8
     * @param period The time step as defined in RFC. Usually 30 or 60
     * @param algorithm The hashing algorithm, "HmacSHA1", "HmacSHA256", "HmacSHA512"
     * @return The OTP value for the HOTP Token
     */
    private static int generateTOTP(byte[] key, long t, int digits, int period, String algorithm) {
         /*
        The unix system time is devided by the time step. This number of time slices is used as
        counter input for the normal HOTP algorithm
        */
        t /= period;
        return generateHOTP(key, t, digits, algorithm);
    }
}
