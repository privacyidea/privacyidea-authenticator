package it.netknights.piauthenticator;

public class AppConstants {

    static final String APP_TITLE = " privacyIDEA Authenticator";
    static final String PACKAGE_NAME = "it.netknights.piauthenticator";
    static String TAG = "it.netknights.piauth";

    static final int INTENT_ADD_TOKEN_MANUALLY = 101;
    static final int INTENT_ABOUT = 102;
    static final int PERMISSIONS_REQUEST_CAMERA = 103;

    static final String CRYPT_ALGORITHM = "AES/GCM/NoPadding";
    static final int KEY_LENGTH = 16;
    static final int IV_LENGTH = 12;

    static final String DATAFILE = "data.dat";
    static final String KEYFILE = "key.key";

    static final String DIGITS = "digits";
    static final String PERIOD = "period";
    static final String ALGORITHM = "algorithm";
    static final String ISSUER = "issuer";
    static final String SECRET = "secret";
    static final String TYPE = "type";
    static final String LABEL = "label";
    static final String COUNTER = "counter";
    static final String TOTP = "totp";
    static final String HOTP = "hotp";
    static final String TAPTOSHOW = "taptoshow";
    static final String PIN = "pin";
    static final String WITHPIN = "withpin";
    static final String TWOSTEP_SALT = "2step_salt";
    static final String TWOSTEP_DIFFICULTY = "2step_difficulty"; // pbkdf2 iterations
    static final String TWOSTEP_OUTPUT = "2step_output"; // length of the key generated by the smartphone in byte
    static final String PROPERTY_PROGRESS = "progress";

    static final String SHA1 = "SHA1";
    static final String SHA256 = "SHA256";
    static final String SHA512 = "SHA512";
    static final String HMACSHA1 = "HmacSHA1";
    static final String HMACSHA256 = "HmacSHA256";
    static final String HMACSHA512 = "HmacSHA512";



    static final String PERIOD_30_STR = "30s";
    static final String PERIOD_60_STR = "60s";
    static final int PERIOD_30 = 30;
    static final int PERIOD_60 = 60;

    static final String DIGITS_6_STR = "6";
    static final String DIGITS_8_STR = "8";
    static final int DIGITS_6 = 6;
    static final int DIGITS_8 = 8;
}