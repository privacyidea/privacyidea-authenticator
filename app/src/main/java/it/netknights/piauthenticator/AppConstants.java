package it.netknights.piauthenticator;

public class AppConstants {

    static final String CRYPT_ALGORITHM = "AES/GCM/NoPadding";
    static final int KEY_LENGTH = 16;
    static final int IV_LENGTH = 12;

    static final int INTENT_ADD_TOKEN_MANUALLY = 101;
    static final int INTENT_ABOUT = 102;
    static final int PERMISSIONS_REQUEST_CAMERA = 103;


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


    static String TAG = "it.netknights.piauth";

    public static final String DATAFILE = "data.dat";
    public static final String KEYFILE = "key.key";

}
