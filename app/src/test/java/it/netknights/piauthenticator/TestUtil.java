package it.netknights.piauthenticator;


import org.apache.commons.codec.binary.Base64;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.mockito.Mockito;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.lang.reflect.Field;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Date;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import static it.netknights.piauthenticator.AppConstants.HOTP;
import static it.netknights.piauthenticator.AppConstants.KEYFILE;
import static it.netknights.piauthenticator.AppConstants.PUBKEYFILE;
import static it.netknights.piauthenticator.AppConstants.TOTP;
import static junit.framework.TestCase.assertNotNull;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.verify;

public class TestUtil {

    Util util;
    private SecretKeyWrapper wrapper;
    private String baseFilePath;
    private TemporaryFolder folder;
    private String in_key;

    @Before
    public void setup() throws IOException {
        wrapper = Mockito.mock(SecretKeyWrapper.class);
        folder = new TemporaryFolder();
        folder.create();

        baseFilePath = folder.getRoot().getAbsolutePath();
        Util tmp = new Util(wrapper, baseFilePath);
        util = Mockito.spy(tmp);

        // Stub the encryption key - keystore is not available
        KeyGenerator gen = null;
        try {
            gen = KeyGenerator.getInstance("AES");
            gen.init(128);
            SecretKey secretKey = gen.generateKey();
            doReturn(secretKey).when(util).getSecretKey(new File(baseFilePath + "/" + KEYFILE));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }

        // Stub android util base64 decoding with the apache one
        in_key = "MIICCgKCAgEA1RxstJljB8fR/mPC8cpG5SVlZuKc38ah8LNAGaZ64w5tlMCWf8xr\n" +
                "ZTSnDvmNxy373HNGNhU/TsE7rnL2FuHFLbLcoz3/kvYKVv2z+wx0hsy2dg5pw1l+\n" +
                "WXZB7HyLstF1p6rvEv/uC9Dycjrcy7QA61cmAJnE5xqglcqGXFLmfxxASmQ1HJhD\n" +
                "OPq83KBTKHQpsZ4Qvu3RY5wVxFNZJJ78NT4TzyRuSHQLHqIEPrNDXwM6zHtO5oSf\n" +
                "zMRUqP7PZOul+iKqgtrJCAH4mSYl24ZSwqqipjLLXzEmdMtPxUoStQPQbku42Ykf\n" +
                "EEXOk36zytQV0mK/f70mJmZyyRYv6+OdrUFUjymXFUDOgqX0X73gHe1IsT6YDXEI\n" +
                "iiv47GtU+ngiU4SyM/JWsUGCg9X+M83iP91ehAj6LIBt4M8tvGCOgRzLMJUFNl+r\n" +
                "yZNK52dPPk1qEC170qCnKb25/SXvRRHw2BU7laSHmEumB3hLpwGHDJ/ZlbxTHxDp\n" +
                "cMMg3+hFmXpxecRDqjq/t1SODoJBL8QLeRug7CnhN8DsJ7MLI62nmakCBWNzKsUp\n" +
                "OT6SVmRZCUQJLC8hzTFSLCLGCbWBEgi6mmRLqJQmDI8Ltxp23CkG2jhsebu/JNp5\n" +
                "KSRNi8WKUbrgS/ifcrYNd/HA5BasdkI24iRtAft8PrNimEHfnt7KoykCAwEAAQ==";

        byte[] toReturn = Base64.decodeBase64(in_key);

        doReturn(toReturn).when(util).decodeBase64(anyString());
    }

    @Test
    public void testSaveAndLoad() {

        ArrayList<Token> list = new ArrayList<>();
        Token t1 = new Token("testetststest".getBytes(), "SERIALSERIAL", "LABEL", HOTP, 6);
        t1.setPersistent(true);
        t1.setLocked(true);
        t1.setWithPIN(true);
        t1.setWithTapToShow(true);
        list.add(t1);

        Token t2 = new Token("testetststest".getBytes(), "SERIALSERIAL2", "LABEL", TOTP, 6);
        list.add(t2);

        Token pushy = new Token("PUSHYSERIAL", "PUSHYLABEL");
        pushy.enrollment_credential = "enrollmentcred";
        pushy.rollout_finished = false;
        pushy.rollout_url = "https://test.com/roll/out";
        pushy.rollout_expiration = new Date();

        list.add(pushy);

        util.saveTokens(list);

        ArrayList<Token> list_loaded = util.loadTokens();
        assertEquals(list.size(), list_loaded.size());
    }

    @Test
    public void byteArrayHexConversion() {
        String hex = "53fc021347cb5d817526e78b2be13c504f7177cf31426d8dc77323d51ce6af3cb858fa938461bba" +
                "0bfe810d7f8aa358bb54eca28e885f29ee35f9239ce9a815b29f31066" +
                "4919a0ca1f94f7b6d66a89ab96636a5a2eeda3b001dd5ffa797c0a9a8" +
                "481e564cd2faa854b418578895e6d7a0f88108a90a77afc2753eb3ec65d7ffd";

        Assert.assertEquals(hex, Util.byteArrayToHexString(Util.hexStringToByteArray(hex)));
    }

    /**
     * Doesn't work, androids base64 is not available here, Apache base64 doesn't work on a real device
     */
    @Test
    public void receiveAndStorePublicKey() {
        // in_key is in setup
        try {
            util.storePIPubkey(in_key, "testkey");
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }

        PublicKey key = util.getPIPubkey("testkey");

        // the key from PI is in PKCS#1
        String in_key_compare = in_key.replace("\n", "");

        // the key from the app is in SubjectPublicKeyInfo format
        // without the info fields (32 bytes) it should be the same key
        // use apache base64 here
        String app_key_compare = Base64.encodeBase64String(key.getEncoded()).substring(32);

        assertEquals(in_key_compare, app_key_compare);
    }

    @Test
    public void stubs() {

    }

    @Test
    public void fileError() {
        assertNull(util.loadDataFromFile("notexisting"));
    }

    @Test
    public void removePublicKey() throws IOException {
        // create a "pubkey" file
        String serial = "serial";
        File test = new File(baseFilePath + "/" + serial + "_" + PUBKEYFILE);
        test.createNewFile();
        // file is there
        assertTrue(test.exists());
        // file still exists when trying to remove wrong serial
        util.removePubkeyFor("wrongserial");
        assertTrue(test.exists());
        // file is gone for correct serial
        util.removePubkeyFor(serial);
        assertFalse(test.exists());
    }

    @Test
    public void saveAndLoadFirebaseConfig() {
        // there is none
        assertNull(util.loadFirebaseConfig());

        // This throws exception -> returns null
        FirebaseInitConfig fbConf = new FirebaseInitConfig(null, null, null, null);
        util.storeFirebaseConfig(fbConf);
        assertNull(util.loadFirebaseConfig());

        // this should work
        fbConf = new FirebaseInitConfig("projID", "appID", "api_key", "projNumber");
        util.storeFirebaseConfig(fbConf);

        FirebaseInitConfig loaded = util.loadFirebaseConfig();
        assertNotNull(loaded);
        assertEquals(fbConf.api_key, loaded.api_key);
        assertEquals(fbConf.appID, loaded.appID);
        assertEquals(fbConf.projID, loaded.projID);
        assertEquals(fbConf.projNumber, loaded.projNumber);
    }

    @Test
    public void getSecretKey() throws GeneralSecurityException, IOException {
        // create some bytes to write to file
        byte[] random = new byte[10];
        new SecureRandom().nextBytes(random);
        // wrapping should return those bytes then
        doReturn(random).when(wrapper).wrap((SecretKey) any());


        // call with keyfile that does not exist yet
        File test = new File(baseFilePath + "/" + "test.key");
        //test.createNewFile();
        SecretKey key = util.getSecretKey(test);
        verify(wrapper).wrap((SecretKey) any());
        // wrapper would be called with the random bytes
        verify(wrapper).unwrap(random);
        // but its still null, because it is a stub
        assertNull(key);
    }

    @Test
    public void testLoadingOldToken() {
        // Older token did not have the serial attribute.
        // Upon loading them, their label should be set as their serial

        Token token = new Token("test".getBytes(), "serial", "label", HOTP, 6);

        // serial is a private field - use reflection to set it to null
        try {
            Field f = token.getClass().getDeclaredField("serial");
            f.setAccessible(true);
            f.set(token, null);
        } catch (NoSuchFieldException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        }
        assertNull(token.getSerial());

        ArrayList<Token> list = new ArrayList<>();
        list.add(token);
        util.saveTokens(list);
        ArrayList<Token> loaded = util.loadTokens();
        // the serial should now be "label"
        assertEquals("label", loaded.get(0).getSerial());
    }

}
