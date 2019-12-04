/*
  privacyIDEA Authenticator

  Authors: Nils Behlen <nils.behlen@netknights.it>

  Copyright (c) 2017-2019 NetKnights GmbH

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

import org.apache.commons.codec.binary.Base32;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;

import it.netknights.piauthenticator.interfaces.MainActivityInterface;
import it.netknights.piauthenticator.interfaces.TokenListViewInterface;
import it.netknights.piauthenticator.model.FirebaseInitConfig;
import it.netknights.piauthenticator.model.Model;
import it.netknights.piauthenticator.model.PushAuthRequest;
import it.netknights.piauthenticator.model.ScanResult;
import it.netknights.piauthenticator.model.Token;
import it.netknights.piauthenticator.presenter.Presenter;
import it.netknights.piauthenticator.utils.SecretKeyWrapper;
import it.netknights.piauthenticator.utils.Util;

import static it.netknights.piauthenticator.utils.AppConstants.HMACSHA1;
import static it.netknights.piauthenticator.utils.AppConstants.HMACSHA256;
import static it.netknights.piauthenticator.utils.AppConstants.HOTP;
import static it.netknights.piauthenticator.utils.AppConstants.PRO_STATUS_BAD_BASE64;
import static it.netknights.piauthenticator.utils.AppConstants.PRO_STATUS_DONE;
import static it.netknights.piauthenticator.utils.AppConstants.PRO_STATUS_MALFORMED_JSON;
import static it.netknights.piauthenticator.utils.AppConstants.PRO_STATUS_REGISTRATION_TIME_EXPIRED;
import static it.netknights.piauthenticator.utils.AppConstants.PRO_STATUS_RESPONSE_NOT_OK;
import static it.netknights.piauthenticator.utils.AppConstants.PRO_STATUS_RESPONSE_NO_KEY;
import static it.netknights.piauthenticator.utils.AppConstants.PRO_STATUS_STEP_1;
import static it.netknights.piauthenticator.utils.AppConstants.PRO_STATUS_STEP_2;
import static it.netknights.piauthenticator.utils.AppConstants.PRO_STATUS_STEP_3;
import static it.netknights.piauthenticator.utils.AppConstants.PUSH;
import static it.netknights.piauthenticator.utils.AppConstants.SHA1;
import static it.netknights.piauthenticator.utils.AppConstants.SHA256;
import static it.netknights.piauthenticator.utils.AppConstants.STATUS_ENDPOINT_MALFORMED_URL;
import static it.netknights.piauthenticator.utils.AppConstants.STATUS_ENDPOINT_SSL_ERROR;
import static it.netknights.piauthenticator.utils.AppConstants.STATUS_ENDPOINT_UNKNOWN_HOST;
import static it.netknights.piauthenticator.utils.AppConstants.STATUS_INIT_FIREBASE;
import static it.netknights.piauthenticator.utils.AppConstants.STATUS_INIT_FIREBASE_DONE;
import static it.netknights.piauthenticator.utils.AppConstants.STATUS_STANDARD_ROLLOUT_DONE;
import static it.netknights.piauthenticator.utils.AppConstants.STATUS_TWO_STEP_ROLLOUT;
import static it.netknights.piauthenticator.utils.AppConstants.STATUS_TWO_STEP_ROLLOUT_DONE;
import static it.netknights.piauthenticator.utils.AppConstants.State.AUTHENTICATING;
import static it.netknights.piauthenticator.utils.AppConstants.State.FINISHED;
import static it.netknights.piauthenticator.utils.AppConstants.State.UNFINISHED;
import static it.netknights.piauthenticator.utils.AppConstants.TOTP;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class TestPresenter {

    private Presenter presenter;
    private TokenListViewInterface tokenListViewInterface;
    private MainActivityInterface mainActivityInterface;
    private Util util;
    private SecretKeyWrapper wrapper;
    private Model model;

    @Before
    public void setup() {
        model = Mockito.spy(Model.class);
        wrapper = Mockito.mock(SecretKeyWrapper.class);
        tokenListViewInterface = Mockito.mock(TokenListViewInterface.class);
        mainActivityInterface = Mockito.mock(MainActivityInterface.class);
        util = Mockito.mock(Util.class);

        Presenter tmp = new Presenter(tokenListViewInterface, mainActivityInterface, util);
        presenter = Mockito.spy(tmp);
        presenter.setModel(model);

        doReturn(wrapper).when(mainActivityInterface).getWrapper();
        doNothing().when(wrapper).removePrivateKeyFor(anyString());

        // stub the saving, it is part of util
        //Mockito.doNothing().when(presenter).saveTokenlist();
        //when(presenter.removeToken((Token) any())).then(model.tokens.remove(model.tokens.size()-1));
    }

    @Test
    public void testInit() {
        presenter.init();
        verify(mainActivityInterface, never()).firebaseInit((FirebaseInitConfig) any());
        verify(mainActivityInterface, never()).makeAlertDialog(anyInt(), anyString());

        FirebaseInitConfig firebaseInitConfig = new FirebaseInitConfig("projid", "appid", "api_key", "projNumber");
        when(util.loadFirebaseConfig()).thenReturn(firebaseInitConfig);
        when(model.checkForExpiredTokens()).thenReturn("serial");

        presenter.init();
        verify(mainActivityInterface).firebaseInit(firebaseInitConfig);
        // When there are expired tokens, it is called with titleID and String message
        verify(mainActivityInterface, times(1)).makeAlertDialog(anyInt(), anyString());


        verify(mainActivityInterface, times(2)).startTimer();
        verify(model, times(2)).checkForExpiredTokens();
    }

    @Test
    public void currentSelection() {
        Token t1 = new Token("testetststest".getBytes(), "SERIALSERIAL", "LABEL", HOTP, 6);
        t1.setPersistent(true);
        t1.setLocked(true);
        t1.setWithPIN(true);

        presenter.addToken(t1);
        verify(presenter).addToken(t1);
        assertEquals(1, presenter.getTokenCount());

        presenter.setCurrentSelection(0);
        verify(presenter).setCurrentSelection(0);
        assertEquals(t1, presenter.getCurrentSelection());

        presenter.setCurrentSelectionLabel("new label");
        assertEquals("new label", presenter.getCurrentSelectionLabel()); // calls notifyChange
        assertTrue(presenter.isCurrentSelectionLocked());
        assertTrue(presenter.isCurrentSelectionPersistent());
        assertTrue(presenter.isCurrentSelectionWithPin());
        assertEquals("992305", presenter.getCurrentSelectionOTP());

        presenter.setPIN("123456", presenter.getCurrentSelection());
        assertTrue(presenter.checkPIN("123456", presenter.getCurrentSelection())); // calls notifyChange

        presenter.changeCurrentSelectionPIN(653242); // calls notifyChange
        assertTrue(presenter.checkPIN("653242", presenter.getCurrentSelection()));

        // remove
        presenter.removeCurrentSelection();
        verify(presenter).removeToken(t1);
        verify(tokenListViewInterface, times(3)).notifyChange();
        verify(mainActivityInterface).makeToast(R.string.toast_token_removed);
        assertEquals(0, presenter.getTokenCount());
    }

    @Test
    public void removeAddAt() {
        Token t1 = new Token("testetststest".getBytes(), "SERIALSERIAL", "LABEL", HOTP, 6);
        Token t2 = new Token("testetststest".getBytes(), "SERIALSERIAL", "LABEL", HOTP, 6);
        presenter.addToken(t1);
        presenter.addToken(t2);
        assertEquals(2, presenter.getTokenCount());
        Token t3 = new Token("anotherone".getBytes(), "someother", "somelabel", TOTP, 6);
        presenter.addTokenAt(0, t3);
        assertEquals(3, presenter.getTokenCount());
        Token removed = presenter.removeTokenAtPosition(0);
        assertEquals(t3, removed);

        Token pushy = new Token("serial", "label");
        presenter.addToken(pushy);
        presenter.removeToken(pushy);
        verify(util).removePubkeyFor("serial");
        verify(wrapper).removePrivateKeyFor("serial");
    }

    /*  @Test
  public void pushAuthRequests() {
        // Add a push token, which gets a PushAuthRequest
        Token t2 = new Token("PUSHserial", "testlabel");
        presenter.addToken(t2);
        presenter.addPushAuthRequest(new PushAuthRequest("asdnflsnf", "https://test.org",
                "PUSHserial", "TESTquestion?", "TESTtitle", "slkdfns", false));
        Map<String, String> map = presenter.getPushAuthRequestInfo(t2);

        assertEquals("TESTtitle", map.get(TITLE));
        assertEquals("TESTquestion?", map.get(QUESTION));

        // checking for another token returns null
        Token t3 = new Token("wrongSerial", "label");
        presenter.addToken(t3);
        map = presenter.getPushAuthRequestInfo(t3);
        assertNull(map);
    } */

    @Test
    public void increaseHOTPCounter() {
        Token t1 = new Token("test".getBytes(), "serial", "label", HOTP, 6);
        presenter.addToken(t1);

        assertEquals("First OTP value", "941117", t1.getCurrentOTP());
        presenter.increaseHOTPCounter(t1);
        // notifyChange should have been called on the interface
        verify(tokenListViewInterface).notifyChange();
        assertEquals("Counter should be increased by 1", 1, t1.getCounter());
        assertEquals("OTP should have changed", "431881", t1.getCurrentOTP());
    }

    @Test
    public void tokenFromIntent() {
        presenter.addTokenFromIntent(TOTP, "test".getBytes(), "label", 8, SHA1, "60", true);

        verify(presenter).saveTokenlist();
        verify(tokenListViewInterface).notifyChange();
        verify(mainActivityInterface).makeToast(anyString());
        Token toCompare = presenter.getTokenAtPosition(presenter.getTokenCount() - 1);

        assertEquals(TOTP, toCompare.getType());
        assertEquals(60, toCompare.getPeriod());
        assertEquals("label", toCompare.getLabel());
        assertEquals(HMACSHA1, toCompare.getAlgorithm());
        assertEquals(8, toCompare.getDigits());
        assertEquals(0, toCompare.getCounter());
        assertTrue(toCompare.isWithPIN());
        Assert.assertArrayEquals("test".getBytes(), toCompare.getSecret());
    }

    @Test
    public void refresh() {
        clearTokenlist();
        Token t1 = new Token("testetststest".getBytes(), "SERIAL_HOTP", "LABEL_HOTP", HOTP, 6);
        Token t2 = new Token("testetststest".getBytes(), "SERIAL_TOTP", "LABEL_TOTP", TOTP, 6);

        presenter.addToken(t1);
        presenter.addToken(t2);
        String oldOTP_hotp = t1.getCurrentOTP();
        String oldOTP_totp = t2.getCurrentOTP();

        t1.setCounter(2);
        try {
            Thread.sleep(30000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        presenter.timerProgress(1);
        verify(tokenListViewInterface).updateProgressbars(1);
        assertNotEquals(oldOTP_hotp, t1.getCurrentOTP());
        assertNotEquals(oldOTP_totp, t2.getCurrentOTP());
    }

    @Test
    public void lifecycle() {
        presenter.onStop(); // saves tokenlist

        presenter.onPause();
        verify(mainActivityInterface).stopTimer();

        presenter.onResume();
        verify(mainActivityInterface).resumeTimer();

        presenter.saveTokenlist();  // saves tokenlist
        verify(util, times(2)).saveTokens(any());
    }

    @Test
    public void updateTaskStatus() {
        clearTokenlist();

        Token t1 = new Token("testetststest".getBytes(), "SERIALSERIAL", "LABEL", HOTP, 6);
        presenter.updateTaskStatus(STATUS_STANDARD_ROLLOUT_DONE, t1);
        assertEquals(t1, presenter.getTokenAtPosition(0));
        assertEquals(1, presenter.getTokenCount());

        presenter.updateTaskStatus(STATUS_INIT_FIREBASE, t1);
        presenter.updateTaskStatus(STATUS_INIT_FIREBASE_DONE, t1);

        presenter.updateTaskStatus(STATUS_TWO_STEP_ROLLOUT, t1);
        // t1 should be added again, because non-push duplicates are allowed
        presenter.updateTaskStatus(STATUS_TWO_STEP_ROLLOUT_DONE, t1);
        assertEquals(t1, presenter.getTokenAtPosition(1));
        assertEquals(2, presenter.getTokenCount());

        presenter.updateTaskStatus(PRO_STATUS_STEP_1, t1);
        presenter.updateTaskStatus(PRO_STATUS_STEP_2, t1);
        presenter.updateTaskStatus(PRO_STATUS_STEP_3, t1);

        // t2 should be added and state is FINISHED
        Token t2 = new Token("pushy", "pushy");
        presenter.updateTaskStatus(PRO_STATUS_DONE, t2); // t2 should be added
        assertEquals(t2, presenter.getTokenAtPosition(2));
        assertEquals(FINISHED, presenter.getTokenAtPosition(2).state);
        assertEquals(3, presenter.getTokenCount());

        // t3 should be added, but unfinished
        Token t3 = new Token("pushyfail", "pushyfail");
        presenter.updateTaskStatus(PRO_STATUS_BAD_BASE64, t3);
        assertEquals(UNFINISHED, presenter.getTokenAtPosition(3).state);
        assertEquals(4, presenter.getTokenCount());

        // t4 should be added, but unfinished
        Token t4 = new Token("pushyfail2", "pushyfail");
        presenter.updateTaskStatus(PRO_STATUS_MALFORMED_JSON, t4);
        assertEquals(UNFINISHED, presenter.getTokenAtPosition(4).state);
        assertEquals(5, presenter.getTokenCount());

        // t5 should be added, but unfinished
        Token t5 = new Token("pushyfail3", "pushyfail");
        presenter.updateTaskStatus(PRO_STATUS_RESPONSE_NO_KEY, t5);
        assertEquals(UNFINISHED, presenter.getTokenAtPosition(5).state);
        assertEquals(6, presenter.getTokenCount());

        // t3 should be removed if registration time is expired
        presenter.updateTaskStatus(PRO_STATUS_REGISTRATION_TIME_EXPIRED, t3);
        assertEquals(5, presenter.getTokenCount());

        // t3 should not be added, because the url is malformed
        presenter.updateTaskStatus(STATUS_ENDPOINT_MALFORMED_URL, t3);
        assertEquals(5, presenter.getTokenCount());

        // t3 should be added again, but unfinished
        presenter.updateTaskStatus(STATUS_ENDPOINT_UNKNOWN_HOST, t3);
        assertEquals(UNFINISHED, presenter.getTokenAtPosition(5).state);
        assertEquals(6, presenter.getTokenCount());

        // t3 should not be added again
        presenter.updateTaskStatus(PRO_STATUS_RESPONSE_NOT_OK, t3);
        assertEquals(6, presenter.getTokenCount());

        // t3 is added but unfinished
        presenter.updateTaskStatus(STATUS_ENDPOINT_SSL_ERROR, t3);
        assertEquals(UNFINISHED, presenter.getTokenAtPosition(5).state);

        verify(mainActivityInterface, times(3)).cancelStatusDialog();
        verify(mainActivityInterface, times(8)).makeAlertDialog(anyInt(), anyInt());
        verify(mainActivityInterface, times(1)).setStatusDialogText(anyInt());
    }

    @Test
    public void authenticationFinished() {
        Token t = new Token("serial", "label");
        t.addPushAuthRequest(new PushAuthRequest("nonce", "url", "serial", "question?",
                "title!", "signature", 5678, true));
        t.state = AUTHENTICATING;
        ArrayList<Token> list = new ArrayList<>();
        list.add(t);
        Model m = new Model(list);
        presenter.setModel(m);

        // check failure first
        presenter.authenticationFinished(false, t);
        verify(mainActivityInterface).makeToast(R.string.AuthenticationFailed);

        presenter.authenticationFinished(true, t);

        verify(mainActivityInterface, times(1)).makeToast(R.string.AuthenticationSuccessful);
        verify(mainActivityInterface, times(1)).cancelNotification(5678);
        assertTrue(t.getPendingAuths().isEmpty());  // The request is removed upon success
        assertEquals(FINISHED, t.state);
        verify(tokenListViewInterface).notifyChange();

    }

    @Test
    public void testStubs() {
        PublicKey key = presenter.generatePublicKeyFor("test");
        assertNull(key); // its a stub
    }

    @Test
    public void receivePubKey() {
        Token pushy = new Token("serial", "label");
        presenter.receivePublicKey("test", pushy);
        try {
            verify(util).storePIPubkey("test", "serial");
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
    }

    @Test
    public void receivePubKeyGSEnIAE() throws GeneralSecurityException {
        Token pushy = new Token("serial", "label");

        doThrow(GeneralSecurityException.class).when(util).storePIPubkey(anyString(), anyString());

        presenter.receivePublicKey("test", pushy);
        verify(presenter).updateTaskStatus(PRO_STATUS_RESPONSE_NO_KEY, pushy);
        assertEquals(pushy.state, UNFINISHED);

        doThrow(IllegalArgumentException.class).when(util).storePIPubkey(anyString(), anyString());

        presenter.receivePublicKey("test", pushy);
        verify(presenter).updateTaskStatus(PRO_STATUS_BAD_BASE64, pushy);
        assertEquals(pushy.state, UNFINISHED);
    }

    /*
    @Test
    public void receivePubKeyIOEx() throws GeneralSecurityException {
        Token pushy = new Token("serial", "label");

        doThrow(IOException.class).when(util).storePIPubkey(anyString(), anyString());
        presenter.receivePublicKey("test", pushy);
    } */

    @Test
    public void scanQRResult() throws InvalidKeyException {
        clearTokenlist();
        ScanResult res = new ScanResult(HOTP, "serial");
        res.secret = "AAAAAAAAAAAAAA";
        res.label = "label";
        res.counter = 21;
        res.algorithm = SHA256;
        res.pin = true;
        res.period = 60;
        res.taptoshow = true;
        res.persistent = true;
        presenter.scanQRfinished(res);

        Token token = presenter.getTokenAtPosition(0);
        assertTrue(Arrays.equals(new Base32().decode(res.secret), token.getSecret()));
        assertEquals("label", token.getLabel());
        assertEquals(HOTP, token.getType());
        assertEquals(21, token.getCounter());
        assertEquals(HMACSHA256, token.getAlgorithm());
        assertEquals(60, token.getPeriod());
        assertEquals("serial", token.getSerial());
        assertTrue(token.isPersistent());
        assertTrue(token.isWithPIN());
        assertTrue(token.isWithTapToShow());

        ScanResult res2 = new ScanResult(PUSH, "serial");
        res2.ttl = 15;
        res2.rollout_url = "https://test.com/rollout";
        res2.enrollment_credential = "randomstuff";
        res2.firebaseInitConfig = new FirebaseInitConfig("projid", "appid", "api_key", "projNumber");


        presenter.scanQRfinished(res2);
        verify(util).storeFirebaseConfig(res2.firebaseInitConfig);
        verify(mainActivityInterface).firebaseInit(res2.firebaseInitConfig);

        Calendar now = Calendar.getInstance();
        now.add(Calendar.MINUTE, res2.ttl);

        /*Token token2 = presenter.getTokenAtPosition(1);
        assertFalse(token2.rollout_finished);
        assertEquals(res2.rollout_url, token2.rollout_url);
        assertEquals(res2.enrollment_credential, token2.enrollment_credential);
        assertEquals(now.getTime(), token2.rollout_expiration); */
    }

    @Test
    public void incompatiblePushVersion() {
        ScanResult res = new ScanResult(PUSH, "serial");
        res.push_version = 2;
        presenter.scanQRfinished(res);
        verify(mainActivityInterface).makeAlertDialog(anyInt(), anyInt());
    }
/*
    @Test
    public void startPushAuth() throws CertificateException, UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException, IOException {
        clearTokenlist();

        Token pushy = new Token("serial", "label");
        presenter.addToken(pushy);
        presenter.startPushAuthentication(0);

        presenter.addPushAuthRequest(new PushAuthRequest("asdnflsnf", "https://test.org", "serial",
                "TESTquestion?", "TESTtitle", "slkdfns", false));

        PublicKey publicKey = Mockito.mock(PublicKey.class);
        PrivateKey privateKey = Mockito.mock(PrivateKey.class);
        when(wrapper.getPrivateKeyFor(anyString())).thenReturn(privateKey);
        when(util.getPIPubkey(anyString())).thenReturn(publicKey);

        presenter.startPushAuthentication(0);

        assertTrue(model.getPushAuthRequests().isEmpty());
        verify(tokenListViewInterface).notifyChange();
    } */

    @Test
    public void lastPushToken() {
        clearTokenlist();
        Token pushy = new Token("serial", "label");
        presenter.addToken(pushy);

        presenter.removeToken(pushy);

        verify(model).hasPushToken();
        verify(mainActivityInterface).removeFirebase();
        verify(util).removeFirebaseConfig();
    }

    private void clearTokenlist() {
        for (int i = 0; i < presenter.getTokenCount(); i++) {
            presenter.removeToken(presenter.getTokenAtPosition(i));
        }
    }
}
