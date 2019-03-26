package it.netknights.piauthenticator;

import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.Mockito;

import java.util.ArrayList;
import java.util.Date;

import static it.netknights.piauthenticator.AppConstants.HOTP;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class TestModel {

    @Test
    public void testInit() {
        // Empty init
        Model m = new Model();
        assertTrue(m.tokens.isEmpty());
        assertTrue(m.pushAuthRequests.isEmpty());

        // Init with elements
        ArrayList<Token> tokens = new ArrayList<>();
        Token token = Mockito.mock(Token.class);
        tokens.add(token);

        ArrayList<PushAuthRequest> requests = new ArrayList<>();
        PushAuthRequest req = Mockito.mock(PushAuthRequest.class);
        requests.add(req);

        Model m2 = new Model(tokens, requests);
        assertEquals(token, m2.tokens.get(0));
        assertEquals(req, m2.pushAuthRequests.get(0));

        Model m3 = new Model(null, null);
        assertTrue(m3.tokens.isEmpty());
        assertTrue(m3.pushAuthRequests.isEmpty());

    }

    @Test
    public void checkForExpired() {
        Token token = new Token("serial", "label");
        token.rollout_finished = false;
        token.rollout_expiration = new Date();
        ArrayList<Token> list = new ArrayList<>();
        list.add(token);
        Model m3 = new Model(list, null);

        try {
            Thread.sleep(10000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        String expired = m3.checkForExpiredTokens();
        // \n is appended to the expired tokens for formatting
        assertEquals("serial\n", expired);
        assertTrue(m3.tokens.isEmpty());

        // message is null when there are no expired tokens
        Model m4 = new Model();
        assertNull(m4.checkForExpiredTokens());
    }

    @Test
    public void currentSelection() {
        Token token = new Token("lfknsw".getBytes(), "serial", "label", HOTP, 6);
        ArrayList<Token> list = new ArrayList<>();
        list.add(token);
        Model m = new Model(list, null);
        m.setCurrentSelection(0);
        assertEquals(token, m.currentSelection);
        m.setCurrentSelection(-1);
        assertNull(m.currentSelection);
    }
}
