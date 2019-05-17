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

import org.junit.Test;
import org.mockito.Mockito;

import java.util.ArrayList;
import java.util.Date;

import it.netknights.piauthenticator.model.Model;
import it.netknights.piauthenticator.model.PushAuthRequest;
import it.netknights.piauthenticator.model.Token;

import static it.netknights.piauthenticator.utils.AppConstants.HOTP;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class TestModel {

    @Test
    public void testInit() {
        // Empty init
        Model m = new Model();
        assertTrue(m.getTokens().isEmpty());
        assertTrue(m.getPushAuthRequests().isEmpty());

        // Init with elements
        ArrayList<Token> tokens = new ArrayList<>();
        Token token = Mockito.mock(Token.class);
        tokens.add(token);

        ArrayList<PushAuthRequest> requests = new ArrayList<>();
        PushAuthRequest req = Mockito.mock(PushAuthRequest.class);
        requests.add(req);

        Model m2 = new Model(tokens, requests);
        assertEquals(token, m2.getTokens().get(0));
        assertEquals(req, m2.getPushAuthRequests().get(0));

        Model m3 = new Model(null, null);
        assertTrue(m3.getTokens().isEmpty());
        assertTrue(m3.getPushAuthRequests().isEmpty());

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
        assertTrue(m3.getTokens().isEmpty());

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
        assertEquals(token, m.getCurrentSelection());
        m.setCurrentSelection(-1);
        assertNull(m.getCurrentSelection());
    }

    @Test
    public void hasPushToken() {
        Token token = new Token("serial", "label");
        ArrayList<Token> list = new ArrayList<>();
        list.add(token);
        Model m = new Model(list, null);

        assertTrue(m.hasPushToken());

        m.getTokens().remove(0);

        assertFalse(m.hasPushToken());
    }
}
