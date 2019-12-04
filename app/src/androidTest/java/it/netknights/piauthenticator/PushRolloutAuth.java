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

import android.app.Activity;
import android.app.Instrumentation;
import android.content.Intent;
import android.util.Log;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;

import androidx.test.espresso.ViewInteraction;
import androidx.test.espresso.intent.Intents;
import androidx.test.espresso.matcher.ViewMatchers;
import androidx.test.internal.runner.junit4.AndroidJUnit4ClassRunner;
import androidx.test.rule.ActivityTestRule;

import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeMatcher;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import it.netknights.piauthenticator.utils.PKCS1ToSubjectPublicKeyInfo;
import it.netknights.piauthenticator.utils.Util;
import it.netknights.piauthenticator.viewcontroller.MainActivity;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.tls.HandshakeCertificates;
import okhttp3.tls.internal.TlsUtil;

import static androidx.test.espresso.Espresso.onView;
import static androidx.test.espresso.action.ViewActions.click;
import static androidx.test.espresso.action.ViewActions.scrollTo;
import static androidx.test.espresso.assertion.ViewAssertions.matches;
import static androidx.test.espresso.intent.Intents.intended;
import static androidx.test.espresso.intent.Intents.intending;
import static androidx.test.espresso.intent.matcher.IntentMatchers.hasAction;
import static androidx.test.espresso.matcher.ViewMatchers.Visibility.GONE;
import static androidx.test.espresso.matcher.ViewMatchers.Visibility.VISIBLE;
import static androidx.test.espresso.matcher.ViewMatchers.withClassName;
import static androidx.test.espresso.matcher.ViewMatchers.withEffectiveVisibility;
import static androidx.test.espresso.matcher.ViewMatchers.withId;
import static androidx.test.espresso.matcher.ViewMatchers.withText;
import static it.netknights.piauthenticator.utils.AppConstants.NONCE;
import static it.netknights.piauthenticator.utils.AppConstants.QUESTION;
import static it.netknights.piauthenticator.utils.AppConstants.SERIAL;
import static it.netknights.piauthenticator.utils.AppConstants.SIGNATURE;
import static it.netknights.piauthenticator.utils.AppConstants.SSL_VERIFY;
import static it.netknights.piauthenticator.utils.AppConstants.TITLE;
import static it.netknights.piauthenticator.utils.AppConstants.URL;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.is;

@RunWith(AndroidJUnit4ClassRunner.class)
public class PushRolloutAuth {

    private String url;
    private PrivateKey privateKeyServer;
    private PublicKey publicKeyServer;
    private MockWebServer server;

    @Rule
    public ActivityTestRule<MainActivity> mActivityTestRule = new ActivityTestRule<>(MainActivity.class);

    @Before
    public void setup() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        server = new MockWebServer();
        // Setup 'https'
        HandshakeCertificates hsc = TlsUtil.localhost();
        server.useHttps(hsc.sslSocketFactory(), false);

        server.start();

        url = server.url("/ttype/push").toString();

        privateKeyServer = KeyFactory.getInstance("RSA").generatePrivate(
                new PKCS8EncodedKeySpec(
                        new Util().decodeBase64(getServerPrivateKeyString())));

        publicKeyServer = PKCS1ToSubjectPublicKeyInfo.decodePKCS1PublicKey(
                new Util().decodeBase64(getServerPublicKeyString()));


        Intents.init();
    }

    @Test
    public void pushQR() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        // Setup Mock

        // First setup a not working response
        server.enqueue(new MockResponse().setResponseCode(400)
                .setBody(""));

        // After that working response
        server.enqueue(new MockResponse().setResponseCode(200)
                .setBody("{\"jsonrpc\": \"2.0\", \"signature\": \"rsa_sha256_pss:8462b9" +
                        "4920feda40fabc8bec87f5764cf88522\", \"detail\": {\"public_key\": \"" + getServerPublicKeyString() + "\", " +
                        "\"serial\": \"PIPU0002463F\", \"rollout_state\": \"enrolled\", \"threadid\": 140326707582720}, \"versionnumber\": \"3.0.dev3\"," +
                        " \"version\": \"privacyIDEA 3.0.dev3\", \"result\": {\"status\": true, \"value\": true}, \"time\": 1554194254.95327, \"id\": 1}"));

        Log.e("Server URL", url);
        // "Scan" the QR
        String qr = "otpauth://pipush/PIPU0001D07B?url=" + url + "&ttl=120&issuer=privacyIDEA&" +
                "apikey=AIzaSyBeFSjwJ8aEcHQaj4-iqT-sLAX6lmSrvbo&sslverify=0&enrollment_credential=96d21604913be978a681b6de24a88797f3c643c2" +
                "&projectid=test-d3861&v=1&appid=1%3A850240559902%3Aandroid%3A812605f9a33242a9&projectnumber=850240559902";


        Intent resultData = new Intent();
        resultData.putExtra(com.google.zxing.client.android.Intents.Scan.RESULT, qr);
        Instrumentation.ActivityResult result = new Instrumentation.ActivityResult(Activity.RESULT_OK, resultData);
        intending(hasAction("com.google.zxing.client.android.SCAN")).respondWith(result);

        onView(withId(R.id.fab)).perform(click());

        intended(hasAction("com.google.zxing.client.android.SCAN"));
        sleep(5000);

        ViewInteraction appCompatButton3 = onView(
                allOf(withId(android.R.id.button1),
                        childAtPosition(
                                childAtPosition(
                                        withClassName(is("android.widget.ScrollView")),
                                        0),
                                3)));
        sleep(5000);
        appCompatButton3.perform(scrollTo(), click());

        // Validate token is there - but unfinished
        onView(withId(R.id.textViewToken)).check(matches(withText("privacyIDEA: PIPU0001D07B")));
        onView(withId(R.id.textViewLabel)).check(matches(withText((R.string.PushtokenLabelRolloutUnfinished))));
        // the button is visible to retry the rollout
        onView(withId(R.id.allow_button)).check(matches(withEffectiveVisibility(ViewMatchers.Visibility.VISIBLE)));

        // Press the retry button
        onView(withId(R.id.allow_button)).perform(click());
        //sleep(5000);

        // Validate token rolled out now
        onView(withId(R.id.textViewToken)).check(matches(withText("privacyIDEA: PIPU0001D07B")));
        onView(withId(R.id.textViewLabel)).check(matches(withText((R.string.PushtokenLabel))));
        onView(withId(R.id.allow_button)).check(matches(withEffectiveVisibility(GONE)));

        // Restart the App with an intent containing the PushAuthRequest(data)
        String title = "titletitle";
        String serial = "PIPU0001D07B";
        String question = "questionquestion";
        String nonce = "nocnencoenocencoecne";

        String toSign = nonce + "|" + url + "|" + serial + "|" + question + "|" + title + "|" + "0";
        String signature = Util.sign(privateKeyServer, toSign);

        Intent intent = new Intent();
        intent.putExtra(TITLE, title)
                .putExtra(SERIAL, serial)
                .putExtra(QUESTION, question)
                .putExtra(NONCE, nonce)
                .putExtra(SIGNATURE, signature)
                .putExtra(SSL_VERIFY, false)
                .putExtra(URL, url);

        mActivityTestRule.finishActivity();
        mActivityTestRule.launchActivity(intent);

        // Now there should be a pending Auth request, the next button should be visible to allow the authentication
        onView(withId(R.id.textViewToken)).check(matches(withText("privacyIDEA: PIPU0001D07B")));
        onView(withId(R.id.textViewLabel)).check(matches(withText(title)));
        onView(withId(R.id.textView_pushStatus)).check(matches(withText(question)));
        onView(withId(R.id.allow_button)).check(matches(allOf(withEffectiveVisibility(VISIBLE),
                withText(R.string.Allow))));


        // Set the server to response with success
        server.enqueue(new MockResponse().setResponseCode(200)
                .setBody("{\"nonce\": \"nocnencoenocencoecne\", \"jsonrpc\": \"2.0\", \"signature\": \"rsa_sha256_pss:339309fb3d362c0249cfdb37175\", " +
                        "\"versionnumber\": \"3.0.dev3\", \"version\": \"privacyIDEA 3.0.dev3\", \"result\":" +
                        " {\"status\": true, \"value\": true}, \"time\": 1554457850.641362, \"id\": 1}"));

        // Click allow
        onView(withId(R.id.allow_button)).perform(click());

        // Toast is displayed indicating success
//        onView(withText(R.string.AuthenticationSuccessful)).check(matches(isDisplayed()));

        // Row in list is back to normal
        onView(withId(R.id.textViewToken)).check(matches(withText("privacyIDEA: PIPU0001D07B")));
        onView(withId(R.id.textViewLabel)).check(matches(withText((R.string.PushtokenLabel))));
        onView(withId(R.id.allow_button)).check(matches(withEffectiveVisibility(GONE)));
    }

    @After
    public void tearDown() throws IOException {
        server.close();
        Intents.release();
    }

    private String getServerPublicKeyString() {
        // PKCS#1 Format
        return "MIICCgKCAgEA4hMxjLOVIHNedYZV2wgA\n" +
                "6vTvNfMmFZxa2TYNl6GZwEJP/t/z6d7jWwqJc/A9bYpSI5OGX0nq8PCocwFfrVyc\n" +
                "nYdAdXzwU+Uyq+Z4QINGAAk6Lbhjiwh8V8brPlV/8SekaJC7BEuX7eB/5DVtAlXh\n" +
                "TdP+14eB5n+wtwnfHiMAx3zF5Eczo0Y7IDzvTLTUlyuu5VdQVwdVJGzXz17mGFMw\n" +
                "j3OjSYneJEXUdBs9A2z9MIW+KJgJd+ytgV32McwjcNzkyMuR0NDp2p0xnH6SYWuI\n" +
                "e3HTTil6GsUjfUuZUHOM0MtTR1g19FKjwohD9gTDfO2ORMp+H7lkCRZAKyK/Z/jO\n" +
                "WyNYE4l93JiBiR4YKJUGfTDK90KDMdARyXwXXyVvMIwQ6v+1XImjJF1AxUpufjec\n" +
                "IPBMtHOF6/yUiWXWZJxH42EpL75JPaPr35HPlA7U0863qR/uXvLWKAgNaGf2GtPK\n" +
                "BLU7c6he1F36MIlzS/4h/Tt+VrQG/JvFG/F9Pz6Zfrv/+zMP9F6nLMll9JDoir6d\n" +
                "exHx9Dyt5eiidIHqHMOzsVuK9ZY0YUxV9lo0zAJQZcsUvYIRMjVSBH8a8f3vfRrG\n" +
                "dAmgDty2FijHkOMNA/b1k3V2TqYQo48RfR0mU2OF6nOHJIQJcyy3/F2gK4xD0Tzy\n" +
                "2Agm5/9S/JefLqFh/37nGpMCAwEAAQ==";
    }

    private String getServerPrivateKeyString() {
        return "MIIJKQIBAAKCAgEA4hMxjLOVIHNedYZV2wgA6vTvNfMmFZxa2TYNl6GZwEJP/t/z\n" +
                "6d7jWwqJc/A9bYpSI5OGX0nq8PCocwFfrVycnYdAdXzwU+Uyq+Z4QINGAAk6Lbhj\n" +
                "iwh8V8brPlV/8SekaJC7BEuX7eB/5DVtAlXhTdP+14eB5n+wtwnfHiMAx3zF5Ecz\n" +
                "o0Y7IDzvTLTUlyuu5VdQVwdVJGzXz17mGFMwj3OjSYneJEXUdBs9A2z9MIW+KJgJ\n" +
                "d+ytgV32McwjcNzkyMuR0NDp2p0xnH6SYWuIe3HTTil6GsUjfUuZUHOM0MtTR1g1\n" +
                "9FKjwohD9gTDfO2ORMp+H7lkCRZAKyK/Z/jOWyNYE4l93JiBiR4YKJUGfTDK90KD\n" +
                "MdARyXwXXyVvMIwQ6v+1XImjJF1AxUpufjecIPBMtHOF6/yUiWXWZJxH42EpL75J\n" +
                "PaPr35HPlA7U0863qR/uXvLWKAgNaGf2GtPKBLU7c6he1F36MIlzS/4h/Tt+VrQG\n" +
                "/JvFG/F9Pz6Zfrv/+zMP9F6nLMll9JDoir6dexHx9Dyt5eiidIHqHMOzsVuK9ZY0\n" +
                "YUxV9lo0zAJQZcsUvYIRMjVSBH8a8f3vfRrGdAmgDty2FijHkOMNA/b1k3V2TqYQ\n" +
                "o48RfR0mU2OF6nOHJIQJcyy3/F2gK4xD0Tzy2Agm5/9S/JefLqFh/37nGpMCAwEA\n" +
                "AQKCAgAulwoFFxVKhLwYuECFTRbzVNrfYWad2YUXcn5Gm3UWHBRkUD7yGY79OiSt\n" +
                "kfr20iSvVD3C8XbLhK0SVlwjXAyiojb0f3T/tSJGLs7lbKhGZaBpv7Az/OGzLTlZ\n" +
                "tUESr7rAGeOQtQtwaG2y2BfI/W3bHi9Mt45btED018H1cf09H0ehDdNkeJrCwAwI\n" +
                "4NNW/BelB+N0q/wt74hiIgqFRM+jII+sHg97pjBsZRij1hgvocBYmUyKPGpdWMHd\n" +
                "7VX4cm1rvBgm0ob/GJoayDLehMyxs/l6CC4zyiDQN343CDki5mQZNeKYoVdCRdbL\n" +
                "opuu6T4Ci0CGxSwKe11qBlUv1iSgXHCmFnXp2DjJPgnxE1Wu68g5I/cmNWYLY6rz\n" +
                "T4TpxrSoW7BdkGDYszTb0qIS2V00fkb1OcKS2B+suxry2/u/U1xhpcp7CrIUqXVJ\n" +
                "WIQm5IiPwM88cxI/XTFclWFbiUtQ1PTAvoa2j100t6QHdCJ2LWEOrQIgcoZBzYHq\n" +
                "0Hkm1nIjfZ6bYy7ATPpQ25brBzFmWKpKyPx+PmKPliXp5Mt5M70XeMJ61fI3W7pt\n" +
                "saCuoSMkJoDRhTPuzxu9xz7FMnTEvA6ecwEpVPgKT5aWIdm5bfQQRJ2NMzI5bk8/\n" +
                "K3SuTctK9h05wXXO+d4T5ydES97AQ2SGJQZgYmnxW3xHVxVbsQKCAQEA9aEsdrqq\n" +
                "y2ByKwkks0WHHg/BIBqqoH2wZ+X6e/iyYI2fe48WviHgE3rIuRW8Ka9JywpVFfWL\n" +
                "PXfKn7o59YWRMhWZF1fxqxN9VoeUPEH+IrEkgTMRUwAXpcgvVBYT3/UY/KSJu1GM\n" +
                "j3WL+09gXcCpvqnzECC/2yEqB9LwbX9oZgxX9Db5edKypQsmVNP0N4+i3TF8sQVF\n" +
                "jtwStwu2RQNywP0tn2fIdRHz+qiCpnL4X5nzIzt8JBPdQgmNAflqRHxLj+Sbk4nK\n" +
                "jakkAmC+PL+1vU32hWukj+4v57PtbxZ2/kbXwIOadNLVj1OuIFZ4N5/KBIOic9ZA\n" +
                "vR2feMFjhEVatwKCAQEA656rMZ7VfXhnh0xx1PbJikZbst/TG3tdxox4XaP1jYmb\n" +
                "Cvp2wmYkLZ2EohELOsVEGyXf02OiPX3GuFEzu16/OjB+dn4JkiqLfEIlZOmBierq\n" +
                "ML0ZV4fGBFFlYRjV4sGpHBIfu42LUkGxnillgEXWDKvTUbKAch4LPZA4Z7cepT0u\n" +
                "t7MqZd6vOEh/pqWngjtEs1slfG7UYhmEY9di6wG2EfY8T1FcvzYcHVMrJO11RTvW\n" +
                "R9fyiCyGe/yQydXERCadXxgqlVb5fg3y0UPM3W5AIy89UBwvi0LBFjJq6FhecoeE\n" +
                "Rh22eTOnLBDdAURIn134U9alsNsQEpFCBknlRPVTBQKCAQEAzeHudwY3qoiIqXHc\n" +
                "hTc97gCei95OLn+roSqvLcJjIXMTvmlNUsjqHOnJ3PlO4lG+tKVQdDuAHmGOQRvD\n" +
                "APyXmzdnPp3EPvTzFdhGc8uMzF9WjcTUPJHTQG3u3bgzqIC0FO+FUrEj9As+7cK2\n" +
                "r16R6PJifZ41seK2bCBuzhkA1Kh8AIMj0Oy+OICD/I48IWYPyP912Jrmlrv4I915\n" +
                "RZeCVCjiWL6Q0y/dJLih6gpsDRXpKhruDv9ncba3rnP0krrsSwv/K0dPtDWVrTiR\n" +
                "vDGkj6wNef+jy9CF7txto7Ncwf13UjH9APbHcn9dcFWKJnWUyvva6uUnFl0CEiFm\n" +
                "3LOVOQKCAQEAjJOdNjy6yWJV+m5MmDAprLsvqLhL3uCq4XQbuFrDfY+1Fka7Jl8E\n" +
                "hMavRHaAya66ZKwjL58JREDPmFayU79CvngCa7XlBfUmRZu9bci3hc7HrQ6VmRij\n" +
                "tx3NK7JCokjDGcFid2cK0afqTiAKtA52mBbIPL0QT4XHVRK/5Hln6lRnlChsSl0j\n" +
                "E6SFrKq3F0c/RPdDlUsWofTxfRQbq3TY6TyNXRGBEYA6I/DkE+MtDYKW5URdKovO\n" +
                "LRlSVWmZ8MNNL1hex70dm+y8i8g06YQG9jcQEMTQRPkt9I1eJYPbzd82txKxNPzx\n" +
                "Z6QkB8ZywcqyB2tQbgU1QK6zwsbB6HOp9QKCAQB4yP+Gz2z2pZxFeH1a5FGR1m6U\n" +
                "k8/28NWy7gvfL45T6lZRpLEA8ZkATYpYriSYcEX4pDEtUtStVbYqfdgxED7MIlwg\n" +
                "4JRASsoRDe8wqn3Op2VzSovVHk2R3M7o32lkWFxnu9IquTtoHjXaxoZn2JQ2tBr3\n" +
                "hePs4avmQHvz340sSOl42ZjhIv/9tL2flee+Yc4HzD3w9VHuCfy6dKOU9lp72RXB\n" +
                "FGM731vNq/y6S3P3AiAXPnOfSTXkRjKjIE+yV6eqK2y2AciUOnpOwMuUP/C9f0Gt\n" +
                "NOu90qtlCi3HyN+HUSrB81faTOBMEmOoOyDccVcdUVPPse82AvrzZ/xKLnhg";
    }

    private static Matcher<View> childAtPosition(final Matcher<View> parentMatcher, final int position) {

        return new TypeSafeMatcher<View>() {
            @Override
            public void describeTo(Description description) {
                description.appendText("Child at position " + position + " in parent ");
                parentMatcher.describeTo(description);
            }

            @Override
            public boolean matchesSafely(View view) {
                ViewParent parent = view.getParent();
                return parent instanceof ViewGroup && parentMatcher.matches(parent)
                        && view.equals(((ViewGroup) parent).getChildAt(position));
            }
        };
    }

    private void sleep() {
        sleep(1000);
    }

    private void sleep(int ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }
}
