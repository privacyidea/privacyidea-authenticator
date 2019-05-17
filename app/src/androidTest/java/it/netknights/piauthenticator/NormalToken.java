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
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;

import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.Matchers;
import org.hamcrest.TypeSafeMatcher;
import org.hamcrest.core.IsInstanceOf;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import androidx.test.espresso.ViewInteraction;
import androidx.test.espresso.intent.Intents;
import androidx.test.espresso.matcher.ViewMatchers;
import androidx.test.internal.runner.junit4.AndroidJUnit4ClassRunner;
import androidx.test.rule.ActivityTestRule;

import it.netknights.piauthenticator.viewcontroller.MainActivity;

import static androidx.test.espresso.Espresso.onData;
import static androidx.test.espresso.Espresso.onView;
import static androidx.test.espresso.action.ViewActions.click;
import static androidx.test.espresso.action.ViewActions.scrollTo;
import static androidx.test.espresso.assertion.ViewAssertions.matches;
import static androidx.test.espresso.intent.Intents.intended;
import static androidx.test.espresso.intent.Intents.intending;
import static androidx.test.espresso.intent.matcher.IntentMatchers.hasAction;
import static androidx.test.espresso.matcher.ViewMatchers.Visibility.GONE;
import static androidx.test.espresso.matcher.ViewMatchers.Visibility.VISIBLE;
import static androidx.test.espresso.matcher.ViewMatchers.isDisplayed;
import static androidx.test.espresso.matcher.ViewMatchers.withClassName;
import static androidx.test.espresso.matcher.ViewMatchers.withEffectiveVisibility;
import static androidx.test.espresso.matcher.ViewMatchers.withId;
import static androidx.test.espresso.matcher.ViewMatchers.withText;
import static it.netknights.piauthenticator.AnyStringMatcher.withAnyString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.anything;
import static org.hamcrest.Matchers.startsWith;

@RunWith(AndroidJUnit4ClassRunner.class)
public class NormalToken {

    @Rule
    public ActivityTestRule<MainActivity> mActivityTestRule = new ActivityTestRule<>(MainActivity.class);

    @Before
    public void setup() {
        Intents.init();
    }

    @Test
    public void hotpQR() {
        onView(withId(R.id.fab)).check(matches(isDisplayed()));
        ViewInteraction floatingActionButton = onView(
                allOf(withId(R.id.fab),
                        childAtPosition(
                                childAtPosition(
                                        withId(android.R.id.content),
                                        0),
                                2),
                        isDisplayed()));

        String qr = "otpauth://hotp/testtoken?secret=TXHEXPREOXHFKDRE6BNZJOFKQ5OLDZWC&counter=1&digits=6&issuer=privacyIDEA";

        // Build a result to return from the ZXING app
        Intent resultData = new Intent();
        resultData.putExtra(com.google.zxing.client.android.Intents.Scan.RESULT, qr);
        Instrumentation.ActivityResult result = new Instrumentation.ActivityResult(Activity.RESULT_OK, resultData);

        // Stub out the Camera. When an intent is sent to the Camera, this tells Espresso to respond
        // with the ActivityResult we just created
        intending(hasAction("com.google.zxing.client.android.SCAN")).respondWith(result);

        floatingActionButton.perform(click());
        // We can also validate that an intent resolving to the "camera" activity has been sent out by our app
        intended(hasAction("com.google.zxing.client.android.SCAN"));
        sleep(2000);

        onData(anything()).
                inAdapterView(withId(R.id.listview)).
                atPosition(0).
                onChildView(withId(R.id.textViewLabel))
                .check(matches(withText(startsWith("privacyIDEA: test"))));
        onData(anything()).
                inAdapterView(withId(R.id.listview)).
                atPosition(0).
                onChildView(withId(R.id.textViewToken))
                .check(matches(withText(startsWith("163584"))));

        // Check that the next button is displayed and the progressbar is not
        onView(withId(R.id.next_button)).check(matches(allOf(isDisplayed(), withEffectiveVisibility(ViewMatchers.Visibility.VISIBLE))));
        onView(withId(R.id.progressBar)).check(matches(allOf(not(isDisplayed()), withEffectiveVisibility(GONE))));
    }

    @Test
    public void totpQR() {
        onView(withId(R.id.fab)).check(matches(isDisplayed()));
        ViewInteraction floatingActionButton = onView(
                allOf(withId(R.id.fab),
                        childAtPosition(
                                childAtPosition(
                                        withId(android.R.id.content),
                                        0),
                                2),
                        isDisplayed()));
        String qr = "otpauth://totp/TOTPtoken?secret=TXHEXPREOXHFKDRE6BNZJOFKQ5OLDZWC&counter=1&digits=6&issuer=privacyIDEA";

        Intent resultData = new Intent();
        resultData.putExtra(com.google.zxing.client.android.Intents.Scan.RESULT, qr);
        Instrumentation.ActivityResult result = new Instrumentation.ActivityResult(Activity.RESULT_OK, resultData);

        intending(hasAction("com.google.zxing.client.android.SCAN")).respondWith(result);

        floatingActionButton.perform(click());
        intended(hasAction("com.google.zxing.client.android.SCAN"));
        sleep(2000);

        onData(anything()).
                inAdapterView(withId(R.id.listview)).
                atPosition(0).
                onChildView(withId(R.id.textViewLabel))
                .check(matches(withText(startsWith("privacyIDEA: TOTP"))));
        onData(anything()).
                inAdapterView(withId(R.id.listview)).
                atPosition(0).
                onChildView(withId(R.id.textViewToken))
                .check(matches(allOf(isDisplayed(),
                        withText(not(startsWith("163584"))),
                        withAnyString()))); // The OTP is not the same even though the secret is the same
        // Check that the progressbar is displayed and the next button not
        onView(withId(R.id.progressBar)).check(matches(allOf(isDisplayed(), withEffectiveVisibility(VISIBLE))));
        onView(withId(R.id.next_button)).check(matches(allOf(not(isDisplayed()), withEffectiveVisibility(GONE))));
    }

    @Test
    public void twoStepQR() {
        onView(withId(R.id.fab)).check(matches(isDisplayed()));
        ViewInteraction floatingActionButton = onView(
                allOf(withId(R.id.fab),
                        childAtPosition(
                                childAtPosition(
                                        withId(android.R.id.content),
                                        0),
                                2),
                        isDisplayed()));
        String qr = "otpauth://totp/TOTP2STEPtoken?secret=TXHEXPREOXHFKDRE6BNZJOFKQ5OLDZWC&counter=1&digits=6&issuer=privacyIDEA" +
                "&2step_salt=20&2step_difficulty=30000";   // 300.000 iterations take ~10sec

        Intent resultData = new Intent();
        resultData.putExtra(com.google.zxing.client.android.Intents.Scan.RESULT, qr);
        Instrumentation.ActivityResult result = new Instrumentation.ActivityResult(Activity.RESULT_OK, resultData);

        intending(hasAction("com.google.zxing.client.android.SCAN")).respondWith(result);

        floatingActionButton.perform(click());
        intended(hasAction("com.google.zxing.client.android.SCAN"));
        sleep(2000);

        // The loading dialog should be visible now TODO needs to be done with idlingResources
        /*onView(withId(R.id.pro_baseLayout)).check(matches(allOf(isDisplayed(), withEffectiveVisibility(VISIBLE))));
        onView(withId(R.id.pro_progress)).check(matches(allOf(isDisplayed(), withEffectiveVisibility(VISIBLE))));
        onView(withId(R.id.tv_status)).check(matches(allOf(isDisplayed(), withEffectiveVisibility(VISIBLE),
                withText(R.string.WaitWhileSecretIsGenerated))));*/

        // The result should be shown
        ViewInteraction textView = onView(
                allOf(IsInstanceOf.instanceOf(android.widget.TextView.class), withText("Phone secret"),
                        isDisplayed()));
        textView.check(matches(withText("Phone secret")));

        ViewInteraction textView2 = onView(
                allOf(withId(android.R.id.message), withAnyString(),
                        isDisplayed()));
        textView2.check(matches(withAnyString()));
        // Press OK
        ViewInteraction appCompatButton = onView(
                allOf(withId(android.R.id.button1), withText("OK"),
                        childAtPosition(
                                childAtPosition(
                                        withClassName(Matchers.is("android.widget.ScrollView")),
                                        0),
                                3)));
        appCompatButton.perform(scrollTo(), click());
        // Token should be there now
        onData(anything()).
                inAdapterView(withId(R.id.listview)).
                atPosition(0).
                onChildView(withId(R.id.textViewLabel))
                .check(matches(withText(startsWith("privacyIDEA: TOTP2STEP"))));
        onData(anything()).
                inAdapterView(withId(R.id.listview)).
                atPosition(0).
                onChildView(withId(R.id.textViewToken))
                .check(matches(allOf(isDisplayed(),
                        withAnyString())));
        // Check that the progressbar is displayed and the next button is not
        onView(withId(R.id.progressBar)).check(matches(allOf(isDisplayed(), withEffectiveVisibility(VISIBLE))));
        onView(withId(R.id.next_button)).check(matches(allOf(not(isDisplayed()), withEffectiveVisibility(GONE))));

    }

    @After
    public void tearDown() {
        Intents.release();
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
