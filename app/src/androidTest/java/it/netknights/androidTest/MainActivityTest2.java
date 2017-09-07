package it.netknights.androidTest;


import android.support.test.espresso.ViewInteraction;
import android.support.test.espresso.matcher.ViewMatchers;
import android.support.test.rule.ActivityTestRule;
import android.support.test.runner.AndroidJUnit4;
import android.test.suitebuilder.annotation.LargeTest;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;

import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeMatcher;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import it.netknights.piauthenticator.MainActivity;
import it.netknights.piauthenticator.OTPGenerator;
import it.netknights.piauthenticator.R;
import it.netknights.piauthenticator.Util;

import static android.support.test.InstrumentationRegistry.getInstrumentation;
import static android.support.test.espresso.Espresso.onData;
import static android.support.test.espresso.Espresso.onView;
import static android.support.test.espresso.Espresso.openActionBarOverflowOrOptionsMenu;
import static android.support.test.espresso.action.ViewActions.click;
import static android.support.test.espresso.action.ViewActions.closeSoftKeyboard;
import static android.support.test.espresso.action.ViewActions.longClick;
import static android.support.test.espresso.action.ViewActions.replaceText;
import static android.support.test.espresso.assertion.ViewAssertions.matches;
import static android.support.test.espresso.matcher.ViewMatchers.isDisplayed;
import static android.support.test.espresso.matcher.ViewMatchers.withClassName;
import static android.support.test.espresso.matcher.ViewMatchers.withId;
import static android.support.test.espresso.matcher.ViewMatchers.withParent;
import static android.support.test.espresso.matcher.ViewMatchers.withText;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.anything;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.startsWith;

@LargeTest
@RunWith(AndroidJUnit4.class)
public class MainActivityTest2 {

    @Rule
    public ActivityTestRule<MainActivity> mActivityTestRule = new ActivityTestRule<>(MainActivity.class);

    @Test
    public void mainActivityTest2() throws Exception {
        // sleep() = Thread.sleep(1000)
        //----------- remove all existing tokens and insert dummytokens ----------------------------
        openActionBarOverflowOrOptionsMenu(getInstrumentation().getTargetContext());

        sleep();

        ViewInteraction appCompatTextView2 = onView(
                allOf(ViewMatchers.withId(R.id.title), withText("Remove all tokens"), isDisplayed()));
        appCompatTextView2.perform(click());

        sleep();

        openActionBarOverflowOrOptionsMenu(getInstrumentation().getTargetContext());

        sleep();

        ViewInteraction appCompatTextView = onView(
                allOf(withId(R.id.title), withText("Insert Dummy-Tokens"), isDisplayed()));
        appCompatTextView.perform(click());

        sleep();
        //------------ check at position x in the listview if the label and OTP are correct --------
        onData(anything()).
                inAdapterView(withId(R.id.listview)).
                atPosition(0).
                onChildView(withId(R.id.textViewLabel))
                .check(matches(withText(startsWith("privacyIDEA: OATH"))));

        onData(anything()).
                inAdapterView(withId(R.id.listview)).
                atPosition(0).
                onChildView(withId(R.id.textViewToken))
                .check(matches(ViewMatchers.withText(OTPGenerator.generate(Util.makeTokenFromURI("otpauth://hotp" +
                        "/OATH00014BE1?secret=2VKLHJMESGDZDXO7UO5GRH6T34CSYWYY&counter=1&digits=6&issuer=privacyIDEA")))));

        onData(anything()).
                inAdapterView(withId(R.id.listview)).
                atPosition(1).
                onChildView(withId(R.id.textViewLabel))
                .check(matches(withText(startsWith("privacyIDEA60"))));

        onData(anything()).
                inAdapterView(withId(R.id.listview)).
                atPosition(1).
                onChildView(withId(R.id.textViewToken))
                .check(matches(withText(OTPGenerator.generate(Util.makeTokenFromURI("otpauth://totp" +
                        "/TOTP00114F8F?secret=HI64N3EHBUWXWHJWAGLNYBHAXWPZMD3N&period=60&digits=6&issuer=privacyIDEA60")))));

        onData(anything()).
                inAdapterView(withId(R.id.listview)).
                atPosition(2).
                onChildView(withId(R.id.textViewLabel))
                .check(matches(withText(startsWith("privacyIDEA30"))));

        onData(anything()).
                inAdapterView(withId(R.id.listview)).
                atPosition(2).
                onChildView(withId(R.id.textViewToken))
                .check(matches(withText(OTPGenerator.generate(Util.makeTokenFromURI("otpauth://totp" +
                        "/TOTP00114F8F?secret=HI64N3EHBUWXWHJWAGLNYBHAXWPZMD3N&period=30&digits=6&issuer=privacyIDEA30")))));

        //------------------- check the next hotp value by clicking on it -----------------------------
        onData(anything()).inAdapterView(withId(R.id.listview)).atPosition(0).onChildView(withId(R.id.textViewToken)).perform(click());

        sleep();

        onData(anything()).inAdapterView(withId(R.id.listview)).atPosition(0).onChildView(withId(R.id.textViewToken))
                .check(matches(withText(OTPGenerator.generate(Util.makeTokenFromURI("otpauth://hotp" +
                        "/OATH00014BE1?secret=2VKLHJMESGDZDXO7UO5GRH6T34CSYWYY&counter=2&digits=6&issuer=privacyIDEA")))));

        sleep();

        //----------------- delete the first token -------------------------------------------------
        onData(anything()).inAdapterView(withId(R.id.listview)).atPosition(0).perform();
        sleep();
        onView(allOf(withId(android.R.id.title), withText("DELETE"), isDisplayed())).perform(click());
        sleep();
        //---------- check if the formerly 2nd is now the first token
        onData(anything()).
                inAdapterView(withId(R.id.listview)).
                atPosition(0).
                onChildView(withId(R.id.textViewLabel))
                .check(matches(withText(startsWith("privacyIDEA60"))));

        sleep();
        //---------------- rename the (then) first token ---------------------------------------------
        onData(anything()).inAdapterView(withId(R.id.listview)).atPosition(0).perform(longClick());
        sleep();
        onView(allOf(withId(android.R.id.title), withText("RENAME"), isDisplayed())).perform(click());
        sleep();
        onView(allOf(withText("privacyIDEA60: TOTP00114F8F"), withParent(allOf(withId(android.R.id.custom), withParent(withClassName(is("android.widget.FrameLayout"))))), isDisplayed())).perform(click());
        sleep();
        onView(allOf(withText("privacyIDEA60: TOTP00114F8F"), withParent(allOf(withId(android.R.id.custom),
                withParent(withClassName(is("android.widget.FrameLayout"))))), isDisplayed())).perform(replaceText("test123"), closeSoftKeyboard());
        sleep();
        //---------- check the new name ---------------
        onData(anything()).
                inAdapterView(withId(R.id.listview)).
                atPosition(0).
                onChildView(withId(R.id.textViewLabel))
                .check(matches(withText(startsWith("test123"))));
        sleep();

        //---------------- open actionbar and remove all tokens-------------------------------------
        openActionBarOverflowOrOptionsMenu(getInstrumentation().getTargetContext());

        sleep();

        ViewInteraction appCompatTextView5 = onView(
                allOf(withId(R.id.title), withText("Remove all tokens"), isDisplayed()));
        appCompatTextView5.perform(click());


    }

    private void sleep() {
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    static class MenuItemTitleMatcher extends BaseMatcher<Object> {
        private final String title;

        public MenuItemTitleMatcher(String title) {
            this.title = title;
        }

        @Override
        public boolean matches(Object o) {
            if (o instanceof MenuItem) {
                return ((MenuItem) o).getTitle().equals(title);
            }
            return false;
        }

        @Override
        public void describeTo(Description description) {
        }
    }
}
