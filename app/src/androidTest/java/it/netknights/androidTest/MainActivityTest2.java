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
import static android.support.test.espresso.assertion.ViewAssertions.matches;
import static android.support.test.espresso.matcher.ViewMatchers.isDisplayed;
import static android.support.test.espresso.matcher.ViewMatchers.withId;
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

        openActionBarOverflowOrOptionsMenu(getInstrumentation().getTargetContext());

        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        ViewInteraction appCompatTextView2 = onView(
                allOf(ViewMatchers.withId(R.id.title), withText("Remove all tokens"), isDisplayed()));
        appCompatTextView2.perform(click());

        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        openActionBarOverflowOrOptionsMenu(getInstrumentation().getTargetContext());

        try {
            Thread.sleep(2000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        ViewInteraction appCompatTextView = onView(
                allOf(withId(R.id.title), withText("Insert Dummy-Tokens"), isDisplayed()));
        appCompatTextView.perform(click());

        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        //------------check at position x in the listview if the label and OTP are correct----------
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

        //-------------------check the next hotp value by clicking on it-----------------------------
        onData(anything()).inAdapterView(withId(R.id.listview)).atPosition(0).onChildView(withId(R.id.textViewToken)).perform(click());
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        onData(anything()).inAdapterView(withId(R.id.listview)).atPosition(0).onChildView(withId(R.id.textViewToken))
                .check(matches(withText(OTPGenerator.generate(Util.makeTokenFromURI("otpauth://hotp" +
                        "/OATH00014BE1?secret=2VKLHJMESGDZDXO7UO5GRH6T34CSYWYY&counter=2&digits=6&issuer=privacyIDEA")))));

        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        openActionBarOverflowOrOptionsMenu(getInstrumentation().getTargetContext());

        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        ViewInteraction appCompatTextView5 = onView(
                allOf(withId(R.id.title), withText("Remove all tokens"), isDisplayed()));
        appCompatTextView5.perform(click());


    }

    private static Matcher<View> childAtPosition(
            final Matcher<View> parentMatcher, final int position) {

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

    static MenuItemTitleMatcher withTitle(String title) {
        return new MenuItemTitleMatcher(title);
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
