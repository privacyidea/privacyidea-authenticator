package it.netknights.piauthenticator;


import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;

import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeMatcher;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import androidx.test.espresso.DataInteraction;
import androidx.test.espresso.ViewInteraction;
import androidx.test.filters.LargeTest;
import androidx.test.internal.runner.junit4.AndroidJUnit4ClassRunner;
import androidx.test.rule.ActivityTestRule;

import static androidx.test.espresso.Espresso.onData;
import static androidx.test.espresso.Espresso.onView;
import static androidx.test.espresso.Espresso.openActionBarOverflowOrOptionsMenu;
import static androidx.test.espresso.action.ViewActions.click;
import static androidx.test.espresso.assertion.ViewAssertions.matches;
import static androidx.test.espresso.matcher.ViewMatchers.isDisplayed;
import static androidx.test.espresso.matcher.ViewMatchers.withClassName;
import static androidx.test.espresso.matcher.ViewMatchers.withId;
import static androidx.test.espresso.matcher.ViewMatchers.withText;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.anything;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.startsWith;
import static androidx.test.platform.app.InstrumentationRegistry.getInstrumentation;

/**
 * Check that the AboutActivity displays the info labels and license correctly
 */

@LargeTest
@RunWith(AndroidJUnit4ClassRunner.class)
public class AboutTest {

    @Rule
    public ActivityTestRule<MainActivity> mActivityTestRule = new ActivityTestRule<>(MainActivity.class);

    @Test
    public void aboutTest() {
        sleep();

        ViewInteraction imageView = onView(
                allOf(
                        childAtPosition(
                                childAtPosition(
                                        withId(R.id.toolbar),
                                        2),
                                0),
                        isDisplayed()));
        imageView.check(matches(isDisplayed()));

        ViewInteraction imageButton = onView(
                allOf(withId(R.id.fab),
                        childAtPosition(
                                allOf(withId(R.id.main_constraint_layout),
                                        childAtPosition(
                                                withId(android.R.id.content),
                                                0)),
                                2),
                        isDisplayed()));
        imageButton.check(matches(isDisplayed()));

        ViewInteraction listView = onView(
                allOf(withId(R.id.listview),
                        childAtPosition(
                                allOf(withId(R.id.main_constraint_layout),
                                        childAtPosition(
                                                withId(android.R.id.content),
                                                0)),
                                1),
                        isDisplayed()));
        listView.check(matches(isDisplayed()));

        sleep();

        openActionBarOverflowOrOptionsMenu(getInstrumentation().getTargetContext());

        sleep();

        ViewInteraction textView = onView(
                allOf(withId(R.id.title), withText((R.string.menu_add_manually)),
                        childAtPosition(
                                childAtPosition(
                                        withId(R.id.content),
                                        0),
                                0),
                        isDisplayed()));
        textView.check(matches(withText((R.string.menu_add_manually))));

        sleep();

        ViewInteraction textView2 = onView(
                allOf(withId(R.id.title), withText((R.string.menu_about)),
                        childAtPosition(
                                childAtPosition(
                                        withId(R.id.content),
                                        0),
                                0),
                        isDisplayed()));
        textView2.check(matches(withText((R.string.menu_about))));

        sleep();

        ViewInteraction appCompatTextView = onView(
                allOf(withId(R.id.title), withText((R.string.menu_about)),
                        childAtPosition(
                                childAtPosition(
                                        withId(R.id.content),
                                        0),
                                0),
                        isDisplayed()));
        appCompatTextView.perform(click());

        sleep();

        onView(withId(R.id.textView_about_applabel)).check(matches(withText((R.string.app_name))));

        PackageInfo info = null;
        try {
            info = getInstrumentation().getTargetContext().getPackageManager().getPackageInfo(AppConstants.PACKAGE_NAME, 0);
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
        }
        if (info != null) {
            onView(withId(R.id.textView_version)).check(matches(withText((getString(R.string.version)) + " " + info.versionName)));
        } else {
            onView(withId(R.id.textView_version)).check(matches(withText(startsWith(getString(R.string.version)))));
        }

        onView(withId(R.id.textView_appLicense)).check(matches(withText((R.string.apache_license_2_0Label))));

        onView(withId(R.id.textView_about_companylabel)).check(matches(withText((R.string.company_label))));

        onView(withId(R.id.textView_licenseslabel)).check(matches(withText((R.string.licenses_label))));

        ViewInteraction textView9 = onView(
                allOf(withId(R.id.about_row_title), withText("Apache License 2.0"),
                        childAtPosition(
                                childAtPosition(
                                        withId(R.id.listView_about),
                                        0),
                                0),
                        isDisplayed()));
        textView9.check(matches(withText("Apache License 2.0")));

        ViewInteraction textView10 = onView(
                allOf(withId(R.id.about_row_title), withText("OTP Authenticator by Bruno Bierbaumer"),
                        childAtPosition(
                                childAtPosition(
                                        withId(R.id.listView_about),
                                        1),
                                0),
                        isDisplayed()));
        textView10.check(matches(withText("OTP Authenticator by Bruno Bierbaumer")));

        ViewInteraction textView11 = onView(
                allOf(withId(R.id.about_row_title), withText("ZXing Embedded"),
                        childAtPosition(
                                childAtPosition(
                                        withId(R.id.listView_about),
                                        2),
                                0),
                        isDisplayed()));
        textView11.check(matches(withText("ZXing Embedded")));

        ViewInteraction textView12 = onView(
                allOf(withId(R.id.about_row_title), withText("Android Code Samples"),
                        childAtPosition(
                                childAtPosition(
                                        withId(R.id.listView_about),
                                        3),
                                0),
                        isDisplayed()));
        textView12.check(matches(withText("Android Code Samples")));

        DataInteraction constraintLayout = onData(anything())
                .inAdapterView(allOf(withId(R.id.listView_about),
                        childAtPosition(
                                withClassName(is("androidx.constraintlayout.widget.ConstraintLayout")),
                                2)))
                .atPosition(0);
        constraintLayout.perform(click());

        onView(withText(startsWith("Apache"))).check(matches(isDisplayed()));
    }

    private void sleep() {
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
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

    private String getString(int resID) {
        return getInstrumentation().getTargetContext().getString(resID);
    }
}
