package it.netknights.piauthenticator;


import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;

import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeMatcher;
import org.hamcrest.core.IsInstanceOf;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import androidx.test.espresso.DataInteraction;
import androidx.test.espresso.ViewInteraction;
import androidx.test.espresso.matcher.ViewMatchers;
import androidx.test.filters.LargeTest;
import androidx.test.internal.runner.junit4.AndroidJUnit4ClassRunner;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.rule.ActivityTestRule;

import static androidx.test.espresso.Espresso.onData;
import static androidx.test.espresso.Espresso.onView;
import static androidx.test.espresso.Espresso.openActionBarOverflowOrOptionsMenu;
import static androidx.test.espresso.action.ViewActions.click;
import static androidx.test.espresso.action.ViewActions.closeSoftKeyboard;
import static androidx.test.espresso.action.ViewActions.longClick;
import static androidx.test.espresso.action.ViewActions.replaceText;
import static androidx.test.espresso.action.ViewActions.scrollTo;
import static androidx.test.espresso.assertion.ViewAssertions.matches;
import static androidx.test.espresso.matcher.ViewMatchers.hasDescendant;
import static androidx.test.espresso.matcher.ViewMatchers.isDisplayed;
import static androidx.test.espresso.matcher.ViewMatchers.withClassName;
import static androidx.test.espresso.matcher.ViewMatchers.withContentDescription;
import static androidx.test.espresso.matcher.ViewMatchers.withEffectiveVisibility;
import static androidx.test.espresso.matcher.ViewMatchers.withId;
import static androidx.test.espresso.matcher.ViewMatchers.withText;
import static androidx.test.platform.app.InstrumentationRegistry.getInstrumentation;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.anything;
import static org.hamcrest.Matchers.is;

@LargeTest
@RunWith(AndroidJUnit4ClassRunner.class)
public class DetailAndMenuTest {

    @Rule
    public ActivityTestRule<MainActivity> mActivityTestRule = new ActivityTestRule<>(MainActivity.class);

    @Before
    public void setup() {

    }

    @Test
    public void testDetail() {
        sleep();

        openActionBarOverflowOrOptionsMenu(getInstrumentation().getTargetContext());

        sleep();

        ViewInteraction appCompatTextView = onView(
                allOf(withId(R.id.title), withText((R.string.menu_add_manually)),
                        childAtPosition(
                                childAtPosition(
                                        withId(R.id.content),
                                        0),
                                0),
                        isDisplayed()));
        appCompatTextView.perform(click());

        sleep();

        onView(withId(R.id.editText_secret)).check(matches(isDisplayed()));
        onView(withId(R.id.editText_secret)).check(matches(withText(R.string.secret)));

        onView(withId(R.id.editText_name)).check(matches(isDisplayed()));
        onView(withId(R.id.editText_name)).check(matches(withText(R.string.name)));

        onView(withId(R.id.checkBox_base32)).check(matches(isDisplayed()));
        onView(withId(R.id.checkBox_base32)).check(matches(withText(R.string.base32_encoded_secret)));

        onView(withId(R.id.checkBox_pin)).check(matches(isDisplayed()));
        onView(withId(R.id.checkBox_pin)).check(matches(withText(R.string.with_pin)));

        ViewInteraction textView = onView(
                allOf(withId(R.id.label), withText(R.string.digits),
                        childAtPosition(
                                allOf(withId(R.id.tableRow),
                                        childAtPosition(
                                                IsInstanceOf.instanceOf(android.view.ViewGroup.class),
                                                0)),
                                0),
                        isDisplayed()));
        textView.check(matches(withText(R.string.digits)));

        ViewInteraction textView2 = onView(
                allOf(withId(android.R.id.text1), withText("6"),
                        childAtPosition(
                                allOf(withId(R.id.spinner_row),
                                        childAtPosition(
                                                withId(R.id.tableRow),
                                                1)),
                                0),
                        isDisplayed()));
        textView2.check(matches(withText("6")));

        ViewInteraction textView3 = onView(
                allOf(withId(R.id.label), withText(R.string.algorithm),
                        childAtPosition(
                                allOf(withId(R.id.tableRow),
                                        childAtPosition(
                                                IsInstanceOf.instanceOf(android.view.ViewGroup.class),
                                                0)),
                                0),
                        isDisplayed()));
        textView3.check(matches(withText(R.string.algorithm)));

        ViewInteraction textView4 = onView(
                allOf(withId(android.R.id.text1), withText("SHA1"),
                        childAtPosition(
                                allOf(withId(R.id.spinner_row),
                                        childAtPosition(
                                                withId(R.id.tableRow),
                                                1)),
                                0),
                        isDisplayed()));
        textView4.check(matches(withText("SHA1")));

        ViewInteraction textView5 = onView(
                allOf(withId(R.id.label), withText(R.string.type),
                        childAtPosition(
                                allOf(withId(R.id.tableRow),
                                        childAtPosition(
                                                IsInstanceOf.instanceOf(android.view.ViewGroup.class),
                                                0)),
                                0),
                        isDisplayed()));
        textView5.check(matches(withText(R.string.type)));

        ViewInteraction textView6 = onView(
                allOf(withId(android.R.id.text1), withText("HOTP"),
                        childAtPosition(
                                allOf(withId(R.id.spinner_row),
                                        childAtPosition(
                                                withId(R.id.tableRow),
                                                1)),
                                0),
                        isDisplayed()));
        textView6.check(matches(withText("HOTP")));

        ViewInteraction appCompatEditText = onView(
                allOf(withId(R.id.editText_name), withText("Name"),
                        childAtPosition(
                                childAtPosition(
                                        withId(android.R.id.content),
                                        0),
                                1),
                        isDisplayed()));
        appCompatEditText.perform(click());

        ViewInteraction appCompatEditText2 = onView(
                allOf(withId(R.id.editText_name), withText("Name"),
                        childAtPosition(
                                childAtPosition(
                                        withId(android.R.id.content),
                                        0),
                                1),
                        isDisplayed()));
        appCompatEditText2.perform(click());

        ViewInteraction appCompatEditText3 = onView(
                allOf(withId(R.id.editText_name), withText("Name"),
                        childAtPosition(
                                childAtPosition(
                                        withId(android.R.id.content),
                                        0),
                                1),
                        isDisplayed()));
        appCompatEditText3.perform(click());

        ViewInteraction appCompatEditText4 = onView(
                allOf(withId(R.id.editText_name), withText("Name"),
                        childAtPosition(
                                childAtPosition(
                                        withId(android.R.id.content),
                                        0),
                                1),
                        isDisplayed()));
        appCompatEditText4.perform(replaceText("Nam"));

        ViewInteraction appCompatEditText5 = onView(
                allOf(withId(R.id.editText_name), withText("Nam"),
                        childAtPosition(
                                childAtPosition(
                                        withId(android.R.id.content),
                                        0),
                                1),
                        isDisplayed()));
        appCompatEditText5.perform(closeSoftKeyboard());

        ViewInteraction appCompatEditText6 = onView(
                allOf(withId(R.id.editText_secret), withText((R.string.secret)),
                        childAtPosition(
                                childAtPosition(
                                        withId(android.R.id.content),
                                        0),
                                2),
                        isDisplayed()));
        appCompatEditText6.perform(replaceText("AAAA"));

        ViewInteraction appCompatEditText7 = onView(
                allOf(withId(R.id.editText_secret), withText("AAAA"),
                        childAtPosition(
                                childAtPosition(
                                        withId(android.R.id.content),
                                        0),
                                2),
                        isDisplayed()));
        appCompatEditText7.perform(closeSoftKeyboard());

        ViewInteraction appCompatCheckBox = onView(
                allOf(withId(R.id.checkBox_base32), withText((R.string.base32_encoded_secret)),
                        childAtPosition(
                                childAtPosition(
                                        withId(android.R.id.content),
                                        0),
                                3),
                        isDisplayed()));
        appCompatCheckBox.perform(click());

        ViewInteraction appCompatCheckBox2 = onView(
                allOf(withId(R.id.checkBox_pin), withText((R.string.with_pin)),
                        childAtPosition(
                                childAtPosition(
                                        withId(android.R.id.content),
                                        0),
                                4),
                        isDisplayed()));
        appCompatCheckBox2.perform(click());

        //pressBack();

        ViewInteraction appCompatSpinner = onView(
                allOf(withId(R.id.spinner_row),
                        hasDescendant(withText("6")),
                        isDisplayed()));
        appCompatSpinner.perform(click());

        DataInteraction appCompatTextView2 = onData(anything())
                .inAdapterView(childAtPosition(
                        withClassName(is("android.widget.PopupWindow$PopupBackgroundView")),
                        0))
                .atPosition(1);
        appCompatTextView2.perform(click());

        ViewInteraction appCompatSpinner2 = onView(
                allOf(withId(R.id.spinner_row), hasDescendant(withText("SHA1")),
                        isDisplayed()));
        appCompatSpinner2.perform(click());

        DataInteraction appCompatTextView3 = onData(anything())
                .inAdapterView(childAtPosition(
                        withClassName(is("android.widget.PopupWindow$PopupBackgroundView")),
                        0))
                .atPosition(2);
        appCompatTextView3.perform(click());

        ViewInteraction appCompatSpinner3 = onView(
                allOf(withId(R.id.spinner_row),
                        childAtPosition(
                                allOf(withId(R.id.tableRow),
                                        childAtPosition(
                                                withClassName(is("androidx.constraintlayout.widget.ConstraintLayout")),
                                                0)),
                                1),
                        hasDescendant(withText("HOTP")),
                        isDisplayed()));
        appCompatSpinner3.perform(click());

        DataInteraction appCompatTextView4 = onData(anything())
                .inAdapterView(childAtPosition(
                        withClassName(is("android.widget.PopupWindow$PopupBackgroundView")),
                        0))
                .atPosition(1);
        appCompatTextView4.perform(click());

        ViewInteraction textView7 = onView(
                allOf(withId(R.id.label), withText((R.string.period)),
                        childAtPosition(
                                allOf(withId(R.id.tableRow),
                                        childAtPosition(
                                                IsInstanceOf.instanceOf(android.view.ViewGroup.class),
                                                0)),
                                0),
                        isDisplayed()));
        textView7.check(matches(withText((R.string.period))));

        ViewInteraction textView8 = onView(
                allOf(withId(android.R.id.text1), withText("30s"),
                        childAtPosition(
                                allOf(withId(R.id.spinner_row),
                                        childAtPosition(
                                                withId(R.id.tableRow),
                                                1)),
                                0),
                        isDisplayed()));
        textView8.check(matches(withText("30s")));

        ViewInteraction appCompatSpinner4 = onView(
                allOf(withId(R.id.spinner_row),
                        childAtPosition(
                                allOf(withId(R.id.tableRow),
                                        childAtPosition(
                                                withClassName(is("androidx.constraintlayout.widget.ConstraintLayout")),
                                                0)),
                                1),
                        hasDescendant(withText("TOTP")),
                        isDisplayed()));
        appCompatSpinner4.perform(click());

        DataInteraction appCompatTextView5 = onData(anything())
                .inAdapterView(childAtPosition(
                        withClassName(is("android.widget.PopupWindow$PopupBackgroundView")),
                        0))
                .atPosition(0);
        appCompatTextView5.perform(click());

        ViewInteraction appCompatButton = onView(
                allOf(withId(R.id.button_add), withText("+"),
                        childAtPosition(
                                childAtPosition(
                                        withId(android.R.id.content),
                                        0),
                                5),
                        isDisplayed()));
        appCompatButton.perform(click());

        sleep();

        onView(withText((R.string.tap_to_set_pin))).check(matches(isDisplayed()));

        ViewInteraction textView10 = onView(
                allOf(withId(R.id.textViewLabel), withText("Nam")));
        textView10.check(matches(withText("Nam")));

        sleep();

        DataInteraction relativeLayout = onData(anything())
                .inAdapterView(allOf(withId(R.id.listview),
                        childAtPosition(
                                withId(R.id.main_constraint_layout),
                                1)))
                .atPosition(0);
        relativeLayout.perform(click());

        sleep();

        ViewInteraction textView11 = onView(
                allOf(IsInstanceOf.instanceOf(android.widget.TextView.class), withText((R.string.set_new_pin)),
                        isDisplayed()));
        textView11.check(matches(withText((R.string.set_new_pin))));

        ViewInteraction editText5 = onView(
                allOf(childAtPosition(
                        allOf(withId(android.R.id.custom),
                                childAtPosition(
                                        IsInstanceOf.instanceOf(android.widget.FrameLayout.class),
                                        0)),
                        0),
                        isDisplayed()));
        editText5.check(matches(isDisplayed()));

        ViewInteraction button2 = onView(
                allOf(withId(android.R.id.button1),
                        isDisplayed()));
        button2.check(matches(isDisplayed()));

        ViewInteraction button3 = onView(
                allOf(withId(android.R.id.button2),
                        isDisplayed()));
        button3.check(matches(isDisplayed()));

        sleep();

        ViewInteraction editText6 = onView(
                allOf(childAtPosition(
                        allOf(withId(android.R.id.custom),
                                childAtPosition(
                                        withClassName(is("android.widget.FrameLayout")),
                                        0)),
                        0),
                        isDisplayed()));
        editText6.perform(click());

        sleep();

        ViewInteraction editText7 = onView(
                allOf(childAtPosition(
                        allOf(withId(android.R.id.custom),
                                childAtPosition(
                                        withClassName(is("android.widget.FrameLayout")),
                                        0)),
                        0),
                        isDisplayed()));
        editText7.perform(replaceText("5"), closeSoftKeyboard());

        sleep();

        ViewInteraction appCompatButton2 = onView(
                allOf(withId(android.R.id.button1), withText(R.string.button_text_save),
                        childAtPosition(
                                childAtPosition(
                                        withClassName(is("android.widget.ScrollView")),
                                        0),
                                3)));
        appCompatButton2.perform(scrollTo(), click());

        sleep();

        onView(withId(R.id.textViewToken)).check(matches(withText("66674061")));

        ViewInteraction textView13 = onView(
                allOf(withId(R.id.textViewLabel), withText("Nam"),
                        childAtPosition(
                                childAtPosition(
                                        withId(R.id.listview),
                                        0),
                                2),
                        isDisplayed()));
        textView13.check(matches(withText("Nam")));

        ViewInteraction button4 = onView(
                allOf(withId(R.id.next_button),
                        isDisplayed()));
        button4.check(matches(isDisplayed()));

        sleep();

        DataInteraction relativeLayout2 = onData(anything())
                .inAdapterView(allOf(withId(R.id.listview),
                        childAtPosition(
                                withId(R.id.main_constraint_layout),
                                1)))
                .atPosition(0);
        relativeLayout2.perform(longClick());

        sleep();

        ViewInteraction actionMenuItemView = onView(
                allOf(withId(R.id.change_pin2), withContentDescription(R.string.change_pin),
                        isDisplayed()));
        actionMenuItemView.perform(click());

        sleep();

        ViewInteraction editText8 = onView(
                allOf(childAtPosition(
                        childAtPosition(
                                withId(android.R.id.custom),
                                0),
                        0),
                        isDisplayed()));
        editText8.perform(click());

        sleep();

        ViewInteraction editText9 = onView(
                allOf(childAtPosition(
                        childAtPosition(
                                withId(android.R.id.custom),
                                0),
                        0),
                        isDisplayed()));
        editText9.perform(replaceText("8"), closeSoftKeyboard());

        sleep();

        ViewInteraction editText10 = onView(
                allOf(childAtPosition(
                        childAtPosition(
                                withId(android.R.id.custom),
                                0),
                        1),
                        isDisplayed()));
        editText10.perform(replaceText("8"), closeSoftKeyboard());

        sleep();

        ViewInteraction textView14 = onView(
                allOf(IsInstanceOf.instanceOf(android.widget.TextView.class), withText(R.string.change_pin),
                        isDisplayed()));
        textView14.check(matches(withText(R.string.change_pin)));

        ViewInteraction editText11 = onView(
                allOf(withText("•"),
                        childAtPosition(
                                childAtPosition(
                                        withId(android.R.id.custom),
                                        0),
                                0),
                        isDisplayed()));
        editText11.check(matches(isDisplayed()));

        ViewInteraction editText12 = onView(
                allOf(withText("•"),
                        childAtPosition(
                                childAtPosition(
                                        withId(android.R.id.custom),
                                        0),
                                1),
                        isDisplayed()));
        editText12.check(matches(isDisplayed()));

        ViewInteraction button5 = onView(
                allOf(withId(android.R.id.button1),
                        isDisplayed()));
        button5.check(matches(isDisplayed()));

        ViewInteraction button6 = onView(
                allOf(withId(android.R.id.button2),
                        isDisplayed()));
        button6.check(matches(isDisplayed()));

        sleep();

        ViewInteraction appCompatButton3 = onView(
                allOf(withId(android.R.id.button1), withText(R.string.button_text_save),
                        childAtPosition(
                                childAtPosition(
                                        withClassName(is("android.widget.ScrollView")),
                                        0),
                                3)));
        appCompatButton3.perform(scrollTo(), click());

        sleep();

        DataInteraction relativeLayout3 = onData(anything())
                .inAdapterView(allOf(withId(R.id.listview),
                        childAtPosition(
                                withId(R.id.main_constraint_layout),
                                1)))
                .atPosition(0);
        relativeLayout3.perform(longClick());

        sleep();

        ViewInteraction textView15 = onView(
                allOf(withId(R.id.change_pin2), withContentDescription(R.string.change_pin),
                        childAtPosition(
                                childAtPosition(
                                        withId(R.id.action_mode_bar),
                                        2),
                                0),
                        isDisplayed()));
        textView15.check(matches(isDisplayed()));

        ViewInteraction textView16 = onView(
                allOf(withId(R.id.edit_token2), withContentDescription(R.string.rename),
                        childAtPosition(
                                childAtPosition(
                                        withId(R.id.action_mode_bar),
                                        2),
                                1),
                        isDisplayed()));
        textView16.check(matches(isDisplayed()));

        ViewInteraction textView17 = onView(
                allOf(withId(R.id.delete_token2), withContentDescription("Item"),
                        childAtPosition(
                                childAtPosition(
                                        withId(R.id.action_mode_bar),
                                        2),
                                2),
                        isDisplayed()));
        textView17.check(matches(isDisplayed()));

        ViewInteraction imageView2 = onView(
                allOf(childAtPosition(
                        allOf(withId(R.id.toolbar),
                                childAtPosition(
                                        withId(R.id.main_constraint_layout),
                                        0)),
                        0),
                        isDisplayed()));
        imageView2.check(matches(isDisplayed()));

        sleep();

        sleep();

        ViewInteraction actionMenuItemView3 = onView(
                allOf(withId(R.id.edit_token2), withContentDescription(R.string.rename),
                        childAtPosition(
                                childAtPosition(
                                        withId(R.id.action_mode_bar),
                                        2),
                                1),
                        isDisplayed()));
        actionMenuItemView3.perform(click());

        sleep();

        ViewInteraction editText13 = onView(
                allOf(withText("Nam"),
                        isDisplayed()));
        editText13.check(matches(isDisplayed()));

        ViewInteraction button7 = onView(
                allOf(withId(android.R.id.button2),
                        isDisplayed()));
        button7.check(matches(isDisplayed()));

        ViewInteraction editText14 = onView(
                allOf(withText("Nam"),
                        isDisplayed()));
        editText14.check(matches(withText("Nam")));

        ViewInteraction button8 = onView(
                allOf(withId(android.R.id.button1),
                        isDisplayed()));
        button8.check(matches(isDisplayed()));

        sleep();

        ViewInteraction editText15 = onView(
                allOf(withText("Nam"),
                        isDisplayed()));
        editText15.perform(click());

        sleep();

        ViewInteraction editText16 = onView(
                allOf(withText("Nam"),
                        childAtPosition(
                                allOf(withId(android.R.id.custom),
                                        childAtPosition(
                                                withClassName(is("android.widget.FrameLayout")),
                                                0)),
                                0),
                        isDisplayed()));
        editText16.perform(replaceText("Name"));

        ViewInteraction editText17 = onView(
                allOf(withText("Name"),
                        childAtPosition(
                                allOf(withId(android.R.id.custom),
                                        childAtPosition(
                                                withClassName(is("android.widget.FrameLayout")),
                                                0)),
                                0),
                        isDisplayed()));
        editText17.perform(closeSoftKeyboard());

        sleep();

        ViewInteraction appCompatButton4 = onView(
                allOf(withId(android.R.id.button1), withText(R.string.button_text_save),
                        childAtPosition(
                                childAtPosition(
                                        withClassName(is("android.widget.ScrollView")),
                                        0),
                                3)));
        appCompatButton4.perform(scrollTo(), click());

        sleep();


        sleep();

        onView(withId(R.id.textViewLabel)).check(matches(withText("Name")));

        sleep();

        openActionBarOverflowOrOptionsMenu(getInstrumentation().getTargetContext());

        sleep();

        ViewInteraction appCompatTextView6 = onView(
                allOf(withId(R.id.title), withText(R.string.menu_add_manually),
                        childAtPosition(
                                childAtPosition(
                                        withId(R.id.content),
                                        0),
                                0),
                        isDisplayed()));
        appCompatTextView6.perform(click());

        sleep();

        ViewInteraction appCompatSpinner5 = onView(
                allOf(withId(R.id.spinner_row), hasDescendant(withText("HOTP")),
                        isDisplayed()));
        appCompatSpinner5.perform(click());

        DataInteraction appCompatTextView7 = onData(anything())
                .inAdapterView(childAtPosition(
                        withClassName(is("android.widget.PopupWindow$PopupBackgroundView")),
                        0))
                .atPosition(1);
        appCompatTextView7.perform(click());

        ViewInteraction appCompatButton6 = onView(
                allOf(withId(R.id.button_add), withText("+"),
                        childAtPosition(
                                childAtPosition(
                                        withId(android.R.id.content),
                                        0),
                                5),
                        isDisplayed()));
        appCompatButton6.perform(click());

        sleep();

        onView(allOf(withId(R.id.progressBar), withEffectiveVisibility(ViewMatchers.Visibility.VISIBLE))).check(matches(isDisplayed()));
    }

    private String getString(int resID) {
        return InstrumentationRegistry.getInstrumentation().getTargetContext().getString(resID);
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
}
