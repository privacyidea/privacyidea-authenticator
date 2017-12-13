package it.netknights.piauthenticator;


import android.content.Context;
import android.support.test.espresso.DataInteraction;
import android.support.test.espresso.ViewInteraction;
import android.support.test.rule.ActivityTestRule;
import android.support.test.runner.AndroidJUnit4;
import android.test.suitebuilder.annotation.LargeTest;
import android.util.Log;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;

import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeMatcher;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.File;

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
import static android.support.test.espresso.matcher.ViewMatchers.withContentDescription;
import static android.support.test.espresso.matcher.ViewMatchers.withId;
import static android.support.test.espresso.matcher.ViewMatchers.withParent;
import static android.support.test.espresso.matcher.ViewMatchers.withText;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.anything;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.startsWith;

@LargeTest
@RunWith(AndroidJUnit4.class)
public class EnterDetailTest {

    @Rule
    public ActivityTestRule<MainActivity> mActivityTestRule = new ActivityTestRule<>(MainActivity.class);

    @Before
    public void setUp() throws Exception {
        Log.d("piauth.test", "triyng to overwrite datafile");
        Context context = getInstrumentation().getTargetContext();
        Util.writeFile(new File(context.getFilesDir() + "/" + AppConstants.DATAFILE), "".getBytes());
    }

    //TODO since deleting appdata before test is not working delete every token after checking
    @Test
    public void testEnterDetail() {
        sleep();

        openActionBarOverflowOrOptionsMenu(getInstrumentation().getTargetContext());

        sleep();

        ViewInteraction appCompatTextView = onView(
                allOf(withId(R.id.title), withText("Add token manually"),
                        childAtPosition(
                                childAtPosition(
                                        withClassName(is("android.support.v7.view.menu.ListMenuItemView")),
                                        0),
                                0),
                        isDisplayed()));
        appCompatTextView.perform(click());


        sleep();

        ViewInteraction appCompatSpinner = onView(
                allOf(withId(R.id.spinner_type),
                        childAtPosition(
                                childAtPosition(
                                        withId(android.R.id.content),
                                        0),
                                9),
                        isDisplayed()));
        appCompatSpinner.perform(click());

        DataInteraction appCompatTextView2 = onData(anything())
                .inAdapterView(withClassName(is("android.support.v7.widget.DropDownListView")))
                .atPosition(1);
        appCompatTextView2.perform(click());

        ViewInteraction appCompatSpinner2 = onView(
                allOf(withId(R.id.spinner_algorithm),
                        childAtPosition(
                                childAtPosition(
                                        withId(android.R.id.content),
                                        0),
                                10),
                        isDisplayed()));
        appCompatSpinner2.perform(click());

        DataInteraction appCompatTextView3 = onData(anything())
                .inAdapterView(withClassName(is("android.support.v7.widget.DropDownListView")))
                .atPosition(2);
        appCompatTextView3.perform(click());
        sleep();
        ViewInteraction appCompatSpinner3 = onView(
                allOf(withId(R.id.spinner_digits),
                        childAtPosition(
                                childAtPosition(
                                        withId(android.R.id.content),
                                        0),
                                13),
                        isDisplayed()));
        appCompatSpinner3.perform(click());
        sleep();
        DataInteraction appCompatTextView4 = onData(anything())
                .inAdapterView(withClassName(is("android.support.v7.widget.DropDownListView")))
                .atPosition(1);
        appCompatTextView4.perform(click());
        sleep();
        ViewInteraction appCompatCheckBox = onView(
                allOf(withId(R.id.checkBox_pin), withText("With PIN"),
                        childAtPosition(
                                childAtPosition(
                                        withId(android.R.id.content),
                                        0),
                                4),
                        isDisplayed()));
        appCompatCheckBox.perform(click());
        sleep();
        ViewInteraction appCompatButton = onView(
                allOf(withId(R.id.button_add), withText("Add"),
                        childAtPosition(
                                childAtPosition(
                                        withId(android.R.id.content),
                                        0),
                                5),
                        isDisplayed()));
        appCompatButton.perform(click());

        sleep();

        DataInteraction relativeLayout = onData(anything())
                .inAdapterView(allOf(withId(R.id.listview),
                        childAtPosition(
                                withClassName(is("android.support.constraint.ConstraintLayout")),
                                1)))
                .atPosition(0);
        relativeLayout.perform(click());
        sleep();

        ViewInteraction editText = onView(
                allOf(childAtPosition(
                        allOf(withId(android.R.id.custom),
                                childAtPosition(
                                        withClassName(is("android.widget.FrameLayout")),
                                        0)),
                        0),
                        isDisplayed()));
        editText.perform(click());
        sleep();

        ViewInteraction editText2 = onView(
                allOf(childAtPosition(
                        allOf(withId(android.R.id.custom),
                                childAtPosition(
                                        withClassName(is("android.widget.FrameLayout")),
                                        0)),
                        0),
                        isDisplayed()));
        editText2.perform(replaceText("5"), closeSoftKeyboard());
        sleep();

        ViewInteraction appCompatButton2 = onView(
                allOf(withId(android.R.id.button1), withText("Save"),
                        childAtPosition(
                                allOf(withClassName(is("android.widget.LinearLayout")),
                                        childAtPosition(
                                                withClassName(is("android.widget.LinearLayout")),
                                                3)),
                                3),
                        isDisplayed()));
        appCompatButton2.perform(click());

        sleep();
        // check the first otp at list position 0
        onData(anything()).
                inAdapterView(withId(R.id.listview)).
                atPosition(0).
                onChildView(withId(R.id.textViewToken))
                .check(matches(withText(startsWith("96418505"))));
        onData(anything()).
                inAdapterView(withId(R.id.listview)).
                atPosition(0).
                onChildView(withId(R.id.textViewLabel))
                .check(matches(withText(startsWith("Name"))));
        // click next
        ViewInteraction appCompatButton3 = onView(
                allOf(withId(R.id.next_button), withText("next"),
                        childAtPosition(
                                withParent(withId(R.id.listview)),
                                3),
                        isDisplayed()));
        appCompatButton3.perform(click());
        sleep();
        // check second otp
        onData(anything()).
                inAdapterView(withId(R.id.listview)).
                atPosition(0).
                onChildView(withId(R.id.textViewToken))
                .check(matches(withText(startsWith("85216514"))));

        // rename
        onData(anything())
                .inAdapterView(allOf(withId(R.id.listview),
                        childAtPosition(
                                withClassName(is("android.support.constraint.ConstraintLayout")),
                                1))).atPosition(0).perform(longClick());
        sleep();
        onView(
                allOf(withId(R.id.edit_token2), withContentDescription("Rename"),
                        childAtPosition(
                                childAtPosition(
                                        withId(R.id.action_mode_bar),
                                        2),
                                1),
                        isDisplayed())).perform(click());
        sleep();
        onView(
                allOf(withText("Name"),
                        childAtPosition(
                                allOf(withId(android.R.id.custom),
                                        childAtPosition(
                                                withClassName(is("android.widget.FrameLayout")),
                                                0)),
                                0),
                        isDisplayed())).perform(replaceText("peter"));
        sleep();
        onView(
                allOf(withId(android.R.id.button1), withText("Save"),
                        childAtPosition(
                                allOf(withClassName(is("android.widget.LinearLayout")),
                                        childAtPosition(
                                                withClassName(is("android.widget.LinearLayout")),
                                                3)),
                                3),
                        isDisplayed())).perform(click());
        sleep();
        // check renaming
        onData(anything()).
                inAdapterView(withId(R.id.listview)).
                atPosition(0).
                onChildView(withId(R.id.textViewLabel))
                .check(matches(withText(startsWith("peter"))));
        sleep();


        // delete the token
        DataInteraction relativeLayout2 = onData(anything())
                .inAdapterView(allOf(withId(R.id.listview),
                        childAtPosition(
                                withClassName(is("android.support.constraint.ConstraintLayout")),
                                1)))
                .atPosition(0);
        relativeLayout2.perform(longClick());

        sleep();

        ViewInteraction actionMenuItemView = onView(
                allOf(withId(R.id.delete_token2), withContentDescription("Item"),
                        childAtPosition(
                                childAtPosition(
                                        withId(R.id.action_mode_bar),
                                        2),
                                2),
                        isDisplayed()));
        actionMenuItemView.perform(click());

        sleep();

        ViewInteraction appCompatButton4 = onView(
                allOf(withId(android.R.id.button1), withText("YES"),
                        childAtPosition(
                                allOf(withClassName(is("android.widget.LinearLayout")),
                                        childAtPosition(
                                                withClassName(is("android.widget.LinearLayout")),
                                                3)),
                                3),
                        isDisplayed()));
        appCompatButton4.perform(click());
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
