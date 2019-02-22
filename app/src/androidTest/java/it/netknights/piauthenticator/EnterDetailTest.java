package it.netknights.piauthenticator;


import android.support.test.espresso.DataInteraction;
import android.support.test.espresso.ViewInteraction;
import android.support.test.filters.LargeTest;
import android.support.test.rule.ActivityTestRule;
import android.support.test.runner.AndroidJUnit4;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.widget.TableLayout;
import android.widget.TableRow;

import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeMatcher;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import static android.support.test.InstrumentationRegistry.getInstrumentation;
import static android.support.test.espresso.Espresso.onData;
import static android.support.test.espresso.Espresso.onView;
import static android.support.test.espresso.Espresso.openActionBarOverflowOrOptionsMenu;
import static android.support.test.espresso.action.ViewActions.click;
import static android.support.test.espresso.action.ViewActions.closeSoftKeyboard;
import static android.support.test.espresso.action.ViewActions.longClick;
import static android.support.test.espresso.action.ViewActions.replaceText;
import static android.support.test.espresso.action.ViewActions.scrollTo;
import static android.support.test.espresso.assertion.ViewAssertions.matches;
import static android.support.test.espresso.intent.Checks.checkNotNull;
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
    public void setUp() {
        mActivityTestRule.getActivity().clearTokenlist();
    }

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
                allOf(withId(R.id.button_add), withText("+"),
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
                                childAtPosition(
                                        withClassName(is("android.widget.ScrollView")),
                                        0),
                                3)));
        appCompatButton2.perform(scrollTo(), click());

        sleep();
        // check the first otp at list position 0 // 96418505
        onData(anything()).
                inAdapterView(withId(R.id.listview)).
                atPosition(0).
                onChildView(withId(R.id.textViewToken))
                .check(matches(withText(startsWith("292574"))));
        onData(anything()).
                inAdapterView(withId(R.id.listview)).
                atPosition(0).
                onChildView(withId(R.id.textViewLabel))
                .check(matches(withText(startsWith("Name"))));
        // click next
        ViewInteraction appCompatButton3 = onView(
                allOf(withId(R.id.next_button), withText("Next"),
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
                .check(matches(withText(startsWith("449381")))); //85216514

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

        ViewInteraction appCompatButton4 = onView(
                allOf(withId(android.R.id.button1), withText("Save"),
                        childAtPosition(
                                childAtPosition(
                                        withClassName(is("android.widget.ScrollView")),
                                        0),
                                3)));
        appCompatButton4.perform(scrollTo(), click());
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
                allOf(withId(R.id.change_pin2), withContentDescription("Change PIN"),
                        childAtPosition(
                                childAtPosition(
                                        withId(R.id.action_mode_bar),
                                        2),
                                0),
                        isDisplayed()));
        actionMenuItemView.perform(click());

        sleep();

        ViewInteraction editText5 = onView(
                allOf(childAtPosition(
                        childAtPosition(
                                withId(android.R.id.custom),
                                0),
                        0),
                        isDisplayed()));
        editText5.perform(click());

        sleep();

        ViewInteraction editText6 = onView(
                allOf(childAtPosition(
                        childAtPosition(
                                withId(android.R.id.custom),
                                0),
                        0),
                        isDisplayed()));
        editText6.perform(replaceText("2"), closeSoftKeyboard());


        sleep();
        ViewInteraction editText7 = onView(
                allOf(childAtPosition(
                        childAtPosition(
                                withId(android.R.id.custom),
                                0),
                        1),
                        isDisplayed()));
        editText7.perform(replaceText("2"), closeSoftKeyboard());


        sleep();
        ViewInteraction appCompatButton6 = onView(
                allOf(withId(android.R.id.button1), withText("Save"),
                        childAtPosition(
                                childAtPosition(
                                        withClassName(is("android.widget.ScrollView")),
                                        0),
                                3)));
        appCompatButton6.perform(scrollTo(), click());
        sleep();


        DataInteraction relativeLayout3 = onData(anything())
                .inAdapterView(allOf(withId(R.id.listview),
                        childAtPosition(
                                withClassName(is("android.support.constraint.ConstraintLayout")),
                                1)))
                .atPosition(0);
        relativeLayout3.perform(longClick());


        sleep();
        ViewInteraction actionMenuItemView2 = onView(
                allOf(withId(R.id.delete_token2), withContentDescription("Item"),
                        childAtPosition(
                                childAtPosition(
                                        withId(R.id.action_mode_bar),
                                        2),
                                2),
                        isDisplayed()));
        actionMenuItemView2.perform(click());


        sleep();
        ViewInteraction appCompatButton7 = onView(
                allOf(withId(android.R.id.button1), withText("Yes"),
                        childAtPosition(
                                childAtPosition(
                                        withClassName(is("android.widget.ScrollView")),
                                        0),
                                3)));
        appCompatButton7.perform(scrollTo(), click());

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

    static Matcher<View> isInRowBelow(final Matcher<View> viewInRowAbove) {
        checkNotNull(viewInRowAbove);
        return new TypeSafeMatcher<View>() {

            @Override
            public void describeTo(Description description) {
                description.appendText("is below a: ");
                viewInRowAbove.describeTo(description);
            }

            @Override
            public boolean matchesSafely(View view) {
                // Find the current row
                ViewParent viewParent = view.getParent();
                if (!(viewParent instanceof TableRow)) {
                    return false;
                }
                TableRow currentRow = (TableRow) viewParent;
                // Find the row above
                TableLayout table = (TableLayout) currentRow.getParent();
                int currentRowIndex = table.indexOfChild(currentRow);
                if (currentRowIndex < 1) {
                    return false;
                }
                TableRow rowAbove = (TableRow) table.getChildAt(currentRowIndex - 1);
                // Does the row above contains at least one view that matches viewInRowAbove?
                for (int i = 0; i < rowAbove.getChildCount(); i++) {
                    if (viewInRowAbove.matches(rowAbove.getChildAt(i))) {
                        return true;
                    }
                }
                return false;
            }
        };
    }

    static Matcher<View> hasChildPosition(final int i) {
        return new TypeSafeMatcher<View>() {

            @Override
            public void describeTo(Description description) {
                description.appendText("is child #" + i);
            }

            @Override
            public boolean matchesSafely(View view) {
                ViewParent viewParent = view.getParent();
                if (!(viewParent instanceof ViewGroup)) {
                    return false;
                }
                ViewGroup viewGroup = (ViewGroup) viewParent;
                return (viewGroup.indexOfChild(view) == i);
            }
        };
    }

    static Matcher<View> atPositionInTable(final int x, final int y) {

        return new TypeSafeMatcher<View>() {


            @Override

            public void describeTo(Description description) {

                description.appendText("is at position # " + x + " , " + y);

            }


            @Override

            public boolean matchesSafely(View view) {

                ViewParent viewParent = view.getParent();

                if (!(viewParent instanceof TableRow)) {

                    return false;

                }

                TableRow row = (TableRow) viewParent;

                TableLayout table = (TableLayout) row.getParent();

                if (table.indexOfChild(row) != y)

                    return false;

                if (row.indexOfChild(view) == x)

                    return true;

                else

                    return false;

            }
        };

    }
}
