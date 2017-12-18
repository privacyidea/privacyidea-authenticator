package it.netknights.androidTest;

import android.app.Activity;
import android.app.Instrumentation;
import android.content.Context;
import android.content.Intent;
import android.support.test.InstrumentationRegistry;
import android.support.test.espresso.ViewInteraction;
import android.support.test.espresso.intent.Intents;
import android.support.test.rule.ActivityTestRule;
import android.support.test.runner.AndroidJUnit4;
import android.util.Log;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.widget.ListView;

import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeMatcher;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;

import it.netknights.piauthenticator.AppConstants;
import it.netknights.piauthenticator.MainActivity;
import it.netknights.piauthenticator.R;
import it.netknights.piauthenticator.Util;

import static android.support.test.InstrumentationRegistry.getInstrumentation;
import static android.support.test.InstrumentationRegistry.getTargetContext;
import static android.support.test.espresso.Espresso.onData;
import static android.support.test.espresso.Espresso.onView;
import static android.support.test.espresso.action.ViewActions.click;
import static android.support.test.espresso.action.ViewActions.longClick;
import static android.support.test.espresso.assertion.ViewAssertions.matches;
import static android.support.test.espresso.intent.Intents.intended;
import static android.support.test.espresso.intent.Intents.intending;
import static android.support.test.espresso.intent.matcher.IntentMatchers.hasAction;
import static android.support.test.espresso.matcher.ViewMatchers.isDisplayed;
import static android.support.test.espresso.matcher.ViewMatchers.withClassName;
import static android.support.test.espresso.matcher.ViewMatchers.withContentDescription;
import static android.support.test.espresso.matcher.ViewMatchers.withId;
import static android.support.test.espresso.matcher.ViewMatchers.withText;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.anything;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.startsWith;

@RunWith(AndroidJUnit4.class)
public class MainActivityTest {

    @Rule
    public ActivityTestRule<MainActivity> mActivityTestRule = new ActivityTestRule<>(MainActivity.class);

    @Before
    public void beforeActivityLaunched() throws Exception {
        //TODO clear app data before running tests
        //Log.d("piauth.test", "triyng to overwrite datafile");
        //Context context = getInstrumentation().getTargetContext();
      /*  Context context = getTargetContext();
        Util.writeFile(new File(context.getFilesDir() + "/" + AppConstants.DATAFILE), "".getBytes());
        if (new File(mActivityTestRule.getActivity().getFilesDir() + "/" + AppConstants.DATAFILE).delete()) {
            Log.d("piauth.test", "datafile deleted");
        }
        if (new File(mActivityTestRule.getActivity().getFilesDir() + "/" + AppConstants.KEYFILE).delete()) {
            Log.d("piauth.test", "keyfile deleted");

        }
        String[] ls = mActivityTestRule.getActivity().fileList();
        for (int i = 0; i < ls.length; i++) {
            Log.d("piauth.test", ls[i]);
        }*/

        //shell("pm clear it.netknights.piauthenticator");
        //Process p = Runtime.getRuntime().exec("su");
        //InstrumentationRegistry.getInstrumentation().getUiAutomation().executeShellCommand("pm clear it.netknights.piauthenticator");
    }

    @Test
    public void test01ValidQR() {
        onView(withId(R.id.fab)).check(matches(isDisplayed()));
        ViewInteraction floatingActionButton = onView(
                allOf(withId(R.id.fab),
                        childAtPosition(
                                childAtPosition(
                                        withId(android.R.id.content),
                                        0),
                                2),
                        isDisplayed()));
        Intents.init();
        String valid_qr = "otpauth://hotp/testtoken?secret=TXHEXPREOXHFKDRE6BNZJOFKQ5OLDZWC&counter=1&digits=6&issuer=privacyIDEA";
        String invalid_qr = "lalalalala";

        // Build a result to return from the ZXING app
        Intent resultData = new Intent();
        resultData.putExtra(com.google.zxing.client.android.Intents.Scan.RESULT, valid_qr);
        Instrumentation.ActivityResult result = new Instrumentation.ActivityResult(Activity.RESULT_OK, resultData);

        // Stub out the Camera. When an intent is sent to the Camera, this tells Espresso to respond
        // with the ActivityResult we just created
        intending(hasAction("com.google.zxing.client.android.SCAN")).respondWith(result);

       /* onView(withId(R.id.fab)).check(matches(isDisplayed()));
        onView(withId(R.id.fab)).perform(click());*/
        floatingActionButton.perform(click());
        // We can also validate that an intent resolving to the "camera" activity has been sent out by our app
        intended(hasAction("com.google.zxing.client.android.SCAN"));
        sleep(2000);
        //onView(withText("Invalid QR Code")).check(matches(isDisplayed()));
        //onData(anything("privacyIDEA: testtoken")).check(matches(isDisplayed()));
        //onData(withRowString(1, "privacyIDEA: testtoken")).check(matches(isDisplayed()));

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

        //onData(withItem

        // delete the token

        onData(anything())
                .inAdapterView(allOf(withId(R.id.listview),
                        childAtPosition(
                                withClassName(is("android.support.constraint.ConstraintLayout")),
                                1)))
                .atPosition(0).perform(longClick());
        sleep();
        ViewInteraction actionMenuItemView = onView(
                allOf(withId(R.id.delete_token2), withContentDescription("Item"),
                        childAtPosition(
                                childAtPosition(
                                        withId(R.id.action_mode_bar),
                                        2),
                                1),
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
        Intents.release();
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

    public String shell(String cmd) {

        String s = null;
        try {
            Process p = null;
            try {
                p = Runtime.getRuntime().exec(cmd);
            } catch (IOException e) {
                e.printStackTrace();
            }

            BufferedReader stdInput = new BufferedReader(new InputStreamReader(
                    p.getInputStream()));

            BufferedReader stdError = new BufferedReader(new InputStreamReader(
                    p.getErrorStream()));

            // read the output from the cmd
            String result = "";
            while ((s = stdInput.readLine()) != null) {
                result = result + s + "\n";
            }

            // read any errors from the attempted comd
            while ((s = stdError.readLine()) != null) {
                System.out.println(s);
            }
            return result;

        } catch (IOException e) {
            System.out.println("exception here's what I know: ");
            e.printStackTrace();
            return "Exception occurred";
        }
    }

    private int getAdapterCount(){
        final int[] counts = new int[1];
        onView(withId(R.id.listview)).check(matches(new TypeSafeMatcher<View>() {
            @Override
            public boolean matchesSafely(View view) {
                ListView listView = (ListView) view;

                counts[0] = listView.getCount();

                return true;
            }

            @Override
            public void describeTo(Description description) {

            }
        }));
        return counts[0];
    }
}
