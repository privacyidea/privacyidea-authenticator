package it.netknights.piauthenticator;

import android.util.Log;
import android.view.View;
import android.widget.TextView;

import org.hamcrest.Description;

import androidx.test.espresso.matcher.BoundedMatcher;

public class AnyStringMatcher extends BoundedMatcher<View, TextView> {

    static AnyStringMatcher withAnyString() {
        return new AnyStringMatcher();
    }

    private AnyStringMatcher() {
        super(TextView.class);
    }

    @Override
    protected boolean matchesSafely(TextView item) {
        Log.e("TEST", "text: " + item.getText());
        return !(item.getText().equals(""));
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("with any text.");
    }
}
