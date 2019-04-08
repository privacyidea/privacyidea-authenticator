package it.netknights.piauthenticator;

import android.view.WindowManager;

import org.hamcrest.Description;
import org.hamcrest.TypeSafeMatcher;

import androidx.test.espresso.Root;

public class ToastMatcher extends TypeSafeMatcher<Root> {
    @Override
    protected boolean matchesSafely(Root root) {
        int type = root.getWindowLayoutParams().get().type;
        if (type == WindowManager.LayoutParams.TYPE_TOAST) {
            if (root.getDecorView().getWindowToken() == root.getDecorView().getApplicationWindowToken()) {
                return true;
            }
        }
        return false;
    }

    @Override
    public void describeTo(Description description) {
        description.appendText("is toast");
    }
}
