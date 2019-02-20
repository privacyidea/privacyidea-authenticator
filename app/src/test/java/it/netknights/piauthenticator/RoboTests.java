package it.netknights.piauthenticator;

import android.widget.ListView;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.shadows.ShadowListView;

import java.util.ArrayList;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.robolectric.Shadows.shadowOf;

@RunWith(RobolectricTestRunner.class)
public class RoboTests {



    @Test
    public void test01(){
        MainActivity mMainActivity = Robolectric.setupActivity(MainActivity.class);
        ListView listView = mMainActivity.findViewById(R.id.listview);
        assertNotNull(listView);
        TokenListAdapter tlAdapter = new TokenListAdapter();
        listView.setAdapter(tlAdapter);

        Token t = new Token("aaaa".getBytes(), "test label", "hotp", 6);
        ArrayList<Token> al = new ArrayList<>();
        al.add(t);

        mMainActivity.tokenlist = al;
        ShadowListView shadowList = shadowOf(listView);
        assertNotNull(listView.getAdapter());

        shadowList.populateItems();
        assertTrue("List should not be empty",listView.getAdapter().getCount()>0);
    }
}
