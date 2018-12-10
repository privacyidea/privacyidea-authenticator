package it.netknights.piauthenticator;

import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.graphics.drawable.ColorDrawable;
import android.os.Build;
import androidx.appcompat.app.ActionBar;
import androidx.appcompat.app.AppCompatActivity;
import android.os.Bundle;
import android.view.Window;
import android.view.WindowManager;
import android.widget.ListView;
import android.widget.TextView;

import java.util.ArrayList;

import static it.netknights.piauthenticator.R.color.PIBLUE;

public class AboutActivity extends AppCompatActivity {
    private ListView listView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_about);
        setupViews();
        paintStatusbar();
        setupActionBar();
        setupList();
    }

    private void setupList() {
        ArrayList<String> acknowledgements = new ArrayList<>();
        acknowledgements.add(getString(R.string.license_apache_20));
        acknowledgements.add(getString(R.string.license_otpauth));
        acknowledgements.add(getString(R.string.license_zxing_embed));
        acknowledgements.add(getString(R.string.license_android_code_sample));
        AboutListAdapter adapter = new AboutListAdapter();
        listView.setAdapter(adapter);
        adapter.setAcknowledgements(acknowledgements);
        adapter.notifyDataSetChanged();
    }

    private void setupViews() {
        listView = (ListView) findViewById(R.id.listView_about);
        TextView textViewVersion = (TextView) findViewById(R.id.textView_version);
        PackageInfo info = null;

        try {
            info = getPackageManager().getPackageInfo(AppConstants.PACKAGE_NAME, 0);
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
        }
        if (info != null) {
            String str = getString(R.string.version) + " "+ info.versionName;
            textViewVersion.setText(str);
        } else {
            textViewVersion.setText(R.string.version);
        }
    }

    public void paintStatusbar() {
        //------------------ try to paint the statusbar -------------------------------
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            Window window = getWindow();
            window.addFlags(WindowManager.LayoutParams.FLAG_DRAWS_SYSTEM_BAR_BACKGROUNDS);
            window.clearFlags(WindowManager.LayoutParams.FLAG_TRANSLUCENT_STATUS);
            window.setStatusBarColor(getResources().getColor(PIBLUE));
        }
    }

    private void setupActionBar() {
        ActionBar actionBar = getSupportActionBar();
        if (actionBar != null) {
            // Show the Up button in the action bar.
            actionBar.setDisplayHomeAsUpEnabled(true);
            actionBar.setBackgroundDrawable(new ColorDrawable(getResources().getColor(PIBLUE)));
        }
    }
}
