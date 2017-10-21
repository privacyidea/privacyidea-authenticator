/*
  privacyIDEA Authenticator

  Authors: Nils Behlen <nils.behlen@netknights.it>

  Copyright (c) 2017 NetKnights GmbH

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

package it.netknights.piauthenticator;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.support.design.widget.FloatingActionButton;
import android.support.design.widget.Snackbar;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.text.InputType;
import android.util.Log;
import android.view.ContextMenu;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.webkit.WebView;
import android.widget.AdapterView;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import com.google.zxing.integration.android.IntentIntegrator;
import com.google.zxing.integration.android.IntentResult;

import org.apache.commons.codec.binary.Base32;

import java.util.ArrayList;

import static it.netknights.piauthenticator.R.color.PIBLUE;


public class MainActivity extends AppCompatActivity {
    private TokenListAdapter tokenlistadapter;
    private ArrayList<Token> tokenlist;
    private Handler handler;
    private Runnable timer;
    private Util utils;
    private static final int INTENT_ADD_TOKEN_MANUALLY = 101;
    private TextView countdown;
    private ListView listview;
    private FloatingActionButton fab;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        PRNGFixes.apply();
        utils = Util.getInstance();
        utils.setmActivity(this);
        setupViews();
        setupFab();
        paintStatusbar();
        setupAdapter();
        startTimerThread();
    }

    private void setupFab() {
        fab = (FloatingActionButton) findViewById(R.id.fab);
        fab.setBackgroundColor(getResources().getColor(PIBLUE));
        fab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                AlertDialog.Builder builder = new AlertDialog.Builder(MainActivity.this);
                LayoutInflater factory = LayoutInflater.from(MainActivity.this);
                final View view = factory.inflate(R.layout.chose_to_add, null);
                builder.setView(view);
                ImageView scan_qr_image = (ImageView) view.findViewById(R.id.icon_scan_qr);
                scan_qr_image.setImageResource(R.mipmap.icon_scan_qr);
                ImageView enter_detail_image = (ImageView) view.findViewById(R.id.icon_enter_details);

                if (scan_qr_image != null) {
                    scan_qr_image.setOnClickListener(new View.OnClickListener() {
                        @Override
                        public void onClick(View v) {
                            scanQR();
                        }
                    });
                }

                if (enter_detail_image != null) {
                    enter_detail_image.setOnClickListener(new View.OnClickListener() {
                        @Override
                        public void onClick(View v) {
                            Intent settingsIntent = EnterDetailsActivity.makeIntent(MainActivity.this);
                            startActivityForResult(settingsIntent, INTENT_ADD_TOKEN_MANUALLY);
                        }
                    });
                }
                builder.show();
            }
        });
    }

    private void startTimerThread() {
        handler = new Handler();
        timer = new Runnable() {
            @Override
            public void run() { //TODO generate totp value only on time
                int progress = (int) (System.currentTimeMillis() / 1000) % 60;
                countdown.setText("" + String.valueOf(progress));
                tokenlistadapter.updatePBs(progress);
                tokenlistadapter.refreshAllTOTP();
                handler.postDelayed(this, 1000);
            }
        };
        handler.post(timer);
    }

    private void setupAdapter() {
        tokenlist = Util.loadTokens(this);
        tokenlistadapter = new TokenListAdapter();
        listview.setAdapter(tokenlistadapter);
        tokenlistadapter.setTokens(tokenlist);
        tokenlistadapter.refreshOTPs();

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

    private void setupViews() {
        setTitle(" PrivacyIDEA Authenticator");
        setContentView(R.layout.activity_main);

        listview = (ListView) findViewById(R.id.listview);
        registerForContextMenu(listview);

        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        toolbar.setBackgroundColor(getResources().getColor(PIBLUE));
        getSupportActionBar().setLogo(R.mipmap.ic_launcher);
        getSupportActionBar().setDisplayUseLogoEnabled(true);

        countdown = (TextView) findViewById(R.id.countdownfield);
    }

    @Override
    public void onCreateContextMenu(ContextMenu menu, View v,
                                    ContextMenu.ContextMenuInfo menuInfo) {
        super.onCreateContextMenu(menu, v, menuInfo);
        MenuInflater inflater = getMenuInflater();

        int pos = ((AdapterView.AdapterContextMenuInfo) menuInfo).position;
        if (tokenlist.get(pos).isWithPIN()) {
            inflater.inflate(R.menu.context_menu, menu);
        } else {
            inflater.inflate(R.menu.context_menu_nopin, menu);
        }
    }

    @Override
    public boolean onContextItemSelected(MenuItem item) {
        //this is the item selected from the context menu of a ListView entry
        AdapterView.AdapterContextMenuInfo info = (AdapterView.AdapterContextMenuInfo) item.getMenuInfo();
        final int position = info.position;
        final Token token = tokenlist.get(position);

        switch (item.getItemId()) {
            case R.id.delete_token: {
                tokenlist.remove(position);
                tokenlistadapter.notifyDataSetChanged();
                save(tokenlist);
                Toast.makeText(this, "Token removed", Toast.LENGTH_LONG).show();
                return true;
            }

            case R.id.edit_token: {
                AlertDialog.Builder alert = new AlertDialog.Builder(this);
                alert.setTitle("Edit Name");
                final EditText input = new EditText(this);
                input.setText(token.getLabel());
                input.setSelectAllOnFocus(true);
                alert.setView(input);

                alert.setPositiveButton("Save", new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int whichButton) {
                        token.setLabel(input.getEditableText().toString());
                        tokenlistadapter.notifyDataSetChanged();
                        save(tokenlist);
                    }
                });

                alert.setNegativeButton("Cancel", new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int whichButton) {
                        dialog.cancel();
                    }
                });
                alert.show();
                return true;
            }

            case R.id.change_pin: {
                if (token.isWithPIN() && !token.isLocked()) {
                    LinearLayout layout = new LinearLayout(this);
                    layout.setOrientation(LinearLayout.VERTICAL);

                    final EditText firstinput = new EditText(this);
                    firstinput.setHint("new PIN");
                    firstinput.setInputType(InputType.TYPE_CLASS_NUMBER | InputType.TYPE_NUMBER_VARIATION_PASSWORD);
                    layout.addView(firstinput);

                    final EditText secondinput = new EditText(this);
                    secondinput.setHint("Repeat new PIN");
                    secondinput.setInputType(InputType.TYPE_CLASS_NUMBER | InputType.TYPE_NUMBER_VARIATION_PASSWORD);
                    layout.addView(secondinput);

                    AlertDialog.Builder alert = new AlertDialog.Builder(this);
                    alert.setTitle("Change PIN");
                    alert.setView(layout);

                    alert.setPositiveButton("Save", new DialogInterface.OnClickListener() {
                        public void onClick(DialogInterface dialog, int whichButton) {
                            int firstpin = Integer.parseInt(firstinput.getEditableText().toString());
                            int secondpin = Integer.parseInt(secondinput.getEditableText().toString());
                            if (firstpin == secondpin) {
                                String hashedPIN = OTPGenerator.hashPIN(firstpin, token);
                                token.setPin(hashedPIN);
                                tokenlistadapter.notifyDataSetChanged();
                                save(tokenlist);
                            } else {
                                Toast.makeText(MainActivity.this, "PINs do not match - Cancelled", Toast.LENGTH_LONG).show();
                            }
                        }
                    });

                    alert.setNegativeButton("Cancel", new DialogInterface.OnClickListener() {
                        public void onClick(DialogInterface dialog, int whichButton) {
                            dialog.cancel();
                        }
                    });
                    alert.show();
                    return true;
                }
            }

            default:
                return super.onContextItemSelected(item);
        }
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.overflow_menu, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        //this is the item selected from the toolbar menu
        int id = item.getItemId();

        if (id == R.id.action_remove_all) {
            tokenlist.clear();
            tokenlistadapter.notifyDataSetChanged();
            save(tokenlist);
            Toast.makeText(this, "All token deleted", Toast.LENGTH_LONG).show();
            return true;
        }
        if (id == R.id.action_about) {
            try {
                tokenlist.add(utils.makeTokenFromURI("otpauth://totp/TOTP002125CE?secret=YXJMGHZADQ3NHW3EQBOTQ4DRUSDFYXEY&algorithm=sha256&period=30&digits=6&issuer=privacyIDEA&2step=true"));
                tokenlistadapter.notifyDataSetChanged();
            } catch (Exception e) {
                e.printStackTrace();
            }
            WebView view = (WebView) LayoutInflater.from(this).inflate(R.layout.dialog_about, null);
            view.loadUrl("file:///android_res/raw/about.html");
            new AlertDialog.Builder(this).setView(view).show();
            return true;
        }

        if (id == R.id.action_settings) {
            Intent settingsintent = new Intent(this, SettingsActivity.class);
            startActivity(settingsintent);
        }

        return super.onOptionsItemSelected(item);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        //after the QRscan make a token from the resulting string, save it and update the View
        IntentResult result = IntentIntegrator.parseActivityResult(requestCode, resultCode, data);
        if (result != null) {
            if (result.getContents() == null) {
                Toast.makeText(this, "Cancelled", Toast.LENGTH_LONG).show();
            } else {
                try {
                    Token t = utils.makeTokenFromURI(result.getContents());
                    tokenlist.add(t);
                    Toast.makeText(this, "Token added for: " + t.getLabel(), Toast.LENGTH_LONG).show();
                    tokenlistadapter.refreshOTPs();
                    save(tokenlist);
                } catch (Exception e) {
                    Toast.makeText(this, "Invalid QR Code", Toast.LENGTH_LONG).show();
                    e.printStackTrace();
                }
            }
        } else if (requestCode == INTENT_ADD_TOKEN_MANUALLY) {
            if (resultCode == Activity.RESULT_OK) {
                String type = data.getStringExtra("type");
                String secret = data.getStringExtra("secret");
                String label = data.getStringExtra("label");
                int digits = data.getIntExtra("digits", 6);
                Token tmp = new Token(secret, label, type, digits);
                if (type.equals("totp")) {
                    int period = data.getIntExtra("period", 30);
                    tmp.setPeriod(period);
                }
                String algorithm = data.getStringExtra("algorithm");
                if (algorithm != null) {
                    tmp.setAlgorithm(algorithm);
                }
                if (data.getBooleanExtra("haspin", false)) {
                    tmp.setWithPIN(true);
                }
                Log.d("piauth:", type + label + secret + digits + "  " + tmp.getAlgorithm());

                if (data.getBooleanExtra("2step", false)) {
                    tmp = utils.start2StepInit(tmp, data.getIntExtra("pp", 10));
                }
                tokenlist.add(tmp);
                tokenlistadapter.refreshOTPs();
                Toast.makeText(this, "Token added for: " + label, Toast.LENGTH_LONG).show();
                save(tokenlist);

            } else {
                Toast.makeText(this, "Cancelled", Toast.LENGTH_LONG).show();
            }

        } else {
            super.onActivityResult(requestCode, resultCode, data);
        }
    }

    private void scanQR() {
        try {
            IntentIntegrator ii = new IntentIntegrator(this);
            ii.initiateScan();
        } catch (Exception e) {
            Snackbar.make(this.getCurrentFocus(), e.getMessage(), Snackbar.LENGTH_LONG).show();
        }
    }

    @Override
    public void onResume() {
        super.onResume();
        handler.post(timer);
    }

    @Override
    public void onPause() {
        super.onPause();
        handler.removeCallbacks(timer);
    }

    public void save(ArrayList<Token> tokenlist) {
        Util.saveTokens(this, tokenlist);
    }
}
