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

import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Color;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.support.design.widget.FloatingActionButton;
import android.support.design.widget.Snackbar;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.text.InputType;
import android.view.ActionMode;
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
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import com.google.zxing.integration.android.IntentIntegrator;
import com.google.zxing.integration.android.IntentResult;

import java.util.ArrayList;
import java.util.List;

import static it.netknights.piauthenticator.R.id.listview;


public class MainActivity extends AppCompatActivity {
    private TokenListAdapter tokenlistadapter;
    private ArrayList<Token> tokens;
    private Handler handler;
    private Runnable timer;
    private Util utils;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        //--------- initialize view components ----------------
        super.onCreate(savedInstanceState);
        setTitle("PrivacyIDEA Authenticator");
        setContentView(R.layout.activity_main);
        final ListView listview = (ListView) findViewById(R.id.listview);
        final TextView countdown = (TextView) findViewById(R.id.countdownfield);
        final FloatingActionButton fab = (FloatingActionButton) findViewById(R.id.fab);
        utils = new Util();
        utils.setmActivity(this);

        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        toolbar.setBackgroundColor(Color.rgb(0x55, 0xb0, 0xe6));
        fab.setBackgroundColor(Color.rgb(0x83, 0xc9, 0x27));
        fab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                try {
                    scanQR();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
        //------------------ try to paint the statusbar -------------------------------
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            Window window = getWindow();
            window.addFlags(WindowManager.LayoutParams.FLAG_DRAWS_SYSTEM_BAR_BACKGROUNDS);
            window.clearFlags(WindowManager.LayoutParams.FLAG_TRANSLUCENT_STATUS);
            window.setStatusBarColor(getResources().getColor(R.color.PIBLUE));
        }

        //-------------- initialize adapter with loaded tokens-------------------------
        PRNGFixes.apply();
        tokens = utils.loadTokens(this);
        tokenlistadapter = new TokenListAdapter();
        listview.setAdapter(tokenlistadapter);
        tokenlistadapter.setTokens(tokens);
        tokenlistadapter.refreshOTPs();
        registerForContextMenu(listview);

        //------------ start the timer thread -----------------------------------------
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

    @Override
    public void onCreateContextMenu(ContextMenu menu, View v,
                                    ContextMenu.ContextMenuInfo menuInfo) {
        super.onCreateContextMenu(menu, v, menuInfo);
        MenuInflater inflater = getMenuInflater();
        inflater.inflate(R.menu.context_menu, menu);
    }

    @Override
    public boolean onContextItemSelected(MenuItem item) {
        //this is the item selected from the context menu of a ListView entry
        AdapterView.AdapterContextMenuInfo info = (AdapterView.AdapterContextMenuInfo) item.getMenuInfo();
        final int position = info.position;
        final Token token = tokens.get(position);

        switch (item.getItemId()) {
            case R.id.delete_token: {
                tokens.remove(position);
                tokenlistadapter.notifyDataSetChanged();
                save(tokens);
                Toast.makeText(this, "Token removed", Toast.LENGTH_LONG).show();
                return true;
            }

            case R.id.edit_token: {
                AlertDialog.Builder alert = new AlertDialog.Builder(this);
                alert.setTitle("Edit Name");
                final EditText input = new EditText(this);
                input.setText(token.getLabel());
                alert.setView(input);

                alert.setPositiveButton("Save", new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int whichButton) {
                        token.setLabel(input.getEditableText().toString());
                        tokenlistadapter.notifyDataSetChanged();
                        save(tokens);
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
                    AlertDialog.Builder alert = new AlertDialog.Builder(this);
                    alert.setTitle("Change PIN");
                    final EditText input = new EditText(this);
                    input.setInputType(InputType.TYPE_CLASS_NUMBER);
                    alert.setView(input);

                    alert.setPositiveButton("Save", new DialogInterface.OnClickListener() {
                        public void onClick(DialogInterface dialog, int whichButton) {
                            token.setPin(Integer.parseInt(input.getEditableText().toString()));
                            tokenlistadapter.notifyDataSetChanged();
                            save(tokens);
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

        if (id == R.id.action_settings) {
            //TODO THIS
            Intent settingsIntent = new Intent(this, SettingsActivity.class);
            startActivityForResult(settingsIntent, 102);
            return true;
        }
        if (id == R.id.action_insertdummy) {
            //insert a TOTP and HOTP dummy-token
            try {
                tokens.add(utils.makeTokenFromURI("otpauth://hotp" +
                        "/HOTP?secret=2VKLHJMESGDZDXO7UO5GRH6T34CSYWYY&counter=1&digits=6&issuer=SampleToken2step&2step=true"));
                tokens.add(utils.makeTokenFromURI("otpauth://totp" +
                        "/TOTP60SSHA1?secret=HI64N3EHBUWXWHJWAGLNYBHAXWPZMD3N&period=60&digits=6&issuer=SampleToken"));
                tokens.add(utils.makeTokenFromURI("otpauth://totp" +
                        "/TOTP30SSHA1?secret=HI64N3EHBUWXWHJWAGLNYBHAXWPZMD3N&period=30&digits=6&issuer=SampleToken&pin=true"));
            } catch (Exception e) {
                e.printStackTrace();
            }
            tokenlistadapter.refreshOTPs();
            save(tokens);
            return true;
        }
        if (id == R.id.action_remove_all) {
            tokens.clear();
            tokenlistadapter.notifyDataSetChanged();
            save(tokens);
            Toast.makeText(this, "All tokens deleted", Toast.LENGTH_LONG).show();
            return true;
        }
        if (id == R.id.action_about) {
            WebView view = (WebView) LayoutInflater.from(this).inflate(R.layout.dialog_about, null);
            view.loadUrl("file:///android_res/raw/about.html");
            new AlertDialog.Builder(this).setView(view).show();
            return true;
        }

        return super.onOptionsItemSelected(item);
    }

    public void showMessageDialog(String message) {


    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent i) {
        //after the QRscan make a token from the resulting string, save it and update the View
        IntentResult result = IntentIntegrator.parseActivityResult(requestCode, resultCode, i);
        if (result != null) {
            if (result.getContents() == null) {
                Toast.makeText(this, "Cancelled", Toast.LENGTH_LONG).show();
            } else {
                try {
                    Token t = utils.makeTokenFromURI(result.getContents());
                    tokens.add(t);
                    Toast.makeText(this, "Token added for: " + t.getLabel(), Toast.LENGTH_LONG).show();
                    tokenlistadapter.refreshOTPs();
                    save(tokens);
                } catch (Exception e) {
                    Toast.makeText(this, "Invalid QR Code", Toast.LENGTH_LONG).show();
                    e.printStackTrace();
                }
            }
        } else {
            super.onActivityResult(requestCode, resultCode, i);
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

    public void save(ArrayList<Token> tokens) {
        utils.saveTokens(this, tokens);
    }
}
