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
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.ProgressDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.graphics.PorterDuff;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.support.annotation.RequiresApi;
import android.support.design.widget.FloatingActionButton;
import android.support.design.widget.Snackbar;
import android.support.v4.app.NotificationManagerCompat;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.view.ActionMode;
import android.support.v7.widget.Toolbar;
import android.text.InputType;
import android.text.TextUtils;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.widget.AdapterView;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.Toast;

import com.google.zxing.integration.android.IntentIntegrator;
import com.google.zxing.integration.android.IntentResult;

import org.apache.commons.codec.binary.Base32;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URL;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;

import static it.netknights.piauthenticator.AppConstants.ALGORITHM;
import static it.netknights.piauthenticator.AppConstants.COUNTER;
import static it.netknights.piauthenticator.AppConstants.DATA;
import static it.netknights.piauthenticator.AppConstants.DIGITS;
import static it.netknights.piauthenticator.AppConstants.HMACSHA1;
import static it.netknights.piauthenticator.AppConstants.HMACSHA256;
import static it.netknights.piauthenticator.AppConstants.HMACSHA512;
import static it.netknights.piauthenticator.AppConstants.HOTP;
import static it.netknights.piauthenticator.AppConstants.INTENT_ADD_TOKEN_MANUALLY;
import static it.netknights.piauthenticator.AppConstants.ISSUER;
import static it.netknights.piauthenticator.AppConstants.LABEL;
import static it.netknights.piauthenticator.AppConstants.NONCE;
import static it.netknights.piauthenticator.AppConstants.NOTIFICATION_CHANNEL_ID;
import static it.netknights.piauthenticator.AppConstants.PERIOD;
import static it.netknights.piauthenticator.AppConstants.PERSISTENT;
import static it.netknights.piauthenticator.AppConstants.PIN;
import static it.netknights.piauthenticator.AppConstants.PUSH;
import static it.netknights.piauthenticator.AppConstants.ROLLOUT_URL;
import static it.netknights.piauthenticator.AppConstants.SECRET;
import static it.netknights.piauthenticator.AppConstants.SERIAL;
import static it.netknights.piauthenticator.AppConstants.SIGNATURE;
import static it.netknights.piauthenticator.AppConstants.TAPTOSHOW;
import static it.netknights.piauthenticator.AppConstants.TOTP;
import static it.netknights.piauthenticator.AppConstants.TTL;
import static it.netknights.piauthenticator.AppConstants.TWOSTEP_DIFFICULTY;
import static it.netknights.piauthenticator.AppConstants.TWOSTEP_OUTPUT;
import static it.netknights.piauthenticator.AppConstants.TWOSTEP_SALT;
import static it.netknights.piauthenticator.AppConstants.TYPE;
import static it.netknights.piauthenticator.AppConstants.WITHPIN;
import static it.netknights.piauthenticator.R.color.PIBLUE;
import static it.netknights.piauthenticator.Util.byteArrayToHexString;
import static it.netknights.piauthenticator.Util.logprint;


public class MainActivity extends AppCompatActivity implements ActionMode.Callback, ActivityInterface {
    TokenListAdapter tokenlistadapter;
    ArrayList<Token> tokenlist;
    private Handler handler;
    private Runnable timer;
    private Util util;
    private Token nextSelection = null;
    private ListView listview;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Intent push = getIntent();
        if (push == null) {
            logprint("NO INTENT FOUND ONCREATE");
        }
        String push_data = push.getStringExtra(DATA);
        //PRNGFixes.apply();
        util = new Util(this);
        setupViews();
        setupFab();

        setupAdapter();
        startTimerThread();

        checkForExpiredTokens();

        if (!isNotificationChannelEnabled(this, NOTIFICATION_CHANNEL_ID)) {
            createNotificationChannel();
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            paintStatusbar();
        }

        if (push_data != null) {
            logprint("push data:" + push_data);
        } else {
            logprint("push data is empty");
        }

        //Log.e("TOKEN MAINACTIVITY", " " + FirebaseInstanceId.getInstance().getToken());
    }

    private void checkForExpiredTokens() {

    }

    private void setupFab() {
        FloatingActionButton fab = findViewById(R.id.fab);
        fab.setBackgroundColor(getResources().getColor(PIBLUE));
        fab.bringToFront();
        fab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                //scanQR();
                // TODO for faster testing purposes skip the qr scan
                String serial = "PIPU000FSA" + String.valueOf(Math.round(Math.random() * 100));
                String url = "https://sdffffff.free.beeceptor.com";
                //String url = "";
                String s = "otpauth://pipush/" + serial + "?url=" + url + "&ttl=120";
                Token t = null;
                try {
                    t = makeTokenFromURI(s);
                } catch (Exception e) {
                    e.printStackTrace();
                }
                if (t != null) {
                    tokenlist.add(t);
                    //   Toast.makeText(this, getString(R.string.toast_token_added_for) + " " + t.getLabel(), Toast.LENGTH_SHORT).show();
                    tokenlistadapter.refreshOTPs();
                    saveTokenlist();
                } else {
                    logprint("ERROR MAKETOKENFROMURI returned null");
                }
            }
        });
    }

    private void startTimerThread() {
        handler = new Handler();
        timer = new Runnable() {
            @Override
            public void run() {
                int progress = (int) (System.currentTimeMillis() / 1000) % 60;
                tokenlistadapter.updatePBs(progress);
                // refresh OTP values only around the periods
                if (progress < 3 || progress > 27 && progress < 33 || progress > 57) {
                    tokenlistadapter.refreshAllTOTP();
                }
                handler.postDelayed(this, 1000);
            }
        };
        handler.post(timer);
        handler.removeCallbacks(timer);
    }

    private void setupAdapter() {
        tokenlist = Util.loadTokens(this);
        tokenlistadapter = new TokenListAdapter();
        listview.setAdapter(tokenlistadapter);
        tokenlistadapter.setTokens(tokenlist);
        tokenlistadapter.setActivityInterface(this);
        tokenlistadapter.refreshOTPs();
    }

    void removeToken(Token currToken) {
        if (currToken.getType() == AppConstants.TokenType.PUSH) {
            util.removePubkeyFor(currToken.getSerial());
            try {
                SecretKeyWrapper.removePrivKeyFor(currToken.getSerial());
            } catch (CertificateException | NoSuchAlgorithmException | KeyStoreException | IOException e) {
                e.printStackTrace();
            }
        }
        int pos = tokenlist.indexOf(currToken);
        tokenlist.remove(pos);
        tokenlistadapter.getPbs().remove(pos);
        tokenlistadapter.notifyDataSetChanged();
        Toast.makeText(MainActivity.this, R.string.toast_token_removed, Toast.LENGTH_SHORT).show();
        saveTokenlist();
    }

    @RequiresApi(api = Build.VERSION_CODES.LOLLIPOP)
    public void paintStatusbar() {
        Window window = getWindow();
        window.addFlags(WindowManager.LayoutParams.FLAG_DRAWS_SYSTEM_BAR_BACKGROUNDS);
        window.clearFlags(WindowManager.LayoutParams.FLAG_TRANSLUCENT_STATUS);
        window.setStatusBarColor(getResources().getColor(PIBLUE));
    }

    private void setupViews() {
        setTitle(AppConstants.APP_TITLE);
        setContentView(R.layout.activity_main);
        listview = findViewById(R.id.listview);
        listview.setOnItemLongClickListener(new AdapterView.OnItemLongClickListener() {
            @Override
            public boolean onItemLongClick(AdapterView<?> adapterView, View view, int i, long l) {
                nextSelection = tokenlist.get(i);
                startSupportActionMode(MainActivity.this);
                return true;
            }
        });
        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        toolbar.setBackgroundColor(getResources().getColor(PIBLUE));
        if (getSupportActionBar() != null) {
            getSupportActionBar().setLogo(R.mipmap.ic_launcher);
            getSupportActionBar().setDisplayUseLogoEnabled(true);
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
        // this is the item selected from the toolbar menu
        int id = item.getItemId();
        // save the tokenlist before another activity starts it's lifecycle
        saveTokenlist();
        if (id == R.id.action_about) {
            Intent aboutintent = new Intent(this, AboutActivity.class);
            startActivity(aboutintent);
            return true;
        }
        if (id == R.id.action_enter_detail) {
            Intent settingsIntent = EnterDetailsActivity.makeIntent(MainActivity.this);
            startActivityForResult(settingsIntent, INTENT_ADD_TOKEN_MANUALLY);
        }

        if (id == R.id.print_keys) {
            printKeystore();
        }

        return super.onOptionsItemSelected(item);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        IntentResult result = IntentIntegrator.parseActivityResult(requestCode, resultCode, data);

        if (result != null) {
            if (result.getContents() == null) {
                Toast.makeText(this, R.string.toast_cancelled, Toast.LENGTH_SHORT).show();
            } else {
                try {
                    Token t = makeTokenFromURI(result.getContents());
                    tokenlist.add(t);
                    //   Toast.makeText(this, getString(R.string.toast_token_added_for) + " " + t.getLabel(), Toast.LENGTH_SHORT).show();
                    tokenlistadapter.refreshOTPs();
                    saveTokenlist();
                } catch (Exception e) {
                    Toast.makeText(this, R.string.toast_invalid_qr, Toast.LENGTH_SHORT).show();
                    e.printStackTrace();
                }
            }
        } else if (requestCode == INTENT_ADD_TOKEN_MANUALLY) {
            if (resultCode == Activity.RESULT_OK) {
                Token token = makeTokenFromIntent(data);
                tokenlist.add(token);
                tokenlistadapter.refreshOTPs();
                saveTokenlist();
                Toast.makeText(this, getString(R.string.toast_token_added_for) + " " + token.getLabel(), Toast.LENGTH_SHORT).show();
            } else {
                Toast.makeText(this, R.string.toast_cancelled, Toast.LENGTH_SHORT).show();
            }
        } /*else if (requestCode == INTENT_ABOUT) {
        }*/ else {
            super.onActivityResult(requestCode, resultCode, data);
        }
    }

    @Override
    public void onResume() {
        super.onResume();
        tokenlistadapter.refreshAllTOTP();
        handler.post(timer);
    }

    @Override
    public void onPause() {
        super.onPause();
        handler.removeCallbacks(timer);
    }

    @Override
    protected void onStop() {
        super.onStop();
        saveTokenlist();
    }

    @Override
    public boolean onCreateActionMode(ActionMode mode, Menu menu) {
        MenuInflater inflater = mode.getMenuInflater();

        if (nextSelection.isWithPIN()) {
            inflater.inflate(R.menu.actionmode_menu, menu);
            if (nextSelection.isUndeletable()) {
                for (int i = 0; i < menu.size(); i++) {
                    if (menu.getItem(i).getItemId() == R.id.delete_token2) {
                        menu.getItem(i).setEnabled(false);
                        menu.getItem(i).setIcon(R.drawable.ic_no_delete);
                    }
                }
            }
        } else {
            inflater.inflate(R.menu.actionmode_menu_nopin, menu);
            if (nextSelection.isUndeletable()) {
                for (int i = 0; i < menu.size(); i++) {
                    if (menu.getItem(i).getItemId() == R.id.delete_token2) {
                        menu.getItem(i).setEnabled(false);
                        menu.getItem(i).setIcon(R.drawable.ic_no_delete);
                    }
                }
            }
        }
        return true;
    }

    @Override
    public boolean onPrepareActionMode(ActionMode mode, Menu menu) {
        tokenlistadapter.setCurrentSelection(nextSelection);
        tokenlistadapter.notifyDataSetChanged();
        mode.setTitle(getString(R.string.actionmode_title));
        return true;
    }

    @Override
    public boolean onActionItemClicked(final ActionMode mode, MenuItem item) {
        final Token currToken = tokenlistadapter.getCurrentSelection();
        final int id = item.getItemId();
        if (id == R.id.delete_token2) {
           /* if (currToken.isUndeletable()) {
                AlertDialog.Builder builder = new AlertDialog.Builder(this);
                builder.setTitle("Deletion not possible");
                builder.setMessage("This Token is persistent and can not be deleted!");
                builder.setPositiveButton(R.string.zxing_button_ok, new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        dialog.dismiss();
                    }
                });
                final AlertDialog alert = builder.create();
                MainActivity.changeDialogFontColor(alert);
                alert.show();
            } else {*/
            AlertDialog.Builder builder = new AlertDialog.Builder(this);
            builder.setTitle(R.string.confirm_deletion_title);
            builder.setMessage(getString(R.string.confirm_deletion_text) + " " + currToken.getLabel() + " ?");
            builder.setPositiveButton(R.string.button_text_yes, new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int which) {
                    removeToken(currToken);

                    //Log.d(Util.TAG,"deletion: pos: "+pos+" ");
                    mode.finish();
                }
            });
            builder.setNegativeButton(R.string.button_text_no, new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int which) {
                    Toast.makeText(MainActivity.this, R.string.toast_deletion_cancelled, Toast.LENGTH_SHORT).show();
                    dialog.cancel();
                    mode.finish();
                }
            });
            final AlertDialog alert = builder.create();
            MainActivity.changeDialogFontColor(alert);
            alert.show();
            //}
            return true;
        }

        if (id == R.id.edit_token2) {
            AlertDialog.Builder builder = new AlertDialog.Builder(this);
            builder.setTitle(R.string.edit_name_title);
            final EditText input = new EditText(this);
            input.setText(currToken.getLabel());
            input.setSelectAllOnFocus(true);
            input.getBackground().setColorFilter(input.getContext().getResources().getColor(PIBLUE), PorterDuff.Mode.SRC_IN);
            builder.setView(input);

            builder.setPositiveButton(getString(R.string.button_text_save), new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface dialog, int whichButton) {
                    currToken.setLabel(input.getEditableText().toString());
                    tokenlistadapter.notifyDataSetChanged();
                    saveTokenlist();
                    Toast.makeText(MainActivity.this, currToken.getLabel() + ": " + getString(R.string.toast_name_changed), Toast.LENGTH_SHORT).show();
                    mode.finish();
                }
            });

            builder.setNegativeButton(getString(R.string.button_text_cancel), new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface dialog, int whichButton) {
                    dialog.cancel();
                    Toast.makeText(MainActivity.this, R.string.toast_edit_cancelled, Toast.LENGTH_SHORT).show();
                    mode.finish();
                }
            });
            final AlertDialog alert = builder.create();
            MainActivity.changeDialogFontColor(alert);
            alert.show();
            return true;
        }

        if (id == R.id.change_pin2) {
            if (currToken.isWithPIN() && !currToken.isLocked()) {
                LinearLayout layout = new LinearLayout(this);
                layout.setOrientation(LinearLayout.VERTICAL);

                final EditText firstinput = new EditText(this);
                firstinput.setHint(R.string.input_hint_new_pin);
                firstinput.setInputType(InputType.TYPE_CLASS_NUMBER | InputType.TYPE_NUMBER_VARIATION_PASSWORD);
                layout.addView(firstinput);
                firstinput.getBackground().setColorFilter(firstinput.getContext().getResources().getColor(PIBLUE), PorterDuff.Mode.SRC_IN);
                final EditText secondinput = new EditText(this);
                secondinput.setHint(R.string.input_hint_repeat_new_pin);
                secondinput.setInputType(InputType.TYPE_CLASS_NUMBER | InputType.TYPE_NUMBER_VARIATION_PASSWORD);
                layout.addView(secondinput);
                secondinput.getBackground().setColorFilter(secondinput.getContext().getResources().getColor(PIBLUE), PorterDuff.Mode.SRC_IN);
                AlertDialog.Builder builder = new AlertDialog.Builder(this);
                builder.setTitle(R.string.title_change_pin);
                builder.setView(layout);

                builder.setPositiveButton(getString(R.string.button_text_save), new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int whichButton) {
                        int firstpin = Integer.parseInt(firstinput.getEditableText().toString());
                        int secondpin = Integer.parseInt(secondinput.getEditableText().toString());
                        if (firstpin == secondpin) {
                            String hashedPIN = OTPGenerator.hashPIN(firstpin, currToken);
                            currToken.setPin(hashedPIN);
                            tokenlistadapter.notifyDataSetChanged();
                            saveTokenlist();
                            Toast.makeText(MainActivity.this, currToken.getLabel() + ": " + getString(R.string.toast_pin_changed), Toast.LENGTH_SHORT).show();
                        } else {
                            Toast.makeText(MainActivity.this, R.string.toast_pins_dont_match, Toast.LENGTH_SHORT).show();
                        }
                        mode.finish();
                    }
                });

                builder.setNegativeButton(getString(R.string.button_text_cancel), new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int whichButton) {
                        dialog.cancel();
                        Toast.makeText(MainActivity.this, R.string.toast_change_pin_cancelled, Toast.LENGTH_SHORT).show();
                        mode.finish();
                    }
                });
                final AlertDialog alert = builder.create();
                MainActivity.changeDialogFontColor(alert);
                alert.show();
                return true;
            }
        }

        if (id == R.id.copy_clipboard) {
            copyToClipboard(this, currToken.getCurrentOTP());
            Toast.makeText(MainActivity.this, R.string.toast_otp_to_clipboard, Toast.LENGTH_SHORT).show();
        }
        return false;
    }

    @Override
    public void onDestroyActionMode(ActionMode mode) {
        tokenlistadapter.setCurrentSelection(null);
        tokenlistadapter.notifyDataSetChanged();
        saveTokenlist();
    }

    /**
     * Creates a token with the parameters passed in KeyURI format
     *
     * @param content The URI String
     * @return Token Object
     * @throws Exception Invalid Protocol / Not HOTP or TOTP type of token
     */
    public Token makeTokenFromURI(String content) throws Exception {
        content = content.replaceFirst("otpauth", "http");
        Uri uri = Uri.parse(content);
        URL url = new URL(content);

        if (!url.getProtocol().equals("http")) {
            throw new Exception("Invalid Protocol");
        }
        if (!url.getHost().equals(TOTP)) {
            if (!url.getHost().equals(HOTP)) {
                if (!url.getHost().equals(PUSH)) {
                    throw new Exception("No TOTP, HOTP or Push Token"); //TODO handle this without crash
                }
            }
        }
        // TOKEN TYPE
        String type = url.getHost();
        AppConstants.TokenType tokentype = AppConstants.TokenType.HOTP;
        if (type.equals(TOTP)) {
            tokentype = AppConstants.TokenType.TOTP;
        } else if (type.equals(PUSH)) {
            tokentype = AppConstants.TokenType.PUSH;
        }

        // LABEL, SERIAL
        String label = uri.getPath().substring(1);

        String serial = label;
        String issuer = uri.getQueryParameter(ISSUER);
        if (issuer != null && !label.startsWith(issuer)) {
            label = issuer + ": " + label;
        }
        // https://github.com/privacyidea/privacyidea/wiki/concept:-PushToken
        // if its a push token, it is returned and the push-rollout is initiated
        if (tokentype == AppConstants.TokenType.PUSH) {
            // TODO start "loading screen"
            //startLoadingScreen();

            Token token = new Token(serial, label);
            token.rollout_url = uri.getQueryParameter(ROLLOUT_URL);
            token.rollout_finished = false;

            // Add the TTL to the token
            int ttl = 10;   // default
            if (uri.getQueryParameter(TTL) != null) {
                ttl = Integer.parseInt(uri.getQueryParameter(TTL));
            }
            Calendar now = Calendar.getInstance();
            now.add(Calendar.MINUTE, ttl);
            Date maxTime = now.getTime();
            token.rollout_expiration = maxTime;
            AsyncTask<Void, Integer, Boolean> pushrollout = new PushRollout(token, this);

            pushrollout.execute();
            return token;
        }

        // SECRET
        String secret_string = uri.getQueryParameter(SECRET);
        byte[] secret = new Base32().decode(secret_string.toUpperCase());

        // DIGITS
        int digits = 6;
        if (uri.getQueryParameter(DIGITS) != null) {
            digits = Integer.parseInt(uri.getQueryParameter(DIGITS));
        }

        // CREATE BASE TOKEN (HOTP/TOTP)
        Token tmp = new Token(secret, serial, label, tokentype, digits);

        // ADD ADDITIONAL INFORMATION TO IT
        if (tokentype == AppConstants.TokenType.TOTP) {
            if (uri.getQueryParameter(PERIOD) != null) {
                tmp.setPeriod(Integer.parseInt(uri.getQueryParameter(PERIOD)));
            } else {
                tmp.setPeriod(30);
            }
        }
        if (tokentype == AppConstants.TokenType.HOTP) {
            if (uri.getQueryParameter(COUNTER) != null) {
                tmp.setCounter(Integer.parseInt(uri.getQueryParameter(COUNTER)));
            } else {
                tmp.setCounter(1);
            }
        }
        if (uri.getQueryParameter(ALGORITHM) != null) {
            tmp.setAlgorithm(uri.getQueryParameter(ALGORITHM).toUpperCase());
        }
        if (uri.getBooleanQueryParameter(PIN, false)) {
            tmp.setWithPIN(true);
            tmp.setLocked(true);
        }
        if (uri.getBooleanQueryParameter(PERSISTENT, false)) {
            tmp.setUndeletable(true);
        }

        // if at least one parameter for 2step is set do 2step init
        if (uri.getQueryParameter(TWOSTEP_SALT) != null ||
                uri.getQueryParameter(TWOSTEP_DIFFICULTY) != null ||
                uri.getQueryParameter(TWOSTEP_OUTPUT) != null) {

            int phonepartlength = 10; // default value
            if (uri.getQueryParameter(TWOSTEP_SALT) != null) {
                phonepartlength = Integer.parseInt(uri.getQueryParameter(TWOSTEP_SALT));
            }
            int iterations = 10000;
            if (uri.getQueryParameter(TWOSTEP_DIFFICULTY) != null) {
                iterations = Integer.parseInt(uri.getQueryParameter(TWOSTEP_DIFFICULTY));
            }
            // comes in bytes, needs to be converted to bit as parameter for pbkdf2
            int output_size = 160;

            if (uri.getQueryParameter(TWOSTEP_OUTPUT) != null) {
                output_size = Integer.parseInt(uri.getQueryParameter(TWOSTEP_OUTPUT)) * 8;
            } else {
                // if the output size is not specified, it is derived from the OTP algorithm
                if (tmp.getAlgorithm().equals(HMACSHA1)) {
                    // do nothing default is already 20bytes = 160bit
                } else if (tmp.getAlgorithm().equals(HMACSHA256)) {
                    output_size = 256;
                } else if (tmp.getAlgorithm().equals(HMACSHA512)) {
                    output_size = 512;
                }
            }
            return do2StepInit(tmp, phonepartlength, iterations, output_size);
        }
        // tap to show is currently not used
        if (uri.getBooleanQueryParameter(TAPTOSHOW, false)) {
            tmp.setWithTapToShow(true);
        }
        return tmp;
    }

    /**
     * This method enhances the "usual" rollout process by combining the secret in the scanned QRCode
     * with a randomly generated salt on the phone. The Phonepart has to be entered into
     * PrivacyIDEA, then the first OTP values can be compared to ensure the rollout was successful
     *
     * @param token           The token after the normal rollout process, secret is only the QR-part
     * @param phonepartlength Number of bytes which shall be generated by the phone (default is 10)
     * @return A token with the combined secret (phone- and QR-part)
     */
    private Token do2StepInit(final Token token, final int phonepartlength,
                              final int iterations, final int output_size) {
        AsyncTask<Void, Void, Boolean> asyncTask = new SecretGenerator(util, token, phonepartlength, iterations, output_size, new SecretGenerator.Response() {
            @Override
            public void processFinished(Token t) {
                tokenlistadapter.refreshOTPs();
                tokenlistadapter.notifyDataSetChanged();
                saveTokenlist();
            }
        });
        asyncTask.execute();

        return token;
    }

    private Token makeTokenFromIntent(Intent data) {
        // Push tokens cannot be created manually so this is simplified
        String type = data.getStringExtra(TYPE);
        AppConstants.TokenType tokentype = AppConstants.TokenType.HOTP;
        if (type.equals(TOTP)) {
            tokentype = AppConstants.TokenType.TOTP;
        }
        byte[] secret = data.getByteArrayExtra(SECRET);
        String label = data.getStringExtra(LABEL);
        int digits = data.getIntExtra(DIGITS, 6);
        String algorithm = data.getStringExtra(ALGORITHM);
        Token tmp = new Token(secret, label, label, tokentype, digits);

        if (type.equals(TOTP)) {
            int period = data.getIntExtra(PERIOD, 30);
            tmp.setPeriod(period);
        }

        if (algorithm != null) {
            tmp.setAlgorithm(algorithm);
        }
        if (data.getBooleanExtra(WITHPIN, false)) {
            tmp.setWithPIN(true);
        }

        return tmp;
    }

    public static void changeDialogFontColor(final AlertDialog dialog) {
        dialog.setOnShowListener(new DialogInterface.OnShowListener() {
            @Override
            public void onShow(DialogInterface dialogInterface) {
                doChangeDialogFontColor(dialog);
            }
        });

    }

    private static void doChangeDialogFontColor(AlertDialog dialog) {
        int piblue = dialog.getContext().getResources().getColor(PIBLUE);
        if (dialog.getButton(AlertDialog.BUTTON_NEGATIVE) != null) {
            dialog.getButton(AlertDialog.BUTTON_NEGATIVE).setTextColor(piblue);
        }

        if (dialog.getButton(AlertDialog.BUTTON_NEUTRAL) != null) {
            dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setTextColor(piblue);
        }

        if (dialog.getButton(AlertDialog.BUTTON_POSITIVE) != null) {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setTextColor(piblue);
        }
    }

    @Override
    public Activity getPresentActivity() {
        return this;
    }

    static class SecretGenerator extends AsyncTask<Void, Void, Boolean> {

        private final Token token;
        private Util util;
        private ProgressDialog pd;
        private int iterations;
        private int output_size_bit;
        Response delegate;
        byte[] phonepartBytes;

        public interface Response {
            void processFinished(Token t);
        }

        SecretGenerator(Util util, Token t, int phonepartlength, int iterations, int output_size, Response delegate) {
            this.util = util;
            this.token = t;
            this.iterations = iterations;
            this.output_size_bit = output_size;
            this.delegate = delegate;
            this.phonepartBytes = new byte[phonepartlength];
            //Log.d(Util.TAG, "ppl: " + phonepartlength + ", it: " + iterations + " ,outs: " + output_size);
        }

        @Override
        protected void onPreExecute() {
            super.onPreExecute();
            pd = new ProgressDialog(util.getmActivity());
            pd.setMessage("Please wait while the secret is generated");
            pd.setProgressStyle(ProgressDialog.STYLE_SPINNER);
            pd.setCancelable(false);
            pd.setIndeterminate(true);
            pd.show();
        }

        @Override
        protected Boolean doInBackground(Void... params) {
            // 1. Generate random bytes for the phonepartBytes
            SecureRandom sr = new SecureRandom(); //Seeded by PRNGFixes
            sr.nextBytes(phonepartBytes);

            String server_secret_hex = byteArrayToHexString(token.getSecret());
            char[] ch = server_secret_hex.toCharArray();
            byte[] completesecretBytes = new byte[(output_size_bit / 8)];
            // 2. PBKDF2 with the specified parameters
            try {
                completesecretBytes = OTPGenerator.generatePBKDFKey(ch, phonepartBytes, iterations, output_size_bit);
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                e.printStackTrace();
            }
            token.setSecret(completesecretBytes);
            return true;
        }

        @Override
        protected void onPostExecute(final Boolean success) {
            // 4. Display the phone-part of the secret and first OTP to verify
            pd.dismiss();
            AlertDialog.Builder builder = new AlertDialog.Builder(util.getmActivity());
            builder.setCancelable(false);
            builder.setPositiveButton("Ok", new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int which) {
                    dialog.cancel();
                }
            });
            builder.setTitle("Phonepart");
            builder.setMessage(buildResultMessage());
            final AlertDialog alert = builder.create();
            MainActivity.changeDialogFontColor(alert);
            alert.show();
            delegate.processFinished(token);
        }

        private String buildResultMessage() {
            /* 3. Build the result to show to the user
            We use the first 4 characters of the sha1 hash of the client(phone) part as checksum.
            client_part being the binary random value, that the client(phone) generated:
            b32encode( sha1(client_part)[0:3] + client_part)*/
            String result;
            byte[] digest = new byte[20];
            try {
                MessageDigest md = MessageDigest.getInstance("SHA-1");
                digest = md.digest(phonepartBytes);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }

            byte[] checksumBytes = new byte[4];
            System.arraycopy(digest, 0, checksumBytes, 0, 4);
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            try {
                outputStream.write(checksumBytes);
                outputStream.write(phonepartBytes);
            } catch (IOException e) {
                e.printStackTrace();
            }

            byte completeOutputBytes[] = outputStream.toByteArray();
            result = insertPeriodically(new Base32().encodeAsString(completeOutputBytes), " ", 4);
            result = result.replaceAll("=", "");
            return result;
        }

        @Override
        protected void onCancelled() {
        }

        String insertPeriodically(String text, String insert, int period) {
            StringBuilder builder = new StringBuilder(text.length() + insert.length() * (text.length() / period) + 1);
            int index = 0;
            String prefix = "";
            while (index < text.length()) {
                builder.append(prefix);
                prefix = insert;
                builder.append(text.substring(index,
                        Math.min(index + period, text.length())));
                index += period;
            }
            return builder.toString();
        }
    }

    public void saveTokenlist() {
        Util.saveTokens(this, tokenlist);
        //Toast.makeText(this, "Tokens saved", Toast.LENGTH_SHORT).show();
    }

    private void scanQR() {
        try {
            IntentIntegrator ii = new IntentIntegrator(this);
            ii.initiateScan();
        } catch (Exception e) {
            if (this.getCurrentFocus() != null) {
                Snackbar.make(this.getCurrentFocus(), e.getMessage(), Snackbar.LENGTH_LONG).show();
            }

        }
    }

    private void copyToClipboard(Context context, String text) {
        android.content.ClipboardManager clipboard = (android.content.ClipboardManager) context.getSystemService(Context.CLIPBOARD_SERVICE);
        android.content.ClipData clip = android.content.ClipData.newPlainText("Copied Text", text);
        if (clipboard != null)
            clipboard.setPrimaryClip(clip);
    }

    protected void clearTokenlist() {
        if (tokenlist.size() > 0) {
            tokenlist.clear();
            saveTokenlist();
        }
    }

    void printKeystore() {
        try {
            SecretKeyWrapper.printKeystore();
            this.util.printPubkeys(tokenlist);
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
            e.printStackTrace();
        }

    }

    public boolean isNotificationChannelEnabled(Context context, String channelId) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            if (!TextUtils.isEmpty(channelId)) {
                NotificationManager manager = (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
                NotificationChannel channel = null;
                if (manager != null) {
                    channel = manager.getNotificationChannel(channelId);
                }
                if (channel != null) {
                    return channel.getImportance() != NotificationManager.IMPORTANCE_NONE;
                }
            }
            return false;
        } else {
            return NotificationManagerCompat.from(context).areNotificationsEnabled();
        }
    }

    private void createNotificationChannel() {
        // Create the NotificationChannel, but only on API 26+ because
        // the NotificationChannel class is new and not in the support library
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            CharSequence name = "privacyIDEAPush";
            String description = "push for privacyIDEA";
            int importance = NotificationManager.IMPORTANCE_DEFAULT;
            NotificationChannel channel = new NotificationChannel(NOTIFICATION_CHANNEL_ID, name, importance);
            channel.setDescription(description);
            // Register the channel with the system; you can't change the importance
            // or other notification behaviors after this
            NotificationManager notificationManager = getSystemService(NotificationManager.class);
            if (notificationManager != null) {
                notificationManager.createNotificationChannel(channel);
            }
        }
    }

}

interface ActivityInterface {
    public Activity getPresentActivity();
}