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
import android.app.ProgressDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.SystemClock;
import android.support.design.widget.FloatingActionButton;
import android.support.design.widget.Snackbar;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.view.ActionMode;
import android.support.v7.widget.Toolbar;
import android.text.InputType;
import android.util.Log;
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
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import com.google.zxing.integration.android.IntentIntegrator;
import com.google.zxing.integration.android.IntentResult;

import org.apache.commons.codec.binary.Base32;

import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;

import static it.netknights.piauthenticator.OTPGenerator.byteArrayToHexString;
import static it.netknights.piauthenticator.R.color.PIBLUE;
import static it.netknights.piauthenticator.Token.ALGORITHM;
import static it.netknights.piauthenticator.Token.COUNTER;
import static it.netknights.piauthenticator.Token.DIGITS;
import static it.netknights.piauthenticator.Token.HOTP;
import static it.netknights.piauthenticator.Token.ISSUER;
import static it.netknights.piauthenticator.Token.PERIOD;
import static it.netknights.piauthenticator.Token.SECRET;
import static it.netknights.piauthenticator.Token.TOTP;


public class MainActivity extends AppCompatActivity implements ActionMode.Callback {
    private TokenListAdapter tokenlistadapter;
    private ArrayList<Token> tokenlist;
    private Handler handler;
    private Runnable timer;
    private Util util;
    private Token nextSelection = null;
    private static final int INTENT_ADD_TOKEN_MANUALLY = 101;
    private static final int INTENT_ABOUT = 102;
    private ListView listview;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        PRNGFixes.apply();
        util = new Util(this);
        setupViews();
        setupFab();
        paintStatusbar();
        setupAdapter();
        startTimerThread();
    }

    private void setupFab() {
        FloatingActionButton fab = (FloatingActionButton) findViewById(R.id.fab);
        fab.setBackgroundColor(getResources().getColor(PIBLUE));
        fab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                scanQR();
            }
        });
    }

    private void startTimerThread() {
        handler = new Handler();
        timer = new Runnable() {
            @Override
            public void run() {
                int progress = (int) (System.currentTimeMillis() / 1000) % 60;
                //countdown.setText("" + String.valueOf(progress));
                tokenlistadapter.updatePBs(progress);
                if (progress < 3 || progress > 27 && progress < 33 || progress > 57) {
                    tokenlistadapter.refreshAllTOTP();
                }
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
        //registerForContextMenu(listview);
        listview.setOnItemLongClickListener(new AdapterView.OnItemLongClickListener() {
            @Override
            public boolean onItemLongClick(AdapterView<?> adapterView, View view, int i, long l) {
                nextSelection = tokenlist.get(i);
                startSupportActionMode(MainActivity.this);

                return true;
            }
        });
        Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        toolbar.setBackgroundColor(getResources().getColor(PIBLUE));
        getSupportActionBar().setLogo(R.mipmap.ic_launcher);
        getSupportActionBar().setDisplayUseLogoEnabled(true);
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
            saveTokenlist();
            Toast.makeText(this, "All token deleted", Toast.LENGTH_SHORT).show();
            return true;
        }
        if (id == R.id.action_about) {
            /*WebView view = (WebView) LayoutInflater.from(this).inflate(R.layout.dialog_about, null);
            view.loadUrl("file:///android_res/raw/about.html");
            new AlertDialog.Builder(this).setView(view).show();*/
            Intent aboutintent = new Intent(this, AboutActivity.class);
            startActivity(aboutintent);
            return true;
        }
        if (id == R.id.action_settings) {
            Intent settingsintent = new Intent(this, SettingsActivity.class);
            startActivity(settingsintent);
        }
        if (id == R.id.action_enter_detail) {
            Intent settingsIntent = EnterDetailsActivity.makeIntent(MainActivity.this);
            startActivityForResult(settingsIntent, INTENT_ADD_TOKEN_MANUALLY);
        }
        return super.onOptionsItemSelected(item);
    }

    private void copyToClipboard(Context context, String text) {
        if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.HONEYCOMB) {
            android.text.ClipboardManager clipboard = (android.text.ClipboardManager) context.getSystemService(Context.CLIPBOARD_SERVICE);
            clipboard.setText(text);
        } else {
            android.content.ClipboardManager clipboard = (android.content.ClipboardManager) context.getSystemService(Context.CLIPBOARD_SERVICE);
            android.content.ClipData clip = android.content.ClipData.newPlainText("Copied Text", text);
            clipboard.setPrimaryClip(clip);
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        IntentResult result = IntentIntegrator.parseActivityResult(requestCode, resultCode, data);

        if (result != null) {
            if (result.getContents() == null) {
                Toast.makeText(this, "Cancelled", Toast.LENGTH_SHORT).show();
            } else {
                try {
                    Token t = makeTokenFromURI(result.getContents());
                    tokenlist.add(t);
                    Toast.makeText(this, "Token added for: " + t.getLabel(), Toast.LENGTH_SHORT).show();
                    tokenlistadapter.refreshOTPs();
                    saveTokenlist();
                } catch (Exception e) {
                    Toast.makeText(this, "Invalid QR Code", Toast.LENGTH_SHORT).show();
                    e.printStackTrace();
                }
            }
        } else if (requestCode == INTENT_ADD_TOKEN_MANUALLY) {
            if (resultCode == Activity.RESULT_OK) {
                Token token = makeTokenFromIntent(data);
                tokenlist.add(token);
                tokenlistadapter.refreshOTPs();
                saveTokenlist();
                Toast.makeText(this, "Token added for: " + token.getLabel(), Toast.LENGTH_SHORT).show();
            } else {
                Toast.makeText(this, "Cancelled", Toast.LENGTH_SHORT).show();
            }
        }else if (requestCode == INTENT_ABOUT){
            //TODO about activity finished

        }
        else {
            super.onActivityResult(requestCode, resultCode, data);
        }
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

    public void saveTokenlist() {
        Util.saveTokens(this, tokenlist);
    }

    @Override
    public boolean onCreateActionMode(ActionMode mode, Menu menu) {
        MenuInflater inflater = mode.getMenuInflater();

        if (nextSelection.isWithPIN()) {
            inflater.inflate(R.menu.actionmode_menu, menu);
        } else {
            inflater.inflate(R.menu.actionmode_menu_nopin, menu);
        }
        return true;
    }

    @Override
    public boolean onPrepareActionMode(ActionMode mode, Menu menu) {
        tokenlistadapter.setCurrentSelection(nextSelection);
        tokenlistadapter.notifyDataSetChanged();
        mode.setTitle("Choose an action");

        return true;
    }

    @Override
    public boolean onActionItemClicked(final ActionMode mode, MenuItem item) {
        final Token currToken = tokenlistadapter.getCurrentSelection();
        final int id = item.getItemId();

        if (id == R.id.delete_token2) {
            AlertDialog.Builder alert = new AlertDialog.Builder(this);
            alert.setTitle("CONFIRM DELETION");
            alert.setMessage("Do you really want to remove\n" + currToken.getLabel() + " ?");
            alert.setPositiveButton("YES", new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int which) {
                    tokenlist.remove(currToken);
                    tokenlistadapter.notifyDataSetChanged();
                    saveTokenlist();
                    Toast.makeText(MainActivity.this, "Token removed", Toast.LENGTH_SHORT).show();
                    mode.finish();
                }
            });
            alert.setNegativeButton("NO", new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int which) {
                    Toast.makeText(MainActivity.this, "Deletion cancelled", Toast.LENGTH_SHORT).show();
                    dialog.cancel();
                    mode.finish();
                }
            });
            alert.show();
            return true;
        }

        if (id == R.id.edit_token2) {
            AlertDialog.Builder alert = new AlertDialog.Builder(this);
            alert.setTitle("Edit Name");
            final EditText input = new EditText(this);
            input.setText(currToken.getLabel());
            input.setSelectAllOnFocus(true);
            alert.setView(input);

            alert.setPositiveButton("Save", new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface dialog, int whichButton) {
                    currToken.setLabel(input.getEditableText().toString());
                    tokenlistadapter.notifyDataSetChanged();
                    saveTokenlist();
                    Toast.makeText(MainActivity.this, "Name was changed", Toast.LENGTH_SHORT).show();
                    mode.finish();
                }
            });

            alert.setNegativeButton("Cancel", new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface dialog, int whichButton) {
                    dialog.cancel();
                    Toast.makeText(MainActivity.this, "Editing cancelled", Toast.LENGTH_SHORT).show();
                    mode.finish();
                }
            });
            alert.show();
            return true;
        }

        if (id == R.id.change_pin2) {
            if (currToken.isWithPIN() && !currToken.isLocked()) {
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
                            String hashedPIN = OTPGenerator.hashPIN(firstpin, currToken);
                            currToken.setPin(hashedPIN);
                            tokenlistadapter.notifyDataSetChanged();
                            saveTokenlist();
                            Toast.makeText(MainActivity.this, "PIN was changed", Toast.LENGTH_SHORT).show();
                        } else {
                            Toast.makeText(MainActivity.this, "PINs do not match - Cancelled", Toast.LENGTH_SHORT).show();
                        }
                        mode.finish();
                    }
                });

                alert.setNegativeButton("Cancel", new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int whichButton) {
                        dialog.cancel();
                        Toast.makeText(MainActivity.this, "Changing PIN cancelled", Toast.LENGTH_SHORT).show();
                        mode.finish();
                    }
                });
                alert.show();
                return true;
            }
        }

        if (id == R.id.copy_clipboard) {
            copyToClipboard(this, currToken.getCurrentOTP());
            Toast.makeText(MainActivity.this, "OTP copied to Clipboard", Toast.LENGTH_SHORT).show();
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
                throw new Exception("No TOTP or HOTP Token");
            }
        }

        String type = url.getHost();
        // the secret is base32 decoded before the OTP value is generated, so there no need to do something here
        String secret = uri.getQueryParameter(SECRET);
        String label = uri.getPath().substring(1);
        String issuer = uri.getQueryParameter(ISSUER);
        if (issuer != null) {
            label = issuer + ": " + label;
        }
        int digits = Integer.parseInt(uri.getQueryParameter(DIGITS));
        //byte[] secretAsbytes = new Base32().decode(secret.toUpperCase());
        Token tmp = new Token(secret, label, type, digits);

        if (type.equals(TOTP)) {
            tmp.setPeriod(Integer.parseInt(uri.getQueryParameter(PERIOD)));
        }
        if (type.equals(HOTP)) {
            tmp.setCounter(Integer.parseInt(uri.getQueryParameter(COUNTER)));
        }
        if (uri.getQueryParameter(ALGORITHM) != null) {
            tmp.setAlgorithm("Hmac" + uri.getQueryParameter(ALGORITHM).toUpperCase());
        }
        boolean pinned = uri.getBooleanQueryParameter("pin", false);
        if (pinned) {
            tmp.setWithPIN(true);
            tmp.setLocked(true);
        }
        if (uri.getBooleanQueryParameter("2step", false)) {
            int phonepartlength = 10; //TODO can be a parameter in QR
            //TODO hardening iterations in QR?
            if (uri.getQueryParameter("2kl") != null) {
                phonepartlength = Integer.parseInt(uri.getQueryParameter("2kl"));
            }
            return do2StepInit(tmp, phonepartlength);
        }
        if (uri.getBooleanQueryParameter("tapshow", false)) {
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
    private Token do2StepInit(final Token token, final int phonepartlength) {
        AsyncTask<Void, Void, Boolean> asyncTask = new SecretGenerator(token, phonepartlength, util, new SecretGenerator.Response() {
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

        if (data.getBooleanExtra("2step", false)) {
            tmp = do2StepInit(tmp, data.getIntExtra("pp", 10));
        }
        return tmp;
    }

    static class SecretGenerator extends AsyncTask<Void, Void, Boolean> {

        private final Token token;
        private final int phonepartlength;
        private final Util util;
        private ProgressDialog pd;
        private String output;
        Response delegate = null;

        public interface Response {
            void processFinished(Token t);
        }

        SecretGenerator(Token t, int phonepartlength, Util util, Response delegate) {
            this.token = t;
            this.phonepartlength = phonepartlength;
            this.util = util;
            this.delegate = delegate;
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
            //------------------- generate random bytes for the phonepart ------------------------------
            final byte[] phonepart = new byte[phonepartlength];
            SecureRandom sr = new SecureRandom();
            sr.nextBytes(phonepart);
            output = byteArrayToHexString(phonepart);
            Log.d(Util.TAG, "phonepart HexString: " + output);
            //------------- combine the phone- and QR-part -------------------
            String QRsecretAsHEX = byteArrayToHexString(new Base32().decode(token.getSecret()));
            //byte[] qrpartBytes = hexStringToByteArray(QRsecretAsHEX);
            char[] ch = QRsecretAsHEX.toCharArray();
            byte[] completesecretBytes = new byte[0];
            int hardeningIterations = 40000;
            long startTime = SystemClock.elapsedRealtime();
            try {
                completesecretBytes = OTPGenerator.generatePBKDFKey(ch, phonepart, hardeningIterations, 256);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (InvalidKeySpecException e) {
                e.printStackTrace();
            }
            long endTime = SystemClock.elapsedRealtime() - startTime;

            Log.d(Util.TAG, "time for PBKDF2 computation: " + endTime + "ms, with " + hardeningIterations + " Iterations");
            String completeSecretAsHexString = byteArrayToHexString(completesecretBytes);
            Log.d(Util.TAG, "complete secret HexString: " + completeSecretAsHexString);
            token.setSecret(completeSecretAsHexString);

            return true;
        }

        @Override
        protected void onPostExecute(final Boolean success) {
            //------------- display the phone-part of the secret and first OTP to verify ------------
            pd.dismiss();
            android.support.v7.app.AlertDialog.Builder builder = new android.support.v7.app.AlertDialog.Builder(util.getmActivity());
            builder.setCancelable(false);
            builder.setPositiveButton("OK", new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int which) {
                    dialog.cancel();
                }
            });
            builder.setTitle("PHONEPART");
            builder.setMessage(util.insertPeriodically(output, " ", 4) + "\n\n" + "First OTP to verify:      " + OTPGenerator.generate(token));
            builder.show();
            delegate.processFinished(token);
        }

        @Override
        protected void onCancelled() {
        }

    }
}

