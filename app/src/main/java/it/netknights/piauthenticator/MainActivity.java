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
import android.content.SharedPreferences;
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
import android.util.Log;
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

import com.google.android.gms.tasks.OnSuccessListener;
import com.google.firebase.FirebaseApp;
import com.google.firebase.FirebaseOptions;
import com.google.firebase.iid.FirebaseInstanceId;
import com.google.firebase.iid.InstanceIdResult;
import com.google.zxing.integration.android.IntentIntegrator;
import com.google.zxing.integration.android.IntentResult;

import org.apache.commons.codec.binary.Base32;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URL;
import java.security.GeneralSecurityException;
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
import static it.netknights.piauthenticator.AppConstants.API_KEY;
import static it.netknights.piauthenticator.AppConstants.APP_ID;
import static it.netknights.piauthenticator.AppConstants.COUNTER;
import static it.netknights.piauthenticator.AppConstants.DATA;
import static it.netknights.piauthenticator.AppConstants.DIGITS;
import static it.netknights.piauthenticator.AppConstants.FB_TOKEN;
import static it.netknights.piauthenticator.AppConstants.HMACSHA1;
import static it.netknights.piauthenticator.AppConstants.HMACSHA256;
import static it.netknights.piauthenticator.AppConstants.HMACSHA512;
import static it.netknights.piauthenticator.AppConstants.HOTP;
import static it.netknights.piauthenticator.AppConstants.INTENT_ADD_TOKEN_MANUALLY;
import static it.netknights.piauthenticator.AppConstants.ISSUER;
import static it.netknights.piauthenticator.AppConstants.LABEL;
import static it.netknights.piauthenticator.AppConstants.NOTIFICATION_CHANNEL_ID;
import static it.netknights.piauthenticator.AppConstants.PERIOD;
import static it.netknights.piauthenticator.AppConstants.PERSISTENT;
import static it.netknights.piauthenticator.AppConstants.PIN;
import static it.netknights.piauthenticator.AppConstants.PROJECT_ID;
import static it.netknights.piauthenticator.AppConstants.PROJECT_NUMBER;
import static it.netknights.piauthenticator.AppConstants.PUSH;
import static it.netknights.piauthenticator.AppConstants.ROLLOUT_URL;
import static it.netknights.piauthenticator.AppConstants.SECRET;
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
        util = new Util(this);
        util.initFirebase();

        Intent intent = getIntent();
        if (intent == null) {
            logprint("NO INTENT FOUND ON CREATE");
        } else {
            String push_data = intent.getStringExtra(DATA);
            if (push_data != null)
                logprint(push_data);
            if (intent.getExtras() != null)
                logprint(intent.getExtras().toString());
        }

        //PRNGFixes.apply();

        setupViews();
        setupFab();

        setupAdapter();
        startTimerThread();

        checkForExpiredTokens();
        createNotificationChannel();

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            paintStatusbar();
        }
    }

    private void checkForExpiredTokens() {
        ArrayList<Token> upForDeletion = new ArrayList<>();
        Date now = new Date();
        for (Token t : tokenlist) {
            if (t.getType() == PUSH) {
                if (!t.rollout_finished && t.rollout_expiration.before(now)) {
                    upForDeletion.add(t);
                }
            }
        }

        if (!upForDeletion.isEmpty()) {
            StringBuffer sb = new StringBuffer();
            for (Token t : upForDeletion) {
                sb.append(t.getSerial() + "\n");
                removeToken(t);
            }
            AlertDialog.Builder builder = new AlertDialog.Builder(MainActivity.this);
            builder.setTitle("Pushtoken rollout expired")
                    .setMessage("The rollout time expired for the following token:\n\n" +
                            sb.toString())
                    .setPositiveButton("OK", new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface dialog, int which) {
                            dialog.cancel();
                        }
                    });
            builder.show();
        }
    }

    private void setupFab() {
        FloatingActionButton fab = findViewById(R.id.fab);
        fab.setBackgroundColor(getResources().getColor(PIBLUE));
        fab.bringToFront();
        fab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                scanQR();
/*
                // TODO for faster testing purposes skip the qr scan
                String serial = "PIPU000FSA" + String.valueOf(Math.round(Math.random() * 100));
                String url = "https://sdffffff.free.beeceptor.com";

                String s2 = "otpauth://pipush/PIPU0012F668?url=https%3A//sdffffff.free.beeceptor.com&ttl=10&issuer=privacyIDEA&projectid=test-d3861" +
                        "&apikey=AIzaSyBeFSjwJ8aEcHQaj4-iqT-sLAX6lmSrvbo" +
                        "&appid=1%3A850240559902%3Aandroid%3A812605f9a33242a9&enrollment_credential=9311ee50678983c0f29d3d843f86e39405e2b427" +
                        "&projectnumber=850240559902";
                try {
                    AsyncTask<String, Integer, Boolean> tokenCreation = new TokenCreationTask(MainActivity.this, MainActivity.this.util);
                    tokenCreation.execute(s2);
                } catch (Exception e) {
                    e.printStackTrace();
                } */
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

    /**
     * Remove a token from the list. This includes Pub/Priv Keys for Pushtoken
     *
     * @param currToken the token to delete
     */
    void removeToken(Token currToken) {
        if (currToken.getType() == PUSH) {
            util.removePubkeyFor(currToken.getSerial());
            try {
                SecretKeyWrapper.removePrivKeyFor(currToken.getSerial());
            } catch (CertificateException | NoSuchAlgorithmException | KeyStoreException | IOException e) {
                e.printStackTrace();
            }
        }
        int pos = tokenlist.indexOf(currToken);

        if (tokenlist.size() >= pos && pos >= 0 && !tokenlist.isEmpty()) {
            tokenlist.remove(pos);
        }

        if (tokenlistadapter.getPbs().size() >= pos && pos >= 0
                && !tokenlistadapter.getPbs().isEmpty()) {
            tokenlistadapter.getPbs().remove(pos);
        }
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
            FirebaseInstanceId.getInstance().getInstanceId().addOnSuccessListener(MainActivity.this, new OnSuccessListener<InstanceIdResult>() {
                @Override
                public void onSuccess(InstanceIdResult instanceIdResult) {
                    logprint("Firebase Token: " + instanceIdResult.getToken());
                }
            });
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
                    AsyncTask<String, Integer, Boolean> tokenCreation = new TokenCreationTask(this, this.util);
                    tokenCreation.execute(result.getContents());
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
        } else {
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

    private Token makeTokenFromIntent(Intent data) {
        // Push tokens cannot be created manually so this is simplified
        String type = data.getStringExtra(TYPE);

        byte[] secret = data.getByteArrayExtra(SECRET);
        String label = data.getStringExtra(LABEL);
        int digits = data.getIntExtra(DIGITS, 6);
        String algorithm = data.getStringExtra(ALGORITHM);
        Token tmp = new Token(secret, label, label, type, digits);

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
        });
    }

    public void saveTokenlist() {
        Util.saveTokens(this, tokenlist);
        //Toast.makeText(this, "Tokens saved", Toast.LENGTH_SHORT).show();
    }

    private void scanQR() {
        try {
            IntentIntegrator ii = new IntentIntegrator(this);
            ii.setBeepEnabled(false);
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

    private void createNotificationChannel() {
        // Create the NotificationChannel, but only on API 26+ because
        // the NotificationChannel class is new and not in the support library
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            CharSequence name = "privacyIDEAPush";
            String description = "push for privacyIDEA";
            int importance = NotificationManager.IMPORTANCE_HIGH;
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

    // ----------------- ActivityInterface implementation -----------------
    @Override
    public Activity getPresentActivity() {
        return this;
    }

    @Override
    public void addToken(Token t) {
        if (t == null) return;
        this.tokenlist.add(t);
        saveTokenlist();
        this.tokenlistadapter.notifyDataSetChanged();
    }
}

interface ActivityInterface {
    public Activity getPresentActivity();

    public void addToken(Token t);
}