/*
  privacyIDEA Authenticator

  Authors: Nils Behlen <nils.behlen@netknights.it>

  Copyright (c) 2017-2019 NetKnights GmbH

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

package it.netknights.piauthenticator.viewcontroller;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.graphics.PorterDuff;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.text.Html;
import android.text.InputType;
import android.text.Spanned;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import com.google.android.material.floatingactionbutton.FloatingActionButton;
import com.google.android.material.snackbar.Snackbar;
import com.google.firebase.FirebaseApp;
import com.google.firebase.FirebaseOptions;
import com.google.firebase.iid.FirebaseInstanceId;
import com.google.zxing.integration.android.IntentIntegrator;
import com.google.zxing.integration.android.IntentResult;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.view.ActionMode;
import androidx.appcompat.widget.Toolbar;
import androidx.core.app.NotificationManagerCompat;

import it.netknights.piauthenticator.interfaces.MainActivityInterface;
import it.netknights.piauthenticator.interfaces.PresenterInterface;
import it.netknights.piauthenticator.model.FirebaseInitConfig;
import it.netknights.piauthenticator.model.PushAuthRequest;
import it.netknights.piauthenticator.model.ScanResult;
import it.netknights.piauthenticator.utils.AppConstants;
import it.netknights.piauthenticator.presenter.Presenter;
import it.netknights.piauthenticator.R;
import it.netknights.piauthenticator.model.Token;
import it.netknights.piauthenticator.utils.SecretKeyWrapper;
import it.netknights.piauthenticator.utils.Util;

import static it.netknights.piauthenticator.utils.AppConstants.ALGORITHM;
import static it.netknights.piauthenticator.utils.AppConstants.API_KEY;
import static it.netknights.piauthenticator.utils.AppConstants.APP_ID;
import static it.netknights.piauthenticator.utils.AppConstants.COUNTER;
import static it.netknights.piauthenticator.utils.AppConstants.DIGITS;
import static it.netknights.piauthenticator.utils.AppConstants.ENROLLMENT_CRED;
import static it.netknights.piauthenticator.utils.AppConstants.HOTP;
import static it.netknights.piauthenticator.utils.AppConstants.INTENT_ADD_TOKEN_MANUALLY;
import static it.netknights.piauthenticator.utils.AppConstants.ISSUER;
import static it.netknights.piauthenticator.utils.AppConstants.LABEL;
import static it.netknights.piauthenticator.utils.AppConstants.NONCE;
import static it.netknights.piauthenticator.utils.AppConstants.NOTIFICATION_CHANNEL_ID;
import static it.netknights.piauthenticator.utils.AppConstants.NOTIFICATION_ID;
import static it.netknights.piauthenticator.utils.AppConstants.PERIOD;
import static it.netknights.piauthenticator.utils.AppConstants.PERSISTENT;
import static it.netknights.piauthenticator.utils.AppConstants.PIN;
import static it.netknights.piauthenticator.utils.AppConstants.PROJECT_ID;
import static it.netknights.piauthenticator.utils.AppConstants.PROJECT_NUMBER;
import static it.netknights.piauthenticator.utils.AppConstants.PUSH;
import static it.netknights.piauthenticator.utils.AppConstants.PUSH_VERSION;
import static it.netknights.piauthenticator.utils.AppConstants.QUESTION;
import static it.netknights.piauthenticator.utils.AppConstants.SECRET;
import static it.netknights.piauthenticator.utils.AppConstants.SERIAL;
import static it.netknights.piauthenticator.utils.AppConstants.SIGNATURE;
import static it.netknights.piauthenticator.utils.AppConstants.SSL_VERIFY;
import static it.netknights.piauthenticator.utils.AppConstants.TAPTOSHOW;
import static it.netknights.piauthenticator.utils.AppConstants.TITLE;
import static it.netknights.piauthenticator.utils.AppConstants.TOTP;
import static it.netknights.piauthenticator.utils.AppConstants.TTL;
import static it.netknights.piauthenticator.utils.AppConstants.TWOSTEP_DIFFICULTY;
import static it.netknights.piauthenticator.utils.AppConstants.TWOSTEP_OUTPUT;
import static it.netknights.piauthenticator.utils.AppConstants.TWOSTEP_SALT;
import static it.netknights.piauthenticator.utils.AppConstants.TYPE;
import static it.netknights.piauthenticator.utils.AppConstants.URL;
import static it.netknights.piauthenticator.utils.AppConstants.WITHPIN;
import static it.netknights.piauthenticator.R.color.PIBLUE;
import static it.netknights.piauthenticator.utils.Util.logprint;


public class MainActivity extends AppCompatActivity implements ActionMode.Callback, MainActivityInterface {
    private PresenterInterface presenterInterface;
    private TokenListAdapter tokenlistadapter;
    private ListView listview;
    private AlertDialog status_dialog;
    private Handler handler;
    private Runnable timer;
    private MainActivityBroadcastReceiver receiver;

    // getting the firebase token requires the Activity
    private SecretKeyWrapper secretKeyWrapper;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        setupViews();
        setupFab();

        // SETUP INTERFACES AND DEPENDENCIES
        tokenlistadapter = new TokenListAdapter();
        secretKeyWrapper = null;
        try {
            secretKeyWrapper = new SecretKeyWrapper(this);
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (IllegalStateException e) {
            // This exception occurs when the creation of the keypair fails, the app cannot save keys then and is unusable
            makeDeviceNotSupportedDialog();
        }

        Util util = new Util(secretKeyWrapper, getFilesDir().getAbsolutePath());
        Presenter presenter = new Presenter(tokenlistadapter, this, util);

        presenterInterface = presenter;

        // this method checks if saving keys works, if not a dialog will appear informing the user
        // that the application cannot be used on the device
        presenter.checkKeyStoreIsWorking();

        tokenlistadapter.setPresenterInterface(presenter);

        // init the model before the adapter is set
        presenterInterface.init();
        listview.setAdapter(tokenlistadapter);
        receiver = new MainActivityBroadcastReceiver(this);
        registerReceiver(receiver, receiver.intentFilter);

        createNotificationChannel();

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            paintStatusbar();
        }

        // Check for intent (=Pending auth requests)
        Intent intent = getIntent();
        if (intent.getExtras() == null) {
            logprint("No intent found onCreate.");
        } else {
            pushAuthRequestReceived(intent);
        }
    }

    void pushAuthRequestReceived(Intent intent) {
        // intent contain push auth info
        logprint("Intent Found onCreate:");
        logprint(intent.getExtras().toString());
        String serial = intent.getStringExtra(SERIAL);
        String nonce = intent.getStringExtra(NONCE);
        String title = intent.getStringExtra(TITLE);
        String url = intent.getStringExtra(URL);
        String signature = intent.getStringExtra(SIGNATURE);
        String question = intent.getStringExtra(QUESTION);
        int notificationID = intent.getIntExtra(NOTIFICATION_ID, 654321);
        boolean sslVerify = intent.getBooleanExtra(SSL_VERIFY, true);
        if (serial != null && nonce != null && title != null && url != null && signature != null && question != null) {
            logprint("Intent data: " + intent.getExtras().toString());
            presenterInterface.addPushAuthRequest(new PushAuthRequest(nonce, url, serial, question, title, signature, notificationID, sslVerify));
        } else {
            logprint("Not all data for PushAuth available");
        }
    }

    void pushAuthFinishedFor(int notificationID, String signature) {
        presenterInterface.removePushAuthFor(notificationID, signature);
    }

    private void setupFab() {
        FloatingActionButton fab = findViewById(R.id.fab);
        fab.setBackgroundColor(getResources().getColor(PIBLUE));
        fab.bringToFront();
        fab.setOnClickListener(v -> scanQR());
    }

    @RequiresApi(api = Build.VERSION_CODES.LOLLIPOP)
    public void paintStatusbar() {
        Window window = getWindow();
        window.addFlags(WindowManager.LayoutParams.FLAG_DRAWS_SYSTEM_BAR_BACKGROUNDS);
        window.clearFlags(WindowManager.LayoutParams.FLAG_TRANSLUCENT_STATUS);
        window.setStatusBarColor(getResources().getColor(PIBLUE));
    }

    private void setupViews() {
        setTitle("      " + AppConstants.APP_TITLE);
        setContentView(R.layout.activity_main);
        listview = findViewById(R.id.listview);
        listview.setOnItemLongClickListener((adapterView, view, i, l) -> {
            presenterInterface.setCurrentSelection(i);
            startSupportActionMode(MainActivity.this);
            return true;
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
        presenterInterface.saveTokenlist();
        if (id == R.id.action_about) {
            Intent aboutintent = new Intent(this, AboutActivity.class);
            startActivity(aboutintent);
            return true;
        }
        if (id == R.id.action_enter_detail) {
            Intent enterDetailIntent = EnterDetailsActivity.makeIntent(MainActivity.this);
            startActivityForResult(enterDetailIntent, INTENT_ADD_TOKEN_MANUALLY);
        }
        return super.onOptionsItemSelected(item);
    }

    @SuppressWarnings("ConstantConditions")
    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        IntentResult result = IntentIntegrator.parseActivityResult(requestCode, resultCode, data);
        if (result != null) {
            if (result.getContents() == null) {
                makeToast(R.string.toast_cancelled);
            } else {
                // Extract data here, URI is an android dependency
                try {
                    String content = result.getContents().replaceFirst("otpauth", "http");
                    Uri uri = Uri.parse(content);
                    URL url = null;
                    try {
                        url = new URL(content);
                    } catch (MalformedURLException e) {
                        e.printStackTrace();
                    }

                    if (!url.getProtocol().equals("http")) {
                        try {
                            throw new Exception("Invalid Protocol");
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                    if (!url.getHost().equals(TOTP) && !url.getHost().equals(HOTP) &&
                            !url.getHost().equals(PUSH)) {
                        try {
                            throw new Exception("No TOTP, HOTP or Push Token");
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                    // otpauth://TYPE/LABEL?PARAMETERS
                    // TOKEN TYPE
                    String type = url.getHost();
                    // LABEL
                    String label = uri.getPath().substring(1);

                    // SERIAL
                    String serial = uri.getQueryParameter(SERIAL);
                    if (serial == null) {
                        serial = label;
                    }

                    ScanResult scanResult = new ScanResult(type, serial);

                    // LABEL = ISSUER: LABEL
                    String issuer = uri.getQueryParameter(ISSUER);
                    if (issuer != null && !label.startsWith(issuer)) {
                        label = issuer + ": " + label;
                    }
                    scanResult.label = label;
                    // ---------------- PUSH ----------------
                    if (type.equals(PUSH)) {
                        // Check for FirebaseInit info
                        if (uri.getQueryParameter(PROJECT_ID) != null) {
                            String projID = uri.getQueryParameter(PROJECT_ID);
                            String appID = uri.getQueryParameter(APP_ID);
                            String api_key = uri.getQueryParameter(API_KEY);
                            String projNumber = uri.getQueryParameter(PROJECT_NUMBER);
                            if (projID != null && appID != null && api_key != null && projNumber != null) {
                                scanResult.firebaseInitConfig = new FirebaseInitConfig(projID, appID, api_key, projNumber);
                            }
                        }
                        scanResult.rollout_url = uri.getQueryParameter(URL);
                        if (uri.getQueryParameter(TTL) != null) {
                            scanResult.ttl = Integer.parseInt(uri.getQueryParameter(TTL));
                        }
                        if (uri.getQueryParameter(ENROLLMENT_CRED) != null) {
                            scanResult.enrollment_credential = uri.getQueryParameter(ENROLLMENT_CRED);
                        }
                        if (uri.getQueryParameter(PUSH_VERSION) != null) {
                            scanResult.push_version = Integer.parseInt(uri.getQueryParameter(PUSH_VERSION));
                        }
                        if (uri.getQueryParameter(SSL_VERIFY) != null) {
                            if (Integer.parseInt(uri.getQueryParameter(SSL_VERIFY)) < 1) {
                                scanResult.sslverify = false;
                            }
                        }
                    }
                    // ---------------- END PUSH ----------------

                    // ---------------- NORMAL TOKEN ----------------
                    scanResult.secret = uri.getQueryParameter(SECRET);

                    if (uri.getQueryParameter(DIGITS) != null) {
                        scanResult.digits = Integer.parseInt(uri.getQueryParameter(DIGITS));
                    }
                    if (uri.getQueryParameter(PERIOD) != null) {
                        scanResult.period = Integer.parseInt(uri.getQueryParameter(PERIOD));
                    }
                    if (uri.getQueryParameter(COUNTER) != null) {
                        scanResult.counter = Integer.parseInt(uri.getQueryParameter(COUNTER));
                    }
                    if (uri.getQueryParameter(ALGORITHM) != null) {
                        scanResult.algorithm = uri.getQueryParameter(ALGORITHM).toUpperCase();
                    }
                    if (uri.getBooleanQueryParameter(PIN, false)) {
                        scanResult.pin = true;
                    }
                    if (uri.getBooleanQueryParameter(PERSISTENT, false)) {
                        scanResult.persistent = true;
                    }
                    // tap to show is currently not used
                    if (uri.getBooleanQueryParameter(TAPTOSHOW, false)) {
                        scanResult.taptoshow = true;
                    }

                    // --------------------- OPTIONAL 2 STEP ---------------------
                    // if at least one parameter for 2step is set do 2step init
                    if (uri.getQueryParameter(TWOSTEP_SALT) != null ||
                            uri.getQueryParameter(TWOSTEP_DIFFICULTY) != null ||
                            uri.getQueryParameter(TWOSTEP_OUTPUT) != null) {
                        scanResult.do2Step = true;
                        if (uri.getQueryParameter(TWOSTEP_SALT) != null) {
                            scanResult.phonepartlength = Integer.parseInt(uri.getQueryParameter(TWOSTEP_SALT));
                        }
                        if (uri.getQueryParameter(TWOSTEP_OUTPUT) != null) {
                            scanResult.output_size = Integer.parseInt(uri.getQueryParameter(TWOSTEP_OUTPUT)) * 8;
                        }

                        if (uri.getQueryParameter(TWOSTEP_DIFFICULTY) != null) {
                            scanResult.iterations = Integer.parseInt(uri.getQueryParameter(TWOSTEP_DIFFICULTY));
                        }
                    }
                    presenterInterface.scanQRfinished(scanResult);
                } catch (Exception e) {
                    makeToast(R.string.toast_invalid_qr);
                    e.printStackTrace();
                }
            }
        } else if (requestCode == INTENT_ADD_TOKEN_MANUALLY) {
            if (resultCode == Activity.RESULT_OK) {
                // Extract values from the intent here, so the logic does not depend on Intent
                String period = null;
                if (data.getStringExtra(TYPE).equals(TOTP)) {
                    period = String.valueOf(data.getIntExtra(PERIOD, 30));
                }
                presenterInterface.addTokenFromIntent(data.getStringExtra(TYPE), data.getByteArrayExtra(SECRET), data.getStringExtra(LABEL),
                        data.getIntExtra(DIGITS, 6), data.getStringExtra(ALGORITHM), period, data.getBooleanExtra(WITHPIN, false));
            } else {
                makeToast(R.string.toast_cancelled);
            }
        } else {
            super.onActivityResult(requestCode, resultCode, data);
        }
    }

    @Override
    public void onResume() {
        super.onResume();
        registerReceiver(receiver, receiver.intentFilter);
        presenterInterface.onResume();
    }

    @Override
    public void onPause() {
        super.onPause();
        unregisterReceiver(receiver);
        presenterInterface.onPause();
    }

    @Override
    protected void onStop() {
        super.onStop();
        presenterInterface.onStop();
    }

    @Override
    public boolean onCreateActionMode(ActionMode mode, Menu menu) {
        MenuInflater inflater = mode.getMenuInflater();
        if (presenterInterface.isCurrentSelectionWithPin()) {
            inflater.inflate(R.menu.actionmode_menu, menu);
            if (presenterInterface.isCurrentSelectionPersistent()) {
                for (int i = 0; i < menu.size(); i++) {
                    if (menu.getItem(i).getItemId() == R.id.delete_token2) {
                        menu.getItem(i).setEnabled(false);
                        menu.getItem(i).setIcon(R.drawable.ic_no_delete);
                    }
                }
            }
        } else {
            inflater.inflate(R.menu.actionmode_menu_nopin, menu);
            if (presenterInterface.isCurrentSelectionPersistent()) {
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
        tokenlistadapter.notifyChange();
        mode.setTitle(getString(R.string.actionmode_title));
        return true;
    }

    @Override
    public boolean onActionItemClicked(final ActionMode mode, MenuItem item) {
        final int id = item.getItemId();
        if (id == R.id.delete_token2) {
           /* if (currToken.isPersistent()) {
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

            String message = getString(R.string.confirm_deletion_text,
                    presenterInterface.getCurrentSelectionLabel());
            Spanned spanned = Html.fromHtml(message);
            builder.setMessage(spanned);

            builder.setPositiveButton(R.string.button_text_yes, (dialog, which) -> {
                presenterInterface.removeCurrentSelection();
                mode.finish();
            });
            builder.setNegativeButton(R.string.button_text_no, (dialog, which) -> {
                makeToast(R.string.toast_deletion_cancelled);
                dialog.cancel();
                mode.finish();
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
            input.setText(presenterInterface.getCurrentSelectionLabel());
            input.setSelectAllOnFocus(true);
            input.getBackground().setColorFilter(input.getContext().getResources().getColor(PIBLUE), PorterDuff.Mode.SRC_IN);
            builder.setView(input);

            builder.setPositiveButton(getString(R.string.button_text_save), (dialog, whichButton) -> {
                presenterInterface.setCurrentSelectionLabel(input.getEditableText().toString());
                tokenlistadapter.notifyChange();
                presenterInterface.saveTokenlist();
                makeToast(presenterInterface.getCurrentSelectionLabel()
                        + ": " + getString(R.string.toast_name_changed));
                mode.finish();
            });

            builder.setNegativeButton(getString(R.string.button_text_cancel), (dialog, whichButton) -> {
                dialog.cancel();
                makeToast(R.string.toast_edit_cancelled);
                mode.finish();
            });
            final AlertDialog alert = builder.create();
            MainActivity.changeDialogFontColor(alert);
            alert.getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_VISIBLE);
            alert.show();

            return true;
        }

        if (id == R.id.change_pin2) {
            if (presenterInterface.isCurrentSelectionWithPin()
                    && !presenterInterface.isCurrentSelectionLocked()) {
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

                builder.setPositiveButton(getString(R.string.button_text_save), (dialog, whichButton) -> {
                    int firstpin = Integer.parseInt(firstinput.getEditableText().toString());
                    int secondpin = Integer.parseInt(secondinput.getEditableText().toString());
                    if (firstpin == secondpin) {
                        presenterInterface.changeCurrentSelectionPIN(firstpin);
                        makeToast(presenterInterface.getCurrentSelectionLabel()
                                + ": " + getString(R.string.toast_pin_changed));
                    } else {
                        makeToast(R.string.toast_pins_dont_match);
                    }
                    mode.finish();
                });

                builder.setNegativeButton(getString(R.string.button_text_cancel), (dialog, whichButton) -> {
                    dialog.cancel();
                    makeToast(R.string.toast_change_pin_cancelled);
                    mode.finish();
                });
                final AlertDialog alert = builder.create();
                MainActivity.changeDialogFontColor(alert);
                alert.show();
                return true;
            }
        }

        if (id == R.id.copy_clipboard) {
            copyToClipboard(this, presenterInterface.getCurrentSelectionOTP());
            makeToast(R.string.toast_otp_to_clipboard);
        }
        return false;
    }

    @Override
    public void onDestroyActionMode(ActionMode mode) {

        // colors are set for the selected views in the TOkenListAdapter, this is due to the
        // implementation. As the color of all views cannot be changed there,
        // it has to be done here
        for (int i = 0; i < listview.getChildCount(); i++) {
            listview.getChildAt(i).setBackgroundColor(getResources().getColor(R.color.white));
        }

        presenterInterface.setCurrentSelection(-1); // equals null in the data model
        tokenlistadapter.notifyChange();
        presenterInterface.saveTokenlist();

    }

    @Override
    public PublicKey generatePublicKeyFor(String alias) {
        try {
            return SecretKeyWrapper.generateKeyPair(alias, this);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public String getStringResource(int id) {
        return getString(id);
    }

    @Override
    public void cancelNotification(int notificationID) {
        NotificationManagerCompat.from(this).cancel(notificationID);
    }

    @Override
    public void makeToast(int resID) {
        Toast.makeText(MainActivity.this, resID, Toast.LENGTH_SHORT).show();
    }

    @Override
    public void makeToast(String message) {
        Toast.makeText(this, message, Toast.LENGTH_LONG).show();
    }

    @Override
    public void setStatusDialogText(String text) {
        // if there is no dialog yet, inflate it
        if (status_dialog == null) {
            View view_pro_progress = getLayoutInflater().inflate(R.layout.pushrollout_loading, listview, false);
            AlertDialog.Builder dialog_builder = new AlertDialog.Builder(this);
            dialog_builder.setView(view_pro_progress);
            dialog_builder.setCancelable(false);
            status_dialog = dialog_builder.show();
        }
        MainActivity.changeDialogFontColor(status_dialog);
        TextView tv_status;
        if (status_dialog == null) {
            logprint("cannot find status dialog");
            return;
        } else {
            tv_status = status_dialog.findViewById(R.id.tv_status);
        }
        if (tv_status == null) {
            logprint("cannot find status text view");
            return;
        }
        tv_status.setText(text);
    }

    @Override
    public void setStatusDialogText(int id) {
        setStatusDialogText(getString(id));
    }

    @Override
    public void cancelStatusDialog() {
        if (status_dialog == null) return;
        status_dialog.cancel();
        status_dialog = null;
    }

    @Override
    public void getFirebaseTokenForPushRollout(Token token) {
        logprint("Getting Firebase token...");
        FirebaseInstanceId.getInstance().getInstanceId().addOnSuccessListener(this, instanceIdResult -> {
            logprint("Firebase Token: " + instanceIdResult.getToken());
            presenterInterface.firebaseTokenReceived(instanceIdResult.getToken(), token);
        });
    }

    @Override
    public void firebaseInit(FirebaseInitConfig firebaseInitConfig) {
        logprint("Initializing Firebase...");
        // Check if Firebase is already initalized
        if (!FirebaseApp.getApps(this).isEmpty()) {
            logprint("Firebase already initialized for: " + FirebaseApp.getApps(this).toString());
        } else {
            // INIT FIREBASE
            String projID = firebaseInitConfig.getProjID();
            String appID = firebaseInitConfig.getAppID();
            String api_key = firebaseInitConfig.getApiKey();
            String gcmSenderID = firebaseInitConfig.getProjNumber();
            String database_url = "https://" + projID + ".firebaseio.com";
            String storage_bucket = projID + ".appspot.com";

            FirebaseOptions.Builder builder = new FirebaseOptions.Builder()
                    .setApplicationId(appID)
                    .setApiKey(api_key)
                    .setDatabaseUrl(database_url)
                    .setStorageBucket(storage_bucket)
                    .setProjectId(projID)
                    .setGcmSenderId(gcmSenderID);
            FirebaseApp.initializeApp(this, builder.build());

            logprint("Firebase initialized!");
        }
    }

    @Override
    public void removeFirebase() {
        FirebaseApp.getApps(this).clear();
    }

    @Override
    public void startTimer() {
        handler = new Handler();
        timer = new Runnable() {
            @Override
            public void run() {
                presenterInterface.timerProgress(((int) (System.currentTimeMillis() / 1000) % 60));
                handler.postDelayed(this, 1000);
            }
        };
        handler.post(timer);
        handler.removeCallbacks(timer);
    }

    @Override
    public void stopTimer() {
        handler.removeCallbacks(timer);
    }

    @Override
    public void resumeTimer() {
        handler.post(timer);
    }

    @Override
    public SecretKeyWrapper getWrapper() {
        return secretKeyWrapper;
    }

    public static void changeDialogFontColor(final AlertDialog dialog) {
        dialog.setOnShowListener(dialogInterface -> {
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
        });
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

    @Override
    public void makeAlertDialog(String title, String message, String positiveBtnText, boolean cancelable,
                                DialogInterface.OnClickListener positiveBtnListener) {
        if (status_dialog != null) {
            cancelStatusDialog();
        }

        AlertDialog.Builder builder = new AlertDialog.Builder(MainActivity.this);
        builder.setTitle(title)
                .setCancelable(cancelable)
                .setMessage(message)
                .setPositiveButton(positiveBtnText, positiveBtnListener);
        final AlertDialog alert = builder.create();
        MainActivity.changeDialogFontColor(alert);
        alert.show();
    }

    @Override
    public void makeAlertDialog(int titleID, int messageID, int positiveBtnTextID,
                                boolean cancelable, DialogInterface.OnClickListener positiveBtnListener) {
        makeAlertDialog(getStringResource(titleID), getStringResource(messageID),
                getStringResource(positiveBtnTextID), cancelable, positiveBtnListener);
    }

    @Override
    public void makeAlertDialog(String title, String message) {
        makeAlertDialog(title, message, "OK", true, (dialog, which) -> dialog.cancel());
    }

    @Override
    public void makeAlertDialog(int titleID, String message) {
        makeAlertDialog(getStringResource(titleID), message);
    }

    @Override
    public void makeAlertDialog(int titleID, int messageID) {
        makeAlertDialog(getStringResource(titleID), getStringResource(messageID));
    }

    @Override
    public void makeDeviceNotSupportedDialog() {
        makeAlertDialog(R.string.device_not_supported, R.string.device_not_supported_text,
                R.string.device_not_supported_btn_text, false,
                (dialog, which) -> {
                    this.finish(); // TODO this does not seem to be the best way to handle this
                });
    }
}
