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

package it.netknights.piauthenticator;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.graphics.PorterDuff;
import android.os.Build;
import android.os.Bundle;
import android.support.annotation.RequiresApi;
import android.support.design.widget.FloatingActionButton;
import android.support.design.widget.Snackbar;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.view.ActionMode;
import android.support.v7.widget.Toolbar;
import android.text.InputType;
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
import android.widget.TextView;
import android.widget.Toast;

import com.google.android.gms.tasks.OnSuccessListener;
import com.google.firebase.iid.FirebaseInstanceId;
import com.google.firebase.iid.InstanceIdResult;
import com.google.zxing.integration.android.IntentIntegrator;
import com.google.zxing.integration.android.IntentResult;

import static it.netknights.piauthenticator.AppConstants.AUTHENTICATION_URL;
import static it.netknights.piauthenticator.AppConstants.INTENT_ADD_TOKEN_MANUALLY;
import static it.netknights.piauthenticator.AppConstants.NONCE;
import static it.netknights.piauthenticator.AppConstants.NOTIFICATION_CHANNEL_ID;
import static it.netknights.piauthenticator.AppConstants.QUESTION;
import static it.netknights.piauthenticator.AppConstants.SERIAL;
import static it.netknights.piauthenticator.AppConstants.SIGNATURE;
import static it.netknights.piauthenticator.AppConstants.TITLE;
import static it.netknights.piauthenticator.Interfaces.*;
import static it.netknights.piauthenticator.R.color.PIBLUE;
import static it.netknights.piauthenticator.Util.logprint;


public class MainActivity extends AppCompatActivity implements ActionMode.Callback, MainActivityInterface {
    private PresenterInterface presenterInterface;
    private TokenListAdapter tokenlistadapter;
    private ListView listview;
    private AlertDialog status_dialog;
    // getting the token requires the Activity
    String firebase_token;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Intent intent = getIntent();
        if (intent.getExtras() == null) {
            logprint("No intent found onCreate.");
        } else {
            // intent contain push auth info
            String serial = intent.getStringExtra(SERIAL);
            String nonce = intent.getStringExtra(NONCE);
            String title = intent.getStringExtra(TITLE);
            String url = intent.getStringExtra(AUTHENTICATION_URL);
            String signature = intent.getStringExtra(SIGNATURE);
            String question = intent.getStringExtra(QUESTION);
            presenterInterface.addPushAuthRequest(nonce, url, serial, question, title, signature);
        }

        setupViews();
        setupFab();

        // SETUP INTERFACES
        Presenter presenter = new Presenter();
        tokenlistadapter = new TokenListAdapter();
        presenter.setMainActivityInterface(this);
        presenter.setTokenListInterface(tokenlistadapter);
        presenterInterface = presenter;
        tokenlistadapter.setPresenterInterface(presenter);
        // init the model before the adapter is set
        presenterInterface.init();

        listview.setAdapter(tokenlistadapter);



        createNotificationChannel();

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            paintStatusbar();
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
                presenterInterface.setCurrentSelection(i);
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

        if (id == R.id.print_keys) {
            presenterInterface.printKeystore();
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
                makeToast(R.string.toast_cancelled);
            } else {
                try {
                    presenterInterface.scanQRfinished(result.getContents());
                } catch (Exception e) {
                    makeToast(R.string.toast_invalid_qr);
                    e.printStackTrace();
                }
            }
        } else if (requestCode == INTENT_ADD_TOKEN_MANUALLY) {
            if (resultCode == Activity.RESULT_OK) {
                presenterInterface.addTokenFromBundle(data);
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
        presenterInterface.onResume();
    }

    @Override
    public void onPause() {
        super.onPause();
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
            builder.setMessage(getString(R.string.confirm_deletion_text)
                    + presenterInterface.getCurrentSelectionLabel() + " ?");
            builder.setPositiveButton(R.string.button_text_yes, new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int which) {
                    presenterInterface.removeCurrentSelection();
                    mode.finish();
                }
            });
            builder.setNegativeButton(R.string.button_text_no, new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int which) {
                    makeToast(R.string.toast_deletion_cancelled);
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
            input.setText(presenterInterface.getCurrentSelectionLabel());
            input.setSelectAllOnFocus(true);
            input.getBackground().setColorFilter(input.getContext().getResources().getColor(PIBLUE), PorterDuff.Mode.SRC_IN);
            builder.setView(input);

            builder.setPositiveButton(getString(R.string.button_text_save), new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface dialog, int whichButton) {
                    presenterInterface.setCurrentSelectionLabel(input.getEditableText().toString());
                    tokenlistadapter.notifyChange();
                    presenterInterface.saveTokenlist();
                    makeToast(presenterInterface.getCurrentSelectionLabel()
                            + ": " + getString(R.string.toast_name_changed));
                    mode.finish();
                }
            });

            builder.setNegativeButton(getString(R.string.button_text_cancel), new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface dialog, int whichButton) {
                    dialog.cancel();
                    makeToast(R.string.toast_edit_cancelled);
                    mode.finish();
                }
            });
            final AlertDialog alert = builder.create();
            MainActivity.changeDialogFontColor(alert);
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

                builder.setPositiveButton(getString(R.string.button_text_save), new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int whichButton) {
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
                    }
                });

                builder.setNegativeButton(getString(R.string.button_text_cancel), new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int whichButton) {
                        dialog.cancel();
                        makeToast(R.string.toast_change_pin_cancelled);
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
            copyToClipboard(this, presenterInterface.getCurrentSelectionOTP());
            makeToast(R.string.toast_otp_to_clipboard);
        }
        return false;
    }

    @Override
    public void makeToast(int resID) {
        Toast.makeText(MainActivity.this, resID, Toast.LENGTH_SHORT).show();
    }

    @Override
    public void setStatusDialogText(String text) {
        // if there is no dialog yet inflate it
        if (status_dialog == null) {
            View view_pro_progress = getLayoutInflater().inflate(R.layout.pushrollout_loading, null);
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
    public void cancelStatusDialog() {
        if (status_dialog == null) return;
        status_dialog.cancel();
        status_dialog = null;
    }

    @Override
    public String getFirebaseToken() {
        logprint("Getting Firebase token...");
        FirebaseInstanceId.getInstance().getInstanceId().addOnSuccessListener(this, new OnSuccessListener<InstanceIdResult>() {
            @Override
            public void onSuccess(InstanceIdResult instanceIdResult) {
                logprint("Firebase Token: " + instanceIdResult.getToken());
                firebase_token = instanceIdResult.getToken();
            }
        });
        return firebase_token;
    }

    @Override
    public void onDestroyActionMode(ActionMode mode) {
        presenterInterface.setCurrentSelection(-1); // equals null in the data model
        tokenlistadapter.notifyChange();
        presenterInterface.saveTokenlist();
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
    public Context getContext() {
        return this;
    }

    @Override
    public void makeAlertDialog(String title, String message) {
        AlertDialog.Builder builder = new AlertDialog.Builder(MainActivity.this);
        builder.setTitle(title)
                .setMessage(message)
                .setPositiveButton("OK", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        dialog.cancel();
                    }
                });
        final AlertDialog alert = builder.create();
        MainActivity.changeDialogFontColor(alert);
        alert.show();
    }

    @Override
    public void makeToast(String message) {
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show();
    }
}
