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
import android.content.Context;
import android.content.Intent;
import android.graphics.drawable.ColorDrawable;
import android.os.Build;
import android.os.Bundle;

import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.appcompat.app.ActionBar;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;

import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.Spinner;
import android.widget.TableLayout;
import android.widget.TextView;
import android.widget.Toast;

import org.apache.commons.codec.binary.Base32;

import it.netknights.piauthenticator.R;

import static android.view.View.GONE;
import static it.netknights.piauthenticator.utils.AppConstants.*;
import static it.netknights.piauthenticator.R.color.PIBLUE;

public class EnterDetailsActivity extends AppCompatActivity {

    private Spinner spinner_digits;
    private Spinner spinner_algorithm;
    private Spinner spinner_period;
    private Spinner spinner_type;
    private TextView periodLabel;

    private String new_label;
    private byte[] new_secret;
    private String new_algorithm;
    private String new_type;
    private int new_period;
    private int new_digits;
    private boolean new_withpin = false;
    private RadioButton currentSelectedEncoding = null;
    TableLayout tl;


    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_enter_detail);
        setupButtons();
        paintStatusbar();
        setupActionBar();
        setupTable();
    }

    private void setupTable() {
        tl = findViewById(R.id.tableLayout);

        final int supportspinnerid = R.layout.support_simple_spinner_dropdown_item;

        String[] types = {"HOTP", "TOTP"};
        String[] periods = {PERIOD_30_STR, PERIOD_60_STR};
        String[] algorithms = {SHA1, SHA256, SHA512};
        String[] digits = {DIGITS_6_STR, DIGITS_8_STR};

        for (int i = 0; i < 4; i++) {
            ConstraintLayout tablerow = (ConstraintLayout) getLayoutInflater().inflate(R.layout.tablelayout, null);
            TextView tv = tablerow.findViewById(R.id.label);
            tv.setTextSize(18);
            Spinner spinner = tablerow.findViewById(R.id.spinner_row);
            switch (i) {
                case 2: {
                    spinner_type = spinner;
                    tv.setText(R.string.type);
                    ArrayAdapter<String> adapter_type = new ArrayAdapter<>(this, supportspinnerid, types);
                    spinner_type.setAdapter(adapter_type);
                    spinner_type.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
                        @Override
                        public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                            if (position == 0) {
                                periodLabel.setVisibility(View.INVISIBLE);
                                spinner_period.setVisibility(View.INVISIBLE);
                            } else {
                                periodLabel.setVisibility(View.VISIBLE);
                                spinner_period.setVisibility(View.VISIBLE);
                            }
                        }

                        @Override
                        public void onNothingSelected(AdapterView<?> parent) {

                        }
                    });
                    tl.addView(tablerow);
                    break;
                }
                case 3: {
                    periodLabel = tv;
                    periodLabel.setText(R.string.period);
                    spinner_period = spinner;
                    ArrayAdapter<String> adapter_period = new ArrayAdapter<>(this, supportspinnerid, periods);
                    spinner_period.setAdapter(adapter_period);
                    tl.addView(tablerow);
                    break;
                }
                case 1: {
                    tv.setText(R.string.algorithm);
                    spinner_algorithm = spinner;
                    ArrayAdapter<String> adapter_algorithm = new ArrayAdapter<>(this, supportspinnerid, algorithms);
                    spinner_algorithm.setAdapter(adapter_algorithm);
                    tl.addView(tablerow);
                    break;
                }
                case 0: {
                    tv.setText(R.string.digits);
                    spinner_digits = spinner;
                    ArrayAdapter<String> adapter_digits = new ArrayAdapter<>(this, supportspinnerid, digits);
                    spinner_digits.setAdapter(adapter_digits);
                    tl.addView(tablerow);
                    break;
                }
                default:
                    break;
            }
        }
    }

    private void setupActionBar() {
        ActionBar actionBar = getSupportActionBar();
        if (actionBar != null) {
            // Show the Back button in the action bar.
            actionBar.setDisplayHomeAsUpEnabled(true);
            actionBar.setBackgroundDrawable(new ColorDrawable(getResources().getColor(PIBLUE)));
        }
    }

    public void paintStatusbar() {
        Toolbar toolbar = findViewById(R.id.toolbar3);
        toolbar.setVisibility(GONE);
        setTitle(getString(R.string.title_enter_details));
        //------------------ try to paint the statusbar -------------------------------
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            Window window = getWindow();
            window.addFlags(WindowManager.LayoutParams.FLAG_DRAWS_SYSTEM_BAR_BACKGROUNDS);
            window.clearFlags(WindowManager.LayoutParams.FLAG_TRANSLUCENT_STATUS);
            window.setStatusBarColor(getResources().getColor(PIBLUE));
        }

    }

    public void onRadioButtonClicked(View view) {
        boolean checked = ((RadioButton) view).isChecked();

        // if a button is clicked twice no encoding is selected
        if (view.equals(currentSelectedEncoding)) {
            ((RadioGroup) view.getParent()).clearCheck();
            currentSelectedEncoding = null;
            return;
        }

        switch (view.getId()) {
            case R.id.radio_base32:
                if (checked) {
                currentSelectedEncoding = (RadioButton) view;
                }

            case R.id.radio_hex:
                if (checked) {
                currentSelectedEncoding = (RadioButton) view;
                }
        }
    }

    private void setupButtons() {
        Button addBtn = findViewById(R.id.button_add);
        addBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (evaluate()) {
                    buildResult();
                    finish();
                }
            }
        });
    }

    private boolean evaluate() {
//        EditText editText_name = findViewById(R.id.editText_name);
//        EditText editText_secret = findViewById(R.id.editText_secret);
//        CheckBox check_base32 = findViewById(R.id.checkBox_base32);
//        CheckBox check_pin = findViewById(R.id.checkBox_pin);
//
//        if (check_pin.isChecked()) {
//            new_withpin = true;
//        }
//
//        new_label = editText_name.getText().toString();
//        if (new_label.equals("")) {
//            Toast.makeText(this, R.string.toast_name_cantbe_empty, Toast.LENGTH_LONG).show();
//            editText_name.requestFocus();
//            return false;
//        }
//        String new_secret_string = editText_secret.getText().toString();
//
//        if (new_secret_string.equals("")) {
//            Toast.makeText(this, R.string.toast_secret_cantbe_empty, Toast.LENGTH_LONG).show();
//            editText_secret.requestFocus();
//            return false;
//        }
//        if (check_base32.isChecked()) {
//            if (new Base32().isInAlphabet(new_secret_string)) {
//                new_secret = new Base32().decode(new_secret_string);
//            } else {
//                Toast.makeText(this, R.string.toast_secret_nob32format, Toast.LENGTH_LONG).show();
//                editText_secret.requestFocus();
//                return false;
//            }
//
//            // TODO create a check for the case that the secret is encoded as hex
//
//        } else {
//            new_secret = new_secret_string.getBytes();
//        }
//
//        new_type = (String) spinner_type.getSelectedItem();
//        new_type = new_type.toLowerCase();
//        if (new_type.equals(TOTP)) {
//            String tmp_string = (String) spinner_period.getSelectedItem();
//            if (tmp_string.equals(PERIOD_30_STR)) {
//                new_period = PERIOD_30;
//            } else new_period = PERIOD_60;
//        }
//
//        String tmp_digits = (String) spinner_digits.getSelectedItem();
//        new_digits = Integer.parseInt(tmp_digits);
//        new_algorithm = (String) spinner_algorithm.getSelectedItem();
        return true;
    }

    private void buildResult() {
        Intent returnIntent = new Intent();
        returnIntent.putExtra(LABEL, new_label);
        returnIntent.putExtra(SECRET, new_secret);
        returnIntent.putExtra(TYPE, new_type);
        returnIntent.putExtra(DIGITS, new_digits);
        if (new_type.equals(TOTP)) {
            returnIntent.putExtra(PERIOD, new_period);
        }
        if (!new_algorithm.equals(SHA1)) {
            // the default is SHA1, so it does not need to be set explicitly
            returnIntent.putExtra(ALGORITHM, new_algorithm);
        }
        if (new_withpin) {
            returnIntent.putExtra(WITHPIN, true);
        }
        setResult(Activity.RESULT_OK, returnIntent);
    }

    public static Intent makeIntent(Context context) {
        return new Intent(context, EnterDetailsActivity.class);
    }
}

