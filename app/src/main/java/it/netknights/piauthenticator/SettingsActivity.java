package it.netknights.piauthenticator;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.support.annotation.Nullable;
import android.support.v7.app.AppCompatActivity;
import android.text.InputType;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.TextView;

import org.apache.commons.codec.binary.Base32;

import java.nio.charset.StandardCharsets;

public class SettingsActivity extends AppCompatActivity {

    private TextView periodLabel;
    private Spinner spinner_digits;
    private Spinner spinner_algorithm;
    private Spinner spinner_period;
    private Spinner spinner_type;
    private EditText editText_secret;
    private EditText editText_name;
    private CheckBox check_base32;
    private String new_label;
    private String new_secret;
    private int new_period;
    private int new_digits;
    private String new_algorithm;
    private String new_type;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.add_token);
        setupSpinners();
        setupButtons();
    }

    private void setupSpinners() {
        spinner_type = (Spinner) findViewById(R.id.spinner_type);
        spinner_period = (Spinner) findViewById(R.id.spinner_period);
        spinner_algorithm = (Spinner) findViewById(R.id.spinner_algorithm);
        spinner_digits = (Spinner) findViewById(R.id.spinner_digits);
        periodLabel = (TextView) findViewById(R.id.textView_period);

        final int supportspinnerid = R.layout.support_simple_spinner_dropdown_item;

        String[] types = {"TOTP", "HOTP"};
        String[] periods = {"30s", "60s"};
        String[] algorithms = {"SHA1", "SHA256", "SHA512"};
        String[] digits = {"6", "8"};


        ArrayAdapter<String> adapter_type = new ArrayAdapter<>(this, supportspinnerid, types);
        spinner_type.setAdapter(adapter_type);
        ArrayAdapter<String> adapter_period = new ArrayAdapter<>(this, supportspinnerid, periods);
        spinner_period.setAdapter(adapter_period);
        ArrayAdapter<String> adapter_algorithm = new ArrayAdapter<>(this, supportspinnerid, algorithms);
        spinner_algorithm.setAdapter(adapter_algorithm);
        ArrayAdapter<String> adapter_digits = new ArrayAdapter<>(this, supportspinnerid, digits);
        spinner_digits.setAdapter(adapter_digits);

        spinner_type.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                if (position == 1) {
                    periodLabel.setVisibility(View.GONE);
                    spinner_period.setVisibility(View.GONE);
                } else {
                    periodLabel.setVisibility(View.VISIBLE);
                    spinner_period.setVisibility(View.VISIBLE);
                }
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {

            }
        });
    }

    private void setupButtons() {
        Button addBtn = (Button) findViewById(R.id.button_addToken);
        addBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                evaluate();
                buildResult();
                finish();
            }
        });
        Button backBtn = (Button) findViewById(R.id.button_back);
        backBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                finish();
            }
        });
    }

    private void buildResult() {
        Intent returnIntent = new Intent();
        returnIntent.putExtra("label", new_label);
        returnIntent.putExtra("secret", new_secret);
        returnIntent.putExtra("type", new_type);
        returnIntent.putExtra("digits", new_digits);
        if (new_type.equals("totp")) {
            returnIntent.putExtra("period", new_period);
        }
        if (!new_algorithm.equals("SHA1")) { // the default is SHA1, so it does not need to be set explicitly
            returnIntent.putExtra("algorithm", new_algorithm);
        }
        setResult(Activity.RESULT_OK, returnIntent);
    }

    private void evaluate() {
        editText_name = (EditText) findViewById(R.id.editText_name);
        editText_secret = (EditText) findViewById(R.id.editText_secret);
        check_base32 = (CheckBox) findViewById(R.id.checkBox_base32);

        new_label = editText_name.getText().toString();
        if (check_base32.isChecked()) { // the secret should be base32 encoded
            new_secret = editText_secret.getText().toString();
        } else {
            byte[] tmp = editText_secret.getText().toString().getBytes();
            new_secret = new Base32().encode(tmp).toString();
        }
        new_type = (String) spinner_type.getSelectedItem();
        new_type = new_type.toLowerCase();
        if (new_type.equals("totp")) {
            String tmp_string = (String) spinner_period.getSelectedItem();
            if (tmp_string.equals("30s")) {
                new_period = 30;
            } else new_period = 60;
        }

        String tmp_digits = (String) spinner_digits.getSelectedItem();
        new_digits = Integer.parseInt(tmp_digits);
        new_algorithm = (String) spinner_algorithm.getSelectedItem();
    }

    public static Intent makeIntent(Context context) {
        return new Intent(context, SettingsActivity.class);
    }
}

