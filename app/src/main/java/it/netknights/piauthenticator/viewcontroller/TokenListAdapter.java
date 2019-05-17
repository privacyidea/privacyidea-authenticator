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

import android.animation.ObjectAnimator;
import android.app.AlertDialog;
import android.content.ClipData;
import android.graphics.Color;
import android.graphics.PorterDuff;
import android.text.InputType;
import android.view.DragEvent;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.view.animation.LinearInterpolator;
import android.widget.BaseAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import java.util.ArrayList;
import java.util.Map;

import androidx.core.widget.TextViewCompat;

import it.netknights.piauthenticator.interfaces.PresenterInterface;
import it.netknights.piauthenticator.interfaces.TokenListViewInterface;
import it.netknights.piauthenticator.utils.AppConstants;
import it.netknights.piauthenticator.R;
import it.netknights.piauthenticator.model.Token;

import static android.view.View.GONE;
import static android.view.View.VISIBLE;
import static it.netknights.piauthenticator.utils.AppConstants.HOTP;
import static it.netknights.piauthenticator.utils.AppConstants.PUSH;
import static it.netknights.piauthenticator.utils.AppConstants.QUESTION;
import static it.netknights.piauthenticator.utils.AppConstants.TITLE;
import static it.netknights.piauthenticator.utils.AppConstants.TOTP;
import static it.netknights.piauthenticator.R.color.PIBLUE;


public class TokenListAdapter extends BaseAdapter implements TokenListViewInterface {
    private PresenterInterface presenterInterface;
    private ArrayList<ProgressBar> progressBars;

    void setPresenterInterface(PresenterInterface presenterInterface) {
        this.presenterInterface = presenterInterface;
    }

    TokenListAdapter() {
        this.progressBars = new ArrayList<>();
    }

    @Override
    public View getView(final int position, View v, ViewGroup parent) {
        if (v == null) {
            final LayoutInflater inflater = LayoutInflater.from(parent.getContext());
            v = inflater.inflate(R.layout.entry, parent, false);
        }
        v.setTag(position);

        final View mView = v;
        final TextView otptext = v.findViewById(R.id.textViewToken);
        final TextView labeltext = v.findViewById(R.id.textViewLabel);
        final Token token = getItem(position);

        Button nextbtn = v.findViewById(R.id.next_button);

        ProgressBar progressBar = v.findViewById(R.id.progressBar);
        progressBar.getProgressDrawable().setColorFilter(
                Color.rgb(0x83, 0xc9, 0x27), PorterDuff.Mode.SRC_IN);
        progressBars.add(position, progressBar);

        if (token.getType().equals(TOTP)) {
            if (token.getPeriod() == 60) {
                progressBar.setMax(60 * 100);
            } else {
                progressBar.setMax(30 * 100);
            }
            nextbtn.setVisibility(GONE);
        } else {
            progressBar.setVisibility(GONE);
        }

        otptext.setText(token.getCurrentOTP());
        labeltext.setText(token.getLabel());

        // Make the TextViews autoscale the textsize
        enableAutoSizeText(otptext, labeltext);

        if (token.isWithPIN() && token.getPin().equals("")) {
            //----------------------- Pin not set yet ----------------------
            setupPinNotSet(v, mView, otptext, token, nextbtn, progressBar);
        } else if (token.isWithPIN() && token.isLocked()) {
            //------------------- show dialog for PIN input -------------------------------------
            setupPinRequired(v, mView, otptext, token, nextbtn, progressBar);
        } else if (!token.isLocked() && token.isWithTapToShow() && !token.isTapped()) {
            setupTapRequired(v, otptext, token, nextbtn, progressBar);
        }/*else if (!token.isLocked() && token.isWithTapToShow() && token.isTapped()){
        }*/ else {
            //--------------- no PIN protection or token is unlocked ---------------------------
            v.setLongClickable(true);
            v.setOnClickListener(null);
            //------------------ differenciate hotp, totp and push ---------------------------
            switch (token.getType()) {
                case HOTP:
                    setupHOTP(token, nextbtn, progressBar);
                    break;
                case TOTP:
                    setupTOTP(nextbtn, progressBar);
                    break;
                case PUSH:
                    setupPUSH(position, v, otptext, labeltext, token, nextbtn, progressBar);
                    break;
            }
        }
        setupOnDrags(v, position);
        return v;
    }

    private void setupPUSH(final int position, View v, TextView otptext, TextView labeltext, Token token, Button nextbtn, ProgressBar progressBar) {
        Map<String, String> map = presenterInterface.getPushAuthRequestInfo(token);
        if (map != null && token.rollout_finished) {
            nextbtn.setLongClickable(false);
            progressBar.setVisibility(GONE);
            labeltext.setText(map.get(QUESTION));
            otptext.setText(map.get(TITLE));
            nextbtn.setVisibility(VISIBLE);
            nextbtn.setClickable(true);
            nextbtn.setText(v.getContext().getString(R.string.Allow));
            nextbtn.setOnClickListener(view -> presenterInterface.startPushAuthForPosition(position));
        } else if (token.rollout_finished) {
            nextbtn.setVisibility(GONE);
            nextbtn.setClickable(false);
            nextbtn.setLongClickable(false);
            progressBar.setVisibility(GONE);
            labeltext.setText(v.getContext().getString(R.string.PushtokenLabel));
            otptext.setText(token.getLabel());
        } else {
            nextbtn.setVisibility(GONE);
            nextbtn.setClickable(false);
            nextbtn.setLongClickable(false);
            progressBar.setVisibility(GONE);
            labeltext.setText(v.getContext().getString(R.string.PushtokenLabelRolloutUnfinished));
            otptext.setText(token.getLabel());
            nextbtn.setVisibility(VISIBLE);
            nextbtn.setText("");
            nextbtn.setCompoundDrawablesWithIntrinsicBounds(0, 0, R.drawable.ic_retry_rollout, 0);
            nextbtn.setOnClickListener(view -> presenterInterface.startPushRolloutForPosition(position));
        }
    }

    private void setupTOTP(Button nextbtn, ProgressBar progressBar) {
        nextbtn.setVisibility(GONE);
        progressBar.setVisibility(VISIBLE);
    }

    private void setupHOTP(final Token token, Button nextbtn, ProgressBar progressBar) {
        progressBar.setVisibility(GONE);
        nextbtn.setVisibility(VISIBLE);
        nextbtn.setOnClickListener(v -> presenterInterface.increaseHOTPCounter(token));
    }

    private void setupTapRequired(View v, TextView otptext, final Token token, Button nextbtn, ProgressBar progressBar) {
        otptext.setText(R.string.tap_to_show_otp);
        nextbtn.setVisibility(GONE);
        progressBar.setVisibility(GONE);
        v.setOnClickListener(v1 -> {
            token.setTapped(true);
            notifyChange();
        });
    }

    private void setupPinRequired(View v, final View mView, TextView otptext, final Token token, Button nextbtn, ProgressBar progressBar) {
        v.setLongClickable(true);
        progressBar.setVisibility(GONE);
        nextbtn.setVisibility(GONE);
        otptext.setText(R.string.tap_to_unlock);
        v.setOnClickListener(v1 -> {
            AlertDialog.Builder builder = new AlertDialog.Builder(v1.getContext());
            builder.setTitle(R.string.enter_pin_title);
            final EditText input = new EditText(v1.getContext());
            input.setInputType(InputType.TYPE_CLASS_NUMBER | InputType.TYPE_NUMBER_VARIATION_PASSWORD);
            input.getBackground().setColorFilter(input.getContext().getResources().getColor(PIBLUE), PorterDuff.Mode.SRC_IN);
            builder.setView(input);
            builder.setPositiveButton(R.string.button_text_enter, (dialog, which) -> {
                String text = input.getEditableText().toString();
                if (text.equals("")) {
                    Toast.makeText(mView.getContext(), R.string.toast_empty_pin_input, Toast.LENGTH_SHORT).show();
                    return;
                }
                if (presenterInterface.checkPIN(text, token)) {
                    token.setLocked(false);
                    token.setTapped(true);
                } else {
                    Toast.makeText(mView.getContext(), R.string.toast_pin_not_correct, Toast.LENGTH_SHORT).show();
                }
                notifyChange();
            });
            builder.setNegativeButton(R.string.button_text_cancel, (dialog, which) -> dialog.cancel());
            final AlertDialog alert = builder.create();
            alert.getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_VISIBLE);
            MainActivity.changeDialogFontColor(alert);
            alert.show();
        });
    }

    private void setupPinNotSet(View v, final View mView, TextView otptext, final Token token, Button nextbtn, ProgressBar progressBar) {
        nextbtn.setVisibility(GONE);
        progressBar.setVisibility(GONE);
        otptext.setText(R.string.tap_to_set_pin);
        v.setOnClickListener(v1 -> {
            final EditText input = new EditText(v1.getContext());
            input.getBackground().setColorFilter(input.getContext().getResources().getColor(PIBLUE), PorterDuff.Mode.SRC_IN);
            AlertDialog.Builder builder = new AlertDialog.Builder(v1.getContext());
            builder.setPositiveButton(R.string.button_text_save, (dialog, which) -> {
                String text = input.getEditableText().toString();
                if (text.equals("")) {
                    Toast.makeText(mView.getContext(), R.string.toast_pin_set_isEmpty, Toast.LENGTH_SHORT).show();
                    return;
                }
                presenterInterface.setPIN(text, token);
            });
            builder.setNegativeButton(R.string.button_text_cancel, (dialog, which) -> dialog.cancel());
            final AlertDialog alert = builder.create();
            alert.setTitle(R.string.set_new_pin);
            input.setInputType(InputType.TYPE_CLASS_NUMBER | InputType.TYPE_NUMBER_VARIATION_PASSWORD);
            alert.setView(input);
            alert.getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_VISIBLE);
            MainActivity.changeDialogFontColor(alert);
            alert.show();
        });
    }

    private void enableAutoSizeText(TextView otptext, TextView labeltext) {
       /* if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            otptext.setAutoSizeTextTypeUniformWithConfiguration(12, 36,
                    1, TypedValue.COMPLEX_UNIT_SP);
            labeltext.setAutoSizeTextTypeUniformWithConfiguration(8, 28,
                    1, TypedValue.COMPLEX_UNIT_SP);
        } else {
            TextViewCompat.setAutoSizeTextTypeUniformWithConfiguration(otptext, 12, 36,
                    1, TypedValue.COMPLEX_UNIT_SP);
            TextViewCompat.setAutoSizeTextTypeUniformWithConfiguration(labeltext, 8, 28,
                    1, TypedValue.COMPLEX_UNIT_SP);
        } */

        TextViewCompat.setAutoSizeTextTypeWithDefaults(otptext, TextViewCompat.AUTO_SIZE_TEXT_TYPE_UNIFORM);
        TextViewCompat.setAutoSizeTextTypeWithDefaults(labeltext, TextViewCompat.AUTO_SIZE_TEXT_TYPE_UNIFORM);
    }

    private void setupOnDrags(View v, final int position) {
        v.setOnDragListener((v1, event) -> {
            int action = event.getAction();
            switch (action) {
                case DragEvent.ACTION_DRAG_STARTED:
                    break;

                case DragEvent.ACTION_DRAG_EXITED:
                    break;

                case DragEvent.ACTION_DRAG_ENTERED:
                    break;

                case DragEvent.ACTION_DROP: {
                    int from = Integer.parseInt("" + event.getClipDescription().getLabel());
                    int to = (Integer) (v1.getTag());
                    Token toSwap = presenterInterface.removeTokenAtPosition(from);
                    presenterInterface.addTokenAt(to, toSwap);
                    notifyChange();
                    return true;
                }
                case DragEvent.ACTION_DRAG_ENDED: {
                    notifyChange();
                    return true;
                }
                default:
                    break;
            }
            return true;
        });

        v.setOnTouchListener((v12, arg1) -> {
            if (presenterInterface.getCurrentSelection()
                    != presenterInterface.getTokenAtPosition(position)) {
                return false;
            }
            v12.performClick();
            ClipData data = ClipData.newPlainText(v12.getTag() + "", "");
            View.DragShadowBuilder shadow = new View.DragShadowBuilder(v12);
            v12.startDrag(data, shadow, null, 0);
            return false;
        });
    }

    @Override
    public int getCount() {
        return presenterInterface.getTokenCount();
    }

    @Override
    public Token getItem(int position) {
        return presenterInterface.getTokenAtPosition(position);
    }

    @Override
    public long getItemId(int position) {
        return position;
    }

    @Override
    public boolean isEnabled(int position) {
        return true;
    }

    @Override
    public void updateProgressbars(int progress) {
        for (ProgressBar pb : progressBars) {
            if (pb.getMax() == 30 * 100 && progress >= 30) {
                setProgressAnimate(pb, progress - 30);
            } else {
                setProgressAnimate(pb, progress);
            }
        }
    }

    private void setProgressAnimate(ProgressBar pb, int progressTo) {
        ObjectAnimator animation = ObjectAnimator.ofInt(pb, AppConstants.PROPERTY_PROGRESS, pb.getProgress(), progressTo * 100);
        animation.setDuration(2000);
        animation.setInterpolator(new LinearInterpolator());
        animation.start();
    }

    @Override
    public void notifyChange() {
        notifyDataSetChanged();
    }

    @Override
    public void removeProgressbar(int position) {
        if (progressBars.size() >= position && position >= 0
                && progressBars.isEmpty()) {
            progressBars.remove(position);
        }
    }
}
