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
import android.widget.ImageView;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import java.util.ArrayList;

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
import static it.netknights.piauthenticator.utils.AppConstants.State.*;
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
        final Token token = getItem(position);

        if (v == null) {
            // New list entry is generated
            final LayoutInflater inflater = LayoutInflater.from(parent.getContext());
            if (token.getType().equals(PUSH)) {
                v = inflater.inflate(R.layout.entry_push, parent, false);
            } else {
                v = inflater.inflate(R.layout.entry_normal, parent, false);
            }
        } else {
            // If view is recycled, check if it is the correct layout for the token (in case of changing positions)
            if ((v.findViewById(R.id.textView_pushStatus) == null) && token.getType().equals(PUSH)) {
                // wrong layout
                v = LayoutInflater.from(parent.getContext()).inflate(R.layout.entry_push, parent, false);
            } else if ((v.findViewById(R.id.textView_pushStatus) != null) && !token.getType().equals(PUSH)) {
                v = LayoutInflater.from(parent.getContext()).inflate(R.layout.entry_normal, parent, false);
            }
        }

        v.setTag(position);
        // COMMON VIEWS
        final View mView = v;
        final TextView otptext = v.findViewById(R.id.textViewToken);
        final TextView labeltext = v.findViewById(R.id.textViewLabel);
        final Button nextbtn = v.findViewById(R.id.next_button);

        // Progressbar for Normal or Push
        ProgressBar progressBar;
        if (token.getType().equals(PUSH)) {
            progressBar = v.findViewById(R.id.progressBar_push);
            if (progressBar != null) {
                progressBar.setIndeterminate(true);
                progressBar.getIndeterminateDrawable().setColorFilter(
                        Color.rgb(0x83, 0xc9, 0x27), PorterDuff.Mode.SRC_IN);
            }
        } else {
            progressBar = v.findViewById(R.id.progressBar);
            if (progressBar != null) {
                progressBar.getProgressDrawable().setColorFilter(
                        Color.rgb(0x83, 0xc9, 0x27), PorterDuff.Mode.SRC_IN);
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
            }
        }

        progressBars.add(position, progressBar);

        // Make the TextViews autoscale the textsize
        enableAutoSizeText(otptext);
        enableAutoSizeText(labeltext);
        // Normal token row setup
        if (!token.getType().equals(PUSH)) {
            if (token.isWithPIN() && token.getPin().equals("")) {
                //----------------------- Pin not set yet ----------------------
                setupPinNotSet(mView, otptext, token, nextbtn, progressBar);
            } else if (token.isWithPIN() && token.isLocked()) {
                //------------------- show dialog for PIN input -------------------------------------
                setupPinRequired(mView, otptext, token, nextbtn, progressBar);
            } else if (!token.isLocked() && token.isWithTapToShow() && !token.isTapped()) {
                setupTapRequired(v, otptext, token, nextbtn, progressBar);
            }/*else if (!token.isLocked() && token.isWithTapToShow() && token.isTapped()){
        }*/ else {
                //--------------- no PIN protection or token is unlocked ---------------------------
                v.setLongClickable(true);
                v.setOnClickListener(null);
                switch (token.getType()) {
                    case HOTP:
                        setupHOTP(token, nextbtn, progressBar);
                        break;
                    case TOTP:
                        setupTOTP(nextbtn, progressBar);
                        break;
                }
                otptext.setText(token.getCurrentOTP());
                labeltext.setText(token.getLabel());
            }
        } else {
            // PUSH SETUP
            TextView pushStatus = mView.findViewById(R.id.textView_pushStatus);
            ImageView cancelImage = mView.findViewById(R.id.imageView_cancel);
            enableAutoSizeText(pushStatus);
            setupPUSH(position, v, otptext, labeltext, token, nextbtn, progressBar, pushStatus, cancelImage);
        }

        setupOnDrags(v, position); // Position change
        return v;
    }

    private void setupPUSH(final int position, View v, TextView bigText, TextView smallText, Token token, Button nextbtn, ProgressBar progressBar, TextView subTextStatus, ImageView cancelImage) {
        v.setClickable(false);
        v.setOnClickListener(null);
        v.setLongClickable(true);
        // big and small Text are visible by default, bigText = Label
        bigText.setVisibility(VISIBLE);
        smallText.setVisibility(VISIBLE);
        bigText.setText(token.getLabel());

        // By default all additional elements are GONE
        subTextStatus.setVisibility(GONE);
        subTextStatus.setTextAlignment(View.TEXT_ALIGNMENT_CENTER);
        progressBar.setVisibility(GONE);
        nextbtn.setVisibility(GONE);
        cancelImage.setVisibility(GONE);

        if (!token.getPendingAuths().isEmpty() && (token.state.equals(FINISHED))) {
            // If there is a pending Authentication, set the question as label and title as otp
            // Only the first pending Authentication is displayed.
            smallText.setText(token.getPendingAuths().get(0).getTitle());
            subTextStatus.setVisibility(VISIBLE);
            subTextStatus.setText(token.getPendingAuths().get(0).getQuestion());

            nextbtn.setVisibility(VISIBLE);
            nextbtn.setClickable(true);
            nextbtn.setText(v.getContext().getString(R.string.Allow));
            nextbtn.setOnClickListener(__ -> presenterInterface.startPushAuthentication(token));
        } else if (!token.getPendingAuths().isEmpty() && (token.state.equals(AUTHENTICATING))) {
            smallText.setText(token.getPendingAuths().get(0).getTitle());
            subTextStatus.setVisibility(VISIBLE);
            subTextStatus.setText(v.getContext().getString(R.string.PushtokenAuthenticating));

            cancelImage.setVisibility(VISIBLE);
            cancelImage.setClickable(true);
            cancelImage.setOnClickListener(__ -> presenterInterface.cancelAuthentication(token));

            progressBar.setVisibility(VISIBLE);
        } else if (token.state.equals(FINISHED)) {
            // Normal push token appearance
            smallText.setText(v.getContext().getString(R.string.PushtokenLabel));
        } else {
            // Rollout state
            if (token.state.equals(UNFINISHED)) {
                // Retry state
                nextbtn.setVisibility(VISIBLE);
                nextbtn.setText("");
                nextbtn.setCompoundDrawablesWithIntrinsicBounds(0, 0, R.drawable.ic_retry_rollout, 0);
                nextbtn.setOnClickListener(__ -> presenterInterface.startPushRolloutForPosition(position));
                nextbtn.setLongClickable(false);
                subTextStatus.setVisibility(VISIBLE);
                subTextStatus.setText(v.getContext().getString(R.string.PushtokenRetryLabel));
                subTextStatus.setTextAlignment(View.TEXT_ALIGNMENT_VIEW_END);

                smallText.setText(v.getContext().getString(R.string.PushtokenLabelRolloutUnfinished));
            } else {
                // Rollout in progress
                smallText.setVisibility(GONE);

                progressBar.setVisibility(VISIBLE);
                // TODO ROLLOUT CANCELLABLE?
                subTextStatus.setVisibility(VISIBLE);
                subTextStatus.setText(R.string.PushtokenRollingOut);
            }
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

    private void setupPinRequired(final View mView, TextView otptext, final Token token, Button nextbtn, ProgressBar progressBar) {
        mView.setLongClickable(true);
        progressBar.setVisibility(GONE);
        nextbtn.setVisibility(GONE);
        otptext.setText(R.string.tap_to_unlock);
        mView.setOnClickListener(v1 -> {
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

    private void setupPinNotSet(final View mView, TextView otptext, final Token token, Button nextbtn, ProgressBar progressBar) {
        nextbtn.setVisibility(GONE);
        progressBar.setVisibility(GONE);
        otptext.setText(R.string.tap_to_set_pin);
        mView.setOnClickListener(v1 -> {
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

    private void enableAutoSizeText(TextView tv) {
        TextViewCompat.setAutoSizeTextTypeWithDefaults(tv, TextViewCompat.AUTO_SIZE_TEXT_TYPE_UNIFORM);
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
