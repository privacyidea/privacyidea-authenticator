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

import android.animation.ObjectAnimator;
import android.annotation.SuppressLint;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.DialogInterface;
import android.graphics.Color;
import android.graphics.PorterDuff;
import android.text.InputType;
import android.view.DragEvent;
import android.view.LayoutInflater;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.LinearInterpolator;
import android.widget.BaseAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import java.util.ArrayList;
import java.util.Map;

import static android.view.View.GONE;
import static android.view.View.VISIBLE;
import static it.netknights.piauthenticator.AppConstants.HOTP;
import static it.netknights.piauthenticator.AppConstants.OTP_TEXT_SIZE_DEFAULT;
import static it.netknights.piauthenticator.AppConstants.OTP_TEXT_SIZE_PENDING_AUTH;
import static it.netknights.piauthenticator.AppConstants.PUSH;
import static it.netknights.piauthenticator.AppConstants.QUESTION;
import static it.netknights.piauthenticator.AppConstants.TITLE;
import static it.netknights.piauthenticator.AppConstants.TOTP;
import static it.netknights.piauthenticator.Interfaces.*;
import static it.netknights.piauthenticator.R.color.PIBLUE;
import static it.netknights.piauthenticator.Util.logprint;


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

        ProgressBar progressBar = v.findViewById(R.id.progressBar);
        progressBar.setMax(30 * 100);
        if (token.getType().equals(TOTP)) {
            if (token.getPeriod() == 60) {
                progressBar.setMax(60 * 100);
            }
        }
        progressBar.getProgressDrawable().setColorFilter(
                Color.rgb(0x83, 0xc9, 0x27), android.graphics.PorterDuff.Mode.SRC_IN);
        progressBars.add(position, progressBar);

        Button nextbtn = v.findViewById(R.id.next_button);
        otptext.setTextSize(OTP_TEXT_SIZE_DEFAULT);
        nextbtn.setVisibility(GONE);
        progressBar.setVisibility(GONE);
        otptext.setText(token.getCurrentOTP());
        if(token.getCurrentOTP() == null){
            logprint("current otp empty");
        }
        labeltext.setText(token.getLabel());

        if (token.isWithPIN() && token.getPin().equals("")) {
            //----------------------- Pin not set yet ----------------------
            nextbtn.setVisibility(GONE);
            progressBar.setVisibility(GONE);
            otptext.setText(R.string.tap_to_set_pin);
            v.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    final EditText input = new EditText(v.getContext());
                    input.getBackground().setColorFilter(input.getContext().getResources().getColor(PIBLUE), PorterDuff.Mode.SRC_IN);
                    AlertDialog.Builder builder = new AlertDialog.Builder(v.getContext());
                    builder.setPositiveButton(R.string.button_text_save, new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface dialog, int which) {
                            String text = input.getEditableText().toString();
                            if (text.equals("")) {
                                Toast.makeText(mView.getContext(), R.string.toast_pin_set_isEmpty, Toast.LENGTH_SHORT).show();
                                return;
                            }
                            presenterInterface.setPIN(text, token);
                        }
                    });
                    builder.setNegativeButton(R.string.button_text_cancel, new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface dialog, int which) {
                            dialog.cancel();
                        }
                    });
                    final AlertDialog alert = builder.create();
                    alert.setTitle(R.string.set_new_pin);
                    input.setInputType(InputType.TYPE_CLASS_NUMBER | InputType.TYPE_NUMBER_VARIATION_PASSWORD);
                    alert.setView(input);
                    MainActivity.changeDialogFontColor(alert);
                    alert.show();
                }
            });
        } else if (token.isWithPIN() && token.isLocked()) {
            //------------------- show dialog for PIN input -------------------------------------
            v.setLongClickable(true);
            progressBar.setVisibility(GONE);
            nextbtn.setVisibility(GONE);
            otptext.setText(R.string.tap_to_unlock);
            v.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    AlertDialog.Builder builder = new AlertDialog.Builder(v.getContext());
                    builder.setTitle(R.string.enter_pin_title);
                    final EditText input = new EditText(v.getContext());
                    input.setInputType(InputType.TYPE_CLASS_NUMBER | InputType.TYPE_NUMBER_VARIATION_PASSWORD);
                    input.getBackground().setColorFilter(input.getContext().getResources().getColor(PIBLUE), PorterDuff.Mode.SRC_IN);
                    builder.setView(input);
                    builder.setPositiveButton(R.string.button_text_enter, new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface dialog, int which) {
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
                        }
                    });
                    builder.setNegativeButton(R.string.button_text_cancel, new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface dialog, int which) {
                            dialog.cancel();
                        }
                    });
                    final AlertDialog alert = builder.create();
                    MainActivity.changeDialogFontColor(alert);
                    alert.show();
                }
            });
        } else if (!token.isLocked() && token.isWithTapToShow() && !token.isTapped()) {
            // token untapped
            otptext.setText(R.string.tap_to_show_otp);
            nextbtn.setVisibility(GONE);
            progressBar.setVisibility(GONE);
            v.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    token.setTapped(true);
                    notifyChange();
                }
            });
        }/*else if (!token.isLocked() && token.isWithTapToShow() && token.isTapped()){
        }*/ else {
            //--------------- no PIN protection or token is unlocked ---------------------------
            v.setLongClickable(true);
            v.setOnClickListener(null);
            //------------------ differenciate hotp, totp and push ---------------------------
            switch (token.getType()) {
                case HOTP:
                    progressBar.setVisibility(GONE);
                    nextbtn.setVisibility(VISIBLE);
                    nextbtn.setOnClickListener(new View.OnClickListener() {
                        @Override
                        public void onClick(View v) {
                            presenterInterface.increaseHOTPCounter(token);
                        }
                    });
                    otptext.setText(token.getCurrentOTP());
                    break;
                case TOTP:
                    nextbtn.setVisibility(GONE);
                    nextbtn.setClickable(false);
                    nextbtn.setLongClickable(false);
                    progressBar.setVisibility(VISIBLE);
                    v.setClickable(false);
                    otptext.setText(token.getCurrentOTP());
                    break;
                case PUSH:
                    Map<String, String> map = presenterInterface.getPushAuthRequestInfo(token);
                    if (map != null && token.rollout_finished) {
                        nextbtn.setLongClickable(false);
                        progressBar.setVisibility(GONE);
                        labeltext.setText(map.get(QUESTION));
                        otptext.setTextSize(OTP_TEXT_SIZE_PENDING_AUTH);
                        otptext.setText(map.get(TITLE));
                        nextbtn.setVisibility(VISIBLE);
                        nextbtn.setClickable(true);
                        nextbtn.setText(v.getContext().getString(R.string.Allow));
                        nextbtn.setOnClickListener(new View.OnClickListener() {
                            @Override
                            public void onClick(View view) {
                                presenterInterface.startPushAuthForPosition(position);
                            }
                        });
                    } else if (token.rollout_finished) {
                        nextbtn.setVisibility(GONE);
                        nextbtn.setClickable(false);
                        nextbtn.setLongClickable(false);
                        progressBar.setVisibility(GONE);
                        labeltext.setText(token.getSerial());
                        otptext.setText("[PUSH]");
                    } else {
                        nextbtn.setVisibility(GONE);
                        nextbtn.setClickable(false);
                        nextbtn.setLongClickable(false);
                        progressBar.setVisibility(GONE);
                        labeltext.setText(token.getSerial());
                        otptext.setText("[PUSH]");
                        nextbtn.setVisibility(VISIBLE);
                        nextbtn.setText(v.getContext().getString(R.string.Retry));
                        nextbtn.setOnClickListener(new View.OnClickListener() {
                            @Override
                            public void onClick(View view) {
                                presenterInterface.startPushRolloutForPosition(position);
                            }
                        });
                    }
                    break;
            }
        }
        setupOnDrags(v, position);
        return v;
    }

    private void setupOnDrags(View v, final int position) {
        v.setOnDragListener(new View.OnDragListener() {
            @Override
            public boolean onDrag(View v, DragEvent event) {
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
                        int to = (Integer) (v.getTag());
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
            }
        });

        v.setOnTouchListener(new View.OnTouchListener() {
            @SuppressLint("ClickableViewAccessibility")
            @Override
            public boolean onTouch(View v, MotionEvent arg1) {
                if (presenterInterface.getCurrentSelection()
                        != presenterInterface.getTokenAtPosition(position)) {
                    return false;
                }
                ClipData data = ClipData.newPlainText(v.getTag() + "", "");
                View.DragShadowBuilder shadow = new View.DragShadowBuilder(v);
                v.startDrag(data, shadow, null, 0);
                return false;
            }
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
