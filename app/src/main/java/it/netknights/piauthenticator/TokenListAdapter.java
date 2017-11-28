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
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.DialogInterface;
import android.graphics.PorterDuff;
import android.text.InputType;
import android.util.Log;
import android.view.DragEvent;
import android.view.LayoutInflater;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.LinearInterpolator;
import android.widget.BaseAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import org.apache.commons.codec.binary.Base32;

import java.util.ArrayList;
import java.util.List;

import static android.view.View.GONE;
import static android.view.View.VISIBLE;
import static it.netknights.piauthenticator.OTPGenerator.byteArrayToHexString;
import static it.netknights.piauthenticator.OTPGenerator.hashPIN;
import static it.netknights.piauthenticator.R.color.PIBLUE;
import static it.netknights.piauthenticator.Token.HOTP;
import static it.netknights.piauthenticator.Token.TOTP;
import static it.netknights.piauthenticator.Util.TAG;


public class TokenListAdapter extends BaseAdapter {

    private List<Token> tokens;
    private Token currentSelection;

    //update is called from the timer-thread within the MainActivity
    void updatePBs(int progress) {
        ProgressBar pb;
        for (Token t : tokens) {
            if (t.getPb() != null) {
                if (t.getType().equals(TOTP)) {
                    pb = t.getPb();
                    if (t.getPeriod() == 30 && progress >= 30) {
                        //pb.setProgress(progress - 30);
                        setProgressAnimate(pb, progress - 30);
                    } else {
                        //pb.setProgress(progress);
                        setProgressAnimate(pb, progress);
                    }
                }
            }
        }
    }

    private void setProgressAnimate(ProgressBar pb, int progressTo) {
        ObjectAnimator animation = ObjectAnimator.ofInt(pb, "progress", pb.getProgress(), progressTo * 100);
        animation.setDuration(1000);
        animation.setInterpolator(new LinearInterpolator());
        animation.start();
    }

    void refreshOTPs() {
        for (int i = 0; i < tokens.size(); i++) {
            tokens.get(i).setCurrentOTP(OTPGenerator.generate(tokens.get(i)));
        }
        this.notifyDataSetChanged();
    }

    void refreshAllTOTP() {
        for (int i = 0; i < tokens.size(); i++) {
            if (tokens.get(i).getType().equals(TOTP)) {
                tokens.get(i).setCurrentOTP(OTPGenerator.generate(tokens.get(i)));
            }
        }
        this.notifyDataSetChanged();
    }

    @Override
    public View getView(final int position, View v, ViewGroup parent) {
        if (v == null) {
            final LayoutInflater inflater = LayoutInflater.from(parent.getContext());
            v = inflater.inflate(R.layout.entry, parent, false);
        }
        v.setTag(position);
        final View mView = v;


        final Token token = getItem(position);
        final ProgressBar progressBar;
        if (token.getPb() == null) {
            progressBar = (ProgressBar) v.findViewById(R.id.progressBar);
            token.setPb(progressBar);
        } else {
            progressBar = token.getPb();
        }
        final TextView otptext = (TextView) v.findViewById(R.id.textViewToken);
        final TextView labeltext = (TextView) v.findViewById(R.id.textViewLabel);
        final Button nextbtn = (Button) v.findViewById(R.id.next_button);

        otptext.setText(token.getCurrentOTP());
        //labeltext.setText(new Base32().encodeAsString(token.getSecret()));
        //labeltext.setText(byteArrayToHexString(token.getSecret()));
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
                    builder.setPositiveButton("Save", new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface dialog, int which) {
                            int temp_pin = Integer.parseInt(input.getEditableText().toString());
                            String hashedPIN = hashPIN(temp_pin, token);
                            token.setPin(hashedPIN);
                            notifyDataSetChanged();
                            ArrayList<Token> temp = new ArrayList<>(tokens);
                            Util.saveTokens(mView.getContext(), temp);
                        }
                    });
                    builder.setNegativeButton("Cancel", new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface dialog, int which) {
                            dialog.cancel();
                        }
                    });
                    final AlertDialog alert = builder.create();
                    alert.setTitle("Set new PIN");
                    input.setInputType(InputType.TYPE_CLASS_NUMBER | InputType.TYPE_NUMBER_VARIATION_PASSWORD);
                    alert.setView(input);
                    alert.setOnShowListener(new DialogInterface.OnShowListener() {
                        @Override
                        public void onShow(DialogInterface dialog) {
                            MainActivity.changeDialogFontColor(alert);
                        }
                    });

                    alert.show();
                }
            });
        } else if (token.isWithPIN() && token.isLocked()) {
            //------------------- show dialog for PIN input -------------------------------------
            progressBar.setVisibility(GONE);
            nextbtn.setVisibility(GONE);
            otptext.setText(R.string.tap_to_unlock);
            v.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    AlertDialog.Builder builder = new AlertDialog.Builder(v.getContext());
                    builder.setTitle("Enter PIN");
                    final EditText input = new EditText(v.getContext());
                    input.setInputType(InputType.TYPE_CLASS_NUMBER | InputType.TYPE_NUMBER_VARIATION_PASSWORD);
                    input.getBackground().setColorFilter(input.getContext().getResources().getColor(PIBLUE), PorterDuff.Mode.SRC_IN);
                    builder.setView(input);
                    builder.setPositiveButton("Enter", new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface dialog, int which) {
                            int temp_input = Integer.parseInt(input.getEditableText().toString());
                            String hashedPIN = hashPIN(temp_input, token);
                            if (hashedPIN.equals(token.getPin())) {
                                token.setLocked(false);
                                token.setTapped(true);
                            } else {
                                Toast.makeText(mView.getContext(), "The PIN you have entered is not correct", Toast.LENGTH_SHORT).show();
                            }
                            notifyDataSetChanged();
                        }
                    });
                    builder.setNegativeButton("Cancel", new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface dialog, int which) {
                            dialog.cancel();
                        }
                    });
                    final AlertDialog alert = builder.create();
                    alert.setOnShowListener(new DialogInterface.OnShowListener() {
                        @Override
                        public void onShow(DialogInterface dialog) {
                            MainActivity.changeDialogFontColor(alert);
                        }
                    });
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
                    notifyDataSetChanged();
                }
            });
        }/*else if (!token.isLocked() && token.isWithTapToShow() && token.isTapped()){

        }*/ else {
            //--------------- no PIN protection or token is unlocked ---------------------------
            //------------------ differenciate hotp and totp ---------------------------
           /* v.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    token.setCounter((token.getCounter() + 1));
                    token.setCurrentOTP(OTPGenerator.generate(token));
                    notifyDataSetChanged();
                }
            });*/
            v.setOnClickListener(null);
            if (token.getType().equals(HOTP)) {
                progressBar.setVisibility(GONE);
                v.setLongClickable(true);

                nextbtn.setVisibility(VISIBLE);
                nextbtn.setOnClickListener(new View.OnClickListener() {
                    @Override
                    public void onClick(View v) {
                        token.setCounter((token.getCounter() + 1));
                        token.setCurrentOTP(OTPGenerator.generate(token));
                        notifyDataSetChanged();
                    }
                });

                /*nextbtn.setVisibility(GONE);
                nextbtn.setClickable(false);
                nextbtn.setLongClickable(false);*/

            } else {
                nextbtn.setVisibility(GONE);
                nextbtn.setClickable(false);
                nextbtn.setLongClickable(false);
                //nextbtn.setActivated(false);
                progressBar.setVisibility(VISIBLE);
                v.setClickable(false);
            }
            otptext.setText(token.getCurrentOTP());
        }

        //setupOnDrags(v,position);
        //Log.d(TAG, "getView for pos: "+position+" type:"+token.getType()+" progressbar:"+progressBar.getVisibility()+"  button:"+nextbtn.getVisibility());
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
                        Token toSwap = getTokens().remove(from);
                        getTokens().add(to, toSwap);
                        notifyDataSetChanged();
                        return true;
                    }
                    case DragEvent.ACTION_DRAG_ENDED: {
                        //Log.d(TAG, "action drag finished, last token type " + tokens.get(tokens.size() - 1).getType());
                        notifyDataSetChanged();
                        return true;
                    }
                    default:
                        break;
                }
                return true;
            }
        });

        v.setOnTouchListener(new View.OnTouchListener() {

            @Override
            public boolean onTouch(View v, MotionEvent arg1) {

                if (getCurrentSelection() != getTokens().get(position)) {
                    return false;
                }

                ClipData data = ClipData.newPlainText(v.getTag() + "", "");
                View.DragShadowBuilder shadow = new View.DragShadowBuilder(v);
                v.startDrag(data, shadow, null, 0);
                //Log.d(TAG, "Shadow drag finished, last token type " + tokens.get(tokens.size() - 1).getType());
                return false;
            }
        });

    }

    void setTokens(List<Token> tokens) {
        this.tokens = tokens;
    }

    private List<Token> getTokens() {
        return tokens;
    }

    @Override
    public int getCount() {
        if (getTokens() != null) {
            return getTokens().size();
        } else return 0;
    }

    @Override
    public Token getItem(int position) {
        return getTokens().get(position);
    }

    @Override
    public long getItemId(int position) {
        return position;
    }

    @Override
    public boolean isEnabled(int position) {
        return true;
    }

    Token getCurrentSelection() {
        return currentSelection;
    }

    void setCurrentSelection(Token currentSelection) {
        this.currentSelection = currentSelection;
    }
}
