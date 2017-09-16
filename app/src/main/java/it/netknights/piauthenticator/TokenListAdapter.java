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

import android.graphics.Color;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.Button;
import android.widget.ProgressBar;
import android.widget.TextView;

import java.util.List;

import static android.view.View.GONE;
import static android.view.View.VISIBLE;
import static it.netknights.piauthenticator.Token.HOTP;
import static it.netknights.piauthenticator.Token.TOTP;


public class TokenListAdapter extends BaseAdapter {

    private List<Token> tokens;

    //update is called from the timer-thread within the MainActivity
    public void updatePBs(int progress) {
        ProgressBar pb;
        for (Token t : tokens) {
            if (t.getPb() != null) {
                if (t.getType().equals(TOTP)) {
                    pb = t.getPb();
                    if (t.getPeriod() == 30 && progress >= 30) {
                        pb.setProgress(progress - 30);
                    } else {
                        pb.setProgress(progress);
                    }
                }
            }
        }
    }

    public void refreshOTPs() {
        for (int i = 0; i < tokens.size(); i++) {
            tokens.get(i).setCurrentOTP(OTPGenerator.generate(tokens.get(i)));
        }
        this.notifyDataSetChanged();
    }

    public void refreshAllTOTP() {
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
            v = inflater.inflate(R.layout.entry2, parent, false);
        }
        v.setTag(position);

        final ProgressBar progressBar = (ProgressBar) v.findViewById(R.id.progressBar);
        final Token token = getItem(position);
        final TextView tmp2 = (TextView) v.findViewById(R.id.textViewToken);
        final TextView tmp1 = (TextView) v.findViewById(R.id.textViewLabel);
        final Button nextbtn = (Button) v.findViewById(R.id.next_button);

        //------------------ differenciate hotp and totp ---------------------------
        if (token.getType().equals(HOTP)) {
            progressBar.setVisibility(GONE);
            nextbtn.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    token.setCounter((token.getCounter() + 1));
                    token.setCurrentOTP(OTPGenerator.generate(token));
                    notifyDataSetChanged();
                }
            });

        } else {
            nextbtn.setVisibility(GONE);
            nextbtn.setClickable(false);
            nextbtn.setLongClickable(false);
            //nextbtn.setActivated(false);
            progressBar.setVisibility(VISIBLE);
            v.setClickable(false);
        }

        progressBar.setTag(position);
        progressBar.setMax(token.getPeriod());
        progressBar.getProgressDrawable().setColorFilter(
                Color.rgb(0x83, 0xc9, 0x27), android.graphics.PorterDuff.Mode.SRC_IN);

        token.setPb(progressBar);

        tmp1.setText(token.getLabel());
        tmp2.setText(token.getCurrentOTP());

        //------------- switch list entries with drag -----------
        // TODO: not working!!!
        /*v.setOnDragListener(new View.OnDragListener() {
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
                        return true;
                    }
                    default:
                        break;
                }
                return true;
            }
        });*/

        /*v.setOnTouchListener(new View.OnTouchListener() {

            @Override
            public boolean onTouch(View v, MotionEvent arg1) {

                if (getCurrentSelection() != getTokens().get(position)) {
                    return false;
                }

                ClipData data = ClipData.newPlainText(v.getTag() + "", "");
                View.DragShadowBuilder shadow = new View.DragShadowBuilder(v);
                v.startDrag(data, shadow, null, 0);

                return false;
            }
        });*/
        return v;
    }

    public void setTokens(List<Token> tokens) {
        this.tokens = tokens;
    }

    public List<Token> getTokens() {
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

}
