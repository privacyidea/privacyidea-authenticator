package it.netknights.piauthenticator;

import android.app.AlertDialog;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.TextView;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;

public class AboutListAdapter extends BaseAdapter {

    private List<String> acknowledgements;

    @Override
    public View getView(final int position, View v, ViewGroup parent) {
        if (v == null) {
            final LayoutInflater inflater = LayoutInflater.from(parent.getContext());
            v = inflater.inflate(R.layout.about_row, parent, false);
        }
        final View mView = v;
        final TextView about_title = (TextView) v.findViewById(R.id.about_row_title);
        about_title.setText(acknowledgements.get(position));

        v.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String text;
                if (position == 0) {
                    text = readAcknowledgement(R.raw.apache2license, v);
                } else if (position == 1) {
                    text = readAcknowledgement(R.raw.otpauthenticator, v);
                } else if (position == 2) {
                    text = readAcknowledgement(R.raw.zxingandroidembedded, v);
                } else if (position == 3) {
                    text = readAcknowledgement(R.raw.androidcodesamples, v);
                } else {
                    return;
                }
                AlertDialog.Builder alert = new AlertDialog.Builder(v.getContext());
                alert.setMessage(text);
                alert.show();
            }
        });
        return v;
    }

    private String readAcknowledgement(int id, View v) {
        InputStream raw = v.getResources().openRawResource(id);

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        int i;
        try {
            i = raw.read();
            while (i != -1) {
                byteArrayOutputStream.write(i);
                i = raw.read();
            }
            raw.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return byteArrayOutputStream.toString();
    }

    public void setAcknowledgements(List<String> acknowledgements) {
        this.acknowledgements = acknowledgements;
    }

    public List<String> getAcknowledgements() {
        return acknowledgements;
    }

    @Override
    public int getCount() {
        if (getAcknowledgements() != null)
            return getAcknowledgements().size();
        return 0;
    }

    @Override
    public String getItem(int position) {
        return getAcknowledgements().get(position);
    }

    @Override
    public long getItemId(int position) {
        return position;
    }


}
