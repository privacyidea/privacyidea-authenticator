package it.netknights.piauthenticator.viewcontroller;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;

import static it.netknights.piauthenticator.utils.AppConstants.INTENT_FILTER;
import static it.netknights.piauthenticator.utils.AppConstants.SIGNATURE;
import static it.netknights.piauthenticator.utils.Util.logprint;

public class MainActivityBroadcastReceiver extends BroadcastReceiver {
    private MainActivity main;
    public IntentFilter intentFilter = new IntentFilter(INTENT_FILTER);

    public MainActivityBroadcastReceiver(MainActivity main) {
        this.main = main;
    }

    @Override
    public void onReceive(Context context, Intent intent) {
        if (main != null) {
            if (intent.hasExtra("finished")) {
                main.pushAuthFinishedFor(intent.getIntExtra("finished", 654321),
                        intent.getStringExtra(SIGNATURE));
            } else {
                main.pushAuthRequestReceived(intent);
            }
        } else {
            logprint("Received Broadcast for MainActivity but the Activity is not present.");
        }
    }
}
