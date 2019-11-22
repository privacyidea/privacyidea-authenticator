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

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;

import static it.netknights.piauthenticator.utils.AppConstants.INTENT_FILTER;
import static it.netknights.piauthenticator.utils.AppConstants.SERIAL;
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
                main.pushAuthFinishedFor(intent.getStringExtra(SERIAL), intent.getIntExtra("finished", 654321),
                        intent.getStringExtra(SIGNATURE), intent.getBooleanExtra("success", false));
            } else if (intent.hasExtra("running")) {
                main.pushAuthStartedFor(intent.getStringExtra(SERIAL), intent.getIntExtra("running", 654321),
                        intent.getStringExtra(SIGNATURE));
            } else {
                logprint("broadcastreceiver received push request");
                main.pushAuthRequestReceived(intent);
            }
        } else {
            logprint("Received Broadcast for MainActivity but the Activity is not present.");
        }
    }
}
