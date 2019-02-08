package it.netknights.piauthenticator;

import android.app.Service;
import android.content.Intent;
import android.os.AsyncTask;
import android.os.IBinder;
import android.support.annotation.Nullable;

import static it.netknights.piauthenticator.Util.logprint;

public class PushAuthService extends Service {
    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        super.onStartCommand(intent, flags, startId);
        logprint("AuthService started");
        String data = intent.getStringExtra(AppConstants.DATA);
        logprint("data: " + data);
        AsyncTask<Void,Integer,Boolean> pushAuth = new PushAuthTask(data);
        pushAuth.execute();
        return Service.START_REDELIVER_INTENT;
    }
}
