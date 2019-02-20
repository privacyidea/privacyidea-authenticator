package it.netknights.piauthenticator;

import android.app.AlertDialog;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.AsyncTask;
import android.view.View;
import android.widget.TextView;

import com.google.android.gms.tasks.OnSuccessListener;
import com.google.firebase.FirebaseApp;
import com.google.firebase.FirebaseOptions;
import com.google.firebase.iid.FirebaseInstanceId;
import com.google.firebase.iid.InstanceIdResult;

import static it.netknights.piauthenticator.AppConstants.FB_TOKEN;
import static it.netknights.piauthenticator.Util.logprint;

public class FirebaseInitTask extends AsyncTask<Void, Integer, Boolean> {

    private String appID, api_key, database_url, storage_bucket, projID, gcmSenderID;
    private ActivityInterface activityInterface;
    private AlertDialog status_dialog;

    /**
     * Initialize the task with the parameters extracted from the google-services.json
     *
     * @param projID     from project_info/project_id
     * @param appID      from client/client_info_mobilesdk_app_id
     * @param api_key    from client/api_key/current_key
     * @param projNumber from project_info/project_number, this is also the GcmSenderID
     */
    FirebaseInitTask(String projID, String appID, String api_key, String projNumber, ActivityInterface activityInterface) {
        this.projID = projID;
        this.appID = appID;
        this.api_key = api_key;
        this.gcmSenderID = projNumber;
        this.database_url = "https://" + projID + ".firebaseio.com";
        this.storage_bucket = projID + ".appspot.com";
        this.activityInterface = activityInterface;
    }

    @Override
    protected void onPreExecute() {
        super.onPreExecute();
        View view_pro_progress = activityInterface.getPresentActivity().getLayoutInflater().inflate(R.layout.pushrollout_loading, null);
        AlertDialog.Builder dialog_builder = new AlertDialog.Builder(activityInterface.getPresentActivity());
        dialog_builder.setView(view_pro_progress);
        dialog_builder.setCancelable(false);
        status_dialog = dialog_builder.show();
        TextView tv_status;

        if (status_dialog == null) {
            logprint("cannot find status dialog");
            return;
        } else {
            tv_status = status_dialog.findViewById(R.id.tv_status);
        }
        if (tv_status == null) {
            logprint("cannot find status text view");
            return;
        }

        tv_status.setText("Initializing Firebase...");
    }

    @Override
    protected Boolean doInBackground(Void... voids) {
        logprint("Initializing Firebase...");

        // Check if Firebase is already initalized
        if (!FirebaseApp.getApps(activityInterface.getPresentActivity()).isEmpty()) {
            logprint("Firebase already initialized for: " + FirebaseApp.getApps(activityInterface.getPresentActivity()).toString());
            return false;
        }

        // INIT FIREBASE
        FirebaseOptions.Builder builder = new FirebaseOptions.Builder()
                .setApplicationId(appID)
                .setApiKey(api_key)
                .setDatabaseUrl(database_url)
                .setStorageBucket(storage_bucket)
                .setProjectId(projID)
                .setGcmSenderId(gcmSenderID);
        FirebaseApp.initializeApp(activityInterface.getPresentActivity(), builder.build());

        logprint("Firebase initialized!");
        logprint("Getting Firebase token...");
        FirebaseInstanceId.getInstance().getInstanceId().addOnSuccessListener(activityInterface.getPresentActivity(), new OnSuccessListener<InstanceIdResult>() {
            @Override
            public void onSuccess(InstanceIdResult instanceIdResult) {
                logprint("Firebase Token: " + instanceIdResult.getToken());
            }
        });
        return true;
    }

    @Override
    protected void onPostExecute(Boolean aBoolean) {
        super.onPostExecute(aBoolean);
        status_dialog.cancel();
    }
}
