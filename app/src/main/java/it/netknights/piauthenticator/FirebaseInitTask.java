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

package it.netknights.piauthenticator;

import android.os.AsyncTask;

import com.google.firebase.FirebaseApp;
import com.google.firebase.FirebaseOptions;

import it.netknights.piauthenticator.Interfaces.PresenterTaskInterface;

import static it.netknights.piauthenticator.AppConstants.STATUS_INIT_FIREBASE;
import static it.netknights.piauthenticator.AppConstants.STATUS_INIT_FIREBASE_DONE;
import static it.netknights.piauthenticator.Util.logprint;

public class FirebaseInitTask extends AsyncTask<Void, Integer, Boolean> {

    private String appID, api_key, database_url, storage_bucket, projID, gcmSenderID;
    private PresenterTaskInterface presenterTaskInterface;

    /**
     * Initialize the task with the parameters extracted from the google-services.json
     *
     * @param firebaseInitConfig     config info
     * @param presenterTaskInterface for callbacks
     */
    FirebaseInitTask(FirebaseInitConfig firebaseInitConfig, PresenterTaskInterface presenterTaskInterface) {
        this.projID = firebaseInitConfig.projID;
        this.appID = firebaseInitConfig.appID;
        this.api_key = firebaseInitConfig.api_key;
        this.gcmSenderID = firebaseInitConfig.projNumber;
        this.database_url = "https://" + projID + ".firebaseio.com";
        this.storage_bucket = projID + ".appspot.com";
        this.presenterTaskInterface = presenterTaskInterface;
    }

    @Override
    protected void onPreExecute() {
        super.onPreExecute();
        presenterTaskInterface.updateTaskStatus(STATUS_INIT_FIREBASE, null);
    }

    @Override
    protected Boolean doInBackground(Void... voids) {
        logprint("Initializing Firebase...");

        // Check if Firebase is already initalized
        if (!FirebaseApp.getApps(presenterTaskInterface.getContext()).isEmpty()) {
            logprint("Firebase already initialized for: " + FirebaseApp.getApps(presenterTaskInterface.getContext()).toString());
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
        FirebaseApp.initializeApp(presenterTaskInterface.getContext(), builder.build());

        logprint("Firebase initialized!");

        return true;
    }

    @Override
    protected void onPostExecute(Boolean aBoolean) {
        super.onPostExecute(aBoolean);
        presenterTaskInterface.updateTaskStatus(STATUS_INIT_FIREBASE_DONE, null);
    }
}

class FirebaseInitConfig {
    String projID;
    String appID;
    String api_key;
    String projNumber;

    FirebaseInitConfig(String projID, String appID, String api_key, String projNumber) {
        this.projID = projID;
        this.appID = appID;
        this.api_key = api_key;
        this.projNumber = projNumber;
    }

}
