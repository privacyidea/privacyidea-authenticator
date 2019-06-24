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

package it.netknights.piauthenticator.model;

public class ScanResult {
    // BASE
   public String type, serial, label;

    // NORMAL TOKEN
    public String secret, algorithm = "sha1";              // Default
    public int digits = 6, period = 30, counter = 1;       // Defaults
    public boolean pin = false, persistent = false, taptoshow = false;

    // TWO STEP TOKEN (addition)
    public boolean do2Step = false;
    public int phonepartlength = 10;                       // in bytes
    public int iterations = 10000;
    public int output_size = 160;                          // in bits

    // PUSH TOKEN
    public String rollout_url, enrollment_credential;
    public int ttl = 10;                                   // 10 Minutes is the default
    public FirebaseInitConfig firebaseInitConfig;
    public int push_version = 1;
    public boolean sslverify = true;

    public ScanResult(String type, String serial) {
        this.type = type;
        this.serial = serial;
    }
}