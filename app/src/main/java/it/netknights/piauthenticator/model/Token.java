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


import java.util.Date;

import static it.netknights.piauthenticator.utils.AppConstants.PUSH;
import static it.netknights.piauthenticator.utils.AppConstants.TOTP;

public class Token {

    private String currentOTP;
    private byte[] secret;
    private String label;
    private String type;
    private int digits;
    private int period;
    private String algorithm = "HmacSHA1"; //default is SHA1
    private int counter;
    private boolean withPIN = false;
    private boolean isLocked = false;
    private String Pin = "";
    private boolean withTapToShow = false;
    private boolean tapped = false;
    private boolean persistent = false;
    private String serial;

    public String enrollment_credential;
    public boolean rollout_finished = true;
    public Date rollout_expiration;
    public String rollout_url;
    public boolean sslVerify = true;

    public Token(byte[] secret, String serial, String label, String type, int digits) {
        this.secret = secret;
        this.serial = serial;
        this.label = label;
        this.type = type;
        this.digits = digits;
        this.period = this.type.equals(TOTP) ? 30 : 0;
        this.counter = 0;
    }

    // A push token only contains the serial and a label
    public Token(String serial, String label) {
        type = PUSH;
        this.serial = serial;
        this.label = label;
    }

    public String getSerial() {
        return serial;
    }

    public void setTapped(boolean tapped) {
        this.tapped = tapped;
    }

    public boolean isTapped() {
        return tapped;
    }

    public boolean isWithTapToShow() {
        return withTapToShow;
    }

    public void setWithTapToShow(boolean withTapToShow) {
        this.withTapToShow = withTapToShow;
    }

    public String getPin() {
        return Pin;
    }

    public void setPin(String pin) {
        Pin = pin;
    }

    public boolean isLocked() {
        return isLocked;
    }

    public void setLocked(boolean locked) {
        isLocked = locked;
    }

    public void setWithPIN(boolean withPIN) {
        if (withPIN) {
            this.isLocked = true;
        } else {
            this.isLocked = false;
        }
        this.withPIN = withPIN;
    }

    public boolean isWithPIN() {
        return withPIN;
    }

    public void setPeriod(int period) {
        this.period = period;
    }

    public int getCounter() {
        return counter;
    }

    public void setCounter(int counter) {
        this.counter = counter;
    }

    public void setSecret(byte[] secret) {
        this.secret = secret;
    }

    public byte[] getSecret() {
        return secret;
    }

    public void setLabel(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }

    public String getType() {
        return type;
    }

    public void setAlgorithm(String algorithm) {
        // In the KeyURI the parameter is sha1/sha256/sha512, whereas the Mac instance is HmacSHA1 etc.
        if (algorithm.startsWith("sha") || algorithm.startsWith("SHA")) {
            this.algorithm = "Hmac" + algorithm.toUpperCase();
        } else if (algorithm.startsWith("Hmac")) {
            this.algorithm = algorithm;
        }
    }

    public int getDigits() {
        return digits;
    }

    public int getPeriod() {
        return period;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public String getCurrentOTP() {
        return currentOTP;
    }

    public void setCurrentOTP(String currentOTP) {
        this.currentOTP = currentOTP;
    }

    public boolean isPersistent() {
        return persistent;
    }

    public void setPersistent(boolean val) {
        persistent = val;
    }
}

