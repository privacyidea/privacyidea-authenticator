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

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import static it.netknights.piauthenticator.AppConstants.CONNECT_TIMEOUT;
import static it.netknights.piauthenticator.AppConstants.READ_TIMEOUT;
import static it.netknights.piauthenticator.AppConstants.STATUS_ENDPOINT_ERROR;
import static it.netknights.piauthenticator.AppConstants.STATUS_ENDPOINT_MALFORMED_URL;
import static it.netknights.piauthenticator.AppConstants.STATUS_ENDPOINT_UNKNOWN_HOST;
import static it.netknights.piauthenticator.Util.logprint;

class Endpoint {

    private boolean sslVerify;
    private String url;
    private Map<String, String> data;
    private Interfaces.EndpointCallback callback;

    Endpoint(boolean sslVerify, String url, Map<String, String> data, Interfaces.EndpointCallback callback) {
        this.sslVerify = sslVerify;
        this.url = url;
        this.data = data;
        this.callback = callback;
    }

    boolean connect() {
        logprint("Setting up connection to " + url);
        URL url;
        try {
            url = new URL(this.url);
        } catch (MalformedURLException e) {
            callback.updateStatus(STATUS_ENDPOINT_MALFORMED_URL);
            e.printStackTrace();
            return false;
        }
        HttpURLConnection con;
        try {
            if (url.getProtocol().equals("https")) {
                con = (HttpsURLConnection) url.openConnection();
            } else {
                con = (HttpURLConnection) url.openConnection();
            }
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
        con.setDoOutput(true);
        con.setDoInput(true);
        try {
            con.setRequestMethod("POST");
        } catch (ProtocolException e) {
            e.printStackTrace();
        }
        con.setReadTimeout(READ_TIMEOUT);
        con.setConnectTimeout(CONNECT_TIMEOUT);

        if (!sslVerify && (con instanceof HttpsURLConnection)) {
            con = turnOffSSLVerification((HttpsURLConnection) con);
        }
        logprint("Sending...");
        OutputStream os;
        try {
            os = con.getOutputStream();
        } catch (IOException e) {
            e.printStackTrace();
            callback.updateStatus(STATUS_ENDPOINT_UNKNOWN_HOST);
            return false;
        }

        BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(os, StandardCharsets.UTF_8));
        // Sending the map's k:v pairs separated with & after the first
        try {
            String toSend = "";
            logprint("Data:");
            for (String key : data.keySet()) {
                toSend += key + "=" + data.get(key);
                logprint(toSend);
                writer.write(toSend);
                toSend = "&";
            }
            writer.flush();
            writer.close();
            os.close();
            con.connect();
        } catch (IOException e) {
            e.printStackTrace();
        }

        logprint("Getting response...");
        int responsecode = 0;
        try {
            responsecode = con.getResponseCode();
        } catch (IOException e) {
            e.printStackTrace();
        }
        logprint("response code: " + responsecode);
        BufferedReader br;
        String line;
        StringBuilder response = new StringBuilder();
        try {
            br = new BufferedReader(new InputStreamReader(con.getInputStream()));
            while ((line = br.readLine()) != null) {
                response.append(line);
            }
            logprint("response: " + response.toString());
            callback.responseReceived(response.toString(), responsecode);
        } catch (IOException e) {
            callback.updateStatus(STATUS_ENDPOINT_ERROR);
            e.printStackTrace();
        }
        con.disconnect();
        return true;
    }

    private HttpsURLConnection turnOffSSLVerification(HttpsURLConnection con) {
        logprint("Turning SSL verification off...");
        final TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    @Override
                    public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) {
                    }

                    @Override
                    public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) {
                    }

                    @Override
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return new java.security.cert.X509Certificate[]{};
                    }
                }
        };
        SSLContext sslContext = null;
        try {
            sslContext = SSLContext.getInstance("SSL");
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyManagementException e) {
            e.printStackTrace();
        }
        final SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
        con.setSSLSocketFactory(sslSocketFactory);
        con.setHostnameVerifier(new HostnameVerifier() {
            @Override
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        });
        logprint("Done.");
        return con;
    }
}
