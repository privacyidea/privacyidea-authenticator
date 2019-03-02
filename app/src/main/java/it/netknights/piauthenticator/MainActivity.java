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

import android.app.Activity;
import android.app.AlertDialog;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.graphics.PorterDuff;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.support.annotation.RequiresApi;
import android.support.design.widget.FloatingActionButton;
import android.support.design.widget.Snackbar;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.view.ActionMode;
import android.support.v7.widget.Toolbar;
import android.text.InputType;
import android.util.Base64;
import android.util.Log;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.widget.AdapterView;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.Toast;

import com.google.android.gms.tasks.OnSuccessListener;
import com.google.firebase.iid.FirebaseInstanceId;
import com.google.firebase.iid.InstanceIdResult;
import com.google.zxing.integration.android.IntentIntegrator;
import com.google.zxing.integration.android.IntentResult;

import org.apache.commons.codec.binary.Base32;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;

import static it.netknights.piauthenticator.AppConstants.ALGORITHM;
import static it.netknights.piauthenticator.AppConstants.AUTHENTICATION_URL;
import static it.netknights.piauthenticator.AppConstants.DATA;
import static it.netknights.piauthenticator.AppConstants.DIGITS;
import static it.netknights.piauthenticator.AppConstants.INTENT_ADD_TOKEN_MANUALLY;
import static it.netknights.piauthenticator.AppConstants.LABEL;
import static it.netknights.piauthenticator.AppConstants.NONCE;
import static it.netknights.piauthenticator.AppConstants.NOTIFICATION_CHANNEL_ID;
import static it.netknights.piauthenticator.AppConstants.PERIOD;
import static it.netknights.piauthenticator.AppConstants.PUSH;
import static it.netknights.piauthenticator.AppConstants.QUESTION;
import static it.netknights.piauthenticator.AppConstants.SECRET;
import static it.netknights.piauthenticator.AppConstants.SERIAL;
import static it.netknights.piauthenticator.AppConstants.SIGNATURE;
import static it.netknights.piauthenticator.AppConstants.TITLE;
import static it.netknights.piauthenticator.AppConstants.TOTP;
import static it.netknights.piauthenticator.AppConstants.TYPE;
import static it.netknights.piauthenticator.AppConstants.WITHPIN;
import static it.netknights.piauthenticator.R.color.PIBLUE;
import static it.netknights.piauthenticator.Util.logprint;


public class MainActivity extends AppCompatActivity implements ActionMode.Callback, ActivityInterface {
    TokenListAdapter tokenlistadapter;
    ArrayList<Token> tokenlist;
    ArrayList<PushAuthRequest> pushAuthRequests = new ArrayList<>();
    private Handler handler;
    private Runnable timer;
    private Util util;
    private Token nextSelection = null;
    private ListView listview;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        util = new Util(this);
        util.initFirebase();

        Intent intent = getIntent();
        if (intent.getExtras() == null) {
            logprint("No intent found onCreate.");
        } else {
            // intent contain push auth info
            String serial = intent.getStringExtra(SERIAL);
            String nonce = intent.getStringExtra(NONCE);
            String title = intent.getStringExtra(TITLE);
            String url = intent.getStringExtra(AUTHENTICATION_URL);
            String signature = intent.getStringExtra(SIGNATURE);
            String question = intent.getStringExtra(QUESTION);
            pushAuthRequests.add(new PushAuthRequest(nonce,url,serial,question,title,signature));
        }

        //PRNGFixes.apply();

        setupViews();
        setupFab();

        setupAdapter();
        startTimerThread();

        checkForExpiredTokens();
        createNotificationChannel();

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            paintStatusbar();
        }

        /*try {
            testSign();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }*/
    }

    void testSign() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidKeySpecException, CertificateException, UnrecoverableEntryException, KeyStoreException, IOException, NoSuchProviderException, InvalidAlgorithmParameterException {
        String toVerify = "6DNMPF4MK2OWJOI5MTTDFOMTIR6TIHRU|http://test/ttype/push|PIPU0000015A|Do you want to login to service ABC?" +
                "|PI Authentication";

        String signature = "C3RE7ULFOVH6DJO7RJD2AX7HHMIQFUNH3EIYVMTOTOWK6K64TXNV2VC7GZTHH5Q5BKAMZNQH37P75TCQL3QVOYTHACNMHPTIXWVPOKGRCKIPJBPQTPNG4MD2Y7S4PT6OKL3MP4JHE7AN2LIX2WAFCAC4SV3G55EVEWOS7ZJC33FLBKCSSUBTQOT3EKJIXSYBWJXZM6NS7E6MAEUJYEA4M4IXNG2SOZ5" +
                "KFPSVX5ZELYNIRJLJKIS6LYR7GU5AWKBXT7KG73WSYSMBPMP74OA7I2HFKNEIFDPFNADFEHCNUFSYHJ6ZH4VEJ4K3X2TIF2P4AULLF6CON7GUZJ7FVFARV3HGT73SDJCQOKWKBO3VVCFUF42AAZNLIPW4JON6FB5LA3C4SNIVEM3VPKPRMT4ALWEKISV67CPI5FFHXI6AHROFA53BUOHKD5PUIEQGGEQAJ" +
                "RRBKLIR3BP3RFF5RECCEGVXQDUHO5IO4PPB4SFVXPTZCIHSEHSXT5I5WMC2KXXWOY276GOID7N4U2DCBMAG7LXNVCTMGOSEC7GPCCGBMNQPEAQ2EE4SWTAV77UYGTS6TFM5TTI2PEEKQCRSH32MCNGADWGGFZVT7OIXD3KG34P4L6S5P2OCNIAVKYJZXMVK22GMJJEQU4PT5K3BJ53LSK5BV6I3KPUXZBNIF4TN35WCXCITP" +
                "7THBPZ7BAUV5JQOZAN7HVUZRIATQGADQTM3MHG7O55X6G372GEIFX777EQAOSTUSITBI2ZJ3CSONE736FUEO6BNKD6TKBTJG4PAB2RA6DTBJMPELOEQ4GKHCVL3H7KY7DDQ====";

        String pubkey_str = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8A\n" +
                "MIICCgKCAgEA0x6SH2HNWjJ76jEkxTZuPNauqoUOBEd8LEeU9/tnutFIluXttZ4lLV\n" +
                "4+VIaMgI0Kb9KGwL0xw0cJO1uwFjNSWsca6iyVz2Ek6Fy58jEeIvW49jzmzO2b0ePm\n" +
                "DI/k29BZX7LtLAz9Dqc2GK15xSt1TBZpiPOm26I8tBXgsIBudvJTPbPGnOrJw4F8bY\n" +
                "vG4oiFRtYUX3Ew4hhYSERQ230dUax/jiHgjOeALwY4mIgVroqE6UVubZCYbgLst+Iv\n" +
                "hnmBNOsup9OMbUYBLOQCOvkYJ99LM1K25Jpa79UX3bUgEnedf2jxTIn7VbmXMtQlO4\n" +
                "Aushu4rxFn1WlWC8gfM5cgf3Ia/hqNwEkWO9SwkvuKP/EsWGKos+ibF2HjWnq0HUkq\n" +
                "WlnAYyUzIHaxDzFfp7/XeHkdPsqC+7mzVkGcw5kxkSgB0YUY8P4OGxKZCkZRuuc3pe\n" +
                "SVuXIHYTyKOOZBiMoWOW2Xpyl5A6MDVnHgkuhKmdaYhaIsQNFvBetCJtFhrqwIfo/N\n" +
                "jIVxBn6kMXAgX8UWHqT8W3TgVlG8cHzPx9ggI5hsMH8OdlWp+Xkw7Z6K87ZsW0XSYi\n" +
                "yGaA0fYjOpJje4VQeacXKSHi0LL0GLc7iAaYY6f5MWGOjZ/6BGqRKN1GIKHmrkqpv4\n" +
                "h83xHr9cmVqmk3rZIa7ZeBQ2u9WlA69zxV0CAwEAAQ==";

        String privkey_str = "MIIJJwIBAAKCAgEA0x6SH2HNWjJ76jEkxTZuPNauqoUOBEd8LEeU9/tnutFIluXt\n" +
                "tZ4lLV4+VIaMgI0Kb9KGwL0xw0cJO1uwFjNSWsca6iyVz2Ek6Fy58jEeIvW49jzm\n" +
                "zO2b0ePmDI/k29BZX7LtLAz9Dqc2GK15xSt1TBZpiPOm26I8tBXgsIBudvJTPbPG\n" +
                "nOrJw4F8bYvG4oiFRtYUX3Ew4hhYSERQ230dUax/jiHgjOeALwY4mIgVroqE6UVu\n" +
                "bZCYbgLst+IvhnmBNOsup9OMbUYBLOQCOvkYJ99LM1K25Jpa79UX3bUgEnedf2jx\n" +
                "TIn7VbmXMtQlO4Aushu4rxFn1WlWC8gfM5cgf3Ia/hqNwEkWO9SwkvuKP/EsWGKo\n" +
                "s+ibF2HjWnq0HUkqWlnAYyUzIHaxDzFfp7/XeHkdPsqC+7mzVkGcw5kxkSgB0YUY\n" +
                "8P4OGxKZCkZRuuc3peSVuXIHYTyKOOZBiMoWOW2Xpyl5A6MDVnHgkuhKmdaYhaIs\n" +
                "QNFvBetCJtFhrqwIfo/NjIVxBn6kMXAgX8UWHqT8W3TgVlG8cHzPx9ggI5hsMH8O\n" +
                "dlWp+Xkw7Z6K87ZsW0XSYiyGaA0fYjOpJje4VQeacXKSHi0LL0GLc7iAaYY6f5MW\n" +
                "GOjZ/6BGqRKN1GIKHmrkqpv4h83xHr9cmVqmk3rZIa7ZeBQ2u9WlA69zxV0CAwEA\n" +
                "AQKCAgB79Wc2peY9H4dCarh8UwlHD4Ze+ODSAmcWWLFPKX4uYtOMRlTcXo7VpJBU\n" +
                "cOvuTuHh5mrYoD2nuv3grGUno9qnEmDrPmJ38UIKbOeBHPXk8QI5EmkxyhHDm1xn\n" +
                "49Use5j+Z8B6LOYoxGUu+CyXaHzmwAIXN3ixXQDnfDEBcWdqz72wbO4hFHqDIHQ+\n" +
                "neOY/y/B99DeeUeKeWDcjcAsH7onSnFasul10jehZLW2WbDhWtPPY8UC7/OQJId5\n" +
                "MIVXH+CNgclTIRNC1ee6w+XLWpakUqeE6vwYHclnKGdq9f5u2WzQcn27wwifvOja\n" +
                "H1X9KbZBPaWipUWiOMcdA9POJt4c5K2MJEJjsegAXa/Xir5uE/7XR/ikriFYh7sb\n" +
                "k5ZuhJzjM6mR94N7DMTOjodOVAsfo8ToJn8cdanEon4rPxQ52ZB4nJkkcHT6LrmF\n" +
                "PZHfI5YsFWFCgs57xn1AAt0L4CupzehPJdL4k0/xuCf8fW3fGiNVcY/oxpaCEz4L\n" +
                "RG6SYXRmEXNv8V5KlZmJb1TbiuB0QiVJZ79jPXgDIJi5dc9XkbwMDuv8iDZkakK3\n" +
                "tbLfDE3wGVFDt3f9Fqy0qNYPtIZpYW244amkH+o6AIGFGs8adJxvXOmjYiz77EK9\n" +
                "13pyReO2qQ+FgP0XlQ+7KEjidDNgy2FO/YcQ54p52YF8LZuyAQKCAQEA/AfPJNSX\n" +
                "vCPPLOSNWp+ajEGs57f3HZlPmrGahobMv3CRd7NXvXMljqY4FfpCPgr31GB6wPZi\n" +
                "xXiNYtKbK0v9zkLIudnKO/rNmYOUW+NIos3l5eJh8ve4aujGqyzOGB/FV5VSdXr3\n" +
                "9tiRinEkMLtCUbE8hGhyxtUrmGLYYoU26qUWf05SOPW/k3QQoePH9yp0CnmwVnO3\n" +
                "u0p+iHUIwp1+m9GKu6vvUTi21WsF2ZXq4MLdz5NauqTUY3YJTfJrauJ22tyXfrZo\n" +
                "8Ez8Q/RaBTAi0iul9uF+DZBBtLC9eksmapOp+XvqTp6duJHJCi1HkjniXiGdG1Dv\n" +
                "lCdJLDYkMgN1SQKCAQEA1nHOuL14P82UUlIAV6SL8A+H/R99M0hqXZOoOawTk/mZ\n" +
                "gukimmGnIfMHF2sqWsbxYENW2vwGj33GxCjor+Vo5M0SEvqYDt2wp66bw1GfJpK7\n" +
                "xEesaY18nHRgdCevUva02OVKfy59Gdrm6Zsmgug/Fwk+i6/UtEdoJmClmE8rimrp\n" +
                "/qhOYocDTOCDhwlSFbDqIkVHgZKMFlEn+KPOon3D9H1/DP3BG7wBz3l2/Pu1fmW1\n" +
                "Z1W4uVWSSbCCljwMX3nOlOdnGkSfxz0fOhSrBayHZasw8HMxSoVB2bY2W4gfioed\n" +
                "jVzyAi8RByqkovS0DQrxM0TqBqqbIyooBHl6zJTTdQKCAQAKtMo35lALzfmfDpZy\n" +
                "oxUNoDyYG1iECV84UxMdY9yOxVlonFW91oZh6O25AUiPGigs/Ww5hj3r5ZMb/5ZX\n" +
                "4IKHoI6mVnog0iapvs0umhkb0WNSwKsohx1ubTUDUIPwwmi/r7gxBWhDNC/6kZPX\n" +
                "/hxzG/RWK5m0mJmhf5FxnfcXQKwT/F/By663tNaACg0UktkbGNBE2+WSLzfw1Afr\n" +
                "PIWEWQJrtoIUETSzHDjDZXr00VJa3webpiTflMQQa5vkjno+EeDdoSIUEzEkMd0h\n" +
                "G0pfYztJoYqZSOeBpYBnEYowPNWbo4fwjwxkKs0/gWzo6UyUcxkZb/a9dG3HUwV2\n" +
                "mm8BAoIBADxYJj3iQ1Zg+V346VPAYAibtj7Kf6bQt+3BQVOJUrEPSd2G0U/0Lt3k\n" +
                "z5gNdgu5c+8MxAI3bXkvgaFtiZ0Fx3CrLGzey69TPwTQo9BgxZJLND9Vk/TX9brp\n" +
                "HMNS74k/F0D5tO75HAcMjHIsULgBts86sLkKL6bTeUFjbPXhQXVgBJy+q+AZ8hnO\n" +
                "C/UR8GFeOWSPbkHOBVG6YK8dGWasUVoZfokfVxoA29mQaqViB36cDGIZwzOUGuhV\n" +
                "nUm9eBXd5v4L5/2CVhvw3Tqw2jdsh2VauRjQsYww14j2N3GmaonHA9Tl1Mw8hmQn\n" +
                "4dBhX9FTxPAScnCRzbolgMFRlfa/4okCggEAVD6Iu9rDCAYKlw1mQKCtb7rJ7YOk\n" +
                "g9+sTIaRhCr562Jde7HO+XC3lnTBQASI/mS7P3+IcrG0FYT9CHvBRHTgbIqaWFSU\n" +
                "bO9c/wh1joRjWbUzy+WCsW9cRdyoI0p8ONlyruG/OijXapFqNGPLQ0oSTu7xm73b\n" +
                "l0FC52Xe2dDNUkQtXYAlpq5jjI7quq7mB9Sr1THbnXpmkRktoTqoDK9slt39xVpR\n" +
                "N6UJSk7/nwSbW7KjfkjG1dIvjOGTSqVX6yU/Irztp6Wlb+0k1LQg0EflW5eEDyxL\n" +
                "ybW0bI2zhQ+gFfJR1RSeRxapZSpOhIxK5KXB4l8Qjzp/Ha2MQXX3CzbXHw==";


        logprint("Test siging/verifying...");
        logprint("signature to verify (b32): " + signature);
        logprint("string to verify: " + toVerify);
        // Test with pi data
        byte[] keybytes = Base64.decode(pubkey_str.getBytes(), Base64.DEFAULT);

        //PublicKey pubkey = PKCS1ToSubjectPublicKeyInfo.decodePKCS1PublicKey(keybytes);

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keybytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey pubkey = kf.generatePublic(keySpec);

        byte[] message = toVerify.getBytes(StandardCharsets.UTF_8);
        byte[] bSignature = new Base32().decode(signature);

        Signature sig = Signature.getInstance("SHA256withRSA");

        sig.initVerify(pubkey);
        sig.update(message);
        boolean bSigned = sig.verify(bSignature);
        if (bSigned) {
            logprint("true");
        } else
            logprint("false");


        byte[] privateKeyBytes = Base64.decode(privkey_str, Base64.DEFAULT);
        PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));

        sig.initSign(privateKey);
        sig.update(message);
        String mySignature = new Base32().encodeAsString(sig.sign());

        logprint("my signature: " + mySignature);
        logprint("bytes der message: " + Arrays.toString(message));
        logprint("bytes des private keys:" + Arrays.toString(privateKey.getEncoded()));
        logprint("bytes des public keys:" + Arrays.toString(keybytes));
        sig.initVerify(pubkey);
        sig.update(message);
        boolean bMySigned = sig.verify(new Base32().decode(mySignature));
        if (bMySigned) {
            logprint("my true");
        } else
            logprint("my false");
        /*
        // test sign
        PublicKey publicKey = SecretKeyWrapper.generateKeyPair("test1", this);
        PrivateKey privateKey = SecretKeyWrapper.getPrivateKeyFor("test1");

        Signature s = Signature.getInstance("SHA256withRSA");
        s.initSign(privateKey);
        s.update(message);
        String sig2_b32 = new Base32().encodeAsString(s.sign());
        logprint("signature b32: " + sig2_b32);

        // test verify
        s.initVerify(publicKey);
        s.update(message);
        boolean isValid = s.verify(new Base32().decode(sig2_b32));
        if (isValid)
            logprint("is valid");
        else
            logprint("is NOT valid"); */
    }

    private void checkForExpiredTokens() {
        ArrayList<Token> upForDeletion = new ArrayList<>();
        Date now = new Date();
        for (Token t : tokenlist) {
            if (t.getType().equals(PUSH)) {
                if (!t.rollout_finished && t.rollout_expiration.before(now)) {
                    upForDeletion.add(t);
                }
            }
        }

        if (!upForDeletion.isEmpty()) {
            StringBuilder sb = new StringBuilder();
            for (Token t : upForDeletion) {
                sb.append(t.getSerial()).append("\n");
                removeToken(t);
            }
            AlertDialog.Builder builder = new AlertDialog.Builder(MainActivity.this);
            builder.setTitle("Pushtoken rollout expired")
                    .setMessage("The rollout time expired for the following token:\n\n" +
                            sb.toString())
                    .setPositiveButton("OK", new DialogInterface.OnClickListener() {
                        @Override
                        public void onClick(DialogInterface dialog, int which) {
                            dialog.cancel();
                        }
                    });
            builder.show();
        }
    }

    private void setupFab() {
        FloatingActionButton fab = findViewById(R.id.fab);
        fab.setBackgroundColor(getResources().getColor(PIBLUE));
        fab.bringToFront();
        fab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                scanQR();
/*
                // TODO for faster testing purposes skip the qr scan
                String serial = "PIPU000FSA" + String.valueOf(Math.round(Math.random() * 100));
                String url = "https://sdffffff.free.beeceptor.com";

                String s2 = "otpauth://pipush/PIPU0012F668?url=https%3A//sdffffff.free.beeceptor.com&ttl=10&issuer=privacyIDEA&projectid=test-d3861" +
                        "&apikey=AIzaSyBeFSjwJ8aEcHQaj4-iqT-sLAX6lmSrvbo" +
                        "&appid=1%3A850240559902%3Aandroid%3A812605f9a33242a9&enrollment_credential=9311ee50678983c0f29d3d843f86e39405e2b427" +
                        "&projectnumber=850240559902";
                try {
                    AsyncTask<String, Integer, Boolean> tokenCreation = new TokenCreationTask(MainActivity.this, MainActivity.this.util);
                    tokenCreation.execute(s2);
                } catch (Exception e) {
                    e.printStackTrace();
                } */
            }

        });
    }

    private void startTimerThread() {
        handler = new Handler();
        timer = new Runnable() {
            @Override
            public void run() {
                int progress = (int) (System.currentTimeMillis() / 1000) % 60;
                tokenlistadapter.updatePBs(progress);
                // refresh OTP values only around the periods
                if (progress < 3 || progress > 27 && progress < 33 || progress > 57) {
                    tokenlistadapter.refreshAllTOTP();
                }
                handler.postDelayed(this, 1000);
            }
        };
        handler.post(timer);
        handler.removeCallbacks(timer);
    }

    private void setupAdapter() {
        tokenlist = Util.loadTokens(this);
        tokenlistadapter = new TokenListAdapter();
        listview.setAdapter(tokenlistadapter);
        tokenlistadapter.setTokens(tokenlist);
        tokenlistadapter.setActivityInterface(this);
        tokenlistadapter.refreshOTPs();
    }

    /**
     * Remove a token from the list. This includes Pub/Priv Keys for Pushtoken
     *
     * @param currToken the token to delete
     */
    void removeToken(Token currToken) {
        if (currToken.getType().equals(PUSH)) {
            util.removePubkeyFor(currToken.getSerial());
            try {
                SecretKeyWrapper.removePrivateKeyFor(currToken.getSerial());
            } catch (CertificateException | NoSuchAlgorithmException | KeyStoreException | IOException e) {
                e.printStackTrace();
            }
        }
        int pos = tokenlist.indexOf(currToken);

        if (tokenlist.size() >= pos && pos >= 0 && !tokenlist.isEmpty()) {
            tokenlist.remove(pos);
        }

        if (tokenlistadapter.getPbs().size() >= pos && pos >= 0
                && !tokenlistadapter.getPbs().isEmpty()) {
            tokenlistadapter.getPbs().remove(pos);
        }
        tokenlistadapter.notifyDataSetChanged();
        Toast.makeText(MainActivity.this, R.string.toast_token_removed, Toast.LENGTH_SHORT).show();
        saveTokenlist();
    }

    @RequiresApi(api = Build.VERSION_CODES.LOLLIPOP)
    public void paintStatusbar() {
        Window window = getWindow();
        window.addFlags(WindowManager.LayoutParams.FLAG_DRAWS_SYSTEM_BAR_BACKGROUNDS);
        window.clearFlags(WindowManager.LayoutParams.FLAG_TRANSLUCENT_STATUS);
        window.setStatusBarColor(getResources().getColor(PIBLUE));
    }

    private void setupViews() {
        setTitle(AppConstants.APP_TITLE);
        setContentView(R.layout.activity_main);
        listview = findViewById(R.id.listview);
        listview.setOnItemLongClickListener(new AdapterView.OnItemLongClickListener() {
            @Override
            public boolean onItemLongClick(AdapterView<?> adapterView, View view, int i, long l) {
                nextSelection = tokenlist.get(i);
                startSupportActionMode(MainActivity.this);
                return true;
            }
        });
        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        toolbar.setBackgroundColor(getResources().getColor(PIBLUE));
        if (getSupportActionBar() != null) {
            getSupportActionBar().setLogo(R.mipmap.ic_launcher);
            getSupportActionBar().setDisplayUseLogoEnabled(true);
        }
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.overflow_menu, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // this is the item selected from the toolbar menu
        int id = item.getItemId();
        // save the tokenlist before another activity starts it's lifecycle
        saveTokenlist();
        if (id == R.id.action_about) {
            Intent aboutintent = new Intent(this, AboutActivity.class);
            startActivity(aboutintent);
            return true;
        }
        if (id == R.id.action_enter_detail) {
            Intent settingsIntent = EnterDetailsActivity.makeIntent(MainActivity.this);
            startActivityForResult(settingsIntent, INTENT_ADD_TOKEN_MANUALLY);
        }

        if (id == R.id.print_keys) {
            printKeystore();
            FirebaseInstanceId.getInstance().getInstanceId().addOnSuccessListener(MainActivity.this, new OnSuccessListener<InstanceIdResult>() {
                @Override
                public void onSuccess(InstanceIdResult instanceIdResult) {
                    logprint("Firebase Token: " + instanceIdResult.getToken());
                }
            });
        }

        return super.onOptionsItemSelected(item);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        IntentResult result = IntentIntegrator.parseActivityResult(requestCode, resultCode, data);

        if (result != null) {
            if (result.getContents() == null) {
                Toast.makeText(this, R.string.toast_cancelled, Toast.LENGTH_SHORT).show();
            } else {
                try {
                    AsyncTask<String, Integer, Boolean> tokenCreation = new TokenCreationTask(this, this.util);
                    tokenCreation.execute(result.getContents());
                } catch (Exception e) {
                    Toast.makeText(this, R.string.toast_invalid_qr, Toast.LENGTH_SHORT).show();
                    e.printStackTrace();
                }
            }
        } else if (requestCode == INTENT_ADD_TOKEN_MANUALLY) {
            if (resultCode == Activity.RESULT_OK) {
                Token token = makeTokenFromIntent(data);
                tokenlist.add(token);
                tokenlistadapter.refreshOTPs();
                saveTokenlist();
                Toast.makeText(this, getString(R.string.toast_token_added_for) + " " + token.getLabel(), Toast.LENGTH_SHORT).show();
            } else {
                Toast.makeText(this, R.string.toast_cancelled, Toast.LENGTH_SHORT).show();
            }
        } else {
            super.onActivityResult(requestCode, resultCode, data);
        }
    }

    @Override
    public void onResume() {
        super.onResume();
        tokenlistadapter.refreshAllTOTP();
        handler.post(timer);
    }

    @Override
    public void onPause() {
        super.onPause();
        handler.removeCallbacks(timer);
    }

    @Override
    protected void onStop() {
        super.onStop();
        saveTokenlist();
    }

    @Override
    public boolean onCreateActionMode(ActionMode mode, Menu menu) {
        MenuInflater inflater = mode.getMenuInflater();

        if (nextSelection.isWithPIN()) {
            inflater.inflate(R.menu.actionmode_menu, menu);
            if (nextSelection.isUndeletable()) {
                for (int i = 0; i < menu.size(); i++) {
                    if (menu.getItem(i).getItemId() == R.id.delete_token2) {
                        menu.getItem(i).setEnabled(false);
                        menu.getItem(i).setIcon(R.drawable.ic_no_delete);
                    }
                }
            }
        } else {
            inflater.inflate(R.menu.actionmode_menu_nopin, menu);
            if (nextSelection.isUndeletable()) {
                for (int i = 0; i < menu.size(); i++) {
                    if (menu.getItem(i).getItemId() == R.id.delete_token2) {
                        menu.getItem(i).setEnabled(false);
                        menu.getItem(i).setIcon(R.drawable.ic_no_delete);
                    }
                }
            }
        }
        return true;
    }

    @Override
    public boolean onPrepareActionMode(ActionMode mode, Menu menu) {
        tokenlistadapter.setCurrentSelection(nextSelection);
        tokenlistadapter.notifyDataSetChanged();
        mode.setTitle(getString(R.string.actionmode_title));
        return true;
    }

    @Override
    public boolean onActionItemClicked(final ActionMode mode, MenuItem item) {
        final Token currToken = tokenlistadapter.getCurrentSelection();
        final int id = item.getItemId();
        if (id == R.id.delete_token2) {
           /* if (currToken.isUndeletable()) {
                AlertDialog.Builder builder = new AlertDialog.Builder(this);
                builder.setTitle("Deletion not possible");
                builder.setMessage("This Token is persistent and can not be deleted!");
                builder.setPositiveButton(R.string.zxing_button_ok, new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        dialog.dismiss();
                    }
                });
                final AlertDialog alert = builder.create();
                MainActivity.changeDialogFontColor(alert);
                alert.show();
            } else {*/
            AlertDialog.Builder builder = new AlertDialog.Builder(this);
            builder.setTitle(R.string.confirm_deletion_title);
            builder.setMessage(getString(R.string.confirm_deletion_text) + " " + currToken.getLabel() + " ?");
            builder.setPositiveButton(R.string.button_text_yes, new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int which) {
                    removeToken(currToken);

                    //Log.d(Util.TAG,"deletion: pos: "+pos+" ");
                    mode.finish();
                }
            });
            builder.setNegativeButton(R.string.button_text_no, new DialogInterface.OnClickListener() {
                @Override
                public void onClick(DialogInterface dialog, int which) {
                    Toast.makeText(MainActivity.this, R.string.toast_deletion_cancelled, Toast.LENGTH_SHORT).show();
                    dialog.cancel();
                    mode.finish();
                }
            });
            final AlertDialog alert = builder.create();
            MainActivity.changeDialogFontColor(alert);
            alert.show();
            //}
            return true;
        }

        if (id == R.id.edit_token2) {
            AlertDialog.Builder builder = new AlertDialog.Builder(this);
            builder.setTitle(R.string.edit_name_title);
            final EditText input = new EditText(this);
            input.setText(currToken.getLabel());
            input.setSelectAllOnFocus(true);
            input.getBackground().setColorFilter(input.getContext().getResources().getColor(PIBLUE), PorterDuff.Mode.SRC_IN);
            builder.setView(input);

            builder.setPositiveButton(getString(R.string.button_text_save), new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface dialog, int whichButton) {
                    currToken.setLabel(input.getEditableText().toString());
                    tokenlistadapter.notifyDataSetChanged();
                    saveTokenlist();
                    Toast.makeText(MainActivity.this, currToken.getLabel() + ": " + getString(R.string.toast_name_changed), Toast.LENGTH_SHORT).show();
                    mode.finish();
                }
            });

            builder.setNegativeButton(getString(R.string.button_text_cancel), new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface dialog, int whichButton) {
                    dialog.cancel();
                    Toast.makeText(MainActivity.this, R.string.toast_edit_cancelled, Toast.LENGTH_SHORT).show();
                    mode.finish();
                }
            });
            final AlertDialog alert = builder.create();
            MainActivity.changeDialogFontColor(alert);
            alert.show();
            return true;
        }

        if (id == R.id.change_pin2) {
            if (currToken.isWithPIN() && !currToken.isLocked()) {
                LinearLayout layout = new LinearLayout(this);
                layout.setOrientation(LinearLayout.VERTICAL);

                final EditText firstinput = new EditText(this);
                firstinput.setHint(R.string.input_hint_new_pin);
                firstinput.setInputType(InputType.TYPE_CLASS_NUMBER | InputType.TYPE_NUMBER_VARIATION_PASSWORD);
                layout.addView(firstinput);
                firstinput.getBackground().setColorFilter(firstinput.getContext().getResources().getColor(PIBLUE), PorterDuff.Mode.SRC_IN);
                final EditText secondinput = new EditText(this);
                secondinput.setHint(R.string.input_hint_repeat_new_pin);
                secondinput.setInputType(InputType.TYPE_CLASS_NUMBER | InputType.TYPE_NUMBER_VARIATION_PASSWORD);
                layout.addView(secondinput);
                secondinput.getBackground().setColorFilter(secondinput.getContext().getResources().getColor(PIBLUE), PorterDuff.Mode.SRC_IN);
                AlertDialog.Builder builder = new AlertDialog.Builder(this);
                builder.setTitle(R.string.title_change_pin);
                builder.setView(layout);

                builder.setPositiveButton(getString(R.string.button_text_save), new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int whichButton) {
                        int firstpin = Integer.parseInt(firstinput.getEditableText().toString());
                        int secondpin = Integer.parseInt(secondinput.getEditableText().toString());
                        if (firstpin == secondpin) {
                            String hashedPIN = OTPGenerator.hashPIN(firstpin, currToken);
                            currToken.setPin(hashedPIN);
                            tokenlistadapter.notifyDataSetChanged();
                            saveTokenlist();
                            Toast.makeText(MainActivity.this, currToken.getLabel() + ": " + getString(R.string.toast_pin_changed), Toast.LENGTH_SHORT).show();
                        } else {
                            Toast.makeText(MainActivity.this, R.string.toast_pins_dont_match, Toast.LENGTH_SHORT).show();
                        }
                        mode.finish();
                    }
                });

                builder.setNegativeButton(getString(R.string.button_text_cancel), new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int whichButton) {
                        dialog.cancel();
                        Toast.makeText(MainActivity.this, R.string.toast_change_pin_cancelled, Toast.LENGTH_SHORT).show();
                        mode.finish();
                    }
                });
                final AlertDialog alert = builder.create();
                MainActivity.changeDialogFontColor(alert);
                alert.show();
                return true;
            }
        }

        if (id == R.id.copy_clipboard) {
            copyToClipboard(this, currToken.getCurrentOTP());
            Toast.makeText(MainActivity.this, R.string.toast_otp_to_clipboard, Toast.LENGTH_SHORT).show();
        }
        return false;
    }

    @Override
    public void onDestroyActionMode(ActionMode mode) {
        tokenlistadapter.setCurrentSelection(null);
        tokenlistadapter.notifyDataSetChanged();
        saveTokenlist();
    }

    private Token makeTokenFromIntent(Intent data) {
        // Push tokens cannot be created manually so this is simplified
        String type = data.getStringExtra(TYPE);

        byte[] secret = data.getByteArrayExtra(SECRET);
        String label = data.getStringExtra(LABEL);
        int digits = data.getIntExtra(DIGITS, 6);
        String algorithm = data.getStringExtra(ALGORITHM);
        Token tmp = new Token(secret, label, label, type, digits);

        if (type.equals(TOTP)) {
            int period = data.getIntExtra(PERIOD, 30);
            tmp.setPeriod(period);
        }

        if (algorithm != null) {
            tmp.setAlgorithm(algorithm);
        }
        if (data.getBooleanExtra(WITHPIN, false)) {
            tmp.setWithPIN(true);
        }

        return tmp;
    }

    public static void changeDialogFontColor(final AlertDialog dialog) {
        dialog.setOnShowListener(new DialogInterface.OnShowListener() {
            @Override
            public void onShow(DialogInterface dialogInterface) {
                int piblue = dialog.getContext().getResources().getColor(PIBLUE);
                if (dialog.getButton(AlertDialog.BUTTON_NEGATIVE) != null) {
                    dialog.getButton(AlertDialog.BUTTON_NEGATIVE).setTextColor(piblue);
                }

                if (dialog.getButton(AlertDialog.BUTTON_NEUTRAL) != null) {
                    dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setTextColor(piblue);
                }

                if (dialog.getButton(AlertDialog.BUTTON_POSITIVE) != null) {
                    dialog.getButton(AlertDialog.BUTTON_POSITIVE).setTextColor(piblue);
                }
            }
        });
    }

    public void saveTokenlist() {
        Util.saveTokens(this, tokenlist);
        //Toast.makeText(this, "Tokens saved", Toast.LENGTH_SHORT).show();
    }

    private void scanQR() {
        try {
            IntentIntegrator ii = new IntentIntegrator(this);
            ii.setBeepEnabled(false);
            ii.initiateScan();
        } catch (Exception e) {
            if (this.getCurrentFocus() != null) {
                Snackbar.make(this.getCurrentFocus(), e.getMessage(), Snackbar.LENGTH_LONG).show();
            }

        }
    }

    private void copyToClipboard(Context context, String text) {
        android.content.ClipboardManager clipboard = (android.content.ClipboardManager) context.getSystemService(Context.CLIPBOARD_SERVICE);
        android.content.ClipData clip = android.content.ClipData.newPlainText("Copied Text", text);
        if (clipboard != null)
            clipboard.setPrimaryClip(clip);
    }

    protected void clearTokenlist() {
        if (tokenlist.size() > 0) {
            tokenlist.clear();
            tokenlistadapter.notifyDataSetChanged();
            saveTokenlist();
        }
    }

    void printKeystore() {
        try {
            SecretKeyWrapper.printKeystore();
            this.util.printPubkeys(tokenlist);
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
            e.printStackTrace();
        }

    }

    private void createNotificationChannel() {
        // Create the NotificationChannel, but only on API 26+ because
        // the NotificationChannel class is new and not in the support library
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            CharSequence name = "privacyIDEAPush";
            String description = "push for privacyIDEA";
            int importance = NotificationManager.IMPORTANCE_HIGH;
            NotificationChannel channel = new NotificationChannel(NOTIFICATION_CHANNEL_ID, name, importance);
            channel.setDescription(description);
            // Register the channel with the system; you can't change the importance
            // or other notification behaviors after this
            NotificationManager notificationManager = getSystemService(NotificationManager.class);
            if (notificationManager != null) {
                notificationManager.createNotificationChannel(channel);
            }
        }
    }

    // ----------------- ActivityInterface implementation -----------------
    @Override
    public Activity getPresentActivity() {
        return this;
    }

    @Override
    public void addToken(Token t) {
        if (t == null) return;
        if (t.getType().equals(PUSH)) {
            for (Token token : tokenlist) {
                if(token.getSerial().equals(t.getSerial())){
                    logprint("duplicate token: "+token.getSerial()+". Not adding it.");
                    return;
                }
            }
        }
        this.tokenlist.add(t);
        this.tokenlistadapter.notifyDataSetChanged();
        saveTokenlist();
    }

    @Override
    public void update() {
        tokenlistadapter.notifyDataSetChanged();
    }

    @Override
    public ArrayList<PushAuthRequest> getPushAuthRequests() {
        return pushAuthRequests;
    }
}

interface ActivityInterface {
    Activity getPresentActivity();
    ArrayList<PushAuthRequest> getPushAuthRequests();
    void update();

    void addToken(Token t);
}