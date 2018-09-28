/*
 * Copyright (c) 2013-2018 Jeff Sutton.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package util.android.crypt;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;
import util.android.securepreferences.BuildConfig;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.*;

import static javax.crypto.Cipher.getInstance;

public class SecurePreferences {

    private static final String SECRET_KEY_HASH_TRANSFORMATION = "SHA-256";
    private static final String CHARSET = "UTF-8";
    private final boolean encryptKeys;
    private final Cipher writer;
    private final Cipher reader;
    private final Cipher keyWriter;
    private final SharedPreferences preferences;

    /**
     * This will initialize an instance of the SecurePreferences class
     *
     * @param context        your current context.
     * @param preferenceName name of preferences file (preferenceName.xml)
     * @param secureKey      the key used for encryption, finding a good key scheme is hard. Hardcoding
     *                       your key in the application is bad, but better than plaintext preferences. Having the user
     *                       enter the key upon application launch is a safe(r) alternative, but annoying to the user.
     * @param encryptKeys    settings this to false will only encrypt the values, true will encrypt both
     *                       values and keys. Keys can contain a lot of information about the plaintext value of the
     *                       value which can be used to decipher the value.
     * @throws SecurePreferencesException
     */
    public SecurePreferences(
            Context context, String preferenceName, String secureKey, boolean encryptKeys) {
        try {
            this.writer = getInstance(BuildConfig.TRANSFORMATION);
            this.reader = getInstance(BuildConfig.TRANSFORMATION);
            this.keyWriter = getInstance(BuildConfig.KEY_TRANSFORMATION);

            initCiphers(secureKey);

            this.preferences = context.getSharedPreferences(preferenceName, Context.MODE_PRIVATE);

            this.encryptKeys = encryptKeys;
        } catch (GeneralSecurityException | UnsupportedEncodingException e) {
            throw new SecurePreferencesException(e);
        }
    }

    private static byte[] convert(Cipher cipher, byte[] bs) {
        try {
            return cipher.doFinal(bs);
        } catch (Exception e) {
            throw new SecurePreferencesException(e);
        }
    }

    protected void initCiphers(String secureKey)
            throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException,
            InvalidAlgorithmParameterException {
        IvParameterSpec ivSpec = getIv();
        SecretKeySpec secretKey = getSecretKey(secureKey);

        writer.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        reader.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        keyWriter.init(Cipher.ENCRYPT_MODE, secretKey);
    }

    protected IvParameterSpec getIv() {
        byte[] iv = new byte[writer.getBlockSize()];
        System.arraycopy(BuildConfig.IV.getBytes(Charset.forName(CHARSET)),
                0,
                iv,
                0,
                writer.getBlockSize());
        return new IvParameterSpec(iv);
    }

    protected SecretKeySpec getSecretKey(String key)
            throws UnsupportedEncodingException, NoSuchAlgorithmException {
        byte[] keyBytes = createKeyBytes(key);
        return new SecretKeySpec(keyBytes, BuildConfig.TRANSFORMATION);
    }

    protected byte[] createKeyBytes(String key)
            throws UnsupportedEncodingException, NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(SECRET_KEY_HASH_TRANSFORMATION);
        md.reset();
        return md.digest(key.getBytes(CHARSET));
    }

    public void put(String key, String value) {
        if (value == null) {
            preferences.edit().remove(toKey(key)).apply();
        } else {
            putValue(toKey(key), value);
        }
    }

    public boolean containsKey(String key) {
        return preferences.contains(toKey(key));
    }

    private String toKey(String key) {
        if (encryptKeys) return encrypt(key, keyWriter);
        else return key;
    }

    protected String encrypt(String value, Cipher writer) {
        byte[] secureValue;
        try {
            secureValue = convert(writer, value.getBytes(CHARSET));
        } catch (UnsupportedEncodingException e) {
            throw new SecurePreferencesException(e);
        }
        return Base64.encodeToString(secureValue, Base64.NO_WRAP);
    }

    public void removeValue(String key) {
        preferences.edit().remove(toKey(key)).apply();
    }

    public String getString(String key) {
        if (preferences.contains(toKey(key))) {
            String securedEncodedValue = preferences.getString(toKey(key), "");
            return decrypt(securedEncodedValue);
        }
        return null;
    }

    protected String decrypt(String securedEncodedValue) {
        byte[] securedValue = Base64.decode(securedEncodedValue, Base64.NO_WRAP);
        byte[] value = convert(reader, securedValue);
        try {
            return new String(value, CHARSET);
        } catch (UnsupportedEncodingException e) {
            throw new SecurePreferencesException(e);
        }
    }

    public void clear() {
        preferences.edit().clear().apply();
    }

    private void putValue(String key, String value) {
        String secureValueEncoded = encrypt(value, writer);

        preferences.edit().putString(key, secureValueEncoded).apply();
    }

    public static class SecurePreferencesException extends RuntimeException {

        private static final long serialVersionUID = -359323655915307692L;

        SecurePreferencesException(Throwable e) {
            super(e);
        }
    }
}
