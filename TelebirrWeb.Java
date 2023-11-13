import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
import org.json.JSONObject;

public class DecryptByPublicKey {
    private byte[] modulus;
    private byte[] exponent;

    public DecryptByPublicKey(String publicKey) {
        PublicKey rsaPublicKey = null;
        try {
            byte[] decodedKey = Base64.getUrlDecoder().decode(publicKey);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(decodedKey);
            rsaPublicKey = KeyFactory.getInstance("RSA").generatePublic(spec);
        } catch (Exception e) {
            e.printStackTrace();
        }
        this.modulus = ((RSAPublicKey) rsaPublicKey).getModulus().toByteArray();
        this.exponent = ((RSAPublicKey) rsaPublicKey).getPublicExponent().toByteArray();
    }

    public String decrypt(byte[] base64DecodedEncryptText) throws Exception {
        BigInteger modulus = new BigInteger(1, this.modulus);
        BigInteger publicExponent = new BigInteger(1, this.exponent);
        RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, publicExponent);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(rsaPublicKeySpec);

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);

        byte[] decryptedBytes = cipher.doFinal(base64DecodedEncryptText);
        if (decryptedBytes.length > 0 && decryptedBytes[0] == 1) {
            int index = -1;
            for (int i = 0; i < decryptedBytes.length; i++) {
                if (decryptedBytes[i] == 0) {
                    index = i;
                    break;
                }
            }
            if (index != -1) {
                byte[] rawInfo = Arrays.copyOfRange(decryptedBytes, index + 1, decryptedBytes.length);
                return new String(rawInfo, StandardCharsets.UTF_8);
            }
        }
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }
}

public class TelebirrWeb {
    private String appId;
    private String appKey;
    private String shortCode;
    private String publicKey;
    private String receiveName;
    private String url;

    public TelebirrWeb(String appId, String appKey, String shortCode, String publicKey, String receiveName) {
        this.appId = appId;
        this.appKey = appKey;
        this.shortCode = shortCode;
        this.publicKey = publicKey;
        this.receiveName = receiveName;
        this.url = "https://app.ethiomobilemoney.et:2121/ammapi/payment/service-openup/toTradeWebPay";
    }

    public JSONObject sendRequest(String subject, double totalAmount, String nonce, String outTradeNo, String notifyUrl, String returnUrl) throws Exception {
        if (totalAmount <= 0) {
            throw new IllegalArgumentException("Amount must be greater than 0.");
        }

        int timeoutExpress = 5;
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

        String stringA = String.format(
            "appId=%s&appKey=%s&nonce=%s&notifyUrl=%s&outTradeNo=%s&receiveName=%s&returnUrl=%s&shortCode=%s&subject=%s&timeoutExpress=%s&timestamp=%s&totalAmount=%s",
            appId, appKey, nonce, notifyUrl, outTradeNo, receiveName, returnUrl, shortCode, subject, timeoutExpress,
            timestamp, totalAmount
        );

        JSONObject ussdjson = new JSONObject();
        ussdjson.put("appId", appId);
        ussdjson.put("nonce", nonce);
        ussdjson.put("notifyUrl", notifyUrl);
        ussdjson.put("outTradeNo", outTradeNo);
        ussdjson.put("receiveName", receiveName);
        ussdjson.put("returnUrl", returnUrl);
        ussdjson.put("shortCode", shortCode);
        ussdjson.put("subject", subject);
        ussdjson.put("timeoutExpress", timeoutExpress);
        ussdjson.put("timestamp", timestamp);
        ussdjson.put("totalAmount", totalAmount);

        byte[] ussdjsonBytes = ussdjson.toString().getBytes(StandardCharsets.UTF_8);
        PublicKey rsaPublicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getUrlDecoder().decode(publicKey)));

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey);

        int maxEncryptSize = 245;
        int bufferSize = ussdjsonBytes.length;
        int buffersCount = (int) Math.ceil((double) bufferSize / maxEncryptSize);
        int dividedSize = (int) Math.ceil((double) bufferSize / buffersCount);

        List<byte[]> result = new ArrayList<>();
        for (int bufNum = 0; bufNum < buffersCount; bufNum++) {
            byte[] buf = Arrays.copyOfRange(ussdjsonBytes, bufNum * dividedSize, (bufNum + 1) * dividedSize);
            result.add(cipher.doFinal(buf));
        }
        byte[] encryptedDecode = combineByteArrays(result);
        String encryptedEncode = Base64.getEncoder().encodeToString(encryptedDecode);

        String stringB = sha256Hex(stringA);
        JSONObject data = new JSONObject();
        data.put("appid", appId);
        data.put("sign", stringB);
        data.put("ussd", encryptedEncode);

        HttpClient httpClient = HttpClientBuilder.create().build();
        HttpPost request = new HttpPost(url);
        request.setHeader("Content-Type", "application/json;charset=utf-8");
        request.setEntity(new StringEntity(data.toString(), StandardCharsets.UTF_8));
        request.setConfig(RequestConfig.custom().setSocketTimeout(5000).setConnectTimeout(5000).build());

        HttpResponse response = httpClient.execute(request);
        int statusCode = response.getStatusLine().getStatusCode();
        if (statusCode != HttpStatus.SC_OK) {
            throw new IllegalStateException("Telebirr Transaction Failed");
        }

        String responseString = EntityUtils.toString(response.getEntity());
        return new JSONObject(responseString);
    }

    private static byte[] combineByteArrays(List<byte[]> arrays) {
        int totalLength = 0;
        for (byte[] array : arrays) {
            totalLength += array.length;
        }
        byte[] result = new byte[totalLength];
        int destPos = 0;
        for (byte[] array : arrays) {
            System.arraycopy(array, 0, result, destPos, array.length);
            destPos += array.length;
        }
        return result;
    }

    private static String sha256Hex(String input) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = digest.digest(input.getBytes(StandardCharsets.UTF_8));
        StringBuilder hexString = new StringBuilder();
        for (byte hashByte : hashBytes) {
            String hex = Integer.toHexString(0xff & hashByte);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString().toUpperCase();
    }

    public JSONObject getDecryptData(String data) throws Exception {
        byte[] decodedData = Base64.getUrlDecoder().decode(data);
        DecryptByPublicKey decryptor = new DecryptByPublicKey(publicKey);
        int maxEncryptSize = 256;
        int bufferSize = decodedData.length;
        int buffersCount = (int) Math.ceil((double) bufferSize / maxEncryptSize);
        int dividedSize = (int) Math.ceil((double) bufferSize / buffersCount);

        List<String> result = new ArrayList<>();
        for (int bufNum = 0; bufNum < buffersCount; bufNum++) {
            byte[] buf = Arrays.copyOfRange(decodedData, bufNum * dividedSize, (bufNum + 1) * dividedSize);
            result.add(decryptor.decrypt(buf));
        }
        String message = String.join("", result);
        return new JSONObject(message);
    }
}
