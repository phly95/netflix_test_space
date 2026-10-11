import com.android.apksig.ApkSigner;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Signs an APK with APK Signature Scheme v2 (no v1, no v3), matching what the Morphe CLI produced for the
 * Netflix test builds. Needs apksig.jar and bcprov.jar on the classpath (build-test-apk.sh fetches them).
 *
 *   KS_KEY_PASS=... [KS_STORE_PASS=...] [KS_TYPE=BKS] [KS_ALIAS=...] java -cp ... ApkSign <keystore> <in.apk> <out.apk>
 *
 * The key password has NO default on purpose. KS_STORE_PASS defaults to empty, KS_TYPE to BKS (Morphe's format).
 */
public class ApkSign {
    public static void main(String[] a) throws Exception {
        if (a.length != 3) { System.err.println("usage: ApkSign <keystore> <in.apk> <out.apk>"); System.exit(2); }
        String keyPass = System.getenv("KS_KEY_PASS");
        if (keyPass == null) { System.err.println("KS_KEY_PASS is not set"); System.exit(2); }
        String storePass = System.getenv("KS_STORE_PASS") == null ? "" : System.getenv("KS_STORE_PASS");
        String type = System.getenv("KS_TYPE") == null ? "BKS" : System.getenv("KS_TYPE");
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        KeyStore ks = KeyStore.getInstance(type);
        try (InputStream in = new FileInputStream(a[0])) { ks.load(in, storePass.toCharArray()); }
        String alias = System.getenv("KS_ALIAS") != null ? System.getenv("KS_ALIAS") : ks.aliases().nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, keyPass.toCharArray());
        List<X509Certificate> certs = new ArrayList<>();
        for (java.security.cert.Certificate c : ks.getCertificateChain(alias)) certs.add((X509Certificate) c);
        ApkSigner.SignerConfig sc = new ApkSigner.SignerConfig.Builder(alias, pk, certs).build();
        new ApkSigner.Builder(Collections.singletonList(sc))
            .setInputApk(new File(a[1])).setOutputApk(new File(a[2]))
            .setAlignmentPreserved(true).setLibraryPageAlignmentBytes(4096)
            .setV1SigningEnabled(false).setV2SigningEnabled(true).setV3SigningEnabled(false).setV4SigningEnabled(false)
            .build().sign();
        System.out.println("signed " + a[2] + " (alias " + alias + ")");
    }
}
