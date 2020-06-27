package dev.dmg.signing.httpsign;

import java.io.File;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Option.Builder;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import dev.dmg.signing.httpsign.service.HTTPSigner;
import dev.dmg.signing.httpsign.service.HTTPSigner.HTTPMethod;
import dev.dmg.signing.httpsign.service.HTTPSigner.SignatureType;
import dev.dmg.signing.httpsign.service.impl.BasicHTTPSignerImpl;
import dev.dmg.signing.httpsign.service.impl.BasicSignDataImpl;

public class HTTPSign {

    private static final Logger logger = Logger.getLogger(HTTPSign.class.getName());

    private enum Parameter {
        url("URL to use", new String[] { "url" }, true), method("PUT or POST", new String[] { "method" }, true),
        hash("Hashing Mode: SHA1 or SHA256, SHA384, or SHA512", new String[] { "mode" }, true),
        in("path to the input data to sign or verify", new String[] { "path" }, true),
        headersFile("path to headers file - use properties format - key=value", new String[] { "path" }, false),
        keyFile("path to key file", new String[] { "path" }, false), v("display verbose information", false);

        final String description;
        final String[] args;
        final boolean required;

        Parameter(String description, String[] args, boolean required) {
            this.description = description;
            this.args = args;
            this.required = required;
        }

        Parameter(String description, boolean required) {
            this.description = description;
            this.args = null;
            this.required = required;
        }
    }

    public static void main(String[] args) throws GeneralSecurityException, InterruptedException, Exception {
        final CommandLineParser parser = new DefaultParser();
        final CommandLine cmd;

        try {
            cmd = parser.parse(getOptions(), args);
        } catch (ParseException e) {
            showHelp(e.getMessage());
            return;
        }

        final String keyPath = cmd.getOptionValue(Parameter.keyFile.name());
        final String fname = cmd.getOptionValue(Parameter.in.name());
        final String url = cmd.getOptionValue(Parameter.url.name());
        final boolean verbose = cmd.hasOption(Parameter.v.name());

        final SignatureType algo = SignatureType.valueOf(cmd.getOptionValue(Parameter.hash.name()));
        final HTTPMethod method = HTTPMethod.valueOf(cmd.getOptionValue(Parameter.method.name()));

        final Logger glogger = Logger.getLogger(Logger.GLOBAL_LOGGER_NAME);
        final FileHandler fileTxt = new FileHandler("httpsign.log");
        final SimpleFormatter formatterTxt = new SimpleFormatter();

        fileTxt.setFormatter(formatterTxt);
        glogger.addHandler(fileTxt);

        if (verbose) {
            glogger.setLevel(Level.FINE);
        } else {
            glogger.setLevel(Level.INFO);
        }

        final HTTPSigner httpSigner = BasicHTTPSignerImpl.getHttpSigner(BasicSignDataImpl.INSTANCE);
        final byte[] data = Files.readAllBytes(new File(fname).toPath());

        logger.fine("Arguments: " + String.join(",", cmd.getArgs()));

        Map<String, String> headersMap = new HashMap<>();

        if (cmd.hasOption(Parameter.headersFile.name())) {
            final String headerPath = cmd.getOptionValue(Parameter.headersFile.name());

            List<String> headers = Files.readAllLines(new File(headerPath).toPath());
            logger.fine("read " + headers.size() + "lines from: " + headerPath);
            for (String s : headers) {
                String[] vals = s.split("=");
                if (vals.length == 2) {
                    headersMap.put(vals[0].trim(), vals[1].trim());
                } else {
                    logger.warning("invalid entry in header file: " + s);
                }
            }
            logger.fine("got " + headersMap.size() + " headers");
        }
        HttpResponse<String> resp = httpSigner.signAndSend(url, method, data, readPrivateKey(keyPath), algo,
                headersMap);

        logger.info("Got response code: " + resp.statusCode());
        logger.info("Got body: " + resp.body());
    }

    private static void showHelp(String msg) {
        System.out.println("Error: " + msg);
        System.out.println();
        showHelp();
    }

    private static void showHelp() {
        System.out.println("[-------------------------------------------------------------------------]");
        System.out.println("|                           HTTPSign v1.0                                 |");
        System.out.println("|-------------------------------------------------------------------------|");
        System.out.println("| https://github.com/danielmatthewsgrout/signing/tree/master/httpsign     |");
        System.out.println("[-------------------------------------------------------------------------]");
        System.out.println();

        new HelpFormatter().printHelp("HTTPSign", getOptions());
    }

    private static Options getOptions() {
        final Options options = new Options();

        for (Parameter p : Parameter.values()) {
            if (p.args == null || p.args.length == 0) {
                options.addOption(Option.builder(p.name()).desc(p.description).build());
            } else {
                Builder b = Option.builder(p.name()).desc(p.description);
                b = b.numberOfArgs(p.args.length);
                for (String s : p.args)
                    b = b.argName(s);
                if (p.required)
                    b = b.required();
                options.addOption(b.build());
            }
        }

        return options;
    }

    private static PrivateKey readPrivateKey(String fileName) throws Exception {

        byte[] keyBytes = Files.readAllBytes(Paths.get(fileName));

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

}
