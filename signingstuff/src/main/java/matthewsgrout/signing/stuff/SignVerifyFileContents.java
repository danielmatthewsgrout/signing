package matthewsgrout.signing.stuff;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.util.encoders.Base64;

import matthewsgrout.signing.SignVerify;
import matthewsgrout.signing.impl.PKCS7SignVerifyImpl;
import matthewsgrout.signing.util.CertificateAndKey;
import matthewsgrout.signing.util.CertificateTools;

public class SignVerifyFileContents {

	private enum SignAlgo {
		SHA1("SHA1withRSA"),SHA256("SHA256withRSA"),SHA512("SHA512withRSA");
		
		String internal;
		
		SignAlgo(String internal) {
			this.internal=internal;
		}
	}
	
	public static void main(String[] args) throws OperatorCreationException, CMSException, IOException, PKCSException, NoSuchAlgorithmException, InvalidKeySpecException, CertificateException  {
		CommandLineParser parser = new DefaultParser();
		CommandLine cmd ;
		try {
			cmd= parser.parse( getOptions(), args);
		} catch (ParseException e) {
			showHelp(e.getMessage());
			return;
		}		
		
		String algo = SignAlgo.valueOf(cmd.getOptionValue("hash")).internal;
		
		if (algo==null) {
			showHelp("please select a valid hash");
			return;
		}
		
		String keyType = cmd.getOptionValue("keyType");
	
		
		Certificate cert;
		PrivateKey privateKey;
	
		switch (keyType.toLowerCase()) {
		case "combined":
			if (!cmd.hasOption("certAndKeyFile")) {
				showHelp("please specify path to certificate and key file");
				return;
			}
			CertificateAndKey cak = CertificateTools.loadCombined(
					Files.readAllBytes(new File(cmd.getOptionValue("certAndKeyFile")).toPath()));
			
			cert=cak.getCertificate();
			privateKey=cak.getKey();
			break;
		case "seperate":
			if (!(cmd.hasOption("certFile") && cmd.hasOption("keyFile") )) {
				showHelp("please specify path to certificate and key files");
				return;
			}
			
			cert  = CertificateTools.loadX509Certificate(
					Files.readAllBytes(new File( cmd.getOptionValue("certFile")).toPath()));
			privateKey = CertificateTools.loadRSAPrivateKey(
					Files.readAllBytes(new File(cmd.getOptionValue("keyFile")).toPath()));
			break;
		default:
			showHelp("please use a valid value for keyType");
			return;
		}
		
		if (!(cmd.hasOption("encap")&&cmd.hasOption("det"))) {
			showHelp("please select encapsulated or detached");
			return;
		}
		
		boolean encap=cmd.hasOption("encap");
		
		byte[] data = Files.readAllBytes(new File(cmd.getOptionValue("in")).toPath());
		
		SignVerify sv = new PKCS7SignVerifyImpl(algo);
		
		String mode = cmd.getOptionValue("mode");
		switch (mode.toLowerCase()) {
		case "sign":
			byte[] signed = encap? sv.signEncapulsated(cert, data, privateKey):sv.signDetached(cert, data, privateKey);	
			String base64 = new String(Base64.encode(signed),StandardCharsets.UTF_8);
			System.out.println(base64);
			break;
		case "verify":
			byte[] decoded = Base64.decode(data);
			
			boolean verify = encap? sv.verifyEncapsulated(decoded): sv.verifyDetached(data, 
					Files.readAllBytes(new File(cmd.getOptionValue("sig")).toPath()));
			
			System.out.println(verify?"VERIFIED":"FAILED TO VERIFY");
			
			break;
		default:
			showHelp("please select a valid mode: sign or verify");
		}
		
	}
	
	private static void showHelp(String msg) {
		System.out.println("Error: " + msg);
		System.out.println();
		showHelp();
	}
	
	private static void showHelp()  {
		System.out.println("[-------------------------------------------------------------------]");
		System.out.println("|              Sign and Verify File Contents v2.0                   |");
		System.out.println("|-------------------------------------------------------------------|");
		System.out.println("| https://github.com/danielajgrout/signing/tree/master/signingstuff |");
		System.out.println("[-------------------------------------------------------------------]");
		System.out.println();
		
		HelpFormatter formatter = new HelpFormatter();
		formatter.printHelp("SignVerifyFileContents" , getOptions());
	}
	
	
	private static  Options getOptions() {
		Options options = new Options();

		Option mode = Option.builder("mode")
				.desc("mode in which to operate: sign or verify")
				.hasArg()
				.required()
				.argName("mode")
				.numberOfArgs(1)
				.build();
		
		Option keyType = Option.builder("keyType")
				.desc("how are the keys presented: combined or seperate")
				.hasArg()
				.required()
				.argName("mode")
				.numberOfArgs(1)
				.build();
		
		Option certAndKey = Option.builder("certAndKeyFile")
				.desc("path to combined certificate and key file")
				.hasArg()
				.argName("path")
				.numberOfArgs(1)
				.build();

		Option cert = Option.builder("certFile")
				.desc("path to certificate file")
				.hasArg()
				.argName("path")
				.numberOfArgs(1)
				.build();

		Option key = Option.builder("keyFile")
				.desc("path to key file")
				.hasArg()
				.argName("path")
				.numberOfArgs(1)
				.build();

		Option hashMode = Option.builder("hash")
				.desc("Hashing Mode: SHA1 or SHA256 or SHA512")
				.hasArg()
				.required()
				.argName("mode")
				.numberOfArgs(1)
				.build();
		Option data = Option.builder("in")
				.desc("path to the input data to sign or verify")
				.hasArg()
				.required()
				.argName("path")
				.numberOfArgs(1)
				.build();
		
		Option sig = Option.builder("sig")
				.desc("path to the detached signature for verification mode")
				.hasArg()
				.required()
				.argName("path")
				.numberOfArgs(1)
				.build();
		
		Option encap = new Option( "encap", "encapsulated signature" );
		Option det = new Option( "det", "detached signature" );

		
		options.addOption(mode);
		options.addOption(keyType);
		options.addOption(certAndKey);
		options.addOption(key);
		options.addOption(cert);
		options.addOption(hashMode);
		options.addOption(data);
		options.addOption(encap);
		options.addOption(det);
		options.addOption(sig);

		return options;
	}

}
