package matthewsgrout.signing.stuff;

import java.io.File;
import java.io.IOException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Option.Builder;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.log4j.Logger;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
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
	
	private enum Parameter {
		certAndKeyFile("path to combined certificate and key file",new String[]{"path"},false),
		certFile("path to certificate file",new String[]{"path"},false),
		det("detached signature",false),
		encap("encapsulated signature",false),
		hash("Hashing Mode: SHA1 or SHA256 or SHA512",new String[]{"mode"},true),
		in("path to the input data to sign or verify",new String[]{"path"},true),
		keyFile("path to key file",new String[]{"path"},false),
		keyType("how are the keys presented: combined or separate",new String[]{"type"},true),
		mode("mode in which to operate: sign or verify",new String[]{"mode"},true),
		sig("path to the detached signature for verification",new String[]{"path"},false),
		url("encode/decode signature as URL data",false),
		v("display verbose information",false);
		 
		final String description;
		final String[] args;
		final boolean required;
		Parameter(String description,String[] args, boolean required) {
			this.description=description;
			this.args=args;
			this.required=required;
		}
		Parameter(String description, boolean required) {
			this.description=description;
			this.args=null;
			this.required=required;
		}
	}

	
	private enum Mode {sign,verify};
	private enum KeyType {combined,separate};
	private static final Logger logger = Logger.getLogger(SignVerifyFileContents.class);

	public static void main(String[] args) throws OperatorCreationException, CMSException, IOException, PKCSException, NoSuchAlgorithmException, InvalidKeySpecException, CertificateException  {
		final CommandLineParser parser = new DefaultParser();
		final CommandLine cmd ;
		try {
			cmd= parser.parse( getOptions(), args);
		} catch (ParseException e) {
			showHelp(e.getMessage());
			return;
		}		
		
		final String algo = SignAlgo.valueOf(cmd.getOptionValue(Parameter.hash.name())).internal;
		final String keyType = cmd.getOptionValue(Parameter.keyType.name());
		
		final boolean verbose = cmd.hasOption(Parameter.v.name());
		
		if (verbose)
			for (String s:cmd.getArgs()) logger.info("using option: "+s);
		
		if (algo==null) {
			showHelp("please select a valid hash");
			return;
		}
		
		final SignVerify sv = new PKCS7SignVerifyImpl(algo,verbose);
		
		final Certificate cert;
		final AsymmetricKeyParameter privateKey;
	
		switch (KeyType.valueOf(keyType.toLowerCase())) {
		case combined:
			if (!cmd.hasOption(Parameter.certAndKeyFile.name())) {
				showHelp("please specify path to certificate and key file");
				return;
			}
			CertificateAndKey cak = CertificateTools.loadCombined(
					Files.readAllBytes(new File(cmd.getOptionValue(Parameter.certAndKeyFile.name())).toPath()));
			
			cert=cak.getCertificate();
			privateKey=cak.getKey();
			break;
		case separate:
			if (!(cmd.hasOption("certFile") && cmd.hasOption(Parameter.keyFile.name()) )) {
				showHelp("please specify path to certificate and key files");
				return;
			}
			
			cert  = CertificateTools.loadX509Certificate(
					Files.readAllBytes(new File( cmd.getOptionValue(Parameter.certFile.name())).toPath()));
			privateKey = CertificateTools.loadRSAPrivateKey(
					Files.readAllBytes(new File(cmd.getOptionValue(Parameter.keyFile.name())).toPath()));
			break;
		default:
			showHelp("please use a valid value for keyType");
			return;
		}
		
		if (!(cmd.hasOption(Parameter.encap.name())||cmd.hasOption(Parameter.det.name()))) {
			showHelp("please select encapsulated or detached");
			return;
		}
		
		final boolean encap=cmd.hasOption(Parameter.encap.name());
		
		final byte[] data = Files.readAllBytes(new File(cmd.getOptionValue(Parameter.in.name())).toPath());
		
	
		final String mode = cmd.getOptionValue(Parameter.mode.name());
		
		switch (Mode.valueOf(mode.toLowerCase())) {
		case sign:
			byte[] signed = encap? sv.signEncapulsated(cert, data, privateKey):sv.signDetached(cert, data, privateKey);	
			String base64 = new String(Base64.encode(signed),StandardCharsets.UTF_8);
			if (cmd.hasOption(Parameter.url.name())){
				System.out.println(URLEncoder.encode(base64,StandardCharsets.UTF_8.name()));
				
			}else {
				System.out.println(base64);
			}
			break;
		case verify:
			if (encap) {
				boolean verify =  sv.verifyEncapsulated(Base64.decode(data));
				System.out.println(verify?"VERIFIED":"FAILED TO VERIFY");
			} else {
				byte[] sig=Files.readAllBytes(new File(cmd.getOptionValue(Parameter.sig.name())).toPath());
				if (cmd.hasOption(Parameter.url.name())) 
					sig = URLDecoder.decode(new String(sig),StandardCharsets.UTF_8.name()).getBytes();
			
				boolean verify = sv.verifyDetached(Base64.decode(sig),data);
				System.out.println(verify?"VERIFIED":"FAILED TO VERIFY");
			}
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
		System.out.println("|              Sign and Verify File Contents v2.2                   |");
		System.out.println("|-------------------------------------------------------------------|");
		System.out.println("| https://github.com/danielajgrout/signing/tree/master/signingstuff |");
		System.out.println("[-------------------------------------------------------------------]");
		System.out.println();
		
		HelpFormatter formatter = new HelpFormatter();
		formatter.printHelp("SignVerifyFileContents" , getOptions());
	}
	
	
	private static  Options getOptions() {
		final Options options = new Options();

		for (Parameter p:Parameter.values()) {
			if (p.args==null||p.args.length==0){
				options.addOption(Option.builder(p.name())
					.desc(p.description).build());
			} else {
				Builder b = Option.builder(p.name())
						.desc(p.description);
				b=b.numberOfArgs(p.args.length);
				for (String s :p.args) b=b.argName(s);
				if (p.required) b=b.required();
				options.addOption(b.build());
			}
		}
		
		return options;
	}
}
