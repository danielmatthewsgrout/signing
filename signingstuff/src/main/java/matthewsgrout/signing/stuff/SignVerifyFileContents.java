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

import matthewsgrout.signing.SignAlgorithm;
import matthewsgrout.signing.SignVerify;
import matthewsgrout.signing.impl.PKCS7SignVerifyImpl;
import matthewsgrout.signing.util.CertificateAndKey;
import matthewsgrout.signing.util.CertificateTools;

/**
 * @author Daniel Matthews-Grout
 * 
 * CLI for signing and verifying
 *
 */
public class SignVerifyFileContents {

	private enum Mode {sign,verify,notSpecified};
	private enum KeyType {combined,separate,notSpecified};
	private static final Logger logger = Logger.getLogger(SignVerifyFileContents.class);
	private enum Parameter {
		certAndKeyFile("path to combined certificate and key file",new String[]{"path"},false),
		certFile("path to certificate file",new String[]{"path"},false),
		det("detached signature",false),
		encap("encapsulated signature",false),
		hash("Hashing Mode: SHA1 or SHA256, SHA384, or SHA512",new String[]{"mode"},true),
		in("path to the input data to sign or verify",new String[]{"path"},true),
		keyFile("path to key file",new String[]{"path"},false),
		keyType("how are the keys presented: combined or separate",new String[]{"type"},false),
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

	/**
	 * @param args CLI arguments
	 * @throws OperatorCreationException
	 * @throws CMSException
	 * @throws IOException
	 * @throws PKCSException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 * @throws CertificateException
	 */
	public static void main(String[] args) throws OperatorCreationException, CMSException, IOException, PKCSException, NoSuchAlgorithmException, InvalidKeySpecException, CertificateException  {
		final CommandLineParser parser = new DefaultParser();
		final CommandLine cmd ;
		
		try {
			cmd= parser.parse( getOptions(), args);
		} catch (ParseException e) {
			showHelp(e.getMessage());
			return;
		}		
		
		byte[] data = Files.readAllBytes(new File(cmd.getOptionValue(Parameter.in.name())).toPath());
		
		final SignAlgorithm algo = SignAlgorithm.valueOf(cmd.getOptionValue(Parameter.hash.name()));
		final boolean verbose = cmd.hasOption(Parameter.v.name());
		
		if (verbose) for (String s:cmd.getArgs()) logger.info("using option: "+s);
		
		if (algo==null) {
			showHelp("please select a valid hash");
			return;
		}

		final SignVerify sv = new PKCS7SignVerifyImpl(algo,verbose);
			
		if (!(cmd.hasOption(Parameter.encap.name())||cmd.hasOption(Parameter.det.name()))) {
			showHelp("please select encapsulated or detached");
			return;
		}
		KeyType keyType=KeyType.notSpecified;
		
		if (cmd.hasOption(Parameter.keyType.name())) {
			try {
				keyType=KeyType.valueOf(cmd.getOptionValue(Parameter.keyType.name()).toLowerCase());
			} catch (IllegalArgumentException e) {
				showHelp("please select a key type value of combined or separate");
				return;
			}
		}
		
		final boolean encap=cmd.hasOption(Parameter.encap.name());
		Mode mode=Mode.valueOf( cmd.getOptionValue(Parameter.mode.name()).toLowerCase());
		switch (mode) {
		case sign:
			
			if (!cmd.hasOption(Parameter.keyType.name())) {
				showHelp("please use -keyType option with parameter combined or separate");
				return;
			}
			
			final Certificate cert;
			final AsymmetricKeyParameter privateKey;
		
			switch (keyType) {
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
				if (!(cmd.hasOption(Parameter.certFile.name()) && cmd.hasOption(Parameter.keyFile.name()) )) {
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
			
			byte[] signed = encap? sv.signEncapulsated(cert, data, privateKey):sv.signDetached(cert, data, privateKey);	
			String base64 = new String(Base64.encode(signed),StandardCharsets.UTF_8);
		
			if (cmd.hasOption(Parameter.url.name())){
				System.out.println(URLEncoder.encode(base64,StandardCharsets.UTF_8.name()));
			}else {
				System.out.println(base64);
			}
			
			break;
		case verify:
			boolean verify ;
			boolean hasCert=cmd.hasOption(Parameter.keyType.name());
			Certificate certificate=null;
			if (cmd.hasOption(Parameter.url.name())) 
				data = URLDecoder.decode(new String(data),StandardCharsets.UTF_8.name()).getBytes();
			
			if (hasCert) {
				//has certificate so load it based on the options
			
				switch (keyType) {
				case combined:
					if (!cmd.hasOption(Parameter.certAndKeyFile.name())) {
						showHelp("please specify path to certificate");
						return;
					}
					CertificateAndKey cak = CertificateTools.loadCombined(
							Files.readAllBytes(new File(cmd.getOptionValue(Parameter.certAndKeyFile.name())).toPath()));
					
					certificate=cak.getCertificate();
					break;
				case separate:
					if (!cmd.hasOption(Parameter.certFile.name())) {
						showHelp("please specify path to certificate");
						return;
					}
					
					certificate  = CertificateTools.loadX509Certificate(
							Files.readAllBytes(new File( cmd.getOptionValue(Parameter.certFile.name())).toPath()));
					break;
				default:
					showHelp("please use a valid value for keyType");
					return;
				}
			} 
			
			if (encap) {
					verify = hasCert? sv.verifyEncapsulated(Base64.decode(data),certificate):sv.verifyEncapsulated(Base64.decode(data));					
			} else {
				
				if (!cmd.hasOption(Parameter.sig.name())&&!encap) {
					showHelp("please specify signature to verify");
					return;
				}
				
				byte[] sig=Files.readAllBytes(new File(cmd.getOptionValue(Parameter.sig.name())).toPath());
				if (cmd.hasOption(Parameter.url.name())) 
					sig = URLDecoder.decode(new String(sig),StandardCharsets.UTF_8.name()).getBytes();
			
				verify = hasCert? sv.verifyDetached(Base64.decode(sig),data,certificate):sv.verifyDetached(Base64.decode(sig),data);
			}
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
		System.out.println("|              Sign and Verify File Contents v2.3                   |");
		System.out.println("|-------------------------------------------------------------------|");
		System.out.println("| https://github.com/danielajgrout/signing/tree/master/signingstuff |");
		System.out.println("[-------------------------------------------------------------------]");
		System.out.println();
		
		new HelpFormatter().printHelp("SignVerifyFileContents" , getOptions());
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
