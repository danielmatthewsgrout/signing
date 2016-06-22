package matthewsgrout.signing;

public enum SignAlgorithm {
	SHA1("SHA1withRSA"), SHA256("SHA256withRSA"), SHA384("SHA384withRSA"), SHA512("SHA512withRSA");

	public final String internal;

	SignAlgorithm(String internal) {
		this.internal = internal;
	}
}
