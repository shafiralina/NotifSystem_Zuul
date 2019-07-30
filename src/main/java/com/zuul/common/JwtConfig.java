package com.zuul.common;

import org.springframework.beans.factory.annotation.Value;

// To use this class outside. You have to 
// 1. Define it as a bean, either by adding @Component or use @Bean to instantiate an object from it
// 2. Use the @Autowire to ask spring to auto create it for you, and inject all the values.

// So, If you tried to create an instance manually (i.e. new JwtConfig()). This won't inject all the values. 
// Because you didn't ask Spring to do so (it's done by you manually!).
// Also, if, at any time, you tried to instantiate an object that's not defined as a bean
// Don't expect Spring will autowire the fields inside that class object.

// [IMP] You need to install lombok jar file: https://stackoverflow.com/a/11807022
public class JwtConfig {

	// Spring doesn't inject/autowire to "static" fields.
	// Link: https://stackoverflow.com/a/6897406
	@Value("${security.jwt.uri:/auth/**}")
	private String Uri;

	@Value("${security.jwt.header:Authorization}")
	private String header;

	@Value("${security.jwt.prefix:Bearer }")
	private String prefix;

	@Value("${security.jwt.expiration:#{60}}")
	private int expiration1;

	@Value("${security.jwt.expiration:#{120}}")
	private int expiration2;

	@Value("${security.jwt.secret:JwtSecretKey}")
	private String secret;

	// In case you want to use plain getters instead of lombok.
	public String getUri() {
		return Uri;
	}

	public void setUri(String uri) {
		Uri = uri;
	}

	public String getPrefix() {
		return prefix;
	}

	public void setPrefix(String prefix) {
		this.prefix = prefix;
	}

	public int getExpiration1() {
		return expiration1;
	}

	public void setExpiration1(int expiration1) {
		this.expiration1 = expiration1;
	}

	public int getExpiration2() {
		return expiration2;
	}

	public void setExpiration2(int expiration2) {
		this.expiration2 = expiration2;
	}

	public String getSecret() {
		return secret;
	}

	public void setSecret(String secret) {
		this.secret = secret;
	}

	public String getHeader() {
		return header;
	}

	public void setHeader(String header) {
		this.header = header;
	}

}
