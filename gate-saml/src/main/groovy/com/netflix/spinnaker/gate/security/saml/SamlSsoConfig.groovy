/*
 * Copyright 2014 Netflix, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.netflix.spinnaker.gate.security.saml

import com.netflix.spectator.api.Registry
import com.netflix.spinnaker.fiat.shared.FiatClientConfigurationProperties
import com.netflix.spinnaker.gate.config.AuthConfig
import com.netflix.spinnaker.gate.security.AllowedAccountsSupport
import com.netflix.spinnaker.gate.security.SpinnakerAuthConfig
import com.netflix.spinnaker.gate.security.saml.spring.SpinnakerSaml2Authentication
import com.netflix.spinnaker.gate.services.PermissionService
import com.netflix.spinnaker.kork.core.RetrySupport
import com.netflix.spinnaker.security.AllowedAccountsAuthorities
import groovy.util.logging.Slf4j
import org.joda.time.DateTime
import org.opensaml.core.config.ConfigurationService
import org.opensaml.core.xml.XMLObject
import org.opensaml.core.xml.schema.*
import org.opensaml.saml.saml2.core.Assertion
import org.opensaml.saml.saml2.core.Attribute
import org.opensaml.saml.saml2.core.AttributeStatement
import org.opensaml.saml.saml2.core.Response
import org.opensaml.xmlsec.SignatureSigningConfiguration
import org.opensaml.xmlsec.impl.BasicSignatureSigningConfiguration
import org.opensaml.xmlsec.signature.support.SignatureConstants
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression
import org.springframework.boot.autoconfigure.web.ServerProperties
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.convert.converter.Converter
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.ProviderManager
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.saml2.provider.service.authentication.OpenSamlAuthenticationProvider
import org.springframework.security.saml2.provider.service.authentication.OpenSamlAuthenticationRequestFactory
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationRequestFactory
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationToken
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding
import org.springframework.session.web.http.DefaultCookieSerializer
import org.springframework.stereotype.Component

import javax.annotation.PostConstruct
import java.security.KeyStore
import java.time.Duration
import java.time.Instant

@ConditionalOnExpression('${saml.enabled:false}')
@Configuration
@SpinnakerAuthConfig
@EnableWebSecurity
@Slf4j
class SamlSsoConfig extends WebSecurityConfigurerAdapter {

  @Autowired
  ServerProperties serverProperties

  @Autowired
  DefaultCookieSerializer defaultCookieSerializer

  @Autowired
  AuthConfig authConfig

  @Component
  @ConfigurationProperties("saml")
  static class SAMLSecurityConfigProperties {
    String keyStore
    String keyStorePassword
    String keyStoreAliasName

    // SAML DSL uses a metadata URL instead of hard coding a certificate/issuerId/redirectBase into the config.
    String metadataUrl
    // The parts of this endpoint passed to/used by the SAML IdP.
    String redirectProtocol = "https"
    String redirectHostname
    String redirectBasePath = "/"
    // The application identifier given to the IdP for this app.
    String issuerId

    List<String> requiredRoles
    boolean sortRoles = false
    boolean forceLowercaseRoles = true
    UserAttributeMapping userAttributeMapping = new UserAttributeMapping()
    long maxAuthenticationAge = 7200

    String signatureDigest = "SHA1" // SHA1 is the default registered in DefaultSecurityConfigurationBootstrap.populateSignatureParams

    /**
     * Ensure that the keystore exists and can be accessed with the given keyStorePassword and keyStoreAliasName
     */
    @PostConstruct
    void validate() {
      if (metadataUrl && metadataUrl.startsWith("/")) {
        metadataUrl = "file:" + metadataUrl
      }

      if (keyStore) {
        if (!keyStore.startsWith("file:")) {
          keyStore = "file:" + keyStore
        }
        new File(new URI(keyStore)).withInputStream { is ->
          def keystore = KeyStore.getInstance(KeyStore.getDefaultType())

          // will throw an exception if `keyStorePassword` is invalid
          keystore.load(is, keyStorePassword.toCharArray())

          if (keyStoreAliasName && !keystore.aliases().find { it.equalsIgnoreCase(keyStoreAliasName) }) {
            throw new IllegalStateException("Keystore '${keyStore}' does not contain alias '${keyStoreAliasName}'")
          }
        }
      }

      // Validate signature digest algorithm
      if (SignatureAlgorithms.fromName(signatureDigest) == null) {
        throw new IllegalStateException("Invalid saml.signatureDigest value '${signatureDigest}'. Valid values are ${SignatureAlgorithms.values()}")
      }
    }
  }

  static class UserAttributeMapping {
    String firstName = "User.FirstName"
    String lastName = "User.LastName"
    String roles = "memberOf"
    String rolesDelimiter = ";"
    String username
    String email
  }

  @Autowired
  SAMLSecurityConfigProperties samlSecurityConfigProperties

  static Converter<OpenSamlAuthenticationProvider.ResponseToken, AbstractAuthenticationToken> createDefaultResponseAuthenticationConverter() {
    return { OpenSamlAuthenticationProvider.ResponseToken responseToken ->
      Saml2AuthenticationToken token = responseToken.token
      Response response = responseToken.response
      Assertion assertion = response.assertions.find { it }
      String username = assertion.subject.nameID.value
      Map<String, List<Object>> attributes = getAssertionAttributes(assertion)
      def userAttributeMapping = samlSecurityConfigProperties.userAttributeMapping
      def roles = extractRoles(attributes, userAttributeMapping)
      def userObject = loadUserByUsername(username, roles)
      return new SpinnakerSaml2Authentication(userObject, token.saml2Response, roles)
    }
  }

  private static Map<String, List<Object>> getAssertionAttributes(Assertion assertion) {
    Map<String, List<Object>> attributeMap = new LinkedHashMap<>()
    for (AttributeStatement attributeStatement : assertion.getAttributeStatements()) {
      for (Attribute attribute : attributeStatement.getAttributes()) {
        List<Object> attributeValues = new ArrayList<>()
        for (XMLObject xmlObject : attribute.getAttributeValues()) {
          Object attributeValue = getXmlObjectValue(xmlObject)
          if (attributeValue != null) {
            attributeValues.add(attributeValue)
          }
        }
        attributeMap.put(attribute.getName(), attributeValues)
      }
    }
    return attributeMap
  }

  private static Object getXmlObjectValue(XMLObject xmlObject) {
    if (xmlObject instanceof XSAny) {
      return ((XSAny) xmlObject).textContent
    }
    if (xmlObject instanceof XSString) {
      return ((XSString) xmlObject).value
    }
    if (xmlObject instanceof XSInteger) {
      return ((XSInteger) xmlObject).value
    }
    if (xmlObject instanceof XSURI) {
      return ((XSURI) xmlObject).value
    }
    if (xmlObject instanceof XSBoolean) {
      XSBooleanValue xsBooleanValue = ((XSBoolean) xmlObject).value
      return (xsBooleanValue != null) ? xsBooleanValue.value : null
    }
    if (xmlObject instanceof XSDateTime) {
      DateTime dateTime = ((XSDateTime) xmlObject).value
      return (dateTime != null) ? Instant.ofEpochMilli(dateTime.millis) : null
    }
    return null
  }

  @Override
  void configure(HttpSecurity http) {
    //We need our session cookie to come across when we get redirected back from the IdP:
    defaultCookieSerializer.setSameSite(null)
    authConfig.configure(http)

    OpenSamlAuthenticationProvider authenticationProvider = new OpenSamlAuthenticationProvider()
    authenticationProvider.setResponseAuthenticationConverter(createDefaultResponseAuthenticationConverter())

    http
      .authorizeRequests({ authorize ->
        authorize
          .anyRequest().authenticated()
      })
      .saml2Login({ saml2 ->
        saml2
          .authenticationManager(new ProviderManager(authenticationProvider))
          .relyingPartyRegistrationRepository(relyingPartyRegistrationRepository())
      })

    initSignatureDigest() // Need to be after SAMLConfigurer initializes the global SecurityConfiguration

  }

  private void initSignatureDigest() {
    def signingConfiguration = ConfigurationService.get(SignatureSigningConfiguration)
    if (signingConfiguration != null && signingConfiguration instanceof BasicSignatureSigningConfiguration) {
      BasicSignatureSigningConfiguration basicSecConfig = (BasicSignatureSigningConfiguration) signingConfiguration
      def algo = SignatureAlgorithms.fromName(samlSecurityConfigProperties.signatureDigest)
      log.info("Using ${algo} digest for signing SAML messages")
      signingConfiguration.setSignatureAlgorithms([algo.rsaSignatureMethod])
      signingConfiguration.setSignatureReferenceDigestMethods([algo.digestMethod])
    } else {
      log.warn("Unable to find global BasicSignatureSigningConfiguration (found '${signingConfiguration}'). Ignoring signatureDigest configuration value.")
    }
  }

//  @Bean Using RelyingPartyRegistration.Builder.assertionConsumerServiceBinding on relyingPartyRegistrationRepository
//  Saml2AuthenticationRequestFactory authenticationRequestFactory() {
//    OpenSamlAuthenticationRequestFactory authenticationRequestFactory = new OpenSamlAuthenticationRequestFactory()
//    authenticationRequestFactory.setProtocolBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect")
//    return authenticationRequestFactory
//  }

  RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() {
    RelyingPartyRegistration relyingPartyRegistration =
      RelyingPartyRegistrations.fromMetadataLocation(
        "https://armory.okta.com/app/exk7dma3uxKN4j4KW2p7/sso/saml/metadata")
        .assertingPartyDetails({ party -> party.wantAuthnRequestsSigned(false) })
      /* // Where to get party details? metadata.xml?
      .assertingPartyDetails(party -> party
                                     .singleSignOnServiceLocation("https://armory.okta.com/app/armory_zachsmithspinnaker_1/exk7dma3uxKN4j4KW2p7/sso/saml"))
                                     */
        .assertionConsumerServiceLocation("{baseUrl}/saml/SSO")
        .assertionConsumerServiceBinding(Saml2MessageBinding.REDIRECT)
        .build()
    return new InMemoryRelyingPartyRegistrationRepository(relyingPartyRegistration);
  }

  private Set<GrantedAuthority> extractRoles(Map<String, List<Object>> attributes,
                                             UserAttributeMapping userAttributeMapping) {
    def assertionRoles = attributes[userAttributeMapping.roles].collect { String roles ->
      def commonNames = roles.split(userAttributeMapping.rolesDelimiter)
      commonNames.collect {
        return it.indexOf("CN=") < 0 ? it : it.substring(it.indexOf("CN=") + 3, it.indexOf(","))
      }
    }.flatten() as Set<String>

    assertionRoles = assertionRoles*.toLowerCase() as Set<String>

    return AuthorityUtils.createAuthorityList(*assertionRoles)
  }

  @Autowired
  PermissionService permissionService

  @Autowired
  AllowedAccountsSupport allowedAccountsSupport

  @Autowired
  FiatClientConfigurationProperties fiatClientConfigurationProperties

  RetrySupport retrySupport = new RetrySupport()

  @Autowired
  Registry registry

  UserDetails loadUserByUsername(String username, Collection<String> roles) throws UsernameNotFoundException {
    if (samlSecurityConfigProperties.requiredRoles) {
      if (!samlSecurityConfigProperties.requiredRoles.any { it in roles }) {
        throw new BadCredentialsException("User $username does not have all roles $samlSecurityConfigProperties.requiredRoles")
      }
    }
    def id = registry
      .createId("fiat.login")
      .withTag("type", "saml")

    try {
      retrySupport.retry({ permissionService.loginWithRoles(username, roles) },
        5,
        Duration.ofSeconds(2),
        false)

      log.debug("Successful SAML authentication (user: {}, roleCount: {}, roles: {})", username, roles.size(), roles)
      id = id.withTag("success", true).withTag("fallback", "none")
    } catch (Exception e) {
      log.debug(
        "Unsuccessful SAML authentication (user: {}, roleCount: {}, roles: {}, legacyFallback: {})",
        username,
        roles.size(),
        roles,
        fiatClientConfigurationProperties.legacyFallback,
        e
      )
      id = id.withTag("success", false).withTag("fallback", fiatClientConfigurationProperties.legacyFallback)

      if (!fiatClientConfigurationProperties.legacyFallback) {
        throw e
      }
    } finally {
      registry.counter(id).increment()
    }
    def userAttributeMapping = samlSecurityConfigProperties.userAttributeMapping
    // We lose the email, firstname, lastname stuff here... and allowedAccounts is translated into granted authorities.
    // TODO:  Dynamic account impacts
    // DOWNSIDE:  What about if we do dynamic accounts with roles?  We'd NOT be getting a consistent list UNLESS we store
    // roles instead of granted accounts here, as this is persistent!!!
    return new org.springframework.security.core.userdetails.User(
      username, "",
      AllowedAccountsAuthorities.buildAllowedAccounts(allowedAccountsSupport.filterAllowedAccounts(username, roles))
    )
//    return new User(
//      email: email,
//      firstName: attributes[userAttributeMapping.firstName]?.get(0),
//      lastName: attributes[userAttributeMapping.lastName]?.get(0),
//      roles: roles,
//      allowedAccounts: allowedAccountsSupport.filterAllowedAccounts(username, roles),
//      username: username
//    )
  }

  // Available digests taken from org.opensaml.xml.signature.SignatureConstants (RSA signatures)
  private enum SignatureAlgorithms {
    SHA1(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1, SignatureConstants.ALGO_ID_DIGEST_SHA1),
    SHA256(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256, SignatureConstants.ALGO_ID_DIGEST_SHA256),
    SHA384(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA384, SignatureConstants.ALGO_ID_DIGEST_SHA384),
    SHA512(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512, SignatureConstants.ALGO_ID_DIGEST_SHA512),
    RIPEMD160(SignatureConstants.ALGO_ID_SIGNATURE_RSA_RIPEMD160, SignatureConstants.ALGO_ID_DIGEST_RIPEMD160),
    MD5(SignatureConstants.ALGO_ID_SIGNATURE_NOT_RECOMMENDED_RSA_MD5, SignatureConstants.ALGO_ID_DIGEST_NOT_RECOMMENDED_MD5)

    String rsaSignatureMethod
    String digestMethod
    SignatureAlgorithms(String rsaSignatureMethod, String digestMethod) {
      this.rsaSignatureMethod = rsaSignatureMethod
      this.digestMethod = digestMethod
    }

    static SignatureAlgorithms fromName(String digestName) {
      SignatureAlgorithms.find { it -> (it.name() == digestName.toUpperCase()) } as SignatureAlgorithms
    }
  }

}
