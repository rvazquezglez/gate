/*
 * Copyright 2021 Netflix, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.netflix.spinnaker.gate.security.saml.spring
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.util.Assert
import org.springframework.security.core.Authentication


/**
 * An implementation of an {@link AbstractAuthenticationToken} that represents an authenticated SAML
 * 2.0 {@link Authentication}.
 *
 * <p>The {@link Authentication} associates valid SAML assertion data with a Spring Security
 * authentication object The complete assertion is contained in the object in String format, {@link
 * com.netflix.spinnaker.gate.security.saml.spring.SpinnakerSaml2Authentication#getSaml2Response()}
 *
 * @since 5.2* @see AbstractAuthenticationToken
 */
class SpinnakerSaml2Authentication extends AbstractAuthenticationToken {

  private final UserDetails principal
  private final String saml2Response

  SpinnakerSaml2Authentication(
    UserDetails principal,
    String saml2Response,
    Collection<? extends GrantedAuthority> authorities) {
    super(authorities)
    Assert.notNull(principal, "principal cannot be null")
    Assert.hasText(saml2Response, "saml2Response cannot be null")
    this.principal = principal
    this.saml2Response = saml2Response
    setAuthenticated(true)
  }

  @Override
  Object getPrincipal() {
    return this.principal
  }

  /**
   * Returns the SAML response object, as decoded XML. May contain encrypted elements
   *
   * @return string representation of the SAML Response XML object
   */
  String getSaml2Response() {
    return this.saml2Response
  }

  @Override
  Object getCredentials() {
    return getSaml2Response()
  }
}
