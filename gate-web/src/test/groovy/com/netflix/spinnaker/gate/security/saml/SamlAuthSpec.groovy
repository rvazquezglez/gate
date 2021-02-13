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

package com.netflix.spinnaker.gate.security.saml

import com.netflix.spinnaker.gate.Main
import com.netflix.spinnaker.gate.config.RedisTestConfig
import com.netflix.spinnaker.gate.security.GateSystemTest
import com.netflix.spinnaker.gate.security.YamlFileApplicationContextInitializer
import groovy.util.logging.Slf4j
import org.apache.commons.io.FileUtils
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Primary
import org.springframework.http.MediaType
import org.springframework.test.context.ContextConfiguration
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.MvcResult
import spock.lang.Specification

import javax.servlet.http.Cookie
import java.nio.file.Paths

import static org.hamcrest.core.StringContains.containsString
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status

@Slf4j
@GateSystemTest
@SpringBootTest(
  properties = ['saml.enabled=true', 'spring.application.name=gate', 'fiat.enabled=false', 'services.fiat.baseUrl=https://localhost'])
@ContextConfiguration(
  classes = [Main, SamlSsoConfig, SamlSsoTestConfig, RedisTestConfig],
  initializers = YamlFileApplicationContextInitializer
)
@AutoConfigureMockMvc
class SamlAuthSpec extends Specification {

  @Autowired
  MockMvc mockMvc

  def "should allow http-basic authentication"() {
    when:
    def result = mockMvc.perform(
      get("/credentials")
        .with(httpBasic("batman", "batman")))
      .andDo(print())
      .andExpect(status().isOk())
      .andReturn()

    then:
    result.response.contentAsString.contains("form action=\"https&#x3a;&#x2f;&#x2f;test.com&#x2f;app&#x2f;sso&#x2f;saml\" method=\"post\"")
  }

  def "should do saml authentication"() {
    setup:
    Cookie sessionCookie = null
    def extractSession = { MvcResult result ->
      sessionCookie = result.response.getCookie("SESSION")
    }

    when:
    mockMvc.perform(get("/auth/user"))
      .andDo(print())
      .andExpect(status().is2xxSuccessful())
      .andExpect(content().string(""))

    mockMvc.perform(get("/auth/redirect?to=http%3A%2F%2Flocalhost%3A9000%2F"))
      .andDo(print())
      .andExpect(status().is2xxSuccessful())
      .andExpect(content().string(containsString("form action=\"https&#x3a;&#x2f;&#x2f;test.com&#x2f;app&#x2f;sso&#x2f;saml\" method=\"post\"")))
      .andDo(extractSession)

    // TODO: test process saml response
    println "Sending saml response"
    mockMvc.perform(
      post("/saml/SSO")
        .accept(MediaType.APPLICATION_FORM_URLENCODED)
        .param("SAMLResponse", FileUtils.readFileToString(new File("src/test/resources/saml/test-saml-response.txt"), "UTF-8"))
        .cookie(sessionCookie))
      .andExpect(status().is2xxSuccessful())

    then:
    mockMvc.perform(get("/auth/user"))
      .andDo(print())
      .andExpect(status().is2xxSuccessful())
      .andExpect(content().string(""))
  }

  static class SamlSsoTestConfig {
    @Bean
    @Primary
    @ConfigurationProperties("saml")
    SamlSsoConfig.SAMLSecurityConfigProperties samlConfigProps() {
      new SamlSsoConfig.SAMLSecurityConfigProperties().tap {
        metadataUrl = "file://${Paths.get("").toAbsolutePath()}/src/test/resources/saml/metadata.xml"
        keyStore = "file://${Paths.get("").toAbsolutePath()}/src/test/resources/saml/test-keystore.jks"
        keyStorePassword = 'keypassword'
        keyStoreAliasName = 'saml'
        issuerId = 'localhost:8084'
        redirectHostname = 'localhost:8084'
        redirectBasePath = '/'
        redirectProtocol = 'http'
        maxAuthenticationAge = Integer.MAX_VALUE
        responseSkew = Integer.MAX_VALUE
      }
    }
  }
}
