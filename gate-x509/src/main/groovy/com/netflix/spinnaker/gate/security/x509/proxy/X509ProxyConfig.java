/*
 * Copyright 2019 Armory, Inc.
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

package com.netflix.spinnaker.gate.security.x509.proxy;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

/**
 * Enables the passing of X509 certificates via HTTP headers.
 * Use with care and only with Gate behind a proxy as there is no validation on the X509 certificate itself.
 *
 * roleOids and subjectPrincipalRegex apply here too as the X509AuthenticationFilter is still used.
 */
@ConditionalOnExpression("${x509.proxy.enabled:false}")
@Configuration
@EnableWebSecurity
class X509ProxyConfig {

  @Bean
  public X509ProxyAuthenticationFilter x509ProxyAuthenticationFilter(@Value("${x509.proxy.header:ssl-client-cert}") String x509ProxyHeader) {
    return new X509ProxyAuthenticationFilter(x509ProxyHeader);
  }
}

