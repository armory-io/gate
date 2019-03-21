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

import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * X509ProxyAuthenticationFilter grabs an X509 certificate from the HTTP header and adds it to the request attribute
 * for the X509AuthentifcationFilter.
 *
 * It does not perform any validation besides checking the header contains an X509 certificate.
 *
 */
public class X509ProxyAuthenticationFilter extends GenericFilterBean {
  private String proxyCertificateHeader;

  public X509ProxyAuthenticationFilter(String proxyCertificateHeader) {
    this.proxyCertificateHeader = proxyCertificateHeader;
  }

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
    try {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");

      String clientCert = ((HttpServletRequest) request).getHeader(proxyCertificateHeader);
      if (clientCert != null) {
        String decodedCert = URLDecoder.decode(clientCert, StandardCharsets.UTF_8.name());
        X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(decodedCert.getBytes()));
        X509Certificate[] certs = new X509Certificate[1];
        certs[0] = cert;
        request.setAttribute("javax.servlet.request.X509Certificate", certs);
      }
    } catch (CertificateException e) {
      logger.info("Unable to get X509 certificate factory", e);
    }
    chain.doFilter(request, response);
  }
}
