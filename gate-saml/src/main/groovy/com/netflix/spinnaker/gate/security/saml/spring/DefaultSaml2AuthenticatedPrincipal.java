/*
 * Copyright 2020 Netflix, Inc.
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

package com.netflix.spinnaker.gate.security.saml.spring;

import java.io.Serializable;
import java.security.Principal;
import java.util.List;
import java.util.Map;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.util.Assert;

public class DefaultSaml2AuthenticatedPrincipal
    implements Saml2AuthenticatedPrincipal, Serializable, Principal {

  private final String name;

  private final Map<String, List<Object>> attributes;

  public DefaultSaml2AuthenticatedPrincipal(String name, Map<String, List<Object>> attributes) {
    Assert.notNull(name, "name cannot be null");
    Assert.notNull(attributes, "attributes cannot be null");
    this.name = name;
    this.attributes = attributes;
  }

  @Override
  public String getName() {
    return this.name;
  }

  public Map<String, List<Object>> getAttributes() {
    return this.attributes;
  }
}
