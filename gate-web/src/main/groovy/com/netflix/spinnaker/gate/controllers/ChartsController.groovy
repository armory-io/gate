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


package com.netflix.spinnaker.gate.controllers

import com.netflix.spinnaker.gate.services.ImageService
import io.swagger.v3.oas.annotations.Operation
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.web.bind.annotation.*

import javax.servlet.http.HttpServletRequest

@RequestMapping("/charts")
@RestController
class ChartsController {
  @Autowired
  ImageService imageService

  @Operation(summary = "Retrieve a list of images, filtered by cloud provider, region, and account",
                description = "The query parameter `q` filters the list of images by image name")
  @RequestMapping(value = "/find", method = RequestMethod.GET)
  List<Map> findImages(@RequestParam(value = "provider", defaultValue = "dockerRegistry", required = false) String provider,
                       @RequestParam(value = "q", required = false) String query,
                       @RequestParam(value = "account", required = false) String account,
                       @RequestParam(value = "count", required = false) Integer count,
                       HttpServletRequest httpServletRequest) {
    Map<String, String> additionalFilters = httpServletRequest.getParameterNames().findAll { String parameterName ->
      !["provider", "q", "account", "count"].contains(parameterName.toLowerCase())
    }.collectEntries { String parameterName ->
      [parameterName, httpServletRequest.getParameter(parameterName)]
    }
    imageService.searchCharts(provider, query, account, count, additionalFilters, httpServletRequest.getHeader("X-RateLimit-Header"))
  }

  @Operation(summary = "Find tags")
  @RequestMapping(value = "/tags", method = RequestMethod.GET)
  List<String> findTags(@RequestParam(value = "provider", defaultValue = "aws", required = false) String provider,
                        @RequestParam(value = "account", required = true) String account,
                        @RequestParam(value = "repository", required = true) String repository,
                        @RequestHeader(value = "X-RateLimit-App", required = false) String sourceApp) {
    imageService.findChartTags(provider, account, repository, sourceApp)
  }
}
