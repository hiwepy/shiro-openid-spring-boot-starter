/*
 * Copyright (c) 2017, vindell (https://github.com/vindell).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.shiro.spring.boot;

import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheManager;
import org.mitre.openid.connect.config.ServerConfiguration;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(ShiroOpenidProperties.PREFIX)
public class ShiroOpenidProperties {

	public static final String PREFIX = "shiro.openid";
	
	/**
	 * Enable Shiro Openid.
	 */
	private boolean enabled = false;
	
	private String defaultSignerKeyId;
	
	private String jwkPublishUrl;
	
	/**
	 * map of issuer url -> server configuration information 
	 */
	private Map<String /* pattert */, ServerConfiguration /* Server Configuration */> servers = new LinkedHashMap<String, ServerConfiguration>();
	
	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public Map<String, ServerConfiguration> getServers() {
		return servers;
	}

	public void setServers(Map<String, ServerConfiguration> servers) {
		this.servers = servers;
	}

	public String getDefaultSignerKeyId() {
		return defaultSignerKeyId;
	}

	public void setDefaultSignerKeyId(String defaultSignerKeyId) {
		this.defaultSignerKeyId = defaultSignerKeyId;
	}

	public String getJwkPublishUrl() {
		return jwkPublishUrl;
	}

	public void setJwkPublishUrl(String jwkPublishUrl) {
		this.jwkPublishUrl = jwkPublishUrl;
	}

}

