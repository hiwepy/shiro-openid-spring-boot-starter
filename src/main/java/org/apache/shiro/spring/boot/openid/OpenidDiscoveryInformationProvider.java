/*
 * Copyright (c) 2018, vindell (https://github.com/vindell).
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
package org.apache.shiro.spring.boot.openid;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.openid4java.discovery.DiscoveryInformation;

/**
 * Openid DiscoveryInformation Provider
 * @author 		： <a href="https://github.com/vindell">vindell</a>
 */
public interface OpenidDiscoveryInformationProvider {

	/**
	 * store the discovery information in the user's session  
	 * @author 		： <a href="https://github.com/vindell">vindell</a>
	 * @param request
	 * @param response
	 * @param discovered
	 */
	 void setDiscovered(ServletRequest request, ServletResponse response, DiscoveryInformation discovered);

	 /**
	  * retrieve the previously stored discovery information  
	  * @author 		： <a href="https://github.com/vindell">vindell</a>
	  * @param request
	  * @param response
	  * @return
	  */
	 DiscoveryInformation getDiscovered(ServletRequest request, ServletResponse response);
	 
}
