package org.apache.shiro.spring.boot;

import java.util.Map;

import org.apache.shiro.spring.boot.cache.ShiroEhCacheConfiguration;
import org.apache.shiro.spring.config.web.autoconfigure.ShiroWebAutoConfiguration;
import org.mitre.jose.keystore.JWKSetKeyStore;
import org.mitre.jwt.signer.service.JWTSigningAndValidationService;
import org.mitre.jwt.signer.service.impl.DefaultJWTSigningAndValidationService;
import org.mitre.jwt.signer.service.impl.JWKSetCacheService;
import org.mitre.openid.connect.client.OIDCAuthenticationFilter;
import org.mitre.openid.connect.client.OIDCAuthenticationProvider;
import org.mitre.openid.connect.client.OIDCAuthoritiesMapper;
import org.mitre.openid.connect.client.UserInfoFetcher;
import org.mitre.openid.connect.client.keypublisher.ClientKeyPublisher;
import org.mitre.openid.connect.client.service.AuthRequestOptionsService;
import org.mitre.openid.connect.client.service.AuthRequestUrlBuilder;
import org.mitre.openid.connect.client.service.ClientConfigurationService;
import org.mitre.openid.connect.client.service.IssuerService;
import org.mitre.openid.connect.client.service.RegisteredClientService;
import org.mitre.openid.connect.client.service.ServerConfigurationService;
import org.mitre.openid.connect.client.service.impl.EncryptedAuthRequestUrlBuilder;
import org.mitre.openid.connect.client.service.impl.HybridClientConfigurationService;
import org.mitre.openid.connect.client.service.impl.HybridIssuerService;
import org.mitre.openid.connect.client.service.impl.HybridServerConfigurationService;
import org.mitre.openid.connect.client.service.impl.InMemoryRegisteredClientService;
import org.mitre.openid.connect.client.service.impl.PlainAuthRequestUrlBuilder;
import org.mitre.openid.connect.client.service.impl.SignedAuthRequestUrlBuilder;
import org.mitre.openid.connect.client.service.impl.StaticAuthRequestOptionsService;
import org.mitre.openid.connect.web.UserInfoInterceptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.util.ObjectUtils;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import com.nimbusds.jose.jwk.JWK;

/**
 * 默认拦截器
 * <p>
 * Shiro内置了很多默认的拦截器，比如身份验证、授权等相关的。默认拦截器可以参考org.apache.shiro.web.filter.mgt.DefaultFilter中的枚举拦截器：&nbsp;&nbsp;
 * </p>
 * <table style="border-collapse: collapse; border: 1px; width: 100%;
 * table-layout: fixed;" class="aa" cellspacing="0" cellpadding="0" border="1">
 * <tbody>
 * <tr>
 * <td style="padding: 0cm 5.4pt 0cm 5.4pt; width: 150px;">
 * <p class="MsoNormal">
 * 默认拦截器名
 * </p>
 * </td>
 * <td style="padding: 0cm 5.4pt 0cm 5.4pt; width: 215px;">
 * <p class="MsoNormal">
 * 拦截器类
 * </p>
 * </td>
 * <td style="padding: 0cm 5.4pt 0cm 5.4pt;">
 * <p class="MsoNormal">
 * 说明（括号里的表示默认值）
 * </p>
 * </td>
 * </tr>
 * <tr>
 * <td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 * <p class="MsoNormal">
 * <strong>身份验证相关的</strong>
 * </p>
 * </td>
 * <td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 * <p class="MsoNormal">
 * &nbsp;
 * </p>
 * </td>
 * <td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 * <p class="MsoNormal">
 * &nbsp;
 * </p>
 * </td>
 * </tr>
 * <tr>
 * <td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 * <p class="MsoNormal">
 * authc
 * </p>
 * </td>
 * <td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 * <p class="MsoNormal">
 * org.apache.shiro.web.filter.authc
 * </p>
 * <p class="MsoNormal">
 * .FormAuthenticationFilter
 * </p>
 * </td>
 * <td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 * <p class="MsoNormal">
 * 基于表单的拦截器；如“/**=authc”，如果没有登录会跳到相应的登录页面登录；主要属性：usernameParam：表单提交的用户名参数名（
 * username）； &nbsp;passwordParam：表单提交的密码参数名（password）；
 * rememberMeParam：表单提交的密码参数名（rememberMe）；&nbsp;
 * loginUrl：登录页面地址（/login.jsp）；successUrl：登录成功后的默认重定向地址；
 * failureKeyAttribute：登录失败后错误信息存储key（shiroLoginFailure）；
 * </p>
 * </td>
 * </tr>
 * <tr>
 * <td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 * <p class="MsoNormal">
 * authcBasic
 * </p>
 * </td>
 * <td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 * <p class="MsoNormal">
 * org.apache.shiro.web.filter.authc
 * </p>
 * <p class="MsoNormal">
 * .BasicHttpAuthenticationFilter
 * </p>
 * </td>
 * <td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 * <p class="MsoNormal">
 * Basic HTTP身份验证拦截器，主要属性： applicationName：弹出登录框显示的信息（application）；
 * </p>
 * </td>
 * </tr>
 * <tr>
 * <td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 * <p class="MsoNormal">
 * logout
 * </p>
 * </td>
 * <td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 * <p class="MsoNormal">
 * org.apache.shiro.web.filter.authc
 * </p>
 * <p class="MsoNormal">
 * .LogoutFilter
 * </p>
 * </td>
 * <td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 * <p class="MsoNormal">
 * 退出拦截器，主要属性：redirectUrl：退出成功后重定向的地址（/）;示例“/logout=logout”
 * </p>
 * </td>
 * </tr>
 * <tr>
 * <td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 * <p class="MsoNormal">
 * user
 * </p>
 * </td>
 * <td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 * <p class="MsoNormal">
 * org.apache.shiro.web.filter.authc
 * </p>
 * <p class="MsoNormal">
 * .UserFilter
 * </p>
 * </td>
 * <td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 * <p class="MsoNormal">
 * 用户拦截器，用户已经身份验证/记住我登录的都可；示例“/**=user”
 * </p>
 * </td>
 * </tr>
 * <tr>
 * <td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 * <p class="MsoNormal">
 * anon
 * </p>
 * </td>
 * <td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 * <p class="MsoNormal">
 * org.apache.shiro.web.filter.authc
 * </p>
 * <p class="MsoNormal">
 * .AnonymousFilter
 * </p>
 * </td>
 * <td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 * <p class="MsoNormal">
 * 匿名拦截器，即不需要登录即可访问；一般用于静态资源过滤；示例“/static/**=anon”
 * </p>
 * </td>
 * </tr>
 * <tr>
 * <td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 * <p class="MsoNormal">
 * <strong>授权相关的</strong>
 * </p>
 * </td>
 * <td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 * <p class="MsoNormal">
 * &nbsp;
 * </p>
 * </td>
 * <td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 * <p class="MsoNormal">
 * &nbsp;
 * </p>
 * </td>
 * </tr>
 * <tr>
 * <td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 * <p class="MsoNormal">
 * roles
 * </p>
 * </td>
 * <td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 * <p class="MsoNormal">
 * org.apache.shiro.web.filter.authz
 * </p>
 * <p class="MsoNormal">
 * .RolesAuthorizationFilter
 * </p>
 * </td>
 * <td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 * <p class="MsoNormal">
 * 角色授权拦截器，验证用户是否拥有所有角色；主要属性：
 * loginUrl：登录页面地址（/login.jsp）；unauthorizedUrl：未授权后重定向的地址；示例“/admin/**=roles[admin]”
 * </p>
 * </td>
 * </tr>
 * <tr>
 * <td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 * <p class="MsoNormal">
 * perms
 * </p>
 * </td>
 * <td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 * <p class="MsoNormal">
 * org.apache.shiro.web.filter.authz
 * </p>
 * <p class="MsoNormal">
 * .PermissionsAuthorizationFilter
 * </p>
 * </td>
 * <td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 * <p class="MsoNormal">
 * 权限授权拦截器，验证用户是否拥有所有权限；属性和roles一样；示例“/user/**=perms["user:create"]”
 * </p>
 * </td>
 * </tr>
 * <tr>
 * <td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 * <p class="MsoNormal">
 * port
 * </p>
 * </td>
 * <td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 * <p class="MsoNormal">
 * org.apache.shiro.web.filter.authz
 * </p>
 * <p class="MsoNormal">
 * .PortFilter
 * </p>
 * </td>
 * <td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 * <p class="MsoNormal">
 * 端口拦截器，主要属性：port（80）：可以通过的端口；示例“/test=
 * port[80]”，如果用户访问该页面是非80，将自动将请求端口改为80并重定向到该80端口，其他路径/参数等都一样
 * </p>
 * </td>
 * </tr>
 * <tr>
 * <td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 * <p class="MsoNormal">
 * rest
 * </p>
 * </td>
 * <td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 * <p class="MsoNormal">
 * org.apache.shiro.web.filter.authz
 * </p>
 * <p class="MsoNormal">
 * .HttpMethodPermissionFilter
 * </p>
 * </td>
 * <td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 * <p class="MsoNormal">
 * rest风格拦截器，自动根据请求方法构建权限字符串（GET=read,
 * POST=create,PUT=update,DELETE=delete,HEAD=read,TRACE=read,OPTIONS=read,
 * MKCOL=create）构建权限字符串；示例“/users=rest[user]”，会自动拼出“user:read,user:create,user:update,user:delete”权限字符串进行权限匹配（所有都得匹配，isPermittedAll）；
 * </p>
 * </td>
 * </tr>
 * <tr>
 * <td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 * <p class="MsoNormal">
 * ssl
 * </p>
 * </td>
 * <td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 * <p class="MsoNormal">
 * org.apache.shiro.web.filter.authz
 * </p>
 * <p class="MsoNormal">
 * .SslFilter
 * </p>
 * </td>
 * <td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 * <p class="MsoNormal">
 * SSL拦截器，只有请求协议是https才能通过；否则自动跳转会https端口（443）；其他和port拦截器一样；
 * </p>
 * </td>
 * </tr>
 * <tr>
 * <td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 * <p class="MsoNormal">
 * <strong>其他</strong>
 * </p>
 * </td>
 * <td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 * <p class="MsoNormal">
 * &nbsp;
 * </p>
 * </td>
 * <td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 * <p class="MsoNormal">
 * &nbsp;
 * </p>
 * </td>
 * </tr>
 * <tr>
 * <td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 * <p class="MsoNormal">
 * noSessionCreation
 * </p>
 * </td>
 * <td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 * <p class="MsoNormal">
 * org.apache.shiro.web.filter.session
 * </p>
 * <p class="MsoNormal">
 * .NoSessionCreationFilter
 * </p>
 * </td>
 * <td style=" padding: 0cm 5.4pt 0cm 5.4pt;">
 * <p class="MsoNormal">
 * 不创建会话拦截器，调用 subject.getSession(false)不会有什么问题，但是如果 subject.getSession(true)将抛出
 * DisabledSessionException异常；
 * </p>
 * </td>
 * </tr>
 * </tbody>
 * </table>
 * 自定义Filter通过@Bean注解后，被Spring Boot自动注册到了容器的Filter
 * chain中，这样导致的结果是，所有URL都会被自定义Filter过滤，而不是Shiro中配置的一部分URL。
 * https://docs.spring.io/spring-boot/docs/current/reference/htmlsingle/#howto-disable-registration-of-a-servlet-or-filter
 * https://github.com/mitreid-connect/OpenID-Connect-Java-Spring-Server/wiki/Client-configuration
 */
@Configuration
@AutoConfigureBefore(ShiroWebAutoConfiguration.class)
@AutoConfigureAfter(ShiroEhCacheConfiguration.class)
@ConditionalOnProperty(prefix = ShiroOpenidProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ ShiroOpenidProperties.class })
public class ShiroOpenidAutoConfiguration implements ApplicationContextAware, WebMvcConfigurer {

	private static final Logger LOG = LoggerFactory.getLogger(ShiroOpenidAutoConfiguration.class);
	private ApplicationContext applicationContext;

	@Autowired
	private ShiroOpenidProperties properties;

	/**
	 * <b>Auth Provider</b> <br/>
	 * The OIDCAuthenticationProvider class implements a Spring Security
	 * Authentication Provider that can be used with a standard Authentication
	 * Manager. This Authentication Provider handles fetching UserInfo from the
	 * server's UserInfo endpoint. The UserInfo information is then stored on the
	 * OIDCAuthenticationToken object that is returned from the authentication
	 * process.
	 * @author ： <a href="https://github.com/vindell">vindell</a>
	 * @return
	 */
	@Bean
	@ConditionalOnMissingBean
	protected AuthenticationProvider authenticationProvider(
			@Autowired(required = false) UserInfoFetcher userInfoFetcher,
			@Autowired(required = false) OIDCAuthoritiesMapper authoritiesMapper) {
		OIDCAuthenticationProvider provider = new OIDCAuthenticationProvider();
		if(userInfoFetcher != null) {
			provider.setUserInfoFetcher(userInfoFetcher);
		}
		if(authoritiesMapper != null) {
			provider.setAuthoritiesMapper(authoritiesMapper);
		}
		return provider; 
	}
	
	@Bean
	@ConditionalOnMissingBean
	protected OIDCAuthenticationFilter authenticationFilter(
			@Autowired(required = false) UserInfoFetcher userInfoFetcher,
			@Autowired(required = false) OIDCAuthoritiesMapper authoritiesMapper) {
		OIDCAuthenticationFilter provider = new OIDCAuthenticationFilter();
		return provider; 
	}
	
	
	
	@Bean
	@ConditionalOnMissingBean
	protected UserInfoInterceptor userInfoInterceptor() {
		return new UserInfoInterceptor();
	}
	
	@Override
    public void addInterceptors(InterceptorRegistry registry) {
		//  Inject the UserInfo into the current context
        registry.addInterceptor(userInfoInterceptor());
    }
	
	/**
	 * This service tells the client which issuer, or root server URL, to talk to
	 * for a login request.
	 * 
	 * @author ： <a href="https://github.com/vindell">vindell</a>
	 * @return
	 */
	@Bean
	@ConditionalOnMissingBean
	protected IssuerService issuerService() {
		return new HybridIssuerService();
	}

	@Bean
	@ConditionalOnMissingBean
	protected ClientConfigurationService clientConfigurationService() {
		return new HybridClientConfigurationService();
	}

	@Bean
	@ConditionalOnMissingBean
	protected ServerConfigurationService serverConfigurationService() {
		return new HybridServerConfigurationService();
	}

	@Bean
	@ConditionalOnMissingBean
	protected RegisteredClientService registeredClientService() {
		return new InMemoryRegisteredClientService();
	}

	/**
	 * <b>Static Authorization Request Options Service</b> <br/>
	 * This service will return the same Map of options regardless of the context of
	 * the client, server, or request. <br/>
	 * It is configured by passing in a map of options and their values.
	 * 
	 * @author ： <a href="https://github.com/vindell">vindell</a>
	 * @return
	 */
	@Bean
	@ConditionalOnMissingBean
	protected AuthRequestOptionsService authRequestOptionsService() {
		return new StaticAuthRequestOptionsService();
	}

	@Bean
	@ConditionalOnMissingBean
	protected ClientKeyPublisher clientKeyPublisher(JWTSigningAndValidationService defaultsignerService) {

		ClientKeyPublisher publisher = new ClientKeyPublisher();
		publisher.setJwkPublishUrl(properties.getJwkPublishUrl());
		publisher.setSigningAndValidationService(defaultsignerService);

		return publisher;
	}

	@Bean
	@ConditionalOnMissingBean
	protected JWTSigningAndValidationService signingAndValidationService(JWKSetKeyStore keyStore,
			String defaultSignerId, String algName) throws Exception {

		DefaultJWTSigningAndValidationService signingAndValidationService = null;

		Map<String, JWK> keys = getApplicationContext().getBeansOfType(JWK.class);
		if (ObjectUtils.isEmpty(keys)) {
			signingAndValidationService = new DefaultJWTSigningAndValidationService(keys);
		} else {
			signingAndValidationService = new DefaultJWTSigningAndValidationService(keyStore);
		}
		signingAndValidationService.setDefaultSignerKeyId(defaultSignerId);
		signingAndValidationService.setDefaultSigningAlgorithmName(algName);
		return signingAndValidationService;
	}

	/**
	 * <b>Authorization Request URL Builder</b> <br/>
	 * In order to direct the user to the authorization endpoint of the IdP, the
	 * client filter must create a URL to send to the user's browser.<br/>
	 * This is handled by the Authorization Request URL Builder service. <br/>
	 * 
	 * @author ： <a href="https://github.com/vindell">vindell</a>
	 * @return
	 */
	@Bean
	@ConditionalOnMissingBean
	protected AuthRequestUrlBuilder authRequestUrlBuilder(JWTSigningAndValidationService signingAndValidationService,
			JWKSetCacheService encrypterService) {

		if (signingAndValidationService != null) {
			// 1、Signed Authorization Request ：Builds the URL using a signed Request Object.
			SignedAuthRequestUrlBuilder urlBuilder = new SignedAuthRequestUrlBuilder();
			urlBuilder.setSigningAndValidationService(signingAndValidationService);
			return urlBuilder;
		}

		else if (encrypterService != null) {
			// 2、Encrypted Authorization Request ：Builds the URL using an encrypted Request
			// Object.
			EncryptedAuthRequestUrlBuilder urlBuilder = new EncryptedAuthRequestUrlBuilder();
			urlBuilder.setEncrypterService(encrypterService);
			return urlBuilder;
		}

		else {
			// 3、Plain Authorization Request : Builds the URL using normal HTTP parameters.
			return new PlainAuthRequestUrlBuilder();
		}

	}

	@Override
	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		this.applicationContext = applicationContext;
	}

	public ApplicationContext getApplicationContext() {
		return applicationContext;
	}

}
