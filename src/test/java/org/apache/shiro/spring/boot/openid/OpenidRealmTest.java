package org.apache.shiro.spring.boot.openid;

import static org.assertj.core.api.Assertions.assertThat;

import org.apache.shiro.spring.boot.openid.realm.OpenidStatefulAuthorizingRealm;
import org.apache.shiro.spring.boot.openid.realm.OpenidStatelessAuthorizingRealm;
import org.apache.shiro.spring.boot.openid.token.OpenidAccessToken;
import org.junit.jupiter.api.Test;

/**
 * Tests for Openid realm classes.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
class OpenidRealmTest {

    @Test
    void statefulRealmShouldSupportOpenidAccessToken() {
        OpenidStatefulAuthorizingRealm realm = new OpenidStatefulAuthorizingRealm();
        assertThat(realm.getAuthenticationTokenClass()).isEqualTo(OpenidAccessToken.class);
    }

    @Test
    void statelessRealmShouldSupportOpenidAccessToken() {
        OpenidStatelessAuthorizingRealm realm = new OpenidStatelessAuthorizingRealm();
        assertThat(realm.getAuthenticationTokenClass()).isEqualTo(OpenidAccessToken.class);
    }
}
