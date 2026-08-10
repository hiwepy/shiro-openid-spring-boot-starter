package org.apache.shiro.spring.boot.openid;

import static org.assertj.core.api.Assertions.assertThat;

import org.apache.shiro.spring.boot.openid.token.OpenidAccessToken;
import org.junit.jupiter.api.Test;

/**
 * Tests for {@link OpenidAccessToken}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
class OpenidAccessTokenTest {

    @Test
    void shouldCreateTokenWithHost() {
        OpenidAccessToken token = new OpenidAccessToken("192.168.1.1");
        assertThat(token.getHost()).isEqualTo("192.168.1.1");
        assertThat(token.getPrincipal()).isEqualTo("192.168.1.1");
        assertThat(token.getCredentials()).isEqualTo("192.168.1.1");
    }

    @Test
    void shouldHandleNullHost() {
        OpenidAccessToken token = new OpenidAccessToken(null);
        assertThat(token.getHost()).isNull();
        assertThat(token.getPrincipal()).isNull();
        assertThat(token.getCredentials()).isNull();
    }

    @Test
    void shouldHandleEmptyHost() {
        OpenidAccessToken token = new OpenidAccessToken("");
        assertThat(token.getHost()).isEmpty();
        assertThat(token.getPrincipal()).isEqualTo("");
        assertThat(token.getCredentials()).isEqualTo("");
    }
}
