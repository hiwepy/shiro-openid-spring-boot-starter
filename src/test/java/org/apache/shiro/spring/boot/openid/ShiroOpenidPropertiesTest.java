package org.apache.shiro.spring.boot.openid;

import static org.assertj.core.api.Assertions.assertThat;

import org.apache.shiro.spring.boot.ShiroOpenidProperties;
import org.junit.jupiter.api.Test;

/**
 * Tests for {@link ShiroOpenidProperties}.
 *
 * @author <a href="https://github.com/loong10k">Loong Wan</a>
 * @since 1.0.0
 */
class ShiroOpenidPropertiesTest {

    @Test
    void shouldHaveCorrectPrefix() {
        assertThat(ShiroOpenidProperties.PREFIX).isEqualTo("shiro.openid");
    }

    @Test
    void shouldDefaultToDisabled() {
        ShiroOpenidProperties props = new ShiroOpenidProperties();
        assertThat(props.isEnabled()).isFalse();
    }

    @Test
    void shouldAllowEnabling() {
        ShiroOpenidProperties props = new ShiroOpenidProperties();
        props.setEnabled(true);
        assertThat(props.isEnabled()).isTrue();
    }

    @Test
    void shouldAllowDisabling() {
        ShiroOpenidProperties props = new ShiroOpenidProperties();
        props.setEnabled(true);
        props.setEnabled(false);
        assertThat(props.isEnabled()).isFalse();
    }
}
