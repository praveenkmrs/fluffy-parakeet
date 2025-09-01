package pk.ai.shopping_cart.service.impl;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import pk.ai.shopping_cart.entity.User;
import pk.ai.shopping_cart.repository.UserRepository;

import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * UserDetailsService implementation for Spring Security authentication
 */
@Slf4j
@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.debug("Loading user by username: {}", username);

        User user = userRepository.findByUsernameOrEmail(username, username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        return new CustomUserPrincipal(user);
    }

    /**
     * Custom UserDetails implementation
     */
    public static class CustomUserPrincipal implements UserDetails {

        private final User user;

        public CustomUserPrincipal(User user) {
            this.user = user;
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            Set<User.UserRole> roles = user.getRoles();
            if (roles == null || roles.isEmpty()) {
                return Set.of(new SimpleGrantedAuthority("ROLE_USER"));
            }

            return roles.stream()
                    .map(role -> new SimpleGrantedAuthority("ROLE_" + role.name()))
                    .collect(Collectors.toSet());
        }

        @Override
        public String getPassword() {
            return user.getPasswordHash();
        }

        @Override
        public String getUsername() {
            return user.getUsername();
        }

        @Override
        public boolean isAccountNonExpired() {
            return true; // We can add account expiration logic later if needed
        }

        @Override
        public boolean isAccountNonLocked() {
            return user.getStatus() != User.UserStatus.SUSPENDED;
        }

        @Override
        public boolean isCredentialsNonExpired() {
            return true; // We can add credential expiration logic later if needed
        }

        @Override
        public boolean isEnabled() {
            return user.getStatus() == User.UserStatus.ACTIVE ||
                    user.getStatus() == User.UserStatus.PENDING_VERIFICATION;
        }

        /**
         * Get the underlying User entity
         */
        public User getUser() {
            return user;
        }
    }
}
