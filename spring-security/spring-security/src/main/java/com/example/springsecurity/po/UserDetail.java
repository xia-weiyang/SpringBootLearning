package com.example.springsecurity.po;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Created by zk on 2018/8/6.
 */
public class UserDetail implements UserDetails {

    private final String account;
    private final String password;
    private List<Role> roleList;

    public UserDetail(String account, String password) {
        this.account = account;
        this.password = password;
    }

    /**
     * 设置权限
     *
     * @param role
     */
    public void setRole(String role) {
        if (roleList == null) roleList = new ArrayList<>();
        roleList.add(new Role(role));
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roleList;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return account;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }


    @Override
    public String toString() {
        return "UserDetail{" +
                "account='" + account + '\'' +
                ", password='" + password + '\'' +
                ", roleList=" + roleList +
                '}';
    }

    public static class Role implements GrantedAuthority {

        private final String role;

        public Role(String role) {
            this.role = role;
        }

        @Override
        public String getAuthority() {
            return role;
        }
    }
}
