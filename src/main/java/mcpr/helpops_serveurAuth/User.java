package mcpr.helpops_serveurAuth;

import mcpr.hellpops_interfaces.Role;

public class User {

    private final String username;
    private final String password;
    private Role role;

    public User(String username, String password, Role role) {
        this.username = username;
        this.password = password;
        this.role = role;
    }

    public String getUsername() { return username; }

    public String getPassword() { return password; }

    public Role getRole() { return role; }


}

