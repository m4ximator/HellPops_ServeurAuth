package mcpr.helpops_serveurAuth;

public class User {

    public static final String UTILISATEUR = "Utilisateur";
    public static final String AGENT = "Agent";

    private final String username;
    private final String password;
    private String role;

    public User(String username, String password, String role) {
        this.username = username;
        this.password = password;
        this.role = role;
    }

    public String getUsername() { return username; }

    public String getPassword() { return password; }

    public String getRole() { return role; }


}

