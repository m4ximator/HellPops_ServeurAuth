package mcpr.helpops_serveurAuth;

import mcpr.hellpops_interfaces.IAuthService;
import mcpr.hellpops_interfaces.Jeton;

import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

public class Authentification extends UnicastRemoteObject implements IAuthService {

    private final Map<String, User> sessionsActives = new ConcurrentHashMap<>();
    private final List<User> utilisateursEnBase = new CopyOnWriteArrayList<>();

    public Authentification() throws RemoteException {
        super();
    }

    @Override
    public void inscription(String username, String passwd) {
        User user = new User(username, passwd);
        utilisateursEnBase.add(user);
        //ecriture dans le fichier json
    }

    @Override
    public Jeton connexion(String username, String password) throws RemoteException {
        StringBuilder chaine = new StringBuilder();
        User userTrouve = chercherUser(username, password);

        if (userTrouve != null) {
            Jeton jeton = delivrerJeton();
            sessionsActives.put(jeton.getValeur(), userTrouve);
            chaine.append("Connexion reussie pour : ").append(username);
            System.out.println(chaine.toString());
            return jeton;
        }
        chaine.append("Tentative de connexion echouee pour : ").append(username);
        System.out.println(chaine.toString());
        return null;
    }

    @Override
    public void deconnexion() {
        // TODO Auto-generated method stub

    }

    private Jeton delivrerJeton() {
        long deuxJours = 2L * 24 * 60 * 60 * 1000;
        Date dateExp = new Date(System.currentTimeMillis() + deuxJours);
        return new Jeton(dateExp);
    }

    @Override
    public boolean estValide(Jeton jeton) throws RemoteException {
        // Vérification validite jeton
        if (jeton == null) return false;
        return sessionsActives.containsKey(jeton.getValeur()) && jeton.getDateExpiration().after(new Date());
    }

    public User chercherUser(String username, String password) {
        //ajouter du hashage et chiffrement
        for (User user : utilisateursEnBase) {
            if (user.getUsername().equals(username) && user.getPassword().equals(password)) {
                return user;
            }
        }
        return null;
    }

}
