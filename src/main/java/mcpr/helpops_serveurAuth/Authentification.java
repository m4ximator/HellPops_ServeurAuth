package mcpr.helpops_serveurAuth;

import mcpr.hellpops_interfaces.IAuthService;
import mcpr.hellpops_interfaces.Jeton;

import java.io.*;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import mcpr.hellpops_interfaces.Role;

import java.lang.reflect.Type;

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

import java.security.MessageDigest;

public class Authentification extends UnicastRemoteObject implements IAuthService {

    private final Map<String, User> sessionsActives = new ConcurrentHashMap<>();
    private final List<User> utilisateursEnBase = new CopyOnWriteArrayList<>();

    private final String CHEMIN_FICHIER = "utilisateurs.json";
    private final Gson gson = new GsonBuilder().setPrettyPrinting().create();

    public Authentification() throws RemoteException {
        super();
        chargerDonnees();
    }

    @Override
    public boolean inscription(String username, String passwd) {

        String mdp_chiff = HashMdp(passwd);

        if (verif_login_doublon(username)) {
            System.out.println("Inscription refusée, login déjà existant ! ");
            return false;
        }

        User user = new User(username, mdp_chiff, Role.UTILISATEUR);
        utilisateursEnBase.add(user);

        System.out.println("Nouvel utilisateur inscrit en base : " + username);

        //ecriture dans le fichier JSON
        sauvegarderDonnees();

        return true;
    }



    @Override
    public Jeton connexion(String username, String password) throws RemoteException {
        StringBuilder chaine = new StringBuilder();
        User userTrouve = chercherUser(username, password);

        if (userTrouve != null) {
            Jeton jeton = delivrerJeton(userTrouve);
            sessionsActives.put(jeton.getValeur(), userTrouve);
            chaine.append("Connexion reussie pour : ").append(username);
            System.out.println(chaine);
            return jeton;
        }
        chaine.append("Tentative de connexion echouee pour : ").append(username);
        System.out.println(chaine);
        return null;
    }

    @Override
    public void deconnexion(Jeton jeton) {
        if (jeton != null) {
            //supprime l'entrée et renvoie le User associé
            User userDeconnecte = sessionsActives.remove(jeton.getValeur());

            if (userDeconnecte != null) {
                System.out.println("Déconnexion reussie pour : " + userDeconnecte.getUsername());
            }
        }
    }

    @Override
    public boolean estValide(Jeton jeton) throws RemoteException {
        // Vérification validite jeton
        if (jeton == null) return false;
        return sessionsActives.containsKey(jeton.getValeur()) && jeton.getDateExpiration().after(new Date());
    }


    private Jeton delivrerJeton(User userCo) {
        long deuxJours = 2L * 24 * 60 * 60 * 1000;
        Date dateExp = new Date(System.currentTimeMillis() + deuxJours);
        return new Jeton(dateExp,userCo.getUsername(), userCo.getRole()
        );
    }

    @Override
    public String getLoginParJeton(Jeton jeton) throws RemoteException {
        if (estValide(jeton)) {
            User u = sessionsActives.get(jeton.getValeur());
            return (u != null) ? u.getUsername() : null;
        }
        return null;
    }

    @Override
    public Role getRoleParJeton(Jeton jeton) throws RemoteException {

        if (estValide(jeton)) {
            User u = sessionsActives.get(jeton.getValeur());
            return (u != null) ? u.getRole() : null;
        }

        return null;

    }

    private boolean verif_login_doublon(String login) {

        for (User user : utilisateursEnBase) {
            if (user.getUsername().equals(login)) {
                return true;
            }
        }

        return false;
    }

    // methode permettant de chiffrer le mdp de l'utilisateur lors de l'inscription / connexion
    public String HashMdp(String mdp) {

        try {
            MessageDigest sha_256 = MessageDigest.getInstance("SHA-256");
            byte[] hash = sha_256.digest(mdp.getBytes());

            StringBuilder hash_hexa = new StringBuilder();
            for (byte b : hash) {
                hash_hexa.append(String.format("%02x", b));
            }

            return hash_hexa.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    public User chercherUser(String username, String password) {

        String mdp_chiff = HashMdp(password);

        for (User user : utilisateursEnBase) {
            if (user.getUsername().equals(username) && user.getPassword().equals(mdp_chiff)) {
                return user;
            }
        }

        return null;
    }

    private void sauvegarderDonnees() {
        //déclaration dans les parenthèses pour fermeture du fichier automatique
        try (FileWriter writer = new FileWriter(CHEMIN_FICHIER)) {
            //Transformation liste en texte JSON
            gson.toJson(utilisateursEnBase, writer);
        } catch (Exception e) {
            System.err.println("Erreur lors de la sauvegarde JSON : " + e.getMessage());
        }
    }

    private void chargerDonnees() {
        File fichier = new File(CHEMIN_FICHIER);
        if (fichier.exists()) {
            try (FileReader reader = new FileReader(fichier)) {
                //Astuce Gson pour lire une liste typée (permet d'instancier le bon type)
                Type typeListe = new TypeToken<List<User>>() {
                }.getType();
                List<User> usersCharges = gson.fromJson(reader, typeListe);

                if (usersCharges != null) {
                    utilisateursEnBase.addAll(usersCharges);
                    String chaine = "Base chargée : " +
                            utilisateursEnBase.size() +
                            " utilisateur(s).";
                    System.out.println(chaine);
                }

            } catch (Exception e) {
                System.err.println("Impossible de lire le fichier JSON : " + e.getMessage());
            }
        } else {
            System.out.println("Aucun fichier JSON trouvé, démarrage avec une base vide.");
        }
    }

}
