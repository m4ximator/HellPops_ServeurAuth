package mcpr.helpops_serveurAuth;

import mcpr.hellpops_interfaces.IAuthService;
import mcpr.hellpops_interfaces.Jeton;

import java.io.*;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

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
    public void inscription(String username, String passwd) {
        User user = new User(username, passwd);
        utilisateursEnBase.add(user);
        System.out.println("Nouvel utilisateur inscrit en base : " + username);
        //ecriture dans le fichier JSON
        sauvegarderDonnees();
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

    private Jeton delivrerJeton() {
        long deuxJours = 2L * 24 * 60 * 60 * 1000;
        Date dateExp = new Date(System.currentTimeMillis() + deuxJours);
        return new Jeton(dateExp);
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
                Type typeListe = new TypeToken<List<User>>() {}.getType();
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
