package mcpr.helpops_serveurAuth;

import java.rmi.Naming;
import java.rmi.registry.LocateRegistry;

public class Main {
    public static void main(String args[]) {
        try {
            // 1. Démarre le rmi registry
            LocateRegistry.createRegistry(1099);

            // 2. Instancie objet
            Authentification obj = new Authentification();

            // 3. Déclare l'objet auprès du serveur de noms
            Naming.rebind("AuthService", obj);

            System.out.println("Le Serveur d'Authentification est déclaré et prêt !");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}