const express = require("express");
const firebaseAdmin = require("firebase-admin");
const cors = require("cors");
const dotenv = require("dotenv");  // Ajouter dotenv
const app = express();
const port = 3000;

// Charger les variables d'environnement du fichier .env
dotenv.config();

// Initialisation de Firebase Admin avec les clés de service depuis les variables d'environnement
const serviceAccount = {
  type: "service_account",
  apiKey: process.env.VITE_API_KEY,
  authDomain: process.env.VITE_AUTH_DOMAIN,
  projectId: process.env.VITE_PROJECT_ID,
  storageBucket: process.env.VITE_STORAGE_BUCKET,
  messagingSenderId: process.env.VITE_MESSAGING_SENDER_ID,
  appId: process.env.VITE_APP_ID,
};

firebaseAdmin.initializeApp({
  credential: firebaseAdmin.credential.cert(serviceAccount),
});

// Middleware
app.use(cors());
app.use(express.json()); // pour pouvoir traiter les données JSON

// Endpoint pour se connecter
app.post("/login", async (req, res) => {
  const { idToken } = req.body; // Le token Firebase envoyé depuis le frontend

  try {
    // Vérification du token ID envoyé par le frontend
    const decodedToken = await firebaseAdmin.auth().verifyIdToken(idToken);
    const uid = decodedToken.uid;
    res.status(200).send({ message: "Authentification réussie", uid });
  } catch (error) {
    res.status(401).send({ message: "Token invalide ou expiré", error: error.message });
  }
});

// Endpoint pour s'inscrire (sign-up)
app.post("/signup", async (req, res) => {
  const { email, password } = req.body;

  try {
    // Créer un utilisateur avec l'email et le mot de passe
    const userRecord = await firebaseAdmin.auth().createUser({
      email: email,
      password: password,
    });

    res.status(201).send({ message: "Utilisateur créé", uid: userRecord.uid });
  } catch (error) {
    res.status(400).send({ message: "Erreur lors de la création de l'utilisateur", error: error.message });
  }
});

// Endpoint protégé
app.get("/private", async (req, res) => {
  const idToken = req.headers.authorization?.split("Bearer ")[1]; // Extraire le token du header

  if (!idToken) {
    return res.status(401).send({ message: "Token manquant" });
  }

  try {
    const decodedToken = await firebaseAdmin.auth().verifyIdToken(idToken);
    const uid = decodedToken.uid;
    res.status(200).send({ message: "Accès autorisé", uid });
  } catch (error) {
    res.status(401).send({ message: "Token invalide", error: error.message });
  }
});

// Démarrer le serveur
app.listen(port, () => {
  console.log(`Identify Provider started.`);
});
