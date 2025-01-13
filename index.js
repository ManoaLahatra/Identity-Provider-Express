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
  projectId: process.env.PROJECT_ID,
  privateKey: process.env.PRIVATE_KEY.replace(/\\n/g, '\n'),  // Remplacer les \n par des sauts de ligne
  clientEmail: process.env.CLIENT_EMAIL,
  clientId: process.env.CLIENT_ID,
  authUri: process.env.AUTH_URI,
  tokenUri: process.env.TOKEN_URI,
  authProviderX509CertUrl: process.env.AUTH_PROVIDER_X509_CERT_URL,
  clientX509CertUrl: process.env.CLIENT_X509_CERT_URL,
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
    res.status(401).send({ message: "Token invalide ou expiré", error: error.message });
  }
});

app.listen(port, () => {
  console.log(`Le serveur écoute sur le port ${port}`);
});
