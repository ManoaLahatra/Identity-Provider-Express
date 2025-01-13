const express = require("express");
const firebaseAdmin = require("firebase-admin");
const cors = require("cors");
const dotenv = require("dotenv");
const firebaseAuth = require("firebase-admin").auth;
const app = express();
const port = 3000;

// Charger les variables d'environnement du fichier .env
dotenv.config();

// Initialisation de Firebase Admin avec les clés de service depuis les variables d'environnement
const serviceAccount = {
  type: "service_account",
  projectId: process.env.PROJECT_ID,
  privateKey: process.env.PRIVATE_KEY.replace(/\\n/g, '\n'),
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


app.use(cors());
app.use(express.json());

// Endpoint pour se connecter
app.post("/login", async (req, res) => {
  const { idToken, email, password } = req.body;

  try {
    let customToken;

    if (email && password) {
        // Authentifier avec l'email et le mot de passe
        const userRecord = await firebaseAdmin.auth().getUserByEmail(email);
        
        // Générer un token personnalisé pour l'utilisateur
        customToken = await firebaseAdmin.auth().createCustomToken(userRecord.uid);
        return res.status(200).send({
          message: "Authentification réussie avec email et mot de passe",
          uid: userRecord.uid,
          token: customToken
        });
    }

    if (idToken) {
      // Vérifier le token d'identification Firebase
      const decodedToken = await firebaseAdmin.auth().verifyIdToken(idToken);
      const uid = decodedToken.uid;
      
      // Générer un token personnalisé pour l'utilisateur
      customToken = await firebaseAdmin.auth().createCustomToken(uid);
      
      return res.status(200).send({
        message: "Authentification réussie avec token",
        uid: uid,
        token: customToken
      });
    }

    return res.status(400).send({ message: "Aucun token ou identifiants fournis" });
  } catch (error) {
    res.status(401).send({ message: "Échec de l'authentification", error: error.message });
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

    // Générer un token personnalisé pour l'utilisateur créé
    const customToken = await firebaseAdmin.auth().createCustomToken(userRecord.uid);

    // Retourner la réponse avec le token personnalisé
    res.status(201).send({
      message: "Utilisateur créé",
      uid: userRecord.uid,
      token: customToken, // Token généré
    });
  } catch (error) {
    res.status(400).send({ message: "Erreur lors de la création de l'utilisateur", error: error.message });
  }
});

// Endpoint protégé
app.get("/private", async (req, res) => {
  const idToken = req.headers.authorization?.split("Bearer ")[1];

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
