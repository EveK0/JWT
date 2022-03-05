const express = require("express");
require("dotenv").config();
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const app = express();
const PORT = 3000;

// Models
const User = require("./models/User");
const res = require("express/lib/response");

// CONFIG
app.use(express.json());

// OPEN ROUTE - PUBLIC ROUTE
app.get("/", (req, res) => {
  res.status(200).json({ msg: "Bem vindo!" });
});
// Private route
const checkToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split("")[1];
  if (!token) {
    return res.status(401).json({ msg: "acesso negado!" });
  }
  try {
    const secret = process.env.SECRET;
    jwt.verify(token, secret);
    next();
  } catch (error) {
    res.status(400).json({msg: "Acesso invalido!"})
  }
};
app.get("/user/:id", checkToken, async (req, res) => {
  const id = req.params.id;
  const user = await User.findById(id, "-password");
  if (!user) {
    return res.status(404).json({ msg: "usuario não encontrado!" });
  }
  res.status(200).json({ user });
});

// Register User
app.post("/auth/register", async (req, res) => {
  const { name, email, password, confirmPassword } = req.body;
  // Validation
  if (!name) {
    return res.status(422).json({ msg: "O nome é obrigatório!" });
  } else if (!email) {
    return res.status(422).json({ msg: "O email é obrigatório!" });
  } else if (!password) {
    return res.status(422).json({ msg: "A senha é obrigatória!" });
  } else if (password != confirmPassword) {
    return res.status(422).json({ msg: "As senhas devem ser iguais!" });
  }
  // Check if user exists
  const userExists = await User.findOne({ email: email });
  if (userExists) {
    return res.status(422).json({ msg: "Email já existente!" });
  }
  // create password
  const salt = await bcrypt.genSalt(12);
  const passwordHash = await bcrypt.hash(password, salt);
  // create user
  const user = new User({
    name,
    email,
    password: passwordHash,
  });
  try {
    await user.save();
    res.status(201).json({ msg: "Usuário criado com sucesso!" });
  } catch (error) {
    console.log(error);
    res.status(500).json({
      msg: "Ocorreu um erro no servidor, tente novamente mais tarde!",
    });
  }
});
// Auth user
app.post("/auth/login/", async (req, res) => {
  const { email, password } = req.body;
  // validations
  if (!email) {
    res.status(201).json({ msg: "Por favor, digite um email!" });
  } else if (!password) {
    res.status(201).json({ msg: "Por favor, digite uma senha!" });
  }
  // check if exists
  const user = await User.findOne({ email: email });
  if (!user) {
    return res.status(404).json({ msg: "Usuario inexistente!" });
  }
  // check password
  const checkPass = await bcrypt.compare(password, user.password);
  if (!checkPass) {
    return res.status(422).json({ msg: "Senha invalida!" });
  }
  try {
    const secret = process.env.SECRET;
    const token = jwt.sign(
      {
        id: user._id,
      },
      secret
    );
    res.status(200).json({ msg: "Autenticação realizada com sucesso!", token });
  } catch (error) {
    console.log(error);
    res.status(500).json({
      msg: "Ocorreu um erro no servidor, tente novamente mais tarde!",
    });
  }
});

// Credentials
const dbUser = process.env.DB_USER;
const dbPass = process.env.DB_PASS;

mongoose
  .connect(
    `mongodb+srv://${dbUser}:${dbPass}@cluster0.icpli.mongodb.net/myFirstDatabase?retryWrites=true&w=majority`
  )
  .then(() => {
    console.log("Database connected");
  })
  .catch((err) => {
    console.log(err);
  });

app.listen(PORT);
