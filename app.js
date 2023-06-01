/* imports */
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const axios = require("axios");

const app = express();

app.use(cors());

//Config JSON response
app.use(express.json());

//Models
const User = require("./models/User");

//Open Route - Public Route
app.get("/", (req, res) => {
  res.status(200).json({ msg: "API TranquiloPay" });
});

//Private Route
app.get("/user/:id", checkToken, async (req, res) => {
  const id = req.params.id;

  //Check if user exists
  const user = await User.findById(id, "-password");

  if (!user) {
    return res.status(404).json({ msg: "Usuário não encontrado." });
  }

  res.status(200).json({ user });
});

function checkToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ msg: "Acesso negado!" });
  }

  try {
    const secret = process.env.SECRET;

    jwt.verify(token, secret);

    next();
  } catch (error) {
    res.status(400).json({ msg: "Token inválido!" });
  }
}

const checkUserExists = async (req, res, next) => {
  const identifier = req.params.identifier;
  const email = req.body.email;
  const cpf = req.body.cpf;

  try {
    const user = await User.findOne({
      $or: [{ cpf: identifier ?? cpf }, { email: identifier ?? email }],
    }).exec();

    if (user) {
      req.isUserAlreadyExists = true;
    } else {
      req.isUserAlreadyExists = false;
    }

    next();
  } catch (error) {
    res.status(500).json({
      msg: "Aconteceu um erro inesperado, por favor, tente novamente mais tarde",
    });
  }
};

// Verify if CPF or Email already exists
app.get("/user/exists/:identifier/", checkUserExists, (req, res) => {
  res.status(200).json({ isUserAlreadyExists: req.isUserAlreadyExists });
});

//Register User
app.post("/auth/register", checkUserExists, async (req, res) => {
  if (req.isUserAlreadyExists) {
    return res.status(422).json({ msg: "Usuário já cadastrado." });
  }

  const requiredFields = [
    "name",
    "cpf",
    "state",
    "city",
    "street",
    "district",
    "number",
    "email",
    "phone",
    "password",
    "confirmpassword",
  ];

  const errors = [];

  for (const field of requiredFields) {
    if (!req.body[field]) {
      errors.push(`O campo ${field} é obrigatório!`);
    }
  }

  if (errors.length > 0) {
    return res.status(422).json({ errors });
  }

  const { body } = req;

  let regex =
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[~!@#$%^&*()_\-+=|{}[\]:;<>?,./])(?!.*\s).{8,}$/;

  if (!regex.test(body.password)) {
    return res.status(422).json({
      msg: "A senha deve conter pelo menos uma letra maiúscula e uma minúscula, um número, um caractere especial e mais de 8 caracteres!",
    });
  }

  if (body.password !== body.confirmpassword) {
    return res.status(422).json({ msg: "As senhas não conferem!" });
  }

  //Create password
  const salt = await bcrypt.genSalt(12);
  const passwordHash = await bcrypt.hash(body.password, salt);
  body.password = passwordHash;

  //Create user
  const user = new User(body);

  try {
    await user.save();

    res.status(201).json({ msg: "Usuário criado com sucesso!" });
  } catch (error) {
    console.log(error);

    res.status(500).json({
      msg: "Aconteceu um erro inesperado, por favor, tente novamente mais tarde",
    });
  }
});

//Login User
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;

  //Validations
  if (!email) {
    return res.status(422).json({ msg: "O email é obrigatório!" });
  }

  if (!password) {
    return res.status(422).json({ msg: "A senha é obrigatória!" });
  }

  //Check if user exists
  const user = await User.findOne({ email: email });

  if (!user) {
    return res.status(404).json({ msg: "Usuário não encontrado." });
  }

  //Check if password match
  const checkPassword = await bcrypt.compare(password, user.password);

  if (!checkPassword) {
    return res.status(422).json({ msg: "Senha inválida." });
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
      msg: "Aconteceu um erro inesperado, por favor, tente novamente mais tarde",
    });
  }
});

//Create Debit
app.post("/payments", async (req, res) => {
  const requestBody = req.body;

  // Define a lista de validações
  const validations = [
    {
      field: requestBody.customer,
      fieldName: "customer",
      errorMsg: "O customer é obrigatório!",
    },
    {
      field: requestBody.billingType,
      fieldName: "billingType",
      errorMsg: "O billingType é obrigatório!",
    },
    {
      field: requestBody.dueDate,
      fieldName: "dueDate",
      errorMsg: "O dueDate é obrigatório!",
    },
    {
      field: requestBody.value,
      fieldName: "value",
      errorMsg: "O value é obrigatório!",
    },
  ];

  // Verifica se algum campo obrigatório está faltando
  const missingFields = validations.filter((validation) => !validation.field);
  if (missingFields.length > 0) {
    return res.status(422).json({ msg: missingFields[0].errorMsg });
  }

  // Array com os valores válidos para billingType
  const validBillingTypes = ["BOLETO", "CREDIT_CARD", "PIX", "UNDEFINED"];

  // Verifica se o valor do campo billingType é válido
  if (!validBillingTypes.includes(requestBody.billingType)) {
    return res.status(422).json({ msg: "O billingType é inválido!" });
  }

  try {
    const response = await axios.post(
      "https://www.asaas.com/api/v3/payments",
      requestBody,
      {
        headers: {
          "Content-Type": "application/json",
          access_token: apiKey,
        },
      }
    );

    res.status(200).json({
      msg: "Débito criado com sucesso!",
      url: response.data.invoiceUrl,
      data: response.data,
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({
      msg: error.message,
    });
  }
});

//Credencials
const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASS;
const apiKey = process.env.API_KEY;

//Port Heroku
const port = 3000;

mongoose
  .connect(
    `mongodb://${dbUser}:${dbPassword}@ac-1rdolrj-shard-00-00.nulb9ru.mongodb.net:27017,ac-1rdolrj-shard-00-01.nulb9ru.mongodb.net:27017,ac-1rdolrj-shard-00-02.nulb9ru.mongodb.net:27017/?ssl=true&replicaSet=atlas-3alxqw-shard-0&authSource=admin&retryWrites=true&w=majority`
  )
  .then(() => {
    app.listen(port);
    console.log(`Envie requisições para: http://localhost:${port}/`);
    console.log("Conectado!");
  })
  .catch((err) => console.log(err));
