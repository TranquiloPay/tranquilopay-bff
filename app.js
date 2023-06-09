/* imports */
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const crypto = require("crypto");
const mailer = require("./modules/mailer");

const app = express();

// Config CORS
app.use(cors());

// Config JSON response
app.use(express.json());

// Models
const User = require("./models/User");

// Functions Auxiliaries //

// Validate CPF
const isValidateCPF = (cpf) => {
  // Transforma o CPF em String, caso seja um número
  cpf = cpf.toString();

  // Remove caracteres que não são dígitos
  cpf = cpf.replace(/\D/g, "");

  // Verifica se possui 11 dígitos
  if (cpf.length !== 11) {
    return false;
  }

  // Verifica se todos os dígitos são iguais (ex: 11111111111)
  if (/^(\d)\1+$/.test(cpf)) {
    return false;
  }

  // Calcula o primeiro dígito verificador
  let sum = 0;
  for (let i = 0; i < 9; i++) {
    sum += parseInt(cpf.charAt(i)) * (10 - i);
  }
  let mod = sum % 11;
  let digit1 = mod < 2 ? 0 : 11 - mod;

  // Verifica o primeiro dígito verificador
  if (parseInt(cpf.charAt(9)) !== digit1) {
    return false;
  }

  // Calcula o segundo dígito verificador
  sum = 0;
  for (let i = 0; i < 10; i++) {
    sum += parseInt(cpf.charAt(i)) * (11 - i);
  }
  mod = sum % 11;
  let digit2 = mod < 2 ? 0 : 11 - mod;

  // Verifica o segundo dígito verificador
  if (parseInt(cpf.charAt(10)) !== digit2) {
    return false;
  }

  // CPF válido
  return true;
};

// Validate required fields
const validateRequiredFields = (fields, body) => {
  const missingFields = [];
  for (const field of fields) {
    if (!body[field]) {
      missingFields.push(field);
    }
  }
  return missingFields;
};

// Middlewares //

// Check if token is valid
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

// Check if CPF or Email already exists
const checkUserExists = async (req, res, next) => {
  const { email, cpf } = req.body;

  try {
    let user;
    if (email) {
      user = await User.findOne({ email }).exec();

      if (user) {
        return res.status(422).json({ msg: "Usuário já cadastrado." });
      }
    }

    if (cpf) {
      user = await User.findOne({ cpf }).exec();

      if (user) {
        return res.status(422).json({ msg: "Usuário já cadastrado." });
      }

      if (!user) {
        try {
          const response = await axios.get(
            `https://www.asaas.com/api/v3/customers?cpfCnpj=${cpf}`,
            {
              headers: {
                "Content-Type": "application/json",
                access_token: apiKey,
              },
            }
          );
          if(response.data.totalCount){
            return res.status(422).json({ msg: "CPF já cadastrado!" });
          }
        } catch (error) {
          console.log(error);
        }
      }
    }

    next();
  } catch (error) {
    res.status(500).json({
      msg: "Aconteceu um erro inesperado, por favor, tente novamente mais tarde",
    });
  }
};

// Validate Registration
const validateRegistration = async (req, res, next) => {
  const requiredFields = [
    "name",
    "cpf",
    "email",
    "password",
    "confirmpassword",
  ];
  const missingFields = validateRequiredFields(requiredFields, req.body);

  if (missingFields.length > 0) {
    return res.status(422).json({
      errors: missingFields.map((field) => `O campo ${field} é obrigatório!`),
    });
  }

  const { body } = req;

  let regexPassword =
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[~!@#$%^&*()_\-+=|{}[\]:;<>?,./])(?!.*\s).{8,}$/;

  if (!regexPassword.test(body.password)) {
    return res.status(422).json({
      msg: "A senha deve conter pelo menos uma letra maiúscula e uma minúscula, um número, um caractere especial e mais de 8 caracteres!",
    });
  }

  if (body.password !== body.confirmpassword) {
    return res.status(422).json({ msg: "As senhas não conferem!" });
  }

  
  if (!isValidateCPF(body.cpf)) {
    return res.status(422).json({ msg: "CPF inválido!" });
  }

  try {
    // Create password
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(body.password, salt);
    body.password = passwordHash;

    next();
  } catch (error) {
    res.status(500).json({
      msg: "Aconteceu um erro inesperado, por favor, tente novamente mais tarde",
    });
  }
};

// Create Customer in Asaas
const createCustomer = async (req, res, next) => {
  const { name, cpfCnpj, email } = req.body;

  try {
    const response = await axios.post(
      "https://www.asaas.com/api/v3/customers",
      {
        name,
        cpfCnpj,
        email,
      },
      {
        headers: {
          access_token: apiKey,
        },
      }
    );

    // Se a criação do cliente foi bem-sucedida, armazene o ID do cliente na requisição
    req.body.customerId = response.data.id;
    next();
  } catch (error) {
    console.error(error);
    return res.status(500).json({ msg: "Ocorreu um erro ao criar o cliente." });
  }
};

// Routes //

// Open Route - Public Route
app.get("/", (req, res) => {
  res.status(200).json({ msg: "API TranquiloPay" });
});

// Get User
app.get("/user/:id", checkToken, async (req, res) => {
  const id = req.params.id;

  //Check if user exists
  const user = await User.findById(id, "-password");

  if (!user) {
    return res.status(404).json({ msg: "Usuário não encontrado." });
  }

  res.status(200).json({ user });
});

// Get Users
app.get("/users", async (req, res) => {
  try {
    const users = await User.find({}, "-password");

    if (users.length === 0) {
      return res.status(404).json({ msg: "Nenhum usuário encontrado." });
    }

    res.status(200).json({ users });
  } catch (error) {
    console.error(error);
    res.status(500).json({ msg: "Ocorreu um erro ao buscar os usuários." });
  }
});


// Verify if CPF or Email already exists
// ToDo: implement this method correct
app.get("/user/exists/:identifier/", checkUserExists, (req, res) => {
  res.status(200).json({ isUserAlreadyExists: req.isUserAlreadyExists });
});

// Verify if CPF already exists in Asaas
app.get("/customers", async (req, res) => {
  const cpfCnpj = req.query.cpfCnpj;

  try {
    const response = await axios.get(
      `https://www.asaas.com/api/v3/customers?cpfCnpj=${cpfCnpj}`,
      {
        headers: {
          "Content-Type": "application/json",
          access_token: apiKey,
        },
      }
    );

    res.status(200).json({
      msg: response.data.totalCount
        ? "CPF já cadastrado!"
        : "CPF não cadastrado!",
      isCpfAlreadyUsed: !!response.data.totalCount,
      data: response.data,
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({
      msg: error.message,
    });
  }
});

// Register User
app.post(
  "/auth/register",
  validateRegistration,
  checkUserExists,
  createCustomer,
  async (req, res) => {
    // Create user
    const user = new User(req.body);

    // Save user in database
    try {
      await user.save();

      res.status(201).json({ msg: "Usuário criado com sucesso!" });
    } catch (error) {
      console.log(error);

      res.status(500).json({
        msg: "Aconteceu um erro inesperado, por favor, tente novamente mais tarde",
      });
    }
  }
);

// Login User
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

  const userObj = {
    name: user.name,
    cpf: user.cpf,
    email: user.email,
    customerId: user.customerId,
  }

  try {
    const secret = process.env.SECRET;

    const token = jwt.sign(
      {
        id: user._id,
      },
      secret
    );
    res.status(200).json({ msg: "Autenticação realizada com sucesso!", token, user: userObj });
  } catch (error) {
    console.log(error);

    res.status(500).json({
      msg: "Aconteceu um erro inesperado, por favor, tente novamente mais tarde",
    });
  }
});

// Create Debit
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
    return res.status(422).json({ msg: "O Tipo de pagamento é inválido!" });
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

// Esqueci minha senha
app.post("/auth/forgot_password", async (req, res) => {
  const { email } = req.body; //E-mail que quer recuperar a senha

  try {
    const user = await User.findOne({ email }); //Faz a busca do usuário no Banco de dados, verificando se ele está cadastrado

    if (!user)
      return res
        .status(400)
        .send({ error: "Usuário não encontrado em nossa base de dados" });

    //Geração do token para o usuário poder alterar a senha
    const token = crypto.randomBytes(20).toString("hex");

    //Data e tempo de expiração do token
    const now = new Date();
    now.setHours(now.getHours() + 1);

    await User.findByIdAndUpdate(
      user.id,
      {
        $set: {
          passwordResetToken: token,
          passwordResetExpires: now,
        },
      },
      { new: true, useFindAndModify: false }
    );

    mailer.sendMail(
      {
        to: email,
        subject: "Recuperação de acesso",
        from: "tranquilopay@gmail.com",
        template: "auth/forgot_password",
        context: { token },
      },
      (err) => {
        if (err)
          return res.status(400).send({
            error: "Não foi possivel enviar o e-mail de recuperação de senha",
          });

        return res.status(200).send({ status: "E-mail enviado com sucesso" });
      }
    );
  } catch (err) {
    res.status(400).send({
      error:
        "Falha no sistema de recuperação de senha, tente novamente mais tarde",
    });
  }
});

// Cadastro da nova senha
app.post("/auth/reset_password", async (req, res) => {
  const { email, token, password } = req.body;

  try {
    const user = await User.findOne({ email }).select(
      "+passwordResetToken passwordResetExpires"
    );

    if (!user)
      return res
        .status(400)
        .send({ error: "Usuário não encontrado em nossa base de dados" });

    if (token !== user.passwordResetToken)
      return res.status(400).send({ error: "O tokken informado não é valido" });

    //Verificação da expiração do token
    const now = new Date();

    if (now > user.passwordResetExpires)
      return res.status(400).send({
        error: "O tokken informado está espirado, por favor gere um novo",
      });

    user.password = password;

    await user.save();

    return res.status(200).send({ status: "Senha alterada com sucesso" });
  } catch (err) {
    return res.status(400).send({
      error: "Não foi possivel alterar sua senha, tente novamente mais tarde",
    });
  }
});

// Credencials //
const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASS;
const apiKey = process.env.API_KEY;

// Port Heroku
const port = process.env.PORT; // 3000;

// Connect to MongoDB //
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
