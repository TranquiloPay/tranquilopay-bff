/* imports */
require('dotenv').config()
const express = require('express')
const cors = require('cors');
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()

app.use(cors());

//Config JSON response
app.use(express.json())

//Models
const User = require('./models/User')

//Open Route - Public Route
app.get('/', (req, res) => {
    res.status(200).json({ msg: "API TranquiloPay" })
})

//Private Route
app.get("/user/:id", checkToken, async (req, res) => {
    const id = req.params.id

    //Check if user exists
    const user = await User.findById(id, '-password')

    if (!user) {
        return res.status(404).json({ msg: "Usuário não encontrado." })
    }

    res.status(200).json({ user })
})

function checkToken(req, res, next) {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" ")[1]

    if (!token) {
        return res.status(401).json({ msg: 'Acesso negado!' })
    }

    try {
        const secret = process.env.SECRET

        jwt.verify(token, secret)

        next()
    } catch (error) {
        res.status(400).json({ msg: "Token inválido!" })
    }
}

//Register User
app.post('/auth/register', async (req, res) => {
    const { name, cpf, state, city, street, district, number, email, phone, password, confirmpassword } = req.body

    //Validations
    if (!name) {
        return res.status(422).json({ msg: 'O nome é obrigatório!' })
    }

    if (!cpf) {
        return res.status(422).json({ msg: 'O CPF é obrigatório!' })
    }

    if (!state) {
        return res.status(422).json({ msg: 'O estado é obrigatório!' })
    }

    if (!city) {
        return res.status(422).json({ msg: 'A cidade é obrigatória!' })
    }

    if (!street) {
        return res.status(422).json({ msg: 'A rua é obrigatória!' })
    }

    if (!district) {
        return res.status(422).json({ msg: 'O bairro é obrigatório!' })
    }

    if (!number) {
        return res.status(422).json({ msg: 'O número da casa é obrigatório!' })
    }

    if (!email) {
        return res.status(422).json({ msg: 'O email é obrigatório!' })
    }

    if (!phone) {
        return res.status(422).json({ msg: 'O telefone é obrigatório!' })
    }

    if (!password) {
        return res.status(422).json({ msg: 'A senha é obrigatória!' })
    }

    let regex = /^(?=.*[a-zA-Z])(?=.*[0-9])(?=.*[!@#$%*()_+^&}{:;?.])(?:([0-9a-zA-Z!@#$%;*(){}_+^&])(?!\1)){8,}$/;

    if (!(regex.test(password))) {
        return res.status(422).json({ msg: 'A senha deve conter pelo menos uma letra maiúscula e uma minúscula, um número, um caractere especial e mais de 8 caracteres!' })
    }

    if (password !== confirmpassword) {
        return res.status(422).json({ msg: 'As senhas não conferem!' })
    }

    //Check if user dont exists
    const userExists = await User.findOne({ email: email })

    if (userExists) {
        return res.status(422).json({ msg: 'Email já cadastrado, por favor, insira outro email.' })
    }

    //Create password
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    //Create user
    const user = new User({
        name,
        cpf,
        state,
        city,
        street,
        district,
        number,
        complement,
        email,
        phone,
        password: passwordHash,
    })

    try {
        await user.save()

        res.status(201).json({ msg: 'Usuário criado com sucesso!' })
    } catch (error) {
        console.log(error)

        res.status(500).json({
            msg: 'Aconteceu um erro inesperado, por favor, tente novamente mais tarde',
        })
    }
})

//Login User
app.post("/auth/login", async (req, res) => {
    const { email, password } = req.body

    //Validations
    if (!email) {
        return res.status(422).json({ msg: 'O email é obrigatório!' })
    }

    if (!password) {
        return res.status(422).json({ msg: 'A senha é obrigatória!' })
    }

    //Check if user exists
    const user = await User.findOne({ email: email })

    if (!user) {
        return res.status(404).json({ msg: 'Usuário não encontrado.' })
    }

    //Check if password match
    const checkPassword = await bcrypt.compare(password, user.password)

    if (!checkPassword) {
        return res.status(422).json({ msg: 'Senha inválida.' })
    }

    try {
        const secret = process.env.SECRET

        const token = jwt.sign(
            {
                id: user._id,
            },
            secret,
        )
        res.status(200).json({ msg: "Autenticação realizada com sucesso!", token })
    } catch (error) {
        console.log(error)

        res.status(500).json({
            msg: 'Aconteceu um erro inesperado, por favor, tente novamente mais tarde',
        })
    }
})

//Credencials
const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS

//Port Heroku
const port = process.env.PORT

mongoose
    .connect(
        `mongodb://${dbUser}:${dbPassword}@ac-1rdolrj-shard-00-00.nulb9ru.mongodb.net:27017,ac-1rdolrj-shard-00-01.nulb9ru.mongodb.net:27017,ac-1rdolrj-shard-00-02.nulb9ru.mongodb.net:27017/?ssl=true&replicaSet=atlas-3alxqw-shard-0&authSource=admin&retryWrites=true&w=majority`,
    )
    .then(() => {
        app.listen(port)
        console.log('Conectado!')
    })
    .catch((err) => console.log(err))


