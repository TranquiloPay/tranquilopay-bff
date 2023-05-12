const mongoose = require('mongoose')

const User = mongoose.model('User', {
    name: String,
    cpf: String,
    state: String,
    city: String,
    street: String,
    district: String,
    number: String,
    complement: String,
    email: String,
    phone: String,
    password: String
})

module.exports = User
