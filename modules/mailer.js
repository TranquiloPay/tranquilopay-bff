const path = require('path');
const nodemailer = require('nodemailer');
const hbs = require('nodemailer-express-handlebars');

const transport = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    service: 'gmail',
    secure: true,
    auth: { 
      user: process.env.EMAIL_USER, 
      pass: process.env.EMAIL_PASS
    },
    tls: {
      rejectUnauthorized: false
    }
  });

  /*transport.use('compile', hbs({
    viewEngine:'handlebars',
    viewPath: path.resolve('./resources/mail/'),
    extName: '.html',
  })); */

  transport.use('compile', hbs({
    viewEngine: {
      extName: '.html',
      partialsDir: path.resolve('./resources/mail/'),
      layoutsDir: path.resolve('./resources/mail/'),
      defaultLayout: 'auth/forgot_password.html',
  },
  viewPath: path.resolve('./resources/mail/'),
  extName: '.html'
}));

  module.exports = transport;