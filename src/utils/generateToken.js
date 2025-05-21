const jwt = require('jsonwebtoken')
const config = require('../config')
const { TIME } = require('../constant/app.constant')

const generateToken = (id, email) =>
  jwt.sign({ id, email }, config.get('JWT_SECRET'), {
    expiresIn: TIME.JWT_EXP_TIME
  })

module.exports = generateToken
