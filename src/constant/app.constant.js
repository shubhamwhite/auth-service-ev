const { JWT } = require('google-auth-library')
const config = require('../config')

const URL = {
  BASE: `${config.get('APP_URL')}${config.get('PORT')}/api/v1`
}

const TIME = {
  JWT_EXP_TIME: '1h'
}

module.exports = { URL, TIME }
