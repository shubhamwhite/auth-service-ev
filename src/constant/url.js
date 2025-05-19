const config = require('../config')

const URL = {
  BASE: `${config.get('APP_URL')}${config.get('PORT')}/api/v1`
}

module.exports = URL
