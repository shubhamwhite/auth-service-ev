// docs/swagger.js
const YAML = require('yamljs')
const path = require('path')

const swaggerDocument = YAML.load(path.join(__dirname, 'auth.swagger.yaml'))

module.exports = swaggerDocument
