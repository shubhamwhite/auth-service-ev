const router = require('express').Router()
const { getAllCompanies } = require('../controllers/company.controller')

router.route('/get/all').get(getAllCompanies)

module.exports = router
