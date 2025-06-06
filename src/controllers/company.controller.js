const db = require('../models')
const { User: _User } = db
const { responder } = require('../constant/response')
const path = require('path')
const fs = require('fs')
const { URL } = require('../constant/app.constant') // your base URL config

exports.getAllCompanies = async (req, res) => {
  try {
    const companies = await _User.findAll({
      where: { role: 'company' },
      attributes: [
        'id',
        'role',
        'first_name',
        'last_name',
        'email',
        'is_verified',
        'profile_image',
        'login_type',
        'block',
        'google_id',
        'ip_address',
        'last_login_ip',
        'user_agent',
        'verification_otp',
        'otp_expires_at',
        'updatedAt',
        'createdAt'
      ],
      order: [['createdAt', 'DESC']]
    })

    if (!companies || companies.length === 0) {
      return res.status(404).json({ message: 'No companies found' })
    }

    // Process each company's profile_image like in getUser
    for (const company of companies) {
      const imagePath = company.profile_image || ''
      const fileName = imagePath.split('/').pop()
      const profilePicPath = path.join(__dirname, '..', 'uploads', 'Profile-Pic', fileName)
      const fileExists = fs.existsSync(profilePicPath)

      if (fileExists) {
        company.profile_image = imagePath.startsWith(URL.BASE)
          ? imagePath
          : `/uploads/Profile-Pic/${fileName}`
      } else {
        company.profile_image = '/uploads/Profile-Pic/user.png'
        await company.save() // save updated image path to DB
      }

      // Add full URL prefix
      company.profile_image = `${URL.BASE}${company.profile_image}`
    }

    return responder(res, 200, 'Companies fetched successfully', companies)
  } catch (error) {
    console.error('Error fetching companies:', error)
    return responder(res, 500, 'Internal server error')
  }
}
