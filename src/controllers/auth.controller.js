const db = require('../models')
const { User: _User } = db
const config = require('../config')
const { deleteImage } = require('../helper/imageUpload.helper')
const { generateOTP } = require('../utils/generateOTP')
const { responder } = require('../constant/response')
const generateToken = require('../utils/generateToken')
const { OAuth2Client } = require('google-auth-library')
const { connectRabbitMQ, getChannel } = require('../service/rabbitmq.service')
const CustomErrorHandler = require('../utils/CustomError')
const bcrypt = require('bcryptjs')
const { URL } = require('../constant/app.constant')
const fs = require('fs')
const path = require('path')

exports.signup = async (req, res, next) => {
  try {
    const { first_name, last_name, email, password, role } = req.body

    // Validate role - only 'user' and 'company' allowed in signup
    const allowedRoles = ['user', 'company']
    const userRole = allowedRoles.includes(role) ? role : 'user'

    const profileImagePath =
      req.file && req.file.filename
        ? `/uploads/${req.file.filename}`
        : '/uploads/user.png'

    const existingUser = await _User.findOne({ where: { email } })

    if (existingUser) {
      if (req.file?.filename) {
        deleteImage(req.file.filename)
      }
      return next(CustomErrorHandler.alreadyExist('User already exists'))
    }

    const hashedPassword = await bcrypt.hash(password, 10)
    const otp = generateOTP(6)

    const newUser = await _User.create({
      first_name,
      last_name,
      email,
      password: hashedPassword,
      verification_otp: otp,
      is_verified: false,
      otp_expires_at: new Date(Date.now() + 1 * 60 * 1000),
      profile_image: profileImagePath,
      role: userRole,
      ip_address: req.metadata.ip_address,
      user_agent: req.metadata.user_agent
    })

    const { password: _, ...user } = newUser.dataValues

    const channel = getChannel() || (await connectRabbitMQ())

    const emailJob = { email, otp, name: first_name, flag: 'verify' }
    channel.sendToQueue('emailQueue', Buffer.from(JSON.stringify(emailJob)), {
      persistent: true
    })

    console.log('+++++emailJob+++++', userRole)

    if (userRole === 'company') {
      const welcomeJob = { email, name: first_name, flag: 'welcome-company' }
      channel.sendToQueue('emailQueue', Buffer.from(JSON.stringify(welcomeJob)), {
        persistent: true
      })} else {
      const welcomeJob = { email, name: first_name, flag: 'welcome-user' }
      channel.sendToQueue('emailQueue', Buffer.from(JSON.stringify(welcomeJob)), {
        persistent: true
      })}

    const token = generateToken({
      id: newUser.id,
      email: newUser.email,
      role: userRole
    })
    res.cookie('token', token, { maxAge: 86400000, httpOnly: true })
    user.profile_image = `${URL.BASE}${user.profile_image}`

    return responder(
      res,
      201,
      'User created successfully. Check your email for OTP verification',
      {
        user,
        token
      }
    )
  } catch (err) {
    if (req.file && req.file.filename) {
      deleteImage(req.file.filename)
    }
    console.error('Error in signup:', err)
    return next(err)
  }
}

exports.login = async (req, res, next) => {
  try {
    const { email, password } = req.body

    if (!email || !password) {
      return responder(res, 400, 'Email and password are required')
    }

    const user = await _User.findOne({ where: { email } })

    if (!user) {
      return responder(res, 404, 'User not found')
    }

    if (!user.is_verified) {
      return responder(res, 403, 'User is not verified')
    }

    const isPasswordValid = await bcrypt.compare(password, user.password)

    if (!isPasswordValid) {
      return responder(res, 401, 'Invalid email and password')
    }

    if (user.role !== 'user' && user.role !== 'company') {
      return responder(res, 403, 'Role not allowed to login')
    }

    // ✅ Fix: update using the instance
    await user.update({
      last_login_ip: req.metadata?.last_login_ip || req.ip,
      user_agent: req.metadata?.user_agent || req.headers['user-agent']
    })

    user.profile_image = `${URL.BASE}${user.profile_image}`
    const { password: _, ...userData } = user.dataValues

    const token = generateToken({
      id: user.id,
      email: user.email,
      role: user.role
    })
    res.cookie('token', token, { maxAge: 24 * 60 * 60 * 1000, httpOnly: true })

    return responder(res, 200, 'Login successful', { ...userData, token })
  } catch (err) {
    console.error('Error in login:', err)
    return next(err)
  }
}

exports.googleLogin = async (req, res, next) => {
  const client = new OAuth2Client(config.get('GOOGLE_CLIENT_ID')) // from .env
  try {
    const { idToken, role } = req.body

    if (!idToken) {
      return responder(res, 400, 'ID Token is required')
    }

    const allowedRoles = ['user', 'company']
    const userRole = allowedRoles.includes(role) ? role : 'user'

    const ticket = await client.verifyIdToken({
      idToken,
      audience: config.get('GOOGLE_CLIENT_ID')
    })

    const payload = ticket.getPayload()
    const { sub: google_id, email, given_name, family_name, picture } = payload

    let user = await _User.findOne({ where: { google_id } })

    if (user) {
      if (user.role !== userRole) {
        return responder(
          res,
          403,
          `You are registered as a '${user.role}'. Please login using the correct role.`
        )
      }

      // ✅ Update last_login_ip and user_agent on repeat login
      await user.update({
        last_login_ip: req.metadata?.last_login_ip || req.ip,
        user_agent: req.metadata?.user_agent || req.headers['user-agent']
      })
    } else {
      const emailExists = await _User.findOne({ where: { email } })
      if (emailExists) {
        return responder(
          res,
          409,
          'Email is already registered with manual login'
        )
      }

      user = await _User.create({
        first_name: given_name,
        last_name: family_name,
        email,
        profile_image: picture,
        google_id,
        is_verified: true,
        login_type: 'google',
        password: 'not_required',
        role: userRole,
        ip_address: req.metadata?.ip_address || req.ip,
        user_agent: req.metadata?.user_agent || req.headers['user-agent'],
        last_login_ip: req.metadata?.last_login_ip || req.ip
      })
    }

    const { password: _, ...userData } = user.dataValues

    const token = generateToken({
      id: user.id,
      email: user.email,
      role: user.role
    })

    res.cookie('token', token, {
      maxAge: 24 * 60 * 60 * 1000,
      httpOnly: true,
      secure: true,
      sameSite: 'None'
    })

    console.log('get user info',{ userData, token })
    return responder(res, 200, 'Google login successful', { userData, token })
  } catch (err) {
    console.error('Error in Google login:', err)
    return next(err)
  }
}

exports.googleLogout = (req, res, next) => {
  try {
    res.clearCookie('token', {
      httpOnly: true,
      sameSite: 'Lax', // adjust as needed based on your frontend/backend setup
      secure: process.env.NODE_ENV === 'production' // true in production with HTTPS
    })

    return responder(res, 200, 'Logout successful')
  } catch (err) {
    console.error('Error in verifyOtp:', err)
    return next(err)
  }
}

exports.verifyOtp = async (req, res, next) => {
  try {
    const { verification_otp } = req.body

    const otp = await _User.findOne({ where: { verification_otp } })

    if (!otp) {
      return responder(res, 404, 'Invalid otp')
    }

    if (otp.otp_expires_at < new Date()) {
      return responder(res, 400, 'OTP has expired')
    }

    otp.is_verified = true
    otp.verification_otp = null
    otp.otp_expires_at = null
    await otp.save()

    const data = {
      id: otp.id,
      name: otp.name,
      email: otp.email,
      is_verified: otp.is_verified
    }

    return responder(res, 200, 'User verified successfully', data)
  } catch (err) {
    console.error('Error in verifyOtp:', err)
    return next(err)
  }
}

exports.resendOtpOrForgotPassword = async (req, res, next) => {
  try {
    const { email, flag } = req.body

    if (!email || !flag) {
      return responder(res, 400, 'Email and flag are required')
    }

    const user = await _User.findOne({ where: { email } })

    if (!user) {
      return responder(res, 404, 'User not found')
    }

    const generateAndQueueOtp = async (message) => {
      const otp = generateOTP(6)
      user.verification_otp = otp
      user.otp_expires_at = new Date(Date.now() + 1 * 60 * 1000)
      await user.save()

      const channel = getChannel() || (await connectRabbitMQ())
      const emailJob = {
        email,
        otp,
        name: user.first_name,
        flag
      }

      channel.sendToQueue('emailQueue', Buffer.from(JSON.stringify(emailJob)), {
        persistent: true
      })

      return responder(res, 200, message)
    }

    switch (flag) {
    case 'forgot_password':
      return await generateAndQueueOtp('OTP sent for password reset')

    case 'resend_otp':
      if (user.is_verified) {
        return responder(res, 400, 'User is already verified')
      }
      return await generateAndQueueOtp('OTP resent successfully')

    default:
      return responder(res, 400, 'Invalid flag provided')
    }
  } catch (err) {
    console.error('Error in resendOtpOrForgotPassword:', err)
    return next(err)
  }
}

exports.resetPassword = async (req, res, next) => {
  try {
    const { verification_otp, new_password } = req.body

    if (!verification_otp || !new_password) {
      return responder(res, 400, 'OTP and new password are required')
    }
    const user = await _User.findOne({ where: { verification_otp } })
    if (!user) {
      return responder(res, 404, 'User not found')
    }
    if (user.otp_expires_at < new Date()) {
      return responder(res, 400, 'OTP has expired')
    }

    const hashedPassword = await bcrypt.hash(new_password, 10)
    user.password = hashedPassword
    user.verification_otp = null
    user.otp_expires_at = null
    await user.save()

    const { password: _, ...userData } = user.dataValues

    const token = generateToken({ id: user.id, email: user.email })

    res.cookie('token', token, { maxAge: 24 * 60 * 60 * 1000, httpOnly: true })

    return responder(res, 200, 'Password reset successfully', {
      userData,
      token
    })
  } catch (err) {
    console.error('Error in resetPassword:', err)
    return next(err)
  }
}

exports.logout = async (req, res, next) => {
  try {
    res.clearCookie('token')
    return responder(res, 200, 'Logout successful')
  } catch (err) {
    console.error('Error in logout:', err)
    return next(err)
  }
}

exports.getUser = async (req, res, next) => {
  try {
    const userId = req.params.id

    const user = await _User.findOne({
      where: { id: userId }
    })

    // Check here before doing anything else
    if (!user) {
      return next(CustomErrorHandler.notFound('User not found'))
    }

    const imagePath = user.profile_image
    const split = imagePath.split('/')
    const fileName = split[split.length - 1]
    console.log('fileName', fileName)

    const filePath = path.join(__dirname, '..', 'uploads', 'Profile-Pic')
    const files = fs.readdirSync(filePath)

    let fileExists = false

    for (const file of files) {
      if (file === fileName) {
        fileExists = true
        console.log('File exists')
        break
      }
    }

    if (fileExists) {
      if (!imagePath.startsWith(URL.BASE)) {
        user.profile_image = `/uploads/${fileName}`
      } else {
        user.profile_image = imagePath
      }
    } else {
      user.profile_image = '/uploads/user.png'
    }

    const userData = user.toJSON()

    if (userData.profile_image) {
      userData.profile_image = `${URL.BASE}${userData.profile_image}`
    }

    return responder(res, 200, 'User fetched successfully', userData)
  } catch (err) {
    console.error('Error in getUser:', err)
    return next(err)
  }
}

exports.updateUser = async (req, res, next) => {
  try {
    const userId = req.params.id
    const { first_name, last_name, email, password, otp, role } = req.body

    const user = await _User.findByPk(userId)
    if (!user) {
      if (req.file && req.file.filename) {
        deleteImage(req.file.filename)
      }
      return next(CustomErrorHandler.notFound('User not found'))
    }

    if (!user.is_verified) {
      if (req.file && req.file.filename) {
        deleteImage(req.file.filename)
      }
      return next(
        CustomErrorHandler.unprocessableEntity(
          'Please verify your account before updating profile'
        )
      )
    }

    if (user.block) {
      if (req.file && req.file.filename) {
        deleteImage(req.file.filename)
      }
      return next(CustomErrorHandler.forbidden('Your account is blocked'))
    }

    // Role change restriction: disallow switching between user and company
    if (role && role !== user.role) {
      if (
        (user.role === 'user' && role === 'company') ||
        (user.role === 'company' && role === 'user')
      ) {
        if (req.file && req.file.filename) {
          deleteImage(req.file.filename)
        }
        return next(
          CustomErrorHandler.forbidden(
            'Switching between user and company role is not allowed'
          )
        )
      }
    }

    // Profile image update logic (same as before) ...
    let profileImagePath = user.profile_image
    if (req.file && req.file.filename) {
      if (user.profile_image && !user.profile_image.includes('user.png')) {
        const oldImage = user.profile_image.split('/').pop()
        deleteImage(oldImage)
      }
      profileImagePath = `/uploads/${req.file.filename}`
    }

    // Password update with OTP validation (same as before) ...
    let hashedPassword = user.password
    if (password) {
      if (!otp) {
        if (req.file && req.file.filename) {
          deleteImage(req.file.filename)
        }
        return next(
          CustomErrorHandler.unprocessableEntity(
            'OTP is required to update password'
          )
        )
      }
      if (
        user.verification_otp !== otp ||
        new Date(user.otp_expires_at) < new Date()
      ) {
        if (req.file && req.file.filename) {
          deleteImage(req.file.filename)
        }
        return next(
          CustomErrorHandler.unprocessableEntity('Invalid or expired OTP')
        )
      }
      hashedPassword = await bcrypt.hash(password, 10)
      user.verification_otp = null
      user.otp_expires_at = null
    }

    await user.update({
      first_name: first_name || user.first_name,
      last_name: last_name || user.last_name,
      email: email || user.email,
      password: hashedPassword,
      profile_image: profileImagePath,
      role: role || user.role,
      verification_otp: user.verification_otp,
      otp_expires_at: user.otp_expires_at
    })

    const { password: _, ...updatedUser } = user.dataValues
    updatedUser.profile_image = `${URL.BASE}${updatedUser.profile_image}`

    return responder(res, 200, 'User updated successfully', updatedUser)
  } catch (err) {
    if (req.file && req.file.filename) {
      deleteImage(req.file.filename)
    }
    console.error('Error in updateUser:', err)
    return next(err)
  }
}
