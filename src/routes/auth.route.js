const router = require('express').Router()
const {
  signup,
  verifyOtp,
  resendOtpOrForgotPassword,
  login,
  resetPassword,
  logout,
  getUser,
  updateUser,
  googleLogin
} = require('../controllers/auth.controller')
const { upload } = require('../helper/imageUpload.helper')
const authMiddleware = require('../middleware/auth.middleware')
const errorHandler = require('../middleware/errorHandler.middleware')
const signupValidationSchema = require('../validation/auth.validation')
const swaggerUi = require('swagger-ui-express')
const swaggerSpec = require('../../docs/swagger')

router
  .route('/signup')
  .post(upload.single('profile_image'), signupValidationSchema, signup)
router.route('/verify-otp').post(verifyOtp)
router.route('/password-reset/otp/resend').post(resendOtpOrForgotPassword)
router.route('/login').post(login)
router.route('/password-reset').post(resetPassword)
router.route('/logout').get(logout)
router.route('/user/:id').get(authMiddleware, getUser)
router
  .route('/user/update/:id')
  .patch(authMiddleware, upload.single('profile_image'), updateUser)
router.route('/google-login').post(googleLogin)

router.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec)) // localhost:4000/api/v1/auth/api-docs

router.use(errorHandler)

module.exports = router
