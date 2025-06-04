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
  googleLogin,
  googleLogout
} = require('../controllers/auth.controller')

const { upload } = require('../helper/imageUpload.helper')
const authMiddleware = require('../middleware/auth.middleware')
const errorHandler = require('../middleware/errorHandler.middleware')
const { saveLoginMetadata } = require('../middleware/saveLoginMetadata')
const {
  signupValidationSchema,
  loginValidationSchema
} = require('../validation/auth.validation')

const swaggerUi = require('swagger-ui-express')
const swaggerSpec = require('../../docs/swagger')

// Swagger documentation setup
router.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec))

// Routes for authentication
router.route('/login').post(loginValidationSchema, saveLoginMetadata, login)
router
  .route('/signup')
  .post(
    upload.single('profile_image'),
    signupValidationSchema,
    saveLoginMetadata,
    signup
  )
router.route('/google-login').post(saveLoginMetadata, googleLogin)
router.route('/google-logout').get(googleLogout)
router.route('/verify-otp').post(verifyOtp)
router.route('/password/resend-otp').post(resendOtpOrForgotPassword)
router.route('/password/reset').post(resetPassword)
router.route('/logout').get(logout)
router.route('/:id').get(authMiddleware, getUser)
router
  .route('/:id')
  .patch(authMiddleware, upload.single('profile_image'), updateUser)

// Error handling middleware
router.use(errorHandler)

module.exports = router
