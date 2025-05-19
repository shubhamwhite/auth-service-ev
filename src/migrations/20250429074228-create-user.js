'use strict'
/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('Users', {
      id: {
        allowNull: false,
        primaryKey: true,
        autoIncrement: true,
        type: Sequelize.INTEGER
      },
      first_name: {
        type: Sequelize.STRING
      },
      last_name: {
        type: Sequelize.STRING
      },
      email: {
        type: Sequelize.STRING
      },
      password: {
        type: Sequelize.STRING
      },
      is_verified: {
        type: Sequelize.BOOLEAN
      },
      verification_otp: {
        type: Sequelize.STRING
      },
      otp_expires_at: {
        type: Sequelize.DATE
      },

      profile_image: {
        type: Sequelize.STRING
      },
      createdAt: {
        allowNull: false,
        type: Sequelize.DATE
      },
      updatedAt: {
        allowNull: false,
        type: Sequelize.DATE
      },
      google_id: {
        type: Sequelize.STRING,
        allowNull: true,
        unique: true
      },
      login_type: {
        type: Sequelize.ENUM('manual', 'google'),
        allowNull: false,
        defaultValue: 'manual'
      }
    })
  },
  async down(queryInterface, _Sequelize) {
    await queryInterface.dropTable('Users')
  }
}
