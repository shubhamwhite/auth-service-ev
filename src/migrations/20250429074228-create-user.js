'use strict'
module.exports = {
  up: async (queryInterface, Sequelize) => {
    await queryInterface.createTable('Users', {
      id: {
        allowNull: false,
        primaryKey: true,
        type: Sequelize.UUID,
        defaultValue: Sequelize.UUIDV4
      },
      first_name: {
        type: Sequelize.STRING,
        allowNull: false
      },
      last_name: {
        type: Sequelize.STRING,
        allowNull: false
      },
      email: {
        type: Sequelize.STRING,
        allowNull: false,
        unique: true
      },
      password: {
        type: Sequelize.STRING,
        allowNull: false
      },
      is_verified: {
        type: Sequelize.BOOLEAN,
        defaultValue: false
      },
      verification_otp: {
        type: Sequelize.STRING,
        allowNull: true
      },
      otp_expires_at: {
        type: Sequelize.DATE,
        allowNull: true
      },
      profile_image: {
        type: Sequelize.STRING,
        allowNull: true
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
      },
      block: {
        type: Sequelize.BOOLEAN,
        defaultValue: false
      },
      role: {
        type: Sequelize.ENUM('user', 'company', 'admin'),
        allowNull: false,
        defaultValue: 'user'
      },
      ip_address: {
        type: Sequelize.STRING,
        allowNull: true
      },
      last_login_ip: {
        type: Sequelize.STRING,
        allowNull: true
      },
      user_agent: {
        type: Sequelize.STRING,
        allowNull: true
      },
      createdAt: {
        allowNull: false,
        type: Sequelize.DATE
      },
      updatedAt: {
        allowNull: false,
        type: Sequelize.DATE
      }
    })
  },

  down: async (queryInterface, Sequelize) => {
    await queryInterface.dropTable('Users')
  }
}
