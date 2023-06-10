export const mailFormat = {
  ChangeEmailOTPNewEmail: {
    subject: 'Your Change Email Code',
    body: 'Your one-time security code is: {{one_time_password}}'
  },
  ChangeEmailCompleat: {
    subject: 'Email Update Notice',
    body: 'Dear {{name}}. Email update completed.'
  },
  CreateOTP: {
    subject: 'Your Access Code for Registration',
    body: 'Your one-time security code is: {{one_time_password}}'
  },
  CreateCompleat: {
    subject: 'Your Registration is Complete',
    body: 'Dear {{name}}.\nThank you for joining us, your account is now active and ready to use.'
  },
  deletionOTP: {
    subject: 'Access Code for Account Deactivation',
    body: 'Your one-time security code is: {{one_time_password}}'
  },
  deletionCompleat: {
    subject: 'Account Deletion Confirmation',
    body: 'Your account has been deleted. Thank you for being a part of our community.'
  },
  loginOTP: {
    subject: 'Your Access Code for SignIn',
    body: 'Your one-time security code is: {{one_time_password}}'
  },
  loginCompleat: {
    subject: 'Login Notification',
    body: 'Dear {{name}}\nThank you for logging in to our system.'
  },
  ResetPasswordSendToken: {
    subject: 'Reset Password URL',
    body: 'Dear {{name}},\nPlease access the following link to reset your password.\n http://localhost:3000/v1/test/reset-password/{{jwt_token}}',
  },
  ResetPasswordCompleat: {
    subject: 'Password Update Notice',
    body: 'Dear {{name}}. Password update completed.'
  }
}
