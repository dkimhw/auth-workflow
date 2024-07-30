const sendEmail = require('./sendEmail');

const sendResetPasswordEmail = async({ name, email, token, origin }) => {
  console.log('reset password', token);
  const resetURL = `${origin}/user/reset-password?token=${token}&email=${email}`;
  const message = `
    <p>
      Please reset your password by clicking on the following link:
      <a href="${resetURL}">
        Verify Email
      </a>
    </p>
  `;

  return sendEmail({
    to: email,
    subject: 'Reset Password',
    html: `
      <h4> Hello ${name}
      ${message}
    `,
  });
};

module.exports = sendResetPasswordEmail;
