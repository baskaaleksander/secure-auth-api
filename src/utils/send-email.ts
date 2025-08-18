import * as nodemailer from 'nodemailer';
import * as pug from 'pug';
import config from '../config/env';
import Mail from 'nodemailer/lib/mailer';
import { MailData } from './types';

const renderTemplate = (
  templateName: 'welcome' | 'password-reset',
  data?: MailData,
) => {
  const templatePath = './templates/' + templateName + '.pug';

  if (data) {
    return pug.renderFile(templatePath, data);
  }

  return pug.renderFile(templatePath);
};

export const sendEmail = async (
  to: string,
  subject: string,
  template: 'welcome' | 'password-reset',
  link?: string,
) => {
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: config.emailUser,
      pass: config.emailPass,
    },
  });

  let html;
  if (link) {
    html = renderTemplate(template, { link });
  } else {
    html = renderTemplate(template);
  }

  const mailOptions: Mail.Options = {
    from: `Secure Auth <${config.emailUser}>`,
    to,
    subject,
    html,
  };

  try {
    await transporter.sendMail(mailOptions);
  } catch (error) {
    console.error('Failed to send email', error);
  }
};
