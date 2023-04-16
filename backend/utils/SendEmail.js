import nodeMailer from 'nodemailer';
export const sendEmail = async (emails,subject,text) => {
  
    const transporter = nodeMailer.createTransport({
      host: "smpt.gmail.com",
      port: 465,
      service: process.env.SMPT_SERVICE,
      auth: {
        user: process.env.SMPT_MAIL,
        pass: process.env.SMPT_PASSWORD,
      },
    });
  
    const mailOptions = {
      from: process.env.SMPT_MAIL,
      to: emails,
      subject,
      text,
    };
  
    await transporter.sendMail(mailOptions);
  };
