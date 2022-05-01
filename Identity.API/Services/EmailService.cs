using System.Collections.Generic;
using System.Threading.Tasks;
using Identity.API.Client;
using Identity.API.Client.Models;
using Identity.API.Enums;
using Identity.API.Helpers;
using Identity.API.Interfaces;

namespace Identity.API.Services
{
    public class EmailService : IEmailService
    {
        private readonly IEmailClient _emailClient;

        public EmailService(IEmailClient emailClient)
        {
            _emailClient = emailClient;
        }

        public async Task SendEmailAfterCreateNewAccountAsync(string recipient, string code, string userName)
        {
            var dictData = TemplateData.TemplateRegisterAccount(userName, code);
            var mailData = this.CreateEmailForSend(new List<string>() { recipient }, dictData, $"Register {userName}",
                TemplateType.Account, TemplateName.ConfirmAccount);

            // await _emailClient.SendAsync(mailData);
        }

        public async Task SendEmailResetPasswordAsync(string recipient, string resetToken)
        {
            var dictData = TemplateData.TemplateResetPassword(resetToken);
            var mailData = this.CreateEmailForSend(new List<string>() { recipient }, dictData, "Reset Password",
                TemplateType.Account, TemplateName.ResetPassword);
            //  await _emailClient.SendAsync(mailData);
        }

        private Email CreateEmailForSend(List<string> recipients, Dictionary<string, string> dictionaryData,
            string subjectMail, TemplateType templateType, TemplateName templateName) => new Email(recipients, dictionaryData,
            subjectMail, templateType, templateName);
    }
}