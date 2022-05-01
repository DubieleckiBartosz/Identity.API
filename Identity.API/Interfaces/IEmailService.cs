using System.Threading.Tasks;

namespace Identity.API.Interfaces
{
    public interface IEmailService
    {
        Task SendEmailAfterCreateNewAccountAsync(string recipient, string code, string userName);
        Task SendEmailResetPasswordAsync(string recipient, string resetToken);
    }
}