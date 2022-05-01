using System.Threading.Tasks;
using Identity.API.Client.Models;

namespace Identity.API.Client
{
    public interface IEmailClient
    {
        Task SendAsync(Email email);
    }
}