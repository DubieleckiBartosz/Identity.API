using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using Identity.API.Client.Models;
using Identity.API.Exceptions;
using Newtonsoft.Json;

namespace Identity.API.Client
{
    public class EmailClient : IEmailClient
    {
        private const string SendEmail = "Email/SendMail";
        private readonly HttpClient _httpClient;

        public EmailClient(HttpClient httpClient)
        {
            this._httpClient = httpClient;
        }

        public async Task SendAsync(Email email)
        {
            var serializedModel = JsonConvert.SerializeObject(email);
            var request = new HttpRequestMessage(HttpMethod.Post, _httpClient.BaseAddress + SendEmail);
            request.Content = new StringContent(serializedModel);
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");

            var result = await _httpClient.SendAsync(request);
            if (!result.IsSuccessStatusCode)
            {
                var stringResponse = result.Content.ReadAsStringAsync().Result;
                throw new EmailException(stringResponse);
            }
        }
    }
}