using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Identity.API.AccountModel
{
    public class AuthenticationModel
    {
        public string UserName { get; set; }
        public List<string> Roles { get; set; }
        public string Token { get; set; }
        [JsonIgnore]
        public string RefreshToken { get; set; }
    }
}