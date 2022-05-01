using System.Collections.Generic;

namespace Identity.API.Settings
{
    public class JWTSettings
    {
        public string Key { get; set; }
        public string Issuer { get; set; }
        public List<string> Audiences { get; set; }
        public int DurationInMinutes { get; set; }
    }
}