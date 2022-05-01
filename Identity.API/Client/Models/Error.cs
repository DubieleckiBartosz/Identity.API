using System.Collections.Generic;

namespace Identity.API.Client.Models
{
    public class Error
    {
        public int StatusCode { get; set; }
        public IEnumerable<string> Errors { get; set; }
    }
}