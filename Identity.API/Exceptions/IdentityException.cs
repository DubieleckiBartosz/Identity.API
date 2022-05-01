using System;
using System.Collections.Generic;
using System.Net;

namespace Identity.API.Exceptions
{
    public class IdentityException : Exception
    {
        public HttpStatusCode StatusCode { get; set; }

        public IEnumerable<string> Errors { get; set; }

        public IdentityException()
        {
            StatusCode = HttpStatusCode.BadRequest;
        }

        public IdentityException(string message, HttpStatusCode statusCode) : base(message)
        {
            StatusCode = statusCode;
        }

        public IdentityException(string message, HttpStatusCode statusCode, IEnumerable<string> errors) : this(message,
            statusCode)
        {
            StatusCode = statusCode;
            Errors = new List<string>(errors);
        }
    }
}