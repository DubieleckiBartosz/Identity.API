using System;

namespace Identity.API.Exceptions
{
    public class EmailException : Exception
    {
        public EmailException(string message) : base(message)
        {
        }
    }
}