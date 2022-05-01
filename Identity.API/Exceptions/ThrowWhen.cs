using System;
using System.Net;

namespace Identity.API.Exceptions
{
    public static class ThrowWhen
    {
        public static void WhenNull<T>(this T value, string messageException = null)
        {
            if (value == null)
            {
                if (messageException != null)
                {
                    throw new IdentityException(messageException, HttpStatusCode.BadRequest);
                }

                throw new ArgumentNullException(typeof(T).Name);
            }
        }

        public static void WhenBadRequest<T>(this T value, Func<T, bool> condition, string message,
            HttpStatusCode code = default)
        {
            if (condition(value) && code == default)
            {
                throw new IdentityException(message, HttpStatusCode.BadRequest);
            }

            if (condition(value) && code != default)
            {
                throw new IdentityException(message, code);
            }
        }
    }
}