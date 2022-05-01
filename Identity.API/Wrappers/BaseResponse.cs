using System.Collections.Generic;

namespace Identity.API.Wrapper
{
    public class BaseResponse<T>
    {
        public T Data { get; private set; }
        public string Message { get; private set; }
        public bool Success { get; private set; }
        public IEnumerable<string> Errors { get; set; }

        public BaseResponse()
        {
            Errors = new List<string>();
        }
        public BaseResponse(T data, string message, bool success, IEnumerable<string> errors = null)
        {
            Data = data;
            Message = message;
            Success = success;
            Errors = errors;
        }

        public static BaseResponse<T> Ok(string message)
        {
            return new BaseResponse<T>(default(T), message, true);
        }

        public static BaseResponse<T> Ok(T data)
        {
            return new BaseResponse<T>(data, null, true);
        }

        public static BaseResponse<T> Error(string message)
        {
            return new BaseResponse<T>(default(T), message, false);
        }

        public static BaseResponse<T> Error(IEnumerable<string> errors)
        {
            return new BaseResponse<T>(default(T), null, success: false, errors);
        }
    }
}