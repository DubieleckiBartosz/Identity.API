using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;
using Identity.API.Client.Models;
using Identity.API.Exceptions;
using Identity.API.Wrapper;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

namespace Identity.API.Middlewares
{
    public class ErrorHandlingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<ErrorHandlingMiddleware> _logger;

        public ErrorHandlingMiddleware(RequestDelegate next, ILogger<ErrorHandlingMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task Invoke(HttpContext context)
        {
            try
            {
                await _next.Invoke(context);
            }
            catch (Exception ex)
            {
                var response = context.Response;
                BaseResponse<string> model;

                if (ex is EmailException)
                {
                    var error = JsonConvert.DeserializeObject<Error>(ex?.Message) ?? new Error()
                    {
                        StatusCode = 400,
                        Errors = new List<string>()
                        {
                            "Something went wrong."
                        }
                    };
                    response.StatusCode = error.StatusCode;
                    model = BaseResponse<string>.Error(error.Errors);
                    await this.Response(response, model, ex?.Message);
                }
                else if (ex is IdentityException)
                {
                    response.StatusCode = (int)HttpStatusCode.BadRequest;
                    model = BaseResponse<string>.Error(ex?.Message);
                    await this.Response(response, model, ex?.Message);
                }
                else
                {
                    response.StatusCode = (int)HttpStatusCode.InternalServerError;
                    model = BaseResponse<string>.Error("Internal Server Error");
                    await this.Response(response, model, ex?.Message);
                }
            }
        }

        private async Task Response(HttpResponse response, BaseResponse<string> model, string logMessage)
        {
            _logger.LogError(logMessage);
            await response.WriteAsJsonAsync(model);
        }
    }
}
