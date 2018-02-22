using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace ApiBasicAuthenticationWhiteListIp
{
    public class AuthenticationMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly string _whiteListIps;

        public AuthenticationMiddleware(RequestDelegate next, string whiteListIps)
        {
            _next = next;
            _whiteListIps = whiteListIps;
        }

        public async Task Invoke(HttpContext context)
        {
            if (ValidateIfIpIsInWhiteList(context))
            {
                if (LoginUserBasicAuthentication(context))
                {
                    await _next.Invoke(context);
                }
                else
                {
                    context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                    return;
                }
            }
            else
            {
                context.Response.StatusCode = (int)HttpStatusCode.Forbidden;
                return;
            }
        }

        private bool ValidateIfIpIsInWhiteList(HttpContext context)
        {
            var remoteIp = context.Connection.RemoteIpAddress;

            string[] allowedIps = _whiteListIps.Split(';');
            if (!allowedIps.Any(ip => ip == remoteIp.ToString()))
            {
                context.Response.StatusCode = (int)HttpStatusCode.Forbidden;
                return false;
            }

            return true;
        }

        private bool LoginUserBasicAuthentication(HttpContext context)
        {
            string authHeader = context.Request.Headers["Authorization"];
            if (authHeader != null && authHeader.StartsWith("Basic"))
            {
                //Extract credentials
                string encodedUsernamePassword = authHeader.Substring("Basic ".Length).Trim();
                Encoding encoding = Encoding.GetEncoding("iso-8859-1");
                string usernamePassword = encoding.GetString(Convert.FromBase64String(encodedUsernamePassword));

                int seperatorIndex = usernamePassword.IndexOf(':');

                var username = usernamePassword.Substring(0, seperatorIndex);
                var password = usernamePassword.Substring(seperatorIndex + 1);

                if (username == "test" && password == "test")
                {
                    return true;
                }
            }

            return false;
        }
    }

    public static class AuthenticationMiddlewareExtension
    {
        /// <summary>
        /// Habilita o uso do Middleware de autenticação básica
        /// </summary>
        /// <param name="app"></param>
        /// <returns></returns>
        public static IApplicationBuilder UseAuthenticationMiddleware(this IApplicationBuilder app, string whiteListIps)
        {
            return app.UseWhen(x => (x.Request.Path.StartsWithSegments("/api", StringComparison.OrdinalIgnoreCase)),
                builder =>
                {
                    builder.UseMiddleware<AuthenticationMiddleware>(whiteListIps);
                });
        }
    }
}
