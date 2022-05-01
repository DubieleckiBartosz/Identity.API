using System;
using System.Text;
using FluentValidation;
using Identity.API.AccountModel;
using Identity.API.Client;
using Identity.API.Database;
using Identity.API.Interfaces;
using Identity.API.Services;
using Identity.API.Settings;
using Identity.API.Validators;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

namespace Identity.API.Configurations
{
    public static class ConfigApp
    {

        public static IServiceCollection GetValidators(this IServiceCollection services)
        {
            services.AddScoped<IValidator<RegisterRequest>, RegisterRequestValidator>();
            services.AddScoped<IValidator<LoginRequest>, LoginRequestValidator>();
            services.AddScoped<IValidator<ForgotPasswordRequest>, ForgotPasswordRequestValidator>();
            services.AddScoped<IValidator<ResetPasswordRequest>, ResetPasswordRequestValidator>();

            return services;
        }

        public static IServiceCollection GetClients(this IServiceCollection services,
            IConfiguration configuration)
        {
            services.AddHttpClient<IEmailClient, EmailClient>(client =>
            {
                //httpClient.BaseAddress = new Uri(configuration["EmailClient:BaseAddress"]);
                client.BaseAddress = new Uri("https://localhost:5004/api/");
            });

            return services;
        }
        public static IServiceCollection GetIdentityDependencyInjection(this IServiceCollection services)
        {
            services.AddScoped<IEmailService, EmailService>();
            services.AddScoped<IUserService, UserService>();
            return services;
        }

        public static IServiceCollection GetAuthentication(this IServiceCollection services,
            IConfiguration configuration)
        {
            var jwtSettings = new JWTSettings();

            configuration.GetSection("JWTSettings").Bind(jwtSettings);

            services.AddSingleton(jwtSettings);

            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            })
                .AddJwtBearer(o =>
                {
                    o.RequireHttpsMetadata = false;
                    o.SaveToken = false;
                    o.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuerSigningKey = true,
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidateLifetime = true,
                        ClockSkew = TimeSpan.Zero,
                        ValidIssuer = jwtSettings.Issuer,
                        ValidAudience = jwtSettings.Issuer,
                        IssuerSigningKey =
                            new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.Key))
                    };
                });

            return services;
        }

        public static IServiceCollection GetDatabaseIdentity(this IServiceCollection services,
            IConfiguration configuration)
        {
            services.Configure<JWTSettings>(configuration.GetSection("JWTSettings"));

            if (configuration.GetValue<bool>("UseInMemoryDatabase"))
            {
                services.AddDbContext<IdentityContext>(options =>
                    options.UseInMemoryDatabase("IdentityEventsApp"));
            }
            else
            {
                services.AddDbContext<IdentityContext>(options =>
                    options.UseSqlServer(
                        configuration.GetConnectionString("IdentityConnection")));
            }


            services.AddIdentity<ApplicationUser, IdentityRole>(options =>
            {
                // options.SignIn.RequireConfirmedAccount = true;
            }).AddEntityFrameworkStores<IdentityContext>().AddDefaultTokenProviders();

            services.Configure<DataProtectionTokenProviderOptions>(opt =>
                opt.TokenLifespan = TimeSpan.FromDays(1));

            return services;
        }

        public static void GetSwaggerConfig(this IServiceCollection services)
        {
            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo
                {
                    Title = "IdentityAPI",
                    Version = "v1",
                    Description = "ASP.NET Core 5.0 Web API"
                });

                var securityScheme = new OpenApiSecurityScheme()
                {
                    Name = "Authorization",
                    Description = "Enter JWT Bearer token",
                    Type = SecuritySchemeType.Http,
                    Scheme = "bearer",
                    BearerFormat = "JWT",
                    In = ParameterLocation.Header,
                    Reference = new OpenApiReference
                    {
                        Id = JwtBearerDefaults.AuthenticationScheme,
                        Type = ReferenceType.SecurityScheme
                    }
                };

                c.AddSecurityDefinition(securityScheme.Reference.Id, securityScheme);
                c.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                    {securityScheme,new string[]{ } }
                });
            });
        }
    }
}
