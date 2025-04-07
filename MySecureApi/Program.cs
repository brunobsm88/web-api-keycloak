using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using MySecureApi.Services;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

// Configurar logging
builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.AddDebug();

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidIssuer = $"{builder.Configuration["Keycloak:BaseUrl"]}/realms/{builder.Configuration["Keycloak:Realm"]}",
        
        ValidateAudience = true,
        ValidAudience = "account",
        
        ValidateIssuerSigningKey = true,
        ValidateLifetime = true,

        IssuerSigningKeyResolver = (token, securityToken, kid, parameters) =>
        {
            var client = new HttpClient();
            var keyUri = $"{parameters.ValidIssuer}/protocol/openid-connect/certs";
            var response = client.GetAsync(keyUri).Result;
            var keys = new JsonWebKeySet(response.Content.ReadAsStringAsync().Result);

            if (keys == null || !keys.Keys.Any())
            {
                throw new Exception("No keys found in the JWKS endpoint.");
            }

            return keys.GetSigningKeys();
        }
    };

    options.RequireHttpsMetadata = false; // Only in develop environment
    options.SaveToken = true;

    options.Events = new JwtBearerEvents
    {
        OnTokenValidated = context =>
        {
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogInformation("Token validated successfully.");

            var claimsIdentity = context.Principal.Identity as ClaimsIdentity;
            var realmAccessClaim = context.Principal.FindFirst("realm_access");

            if (realmAccessClaim != null)
            {
                var realmAccess = System.Text.Json.JsonDocument.Parse(realmAccessClaim.Value);
                if (realmAccess.RootElement.TryGetProperty("roles", out var roles))
                {
                    foreach (var role in roles.EnumerateArray())
                    {
                        var roleName = role.GetString();
                        if (!string.IsNullOrEmpty(roleName))
                        {
                            claimsIdentity.AddClaim(new Claim(ClaimTypes.Role, roleName));
                            logger.LogInformation("Added role: {Role}", roleName);
                        }
                    }
                }
            }
            else
            {
                logger.LogWarning("realm_access claim not found.");
            }

            // Log all claims
            var allClaims = context.Principal.Claims.Select(c => new { c.Type, c.Value });
            logger.LogInformation("All claims: {Claims}", string.Join(", ", allClaims.Select(c => $"{c.Type}: {c.Value}")));

            return Task.CompletedTask;
        }
    };
});

builder.Services.AddHttpClient();
builder.Services.AddScoped<KeycloakAuthService>();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();