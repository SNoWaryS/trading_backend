using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.SqlClient;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

// Allow the Angular dev server to call this API from the browser, sending the session cookie.
builder.Services.AddCors(options =>
    options.AddDefaultPolicy(policy =>
        policy.WithOrigins("http://localhost:4200").AllowAnyHeader().AllowAnyMethod().AllowCredentials()));

// Session: an encrypted, HttpOnly cookie set at login. JavaScript cannot read it, and SameSite=Strict
// keeps other sites from sending it, which also protects the API from cross-site request forgery.
builder.Services
    .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.Name = "trading_session";
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Strict;
        options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest; // Always use HTTPS in production.
        options.ExpireTimeSpan = TimeSpan.FromDays(7);
        options.SlidingExpiration = true;
        // An API answers 401/403 instead of redirecting to a login page.
        options.Events.OnRedirectToLogin = context =>
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return Task.CompletedTask;
        };
        options.Events.OnRedirectToAccessDenied = context =>
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return Task.CompletedTask;
        };
    });
builder.Services.AddAuthorization();

var app = builder.Build();

app.UseCors();
app.UseAuthentication();
app.UseAuthorization();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

var summaries = new[]
{
    "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
};

app.MapGet("/weatherforecast", () =>
{
    var forecast =  Enumerable.Range(1, 5).Select(index =>
        new WeatherForecast
        (
            DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
            Random.Shared.Next(-20, 55),
            summaries[Random.Shared.Next(summaries.Length)]
        ))
        .ToArray();
    return forecast;
})
.WithName("GetWeatherForecast");

// Connection check: front -> back -> SQL Server.
app.MapGet("/api/health", async (IConfiguration config, ILogger<Program> logger) =>
{
    try
    {
        await using var connection = new SqlConnection(config.GetConnectionString("DefaultConnection"));
        await connection.OpenAsync();

        await using var command = new SqlCommand("SELECT DB_NAME()", connection);
        var database = (string?)await command.ExecuteScalarAsync();

        return Results.Ok(new { status = "connected", database });
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "Database connection failed");
        return Results.Problem("Cannot connect to the database", statusCode: StatusCodes.Status503ServiceUnavailable);
    }
})
.WithName("GetHealth");

var passwordHasher = new PasswordHasher<string>();
// Verified when the username is unknown, so both failures take about the same time.
var unknownUserHash = passwordHasher.HashPassword(string.Empty, Guid.NewGuid().ToString());

app.MapPost("/api/auth/login", async (LoginRequest request, HttpContext http, IConfiguration config, ILogger<Program> logger) =>
{
    if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrEmpty(request.Password))
    {
        return Results.BadRequest(new { message = "Username and password are required" });
    }

    try
    {
        await using var connection = new SqlConnection(config.GetConnectionString("DefaultConnection"));
        await connection.OpenAsync();

        await using var command = new SqlCommand(
            "SELECT user_id, password FROM USERS WHERE username = @username",
            connection);
        command.Parameters.AddWithValue("@username", request.Username);

        int? userId = null;
        var storedHash = unknownUserHash;
        await using (var reader = await command.ExecuteReaderAsync())
        {
            if (await reader.ReadAsync())
            {
                userId = reader.GetInt32(0);
                storedHash = reader.GetString(1);
            }
        }

        var verification = passwordHasher.VerifyHashedPassword(string.Empty, storedHash, request.Password);
        var profile = userId is int id && verification != PasswordVerificationResult.Failed
            ? await LoadProfileAsync(connection, id)
            : null;
        if (profile is null)
        {
            return Results.Json(new { message = "Incorrect username or password" }, statusCode: StatusCodes.Status401Unauthorized);
        }

        var identity = new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, profile.UserId.ToString()),
                new Claim(ClaimTypes.Name, profile.Username),
            ],
            CookieAuthenticationDefaults.AuthenticationScheme);
        await http.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(identity),
            new AuthenticationProperties { IsPersistent = true });

        return Results.Ok(profile);
    }
    catch (SqlException ex)
    {
        logger.LogError(ex, "Login failed because of a database error");
        return Results.Problem("Cannot connect to the database", statusCode: StatusCodes.Status503ServiceUnavailable);
    }
})
.WithName("Login");

app.MapPost("/api/auth/register", async (RegisterRequest request, IConfiguration config, ILogger<Program> logger) =>
{
    var name = request.Name?.Trim() ?? "";
    var surname = request.Surname?.Trim() ?? "";
    var username = request.Username?.Trim() ?? "";
    var email = request.Email?.Trim() ?? "";
    var password = request.Password ?? "";
    var phoneNumber = request.PhoneNumber?.Trim() ?? "";
    var address = request.Address?.Trim() ?? "";

    var validationError =
        name.Length == 0 || surname.Length == 0 || username.Length == 0 || email.Length == 0 || password.Length == 0
            ? "Please fill in all required fields"
        : name.Length > 100 || surname.Length > 100 ? "Name and surname must be 100 characters or fewer"
        : username.Length > 50 ? "Username must be 50 characters or fewer"
        : email.Length > 255 || !IsValidEmail(email) ? "Please enter a valid email"
        : password.Length is < 8 or > 128 ? "Password must be 8 to 128 characters"
        : phoneNumber.Length > 20 ? "Phone number must be 20 characters or fewer"
        : address.Length > 500 ? "Address must be 500 characters or fewer"
        : null;
    if (validationError is not null)
    {
        return Results.BadRequest(new { message = validationError });
    }

    try
    {
        await using var connection = new SqlConnection(config.GetConnectionString("DefaultConnection"));
        await connection.OpenAsync();

        await using var command = new SqlCommand(
            """
            INSERT INTO USERS (name, surname, username, email, password, phone_number, address)
            OUTPUT INSERTED.user_id
            VALUES (@name, @surname, @username, @email, @password, @phoneNumber, @address)
            """,
            connection);
        command.Parameters.AddWithValue("@name", name);
        command.Parameters.AddWithValue("@surname", surname);
        command.Parameters.AddWithValue("@username", username);
        command.Parameters.AddWithValue("@email", email);
        command.Parameters.AddWithValue("@password", passwordHasher.HashPassword(string.Empty, password));
        command.Parameters.AddWithValue("@phoneNumber", phoneNumber.Length == 0 ? DBNull.Value : phoneNumber);
        command.Parameters.AddWithValue("@address", address.Length == 0 ? DBNull.Value : address);

        var userId = (int)(await command.ExecuteScalarAsync())!;
        return Results.Created($"/api/users/{userId}", new { userId, username });
    }
    catch (SqlException ex) when (ex.Number is 2601 or 2627) // unique constraint violation
    {
        var message = ex.Message.Contains("UQ_USERS_email", StringComparison.OrdinalIgnoreCase)
            ? "This email is already registered"
            : "This username is already taken";
        return Results.Conflict(new { message });
    }
    catch (SqlException ex)
    {
        logger.LogError(ex, "Registration failed because of a database error");
        return Results.Problem("Cannot connect to the database", statusCode: StatusCodes.Status503ServiceUnavailable);
    }
})
.WithName("Register");

// The logged-in user, from the session cookie. 401 when there is no valid session.
app.MapGet("/api/auth/me", async (ClaimsPrincipal principal, HttpContext http, IConfiguration config, ILogger<Program> logger) =>
{
    if (!int.TryParse(principal.FindFirstValue(ClaimTypes.NameIdentifier), out var userId))
    {
        return Results.Unauthorized();
    }

    try
    {
        await using var connection = new SqlConnection(config.GetConnectionString("DefaultConnection"));
        await connection.OpenAsync();

        var profile = await LoadProfileAsync(connection, userId);
        if (profile is null)
        {
            // The account no longer exists, so the session is no longer valid.
            await http.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return Results.Unauthorized();
        }
        return Results.Ok(profile);
    }
    catch (SqlException ex)
    {
        logger.LogError(ex, "Loading the session user failed because of a database error");
        return Results.Problem("Cannot connect to the database", statusCode: StatusCodes.Status503ServiceUnavailable);
    }
})
.RequireAuthorization()
.WithName("GetCurrentUser");

// Ends the session by removing the cookie. Safe to call without a session.
app.MapPost("/api/auth/logout", async (HttpContext http) =>
{
    await http.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.NoContent();
})
.WithName("Logout");

// Searches the card catalog (the cards that may be sold) by card name, set or number.
// Returns at most `limit` cards (default 50, up to 100), sorted by name, so the add card form stays fast.
const string CatalogColumns =
    "catalog_id, card_name, set_name, card_number, card_type, rarity, card_stage, card_element, card_picture, reference_price";

app.MapGet("/api/catalog", async (string? search, int? limit, IConfiguration config, ILogger<Program> logger) =>
{
    var term = search?.Trim() ?? "";
    if (term.Length > 100)
    {
        return Results.BadRequest(new { message = "Search must be 100 characters or fewer" });
    }
    var take = Math.Clamp(limit ?? 50, 1, 100);

    try
    {
        await using var connection = new SqlConnection(config.GetConnectionString("DefaultConnection"));
        await connection.OpenAsync();

        await using var command = new SqlCommand(
            $"""
            SELECT TOP (@take) {CatalogColumns}
            FROM CARD_CATALOG
            WHERE @pattern IS NULL
               OR card_name LIKE @pattern ESCAPE '\'
               OR set_name LIKE @pattern ESCAPE '\'
               OR card_number LIKE @pattern ESCAPE '\'
            ORDER BY card_name, set_name, card_number
            """,
            connection);
        command.Parameters.AddWithValue("@take", take);
        command.Parameters.Add("@pattern", System.Data.SqlDbType.NVarChar, 210).Value =
            term.Length == 0 ? DBNull.Value : $"%{EscapeLike(term)}%";

        var cards = new List<CatalogCard>();
        await using var reader = await command.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            cards.Add(ReadCatalogCard(reader));
        }
        return Results.Ok(cards);
    }
    catch (SqlException ex)
    {
        logger.LogError(ex, "Searching the catalog failed because of a database error");
        return Results.Problem("Cannot connect to the database", statusCode: StatusCodes.Status503ServiceUnavailable);
    }
})
.RequireAuthorization()
.WithName("SearchCatalog");

app.MapGet("/api/catalog/{catalogId:int}", async (int catalogId, IConfiguration config, ILogger<Program> logger) =>
{
    try
    {
        await using var connection = new SqlConnection(config.GetConnectionString("DefaultConnection"));
        await connection.OpenAsync();

        await using var command = new SqlCommand(
            $"SELECT {CatalogColumns} FROM CARD_CATALOG WHERE catalog_id = @catalogId",
            connection);
        command.Parameters.AddWithValue("@catalogId", catalogId);

        await using var reader = await command.ExecuteReaderAsync();
        return await reader.ReadAsync()
            ? Results.Ok(ReadCatalogCard(reader))
            : Results.NotFound(new { message = "This card is not in the catalog" });
    }
    catch (SqlException ex)
    {
        logger.LogError(ex, "Loading a catalog card failed because of a database error");
        return Results.Problem("Cannot connect to the database", statusCode: StatusCodes.Status503ServiceUnavailable);
    }
})
.RequireAuthorization()
.WithName("GetCatalogCard");

app.Run();

// LIKE treats %, _ and [ as wildcards; escape them so they match themselves.
static string EscapeLike(string value) =>
    value.Replace(@"\", @"\\").Replace("%", @"\%").Replace("_", @"\_").Replace("[", @"\[");

static CatalogCard ReadCatalogCard(SqlDataReader reader)
{
    string? Text(int i) => reader.IsDBNull(i) ? null : reader.GetString(i);
    return new CatalogCard(
        reader.GetInt32(0),
        reader.GetString(1),
        Text(2),
        Text(3),
        reader.GetString(4),
        reader.GetString(5),
        Text(6),
        Text(7),
        Text(8),
        reader.IsDBNull(9) ? null : reader.GetDecimal(9));
}

static bool IsValidEmail(string email) =>
    System.Net.Mail.MailAddress.TryCreate(email, out var parsed) && parsed.Address == email;

// Everything about a user except the password hash.
static async Task<UserProfile?> LoadProfileAsync(SqlConnection connection, int userId)
{
    await using var command = new SqlCommand(
        "SELECT user_id, name, surname, username, email, phone_number, address FROM USERS WHERE user_id = @userId",
        connection);
    command.Parameters.AddWithValue("@userId", userId);

    await using var reader = await command.ExecuteReaderAsync();
    if (!await reader.ReadAsync())
    {
        return null;
    }

    return new UserProfile(
        reader.GetInt32(0),
        reader.GetString(1),
        reader.GetString(2),
        reader.GetString(3),
        reader.GetString(4),
        reader.IsDBNull(5) ? null : reader.GetString(5),
        reader.IsDBNull(6) ? null : reader.GetString(6));
}

record UserProfile(
    int UserId,
    string Name,
    string Surname,
    string Username,
    string Email,
    string? PhoneNumber,
    string? Address);

record CatalogCard(
    int CatalogId,
    string CardName,
    string? SetName,
    string? CardNumber,
    string CardType,
    string Rarity,
    string? CardStage,
    string? CardElement,
    string? CardPicture,
    decimal? ReferencePrice);

record LoginRequest(string? Username, string? Password);

record RegisterRequest(
    string? Name,
    string? Surname,
    string? Username,
    string? Email,
    string? Password,
    string? PhoneNumber,
    string? Address);

record WeatherForecast(DateOnly Date, int TemperatureC, string? Summary)
{
    public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
}
