using Microsoft.AspNetCore.Identity;
using Microsoft.Data.SqlClient;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

// Allow the Angular dev server to call this API from the browser.
builder.Services.AddCors(options =>
    options.AddDefaultPolicy(policy =>
        policy.WithOrigins("http://localhost:4200").AllowAnyHeader().AllowAnyMethod()));

var app = builder.Build();

app.UseCors();

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

app.MapPost("/api/auth/login", async (LoginRequest request, IConfiguration config, ILogger<Program> logger) =>
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
            "SELECT user_id, username, name, surname, password FROM USERS WHERE username = @username",
            connection);
        command.Parameters.AddWithValue("@username", request.Username);

        await using var reader = await command.ExecuteReaderAsync();
        var userFound = await reader.ReadAsync();
        var storedHash = userFound ? reader.GetString(4) : unknownUserHash;

        var verification = passwordHasher.VerifyHashedPassword(string.Empty, storedHash, request.Password);
        if (!userFound || verification == PasswordVerificationResult.Failed)
        {
            return Results.Json(new { message = "Incorrect username or password" }, statusCode: StatusCodes.Status401Unauthorized);
        }

        return Results.Ok(new
        {
            userId = reader.GetInt32(0),
            username = reader.GetString(1),
            name = reader.GetString(2),
            surname = reader.GetString(3),
        });
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

app.Run();

static bool IsValidEmail(string email) =>
    System.Net.Mail.MailAddress.TryCreate(email, out var parsed) && parsed.Address == email;

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
