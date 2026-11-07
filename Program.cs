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

// Card photos sellers upload, served at /uploads/... (the folder is not committed to git).
const string UploadsFolder = "uploads";
var uploadsPath = Path.Combine(app.Environment.ContentRootPath, UploadsFolder);
Directory.CreateDirectory(uploadsPath);
app.UseStaticFiles(new StaticFileOptions
{
    FileProvider = new Microsoft.Extensions.FileProviders.PhysicalFileProvider(uploadsPath),
    RequestPath = $"/{UploadsFolder}",
});

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

// ---- Listings: a seller offering one catalog card (the CARDS table) ----

const int MaxDescriptionLength = 1000;
const long MaxPictureBytes = 5 * 1024 * 1024;
// Column order is what ReadListing expects.
const string ListingSelect =
    """
    SELECT c.card_id, c.catalog_id, k.card_name, u.username, k.card_type, k.rarity, k.reference_price,
           c.card_price, k.card_stage, c.card_picture, k.card_picture, k.card_element, c.card_description
    FROM CARDS c
    JOIN CARD_CATALOG k ON k.catalog_id = c.catalog_id
    JOIN USERS u ON u.user_id = c.seller_id
    """;

// All listings, newest first. With ?seller=username, only that seller's.
app.MapGet("/api/listings", async (string? seller, HttpRequest request, IConfiguration config, ILogger<Program> logger) =>
{
    try
    {
        await using var connection = new SqlConnection(config.GetConnectionString("DefaultConnection"));
        await connection.OpenAsync();

        await using var command = new SqlCommand(
            $"{ListingSelect} WHERE @seller IS NULL OR u.username = @seller ORDER BY c.card_id DESC",
            connection);
        command.Parameters.Add("@seller", System.Data.SqlDbType.NVarChar, 50).Value =
            string.IsNullOrWhiteSpace(seller) ? DBNull.Value : seller.Trim();

        var listings = new List<CardListing>();
        await using var reader = await command.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            listings.Add(ReadListing(reader, request));
        }
        return Results.Ok(listings);
    }
    catch (SqlException ex)
    {
        logger.LogError(ex, "Loading listings failed because of a database error");
        return Results.Problem("Cannot connect to the database", statusCode: StatusCodes.Status503ServiceUnavailable);
    }
})
.RequireAuthorization()
.WithName("GetListings");

app.MapGet("/api/listings/{cardId:int}", async (int cardId, HttpRequest request, IConfiguration config, ILogger<Program> logger) =>
{
    try
    {
        await using var connection = new SqlConnection(config.GetConnectionString("DefaultConnection"));
        await connection.OpenAsync();
        var listing = await LoadListingAsync(connection, cardId, request);
        return listing is null ? Results.NotFound(new { message = "This card is not for sale" }) : Results.Ok(listing);
    }
    catch (SqlException ex)
    {
        logger.LogError(ex, "Loading a listing failed because of a database error");
        return Results.Problem("Cannot connect to the database", statusCode: StatusCodes.Status503ServiceUnavailable);
    }
})
.RequireAuthorization()
.WithName("GetListing");

// Lists a catalog card for sale. multipart/form-data: catalogId, cardPrice, cardDescription (optional), photo (optional).
// The form is read by hand, so no antiforgery token is involved; the SameSite=Strict session cookie already
// keeps other sites from posting here.
app.MapPost("/api/listings", async (HttpRequest request, ClaimsPrincipal principal, IWebHostEnvironment env, IConfiguration config, ILogger<Program> logger) =>
{
    if (!int.TryParse(principal.FindFirstValue(ClaimTypes.NameIdentifier), out var sellerId))
    {
        return Results.Unauthorized();
    }
    if (!request.HasFormContentType)
    {
        return Results.BadRequest(new { message = "Send the card as a form" });
    }

    var form = await request.ReadFormAsync();
    var description = form["cardDescription"].ToString().Trim();
    var photo = form.Files.GetFile("photo");

    var hasCatalogId = int.TryParse(form["catalogId"], out var catalogId);
    var priceError = ListingPriceError(form["cardPrice"], out var price);
    var validationError =
        !hasCatalogId ? "Please choose a card from the catalog"
        : priceError is not null ? priceError
        : description.Length > MaxDescriptionLength ? $"Description must be {MaxDescriptionLength} characters or fewer"
        : photo is not null ? await PictureErrorAsync(photo)
        : null;
    if (validationError is not null)
    {
        return Results.BadRequest(new { message = validationError });
    }

    string? photoPath = null;
    try
    {
        await using var connection = new SqlConnection(config.GetConnectionString("DefaultConnection"));
        await connection.OpenAsync();

        // Only catalog cards can be sold.
        await using (var exists = new SqlCommand("SELECT 1 FROM CARD_CATALOG WHERE catalog_id = @catalogId", connection))
        {
            exists.Parameters.AddWithValue("@catalogId", catalogId);
            if (await exists.ExecuteScalarAsync() is null)
            {
                return Results.BadRequest(new { message = "This card is not in the catalog" });
            }
        }

        if (photo is not null)
        {
            photoPath = await SavePictureAsync(photo, env);
        }

        await using var command = new SqlCommand(
            """
            INSERT INTO CARDS (seller_id, catalog_id, card_price, card_picture, card_description)
            OUTPUT INSERTED.card_id
            VALUES (@sellerId, @catalogId, @price, @picture, @description)
            """,
            connection);
        command.Parameters.AddWithValue("@sellerId", sellerId);
        command.Parameters.AddWithValue("@catalogId", catalogId);
        command.Parameters.Add("@price", System.Data.SqlDbType.Decimal).Value = price;
        command.Parameters["@price"].Precision = 12;
        command.Parameters["@price"].Scale = 2;
        command.Parameters.AddWithValue("@picture", (object?)photoPath ?? DBNull.Value);
        command.Parameters.AddWithValue("@description", description.Length == 0 ? DBNull.Value : description);

        var cardId = (int)(await command.ExecuteScalarAsync())!;
        var listing = await LoadListingAsync(connection, cardId, request);
        return Results.Created($"/api/listings/{cardId}", listing);
    }
    catch (SqlException ex)
    {
        DeletePicture(photoPath, env);
        logger.LogError(ex, "Adding a listing failed because of a database error");
        return Results.Problem("Cannot connect to the database", statusCode: StatusCodes.Status503ServiceUnavailable);
    }
})
.RequireAuthorization()
.WithName("AddListing");

// Changes the price and description of the logged-in user's own listing.
app.MapPut("/api/listings/{cardId:int}", async (int cardId, UpdateListingRequest body, HttpRequest request, ClaimsPrincipal principal, IConfiguration config, ILogger<Program> logger) =>
{
    if (!int.TryParse(principal.FindFirstValue(ClaimTypes.NameIdentifier), out var sellerId))
    {
        return Results.Unauthorized();
    }

    var description = body.CardDescription?.Trim() ?? "";
    var priceError = ListingPriceError(body.CardPrice?.ToString(System.Globalization.CultureInfo.InvariantCulture), out var price);
    var validationError =
        priceError is not null ? priceError
        : description.Length > MaxDescriptionLength ? $"Description must be {MaxDescriptionLength} characters or fewer"
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
            UPDATE CARDS SET card_price = @price, card_description = @description
            WHERE card_id = @cardId AND seller_id = @sellerId
            """,
            connection);
        command.Parameters.AddWithValue("@cardId", cardId);
        command.Parameters.AddWithValue("@sellerId", sellerId);
        command.Parameters.Add("@price", System.Data.SqlDbType.Decimal).Value = price;
        command.Parameters["@price"].Precision = 12;
        command.Parameters["@price"].Scale = 2;
        command.Parameters.AddWithValue("@description", description.Length == 0 ? DBNull.Value : description);

        // Someone else's listing looks the same as a missing one.
        return await command.ExecuteNonQueryAsync() == 0
            ? Results.NotFound(new { message = "You have no such card for sale" })
            : Results.Ok(await LoadListingAsync(connection, cardId, request));
    }
    catch (SqlException ex)
    {
        logger.LogError(ex, "Updating a listing failed because of a database error");
        return Results.Problem("Cannot connect to the database", statusCode: StatusCodes.Status503ServiceUnavailable);
    }
})
.RequireAuthorization()
.WithName("UpdateListing");

// Removes the logged-in user's own listing, unless someone has already ordered it.
app.MapDelete("/api/listings/{cardId:int}", async (int cardId, ClaimsPrincipal principal, IWebHostEnvironment env, IConfiguration config, ILogger<Program> logger) =>
{
    if (!int.TryParse(principal.FindFirstValue(ClaimTypes.NameIdentifier), out var sellerId))
    {
        return Results.Unauthorized();
    }

    try
    {
        await using var connection = new SqlConnection(config.GetConnectionString("DefaultConnection"));
        await connection.OpenAsync();

        await using var command = new SqlCommand(
            "DELETE FROM CARDS OUTPUT DELETED.card_picture WHERE card_id = @cardId AND seller_id = @sellerId",
            connection);
        command.Parameters.AddWithValue("@cardId", cardId);
        command.Parameters.AddWithValue("@sellerId", sellerId);

        await using var reader = await command.ExecuteReaderAsync();
        if (!await reader.ReadAsync())
        {
            return Results.NotFound(new { message = "You have no such card for sale" });
        }
        DeletePicture(reader.IsDBNull(0) ? null : reader.GetString(0), env);
        return Results.NoContent();
    }
    catch (SqlException ex) when (ex.Number == 547) // an order refers to this card
    {
        return Results.Conflict(new { message = "Someone has ordered this card, so it cannot be removed" });
    }
    catch (SqlException ex)
    {
        logger.LogError(ex, "Removing a listing failed because of a database error");
        return Results.Problem("Cannot connect to the database", statusCode: StatusCodes.Status503ServiceUnavailable);
    }
})
.RequireAuthorization()
.WithName("DeleteListing");

app.Run();

// A listing joined with its catalog card and seller. card_picture is the seller's photo, or the catalog picture without one.
static async Task<CardListing?> LoadListingAsync(SqlConnection connection, int cardId, HttpRequest request)
{
    await using var command = new SqlCommand($"{ListingSelect} WHERE c.card_id = @cardId", connection);
    command.Parameters.AddWithValue("@cardId", cardId);
    await using var reader = await command.ExecuteReaderAsync();
    return await reader.ReadAsync() ? ReadListing(reader, request) : null;
}

static CardListing ReadListing(SqlDataReader reader, HttpRequest request)
{
    string? Text(int i) => reader.IsDBNull(i) ? null : reader.GetString(i);
    // Uploaded photos are stored as a path on this API; the browser needs the full address.
    var photo = Text(9);
    var picture = photo is null ? Text(10) : $"{request.Scheme}://{request.Host}{photo}";
    return new CardListing(
        reader.GetInt32(0),
        reader.GetInt32(1),
        reader.GetString(2),
        reader.GetString(3),
        reader.GetString(4),
        reader.GetString(5),
        reader.IsDBNull(6) ? null : reader.GetDecimal(6),
        reader.GetDecimal(7),
        Text(8),
        Text(11),
        picture,
        Text(12));
}

// The price must be a whole number of baht from 1 to the largest that fits DECIMAL(12,2).
static string? ListingPriceError(string? value, out decimal price)
{
    if (!decimal.TryParse(value, System.Globalization.NumberStyles.Number, System.Globalization.CultureInfo.InvariantCulture, out price))
    {
        return "Please enter your price";
    }
    return price is < 1 or > 9_999_999_999 || price != decimal.Truncate(price)
        ? "Price must be a whole number from 1 to 9,999,999,999"
        : null;
}

// JPG, PNG or WebP up to 5 MB, checked by the file's first bytes rather than the name the browser sent.
static async Task<string?> PictureErrorAsync(IFormFile file)
{
    if (file.Length == 0 || file.Length > MaxPictureBytes)
    {
        return "The picture must be 5 MB or smaller";
    }
    return await PictureExtensionAsync(file) is null ? "Please choose a JPG, PNG or WebP picture" : null;
}

static async Task<string?> PictureExtensionAsync(IFormFile file)
{
    var head = new byte[12];
    await using var stream = file.OpenReadStream();
    var read = await stream.ReadAtLeastAsync(head, head.Length, throwOnEndOfStream: false);
    if (read >= 3 && head[0] == 0xFF && head[1] == 0xD8 && head[2] == 0xFF) return ".jpg";
    if (read >= 8 && head.AsSpan(0, 8).SequenceEqual(new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A })) return ".png";
    if (read >= 12 && head.AsSpan(0, 4).SequenceEqual("RIFF"u8) && head.AsSpan(8, 4).SequenceEqual("WEBP"u8)) return ".webp";
    return null;
}

// Saves an uploaded picture under uploads/listings with a random name and returns its path on this API.
static async Task<string> SavePictureAsync(IFormFile file, IWebHostEnvironment env)
{
    var extension = await PictureExtensionAsync(file) ?? throw new InvalidOperationException("Not a picture");
    var folder = Path.Combine(env.ContentRootPath, UploadsFolder, "listings");
    Directory.CreateDirectory(folder);
    var name = $"{Guid.NewGuid():N}{extension}";
    await using (var output = File.Create(Path.Combine(folder, name)))
    {
        await file.CopyToAsync(output);
    }
    return $"/{UploadsFolder}/listings/{name}";
}

static void DeletePicture(string? path, IWebHostEnvironment env)
{
    if (path is null || !path.StartsWith($"/{UploadsFolder}/listings/", StringComparison.Ordinal))
    {
        return;
    }
    var file = Path.Combine(env.ContentRootPath, UploadsFolder, "listings", Path.GetFileName(path));
    if (File.Exists(file))
    {
        File.Delete(file);
    }
}

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

// One listing as the pages show it. CardPicture is the seller's photo, or the catalog picture without one.
record CardListing(
    int CardId,
    int CatalogId,
    string CardName,
    string SellerName,
    string CardType,
    string Rarity,
    decimal? ReferencePrice,
    decimal CardPrice,
    string? CardStage,
    string? CardElement,
    string? CardPicture,
    string? CardDescription);

record UpdateListingRequest(decimal? CardPrice, string? CardDescription);

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
