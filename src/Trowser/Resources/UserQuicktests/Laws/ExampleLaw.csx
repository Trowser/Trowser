// @title Example user Law
// @shadow light
// @effects none

// Copy and edit under Documents\Trowser Quicktests\Laws\ — files here reload on save.
// Laws are pure checks: they read page/response/console facts and never act on the page.
// Uncomment and adapt the examples below to your app (Site() scopes every Law after it to a host).

Law("Example: page has a main heading")
    .OnPage("*")
    .When((PageFacts p) => p.Exists("body"))
    .Expect((PageFacts p) => p.Count("h1") >= 1)
    .Severity(Severity.Info);

// Site("shop.example.com");
//
// // Business arithmetic: the cart total equals the sum of its line totals.
// Law("Cart total equals sum of lines")
//     .OnPage("/cart*")
//     .When((PageFacts p) => p.Count(".cart-line") > 0)
//     .Expect((PageFacts p) => p.Number(".cart-total").ApproxEquals(p.Numbers(".cart-line .line-total"), 0.01))
//     .Severity(Severity.High)
//     .Confirm();
//
// // State consistency: the badge count matches the number of rows.
// Law("Cart badge matches cart rows")
//     .OnPage("/cart*")
//     .Expect((PageFacts p) => p.Number(".cart-badge") == p.Count(".cart-line"));
//
// // API contract: successful order responses carry an id and non-negative total.
// Law("Order API returns id and total")
//     .OnResponse("POST /api/orders*")
//     .When((ResponseFacts r) => r.Status >= 200 && r.Status < 300)
//     .Expect((ResponseFacts r) => r.Json.HasValue("id") && r.Json.Number("total") >= 0);
//
// // Array contract: every item in a list response has a price.
// Law("Product list items all have a price")
//     .OnResponse("GET /api/products*")
//     .When((ResponseFacts r) => r.Status == 200 && r.Json.IsValid)
//     .Expect((ResponseFacts r) => r.Json.Numbers("items", "price").Count == r.Json.Count("items"));
//
// // Session cookies are hardened.
// Law("Session cookie is HttpOnly")
//     .OnResponse("*")
//     .When((ResponseFacts r) => r.Cookie("session") != null)
//     .Expect((ResponseFacts r) => (r.Header("Set-Cookie") ?? "").Contains("HttpOnly", StringComparison.OrdinalIgnoreCase));
//
// // Heavy checks run only in Shadow Heavy (POST /api/shadow/check), e.g. after a scripted flow.
// Law("Logged-in pages show the user menu")
//     .OnAction()
//     .When((PageFacts p) => p.Exists("[data-logged-in]"))
//     .Expect((PageFacts p) => p.Visible("#user-menu"));

await CheckLaws();
