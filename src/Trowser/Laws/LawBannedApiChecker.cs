using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace Trowser.Laws;

internal static class LawBannedApiChecker
{
    private static readonly string[] BannedPrefixes =
    [
        "System.IO",
        "System.Diagnostics.Process",
        "System.Net.Http",
        "System.Net",
        "System.Net.Sockets",
        "System.Reflection",
        "System.Runtime.InteropServices",
        "System.Linq.Expressions",
        "Microsoft.Web.WebView2"
    ];

    private static readonly HashSet<string> BannedTypeNames = new(StringComparer.Ordinal)
    {
        "HttpClient",
        "WebClient",
        "WebRequest",
        "HttpWebRequest",
        "SocketsHttpHandler",
        "TcpClient",
        "UdpClient",
        "Socket",
        "NetworkStream",
        "Task",
        "Thread",
        "Environment",
        "AppDomain",
        "Activator",
        "Assembly",
        "Marshal",
        "RuntimeHelpers",
        "GC"
    };

    private static readonly HashSet<string> BannedMemberNames = new(StringComparer.Ordinal)
    {
        "Exit",
        "GetEnvironmentVariable",
        "GetEnvironmentVariables",
        "Run",
        "Sleep",
        "Start",
        "Load",
        "CreateInstance",
        "GetType",
        "Invoke",
        "GetMethod",
        "GetConstructor",
        "GetProperty",
        "GetField",
        "DefineDynamicAssembly",
        "Collect",
        "Compile"
    };

    private static readonly string[] BannedAssemblyNameFragments =
    [
        "System.Net",
        "System.Net.Http",
        "System.Net.Sockets",
        "System.Web",
        "System.Data"
    ];

    public static IReadOnlyList<string> FindViolations(string code)
    {
        var tree = CSharpSyntaxTree.ParseText(code, new CSharpParseOptions(kind: SourceCodeKind.Script));
        var root = tree.GetRoot();
        var violations = new List<string>();
        foreach (var node in root.DescendantNodes())
        {
            switch (node)
            {
                case UsingDirectiveSyntax u when u.Name != null:
                    CheckName(u.Name.ToString(), violations);
                    break;
                case MemberAccessExpressionSyntax m:
                    CheckName(m.ToString(), violations);
                    CheckMemberAccess(m, violations);
                    break;
                case IdentifierNameSyntax id:
                    if (id.Identifier.Text is "Navigate" or "Click" or "Type" or "Fetch")
                        violations.Add($"Automation action '{id.Identifier.Text}' is not allowed in Law files.");
                    else if (BannedTypeNames.Contains(id.Identifier.Text))
                        violations.Add($"Banned type or namespace in Law files: {id.Identifier.Text}");
                    else if (id.Identifier.Text == "dynamic")
                        violations.Add("The dynamic keyword is not allowed in Law files.");
                    break;
                case ObjectCreationExpressionSyntax obj:
                    CheckTypeSyntax(obj.Type, violations);
                    break;
                case VariableDeclarationSyntax v:
                    CheckTypeSyntax(v.Type, violations);
                    break;
                case WhileStatementSyntax w when IsInfiniteLoop(w.Condition):
                    violations.Add("Unbounded while(true) loops are not allowed in Law files.");
                    break;
                case ForStatementSyntax f when f.Condition == null && f.Incrementors.Count == 0:
                    violations.Add("Unbounded for(;;) loops are not allowed in Law files.");
                    break;
                case InvocationExpressionSyntax inv:
                    CheckInvocation(inv, violations);
                    break;
            }
        }

        return violations.Distinct(StringComparer.Ordinal).ToList();
    }

    private static void CheckTypeSyntax(TypeSyntax? type, List<string> violations)
    {
        if (type == null)
            return;
        var text = type.ToString();
        if (text.Equals("dynamic", StringComparison.Ordinal))
            violations.Add("The dynamic keyword is not allowed in Law files.");
        if (type is IdentifierNameSyntax id && BannedTypeNames.Contains(id.Identifier.Text))
            violations.Add($"Banned type in Law files: {id.Identifier.Text}");
    }

    private static bool IsInfiniteLoop(ExpressionSyntax? condition)
    {
        if (condition is LiteralExpressionSyntax lit && lit.IsKind(SyntaxKind.TrueLiteralExpression))
            return true;
        return condition?.ToString() is "true" or "1";
    }

    private static void CheckInvocation(InvocationExpressionSyntax inv, List<string> violations)
    {
        var expr = inv.Expression.ToString();
        if (expr.Contains("CreateInstance", StringComparison.Ordinal)
            || expr.Contains("GetType", StringComparison.Ordinal)
            || expr.EndsWith(".Invoke", StringComparison.Ordinal)
            || expr.EndsWith(".Load", StringComparison.Ordinal)
            || expr.EndsWith(".Compile", StringComparison.Ordinal))
            violations.Add($"Banned reflective or dynamic loading API in Law files: {expr}");

        if (!expr.EndsWith(".Load", StringComparison.Ordinal)
            && !expr.Contains("LoadFrom", StringComparison.Ordinal))
            return;

        foreach (var arg in inv.ArgumentList.Arguments)
        {
            if (arg.Expression is not LiteralExpressionSyntax lit
                || !lit.IsKind(SyntaxKind.StringLiteralExpression))
                continue;
            var name = lit.Token.ValueText;
            foreach (var fragment in BannedAssemblyNameFragments)
            {
                if (name.Contains(fragment, StringComparison.OrdinalIgnoreCase))
                    violations.Add($"Banned assembly load in Law files: {name}");
            }
        }
    }

    private static void CheckMemberAccess(MemberAccessExpressionSyntax m, List<string> violations)
    {
        var member = m.Name.Identifier.Text;
        if (!BannedMemberNames.Contains(member))
            return;

        var expr = m.Expression.ToString();
        if (member is "Load" or "DefineDynamicAssembly")
        {
            if (expr.Contains("AppDomain", StringComparison.Ordinal)
                || expr.Contains("Assembly", StringComparison.Ordinal))
                violations.Add($"Banned API in Law files: {expr}.{member}");
            return;
        }

        if (member is "CreateInstance" or "GetType" or "Invoke"
            or "GetMethod" or "GetConstructor" or "GetProperty" or "GetField" or "Compile")
        {
            violations.Add($"Banned reflective API in Law files: {expr}.{member}");
            return;
        }

        if (member == "Collect" && expr.Equals("GC", StringComparison.Ordinal))
        {
            violations.Add("GC.Collect is not allowed in Law files.");
            return;
        }

        if (expr.Equals("Environment", StringComparison.Ordinal)
            || expr.Equals("Task", StringComparison.Ordinal)
            || expr.Equals("Thread", StringComparison.Ordinal)
            || expr.EndsWith(".Process", StringComparison.Ordinal))
            violations.Add($"Banned API in Law files: {expr}.{member}");
    }

    private static void CheckName(string name, List<string> violations)
    {
        if (name.StartsWith("global::", StringComparison.Ordinal))
            name = name["global::".Length..];
        foreach (var prefix in BannedPrefixes)
        {
            if (name.StartsWith(prefix, StringComparison.Ordinal))
            {
                violations.Add($"Banned API namespace or type: {name}");
                return;
            }
        }
    }
}
