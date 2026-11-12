using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace Trowser.Laws;

/// <summary>
/// Semantic allowlist for Law files. Every symbol and expression type a Law touches must come from
/// a small set of pure, read-only BCL types or the Law fact API. The syntactic
/// <see cref="LawBannedApiChecker"/> gives friendlier messages; this is the actual boundary.
/// </summary>
internal static class LawSandbox
{
    private static readonly HashSet<string> AllowedNamespaces = new(StringComparer.Ordinal)
    {
        "System.Linq",
        "System.Collections",
        "System.Collections.Generic",
        "System.Text.RegularExpressions",
        "System.Globalization",
    };

    /// <summary>Types in <c>System</c> (by <see cref="ISymbol.Name"/>, arity ignored).</summary>
    private static readonly HashSet<string> AllowedSystemTypes = new(StringComparer.Ordinal)
    {
        "Object", "String", "Char", "Boolean", "Byte", "SByte", "Int16", "UInt16", "Int32", "UInt32",
        "Int64", "UInt64", "Single", "Double", "Decimal", "Half", "Void", "ValueType", "Enum",
        "Math", "MathF", "Convert", "MidpointRounding",
        "DateTime", "DateTimeOffset", "DateTimeKind", "TimeSpan", "DateOnly", "TimeOnly", "DayOfWeek",
        "Guid", "Uri", "UriKind", "UriPartial", "UriComponents", "UriFormat", "Version",
        "StringComparison", "StringComparer", "StringSplitOptions", "FormattableString",
        "Array", "Nullable", "Index", "Range", "Span", "ReadOnlySpan",
        "Func", "Action", "Predicate", "Comparison", "Tuple", "ValueTuple",
        "IComparable", "IEquatable", "IFormattable", "IFormatProvider", "IDisposable",
    };

    private static readonly HashSet<string> AllowedQualifiedTypes = new(StringComparer.Ordinal)
    {
        "System.Text.StringBuilder",
        "System.Text.Json.JsonDocument",
        "System.Text.Json.JsonElement",
        "System.Text.Json.JsonElement.ArrayEnumerator",
        "System.Text.Json.JsonElement.ObjectEnumerator",
        "System.Text.Json.JsonProperty",
        "System.Text.Json.JsonValueKind",
        "System.Text.Json.JsonException",
        "System.Text.Json.JsonDocumentOptions",
        "Trowser.Laws.LawDeclarationContext",
        "Trowser.Laws.LawBuilder",
        "Trowser.Laws.PageFacts",
        "Trowser.Laws.ResponseFacts",
        "Trowser.Laws.JsonFacts",
        "Trowser.Laws.ConsoleFacts",
        "Trowser.Laws.LawNumberExtensions",
        "Trowser.Laws.LawCostClass",
        "Trowser.Automation.NetworkEntry",
        "Trowser.Automation.ConsoleEntry",
        "Trowser.Automation.ConsoleLevel",
        "Trowser.Security.Severity",
    };

    /// <summary>Types a Law may hold as values (e.g. <c>await CheckLaws()</c>) but whose members it may not call.</summary>
    private static readonly HashSet<string> ValueOnlyTypes = new(StringComparer.Ordinal)
    {
        "System.Threading.Tasks.Task",
        "System.Threading.Tasks.Task`1",
    };

    private static readonly HashSet<string> BannedMembers = new(StringComparer.Ordinal)
    {
        "System.Object.GetType",
    };

    public static IReadOnlyList<string> FindViolations(Compilation compilation)
    {
        var violations = new List<string>();
        foreach (var tree in compilation.SyntaxTrees)
        {
            var root = tree.GetRoot();
            if (root is CompilationUnitSyntax cu)
            {
                if (cu.GetReferenceDirectives().Count > 0)
                    violations.Add("#r directives are not allowed in Law files.");
                if (cu.GetLoadDirectives().Count > 0)
                    violations.Add("#load directives are not allowed in Law files.");
            }

            var model = compilation.GetSemanticModel(tree);
            foreach (var node in root.DescendantNodes())
            {
                switch (node)
                {
                    case SimpleNameSyntax or BaseObjectCreationExpressionSyntax or ElementAccessExpressionSyntax:
                    {
                        var info = model.GetSymbolInfo(node);
                        var sym = info.Symbol ?? info.CandidateSymbols.FirstOrDefault();
                        if (sym != null && !IsSymbolAllowed(sym, out var why))
                            violations.Add($"Not allowed in Law files: {Describe(sym)}{why} ({Location(node)})");
                        break;
                    }
                }

                if (node is ExpressionSyntax expr and not LambdaExpressionSyntax)
                {
                    var type = model.GetTypeInfo(expr).Type;
                    if (type != null && !IsTypeAllowed(type, valueUse: true))
                        violations.Add($"Not allowed in Law files: values of type {type.ToDisplayString()} ({Location(node)})");
                }
            }
        }

        return violations.Distinct(StringComparer.Ordinal).Take(20).ToList();
    }

    private static string Location(SyntaxNode node)
    {
        var span = node.GetLocation().GetLineSpan().StartLinePosition;
        return $"line {span.Line + 1}";
    }

    private static string Describe(ISymbol sym) =>
        sym switch
        {
            ITypeSymbol t => t.ToDisplayString(),
            _ when sym.ContainingType != null => $"{sym.ContainingType.ToDisplayString()}.{sym.Name}",
            _ => sym.ToDisplayString()
        };

    private static bool IsSymbolAllowed(ISymbol sym, out string why)
    {
        why = "";
        switch (sym)
        {
            case INamespaceSymbol:
            case ILocalSymbol:
            case IParameterSymbol:
            case IRangeVariableSymbol:
            case ILabelSymbol:
            case IDiscardSymbol:
            case ITypeParameterSymbol:
                return true;
            case IAliasSymbol alias:
                return IsSymbolAllowed(alias.Target, out why);
            case ITypeSymbol type:
                return IsTypeAllowed(type, valueUse: false);
        }

        if (IsDefinedInSource(sym))
            return true;

        var method = sym as IMethodSymbol;
        if (method is { ReducedFrom: not null })
            method = method.ReducedFrom;
        var owner = (method ?? sym).ContainingType;
        if (owner == null)
            return false;

        var memberKey = $"{FullName(owner.OriginalDefinition)}.{sym.Name}";
        if (BannedMembers.Contains(memberKey))
        {
            why = " (reflection)";
            return false;
        }

        if (ValueOnlyTypes.Contains(FullName(owner.OriginalDefinition)))
            return false;

        if (!IsTypeAllowed(owner, valueUse: false))
            return false;

        if (method != null)
        {
            foreach (var ta in method.TypeArguments)
                if (!IsTypeAllowed(ta, valueUse: true))
                    return false;
        }

        return true;
    }

    private static bool IsTypeAllowed(ITypeSymbol type, bool valueUse)
    {
        switch (type)
        {
            case IErrorTypeSymbol:
            case ITypeParameterSymbol:
                return true;
            case IDynamicTypeSymbol:
            case IPointerTypeSymbol:
            case IFunctionPointerTypeSymbol:
                return false;
            case IArrayTypeSymbol arr:
                return IsTypeAllowed(arr.ElementType, valueUse);
        }

        if (type is not INamedTypeSymbol named)
            return false;

        if (named.IsAnonymousType || named.IsTupleType && named.TupleElements.All(e => IsTypeAllowed(e.Type, valueUse)))
            return true;

        if (IsDefinedInSource(named))
            return true;

        foreach (var ta in named.TypeArguments)
            if (!IsTypeAllowed(ta, valueUse))
                return false;

        var def = named.OriginalDefinition;
        var full = FullName(def);
        if (AllowedQualifiedTypes.Contains(full))
            return true;
        if (valueUse && ValueOnlyTypes.Contains(full))
            return true;

        var ns = def.ContainingNamespace?.ToDisplayString() ?? "";
        if (def.ContainingType != null)
            return IsTypeAllowed(def.ContainingType, valueUse) && ns.StartsWith("System", StringComparison.Ordinal);
        if (AllowedNamespaces.Contains(ns))
            return true;
        if (ns == "System")
            return AllowedSystemTypes.Contains(def.Name) || def.Name.EndsWith("Exception", StringComparison.Ordinal);
        return false;
    }

    private static string FullName(INamedTypeSymbol type)
    {
        var name = type.Arity > 0 ? $"{type.Name}`{type.Arity}" : type.Name;
        if (type.ContainingType != null)
            return FullName(type.ContainingType) + "." + name;
        var ns = type.ContainingNamespace?.ToDisplayString();
        return string.IsNullOrEmpty(ns) || type.ContainingNamespace!.IsGlobalNamespace ? name : $"{ns}.{name}";
    }

    private static bool IsDefinedInSource(ISymbol sym) =>
        sym.Locations.Any(l => l.IsInSource);
}
