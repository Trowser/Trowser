namespace Trowser.Automation;

/// <summary>
/// Prepares user JavaScript for <see cref="AutomationContext.ExecuteJs"/>.
/// WebView2 evaluates scripts as expressions; statement bodies and top-level
/// <c>return</c> must be wrapped in an IIFE first. When wrapping, the last
/// expression-like statement is auto-returned so callers get a result without
/// needing an explicit <c>return</c>.
/// </summary>
internal static class ExecuteJsScriptPrep
{
    /// <summary>
    /// Wrap the script in an IIFE when it is not a single expression and not already wrapped.
    /// The last expression-like statement in multi-statement scripts is auto-returned.
    /// </summary>
    public static string Prepare(string script)
    {
        if (string.IsNullOrWhiteSpace(script))
            return script ?? string.Empty;

        var trimmed = script.Trim();

        // Strip leading line/block comments — they can cause ASI issues
        // when RunJsAsync prepends 'return' to the expression.
        var effective = StripLeadingComments(trimmed);
        if (string.IsNullOrWhiteSpace(effective))
            return trimmed;

        if (IsAlreadyWrappedExpression(effective))
            return effective;

        if (!NeedsIifeWrapper(effective))
            return effective;

        var body = InsertReturnBeforeLastExpression(effective);
        var asyncPrefix = UsesAwait(effective) ? "async " : "";
        return $"({asyncPrefix}function(){{ {body} }})()";
    }

    /// <summary>True when the script uses <c>await</c> and must run inside an async function body.</summary>
    internal static bool UsesAwait(string script) => ContainsKeyword(script, "await");

    /// <summary>True when the script already ends with an invoked function expression.</summary>
    internal static bool IsAlreadyWrappedExpression(string trimmed)
    {
        if (!trimmed.StartsWith('('))
            return false;

        if (!(trimmed.EndsWith(")()", StringComparison.Ordinal) ||
              trimmed.EndsWith("})()", StringComparison.Ordinal)))
            return false;

        var rest = trimmed.AsSpan(1).TrimStart();
        return rest.StartsWith("function", StringComparison.Ordinal) ||
               rest.StartsWith("async ", StringComparison.Ordinal) ||
               (rest.StartsWith("(", StringComparison.Ordinal) && trimmed.Contains("=>", StringComparison.Ordinal));
    }

    /// <summary>True when the script must run as a function body, not as a bare expression.</summary>
    internal static bool NeedsIifeWrapper(string trimmed)
    {
        if (StartsWithReturnKeyword(trimmed))
            return true;

        if (ContainsKeyword(trimmed, "return"))
            return true;

        if (ContainsKeyword(trimmed, "var") ||
            ContainsKeyword(trimmed, "let") ||
            ContainsKeyword(trimmed, "const"))
            return true;

        if (ContainsKeyword(trimmed, "function") && !trimmed.StartsWith('('))
            return true;

        if (StartsWithStatementPrefix(trimmed))
            return true;

        if (ContainsInteriorSemicolon(trimmed))
            return true;

        // Trailing semicolon => statement form; bare statements fail Runtime.compileScript.
        return trimmed.EndsWith(';');
    }

    /// <summary>
    /// Strip leading line (<c>//</c>) and block (<c>/* */</c>) comments.
    /// Leading comments cause ASI issues when the script is placed after <c>return</c>
    /// in <see cref="AutomationContext.RunJsAsync"/>.
    /// </summary>
    internal static string StripLeadingComments(string s)
    {
        var i = 0;
        while (i < s.Length)
        {
            if (char.IsWhiteSpace(s[i]))
            {
                i++;
                continue;
            }

            if (i + 1 < s.Length && s[i] == '/' && s[i + 1] == '/')
            {
                var end = s.IndexOf('\n', i);
                if (end < 0)
                    return "";
                i = end + 1;
                continue;
            }

            if (i + 1 < s.Length && s[i] == '/' && s[i + 1] == '*')
            {
                var end = s.IndexOf("*/", i + 2, StringComparison.Ordinal);
                if (end < 0)
                    return "";
                i = end + 2;
                continue;
            }

            break;
        }

        return i >= s.Length ? "" : s[i..].TrimEnd();
    }

    /// <summary>
    /// Find the last expression-like top-level statement and prepend <c>return</c>.
    /// If the last statement is a declaration or control-flow keyword, no change is made
    /// (the caller should use an explicit <c>return</c>).
    /// </summary>
    internal static string InsertReturnBeforeLastExpression(string script)
    {
        var lastStart = FindLastStatementStart(script);
        var before = script[..lastStart];
        var lastStmt = script[lastStart..].TrimEnd();

        while (lastStmt.Length > 0 && lastStmt[^1] == ';')
            lastStmt = lastStmt[..^1].TrimEnd();

        if (lastStmt.Length == 0 || !IsExpressionLikeStatement(lastStmt))
            return script;

        // return (expr\n); — the parens prevent ASI after 'return' and the
        // newline before ');' keeps trailing line-comments from eating the closing.
        return before + "return (" + lastStmt + "\n);";
    }

    /// <summary>
    /// Scan the script to find the start index of the last top-level statement.
    /// Statement boundaries are top-level semicolons and closing braces followed by
    /// a new statement (not a block-continuation keyword like <c>else</c>/<c>catch</c>).
    /// </summary>
    private static int FindLastStatementStart(string script)
    {
        int bestStart = 0;
        int depth = 0;
        bool inSingle = false, inDouble = false, inTemplate = false;
        bool inLineComment = false, inBlockComment = false;

        for (int i = 0; i < script.Length; i++)
        {
            var c = script[i];

            if (inLineComment)
            {
                if (c == '\n')
                    inLineComment = false;
                continue;
            }

            if (inBlockComment)
            {
                if (c == '*' && i + 1 < script.Length && script[i + 1] == '/')
                {
                    inBlockComment = false;
                    i++;
                }
                continue;
            }

            if (!inSingle && !inDouble && !inTemplate)
            {
                if (c == '/' && i + 1 < script.Length)
                {
                    if (script[i + 1] == '/')
                    {
                        inLineComment = true;
                        i++;
                        continue;
                    }

                    if (script[i + 1] == '*')
                    {
                        inBlockComment = true;
                        i++;
                        continue;
                    }
                }
            }

            if (!inDouble && !inTemplate && c == '\'' && !IsEscaped(script, i))
                inSingle = !inSingle;
            else if (!inSingle && !inTemplate && c == '"' && !IsEscaped(script, i))
                inDouble = !inDouble;
            else if (!inSingle && !inDouble && c == '`' && !IsEscaped(script, i))
                inTemplate = !inTemplate;

            if (inSingle || inDouble || inTemplate)
                continue;

            if (c == '{' || c == '(' || c == '[')
            {
                depth++;
                continue;
            }

            if (c == '}' || c == ')' || c == ']')
            {
                if (depth > 0)
                    depth--;

                // After } returns to top level, the next identifier may start a new statement
                // (unless it's a block-continuation keyword like else/catch/finally/while).
                if (depth == 0 && c == '}')
                {
                    var next = NextNonWhitespace(script, i + 1);
                    if (next >= 0 && char.IsLetter(script[next]) && !IsBlockContinuation(script, next))
                        bestStart = next;
                }

                continue;
            }

            if (depth != 0)
                continue;

            if (c == ';')
            {
                var next = NextNonWhitespace(script, i + 1);
                if (next >= 0)
                    bestStart = next;
            }
        }

        return bestStart;
    }

    private static int NextNonWhitespace(string s, int from)
    {
        for (int i = from; i < s.Length; i++)
        {
            if (!char.IsWhiteSpace(s[i]))
                return i;
        }

        return -1;
    }

    private static readonly string[] BlockContinuationKeywords = ["else", "catch", "finally", "while"];

    private static bool IsBlockContinuation(string s, int pos)
    {
        var remaining = s.AsSpan(pos);
        foreach (var kw in BlockContinuationKeywords)
        {
            if (!remaining.StartsWith(kw.AsSpan(), StringComparison.Ordinal))
                continue;
            if (remaining.Length == kw.Length || !char.IsLetterOrDigit(remaining[kw.Length]))
                return true;
        }

        return false;
    }

    /// <summary>
    /// True when the statement looks like an expression (identifier, literal, call, member access, etc.)
    /// rather than a declaration or control-flow keyword.
    /// </summary>
    private static bool IsExpressionLikeStatement(string stmt)
    {
        var t = stmt.AsSpan().TrimStart();
        if (t.Length == 0)
            return false;

        ReadOnlySpan<string> notExpressions =
        [
            "var ", "let ", "const ",
            "function ", "function(",
            "class ",
            "if ", "if(",
            "for ", "for(",
            "while ", "while(",
            "do ", "do{",
            "switch ", "switch(",
            "try ", "try{",
            "throw ",
            "return ", "return;",
            "import ", "export "
        ];

        foreach (var prefix in notExpressions)
        {
            if (t.StartsWith(prefix.AsSpan(), StringComparison.Ordinal))
                return false;
        }

        // Bare keywords without trailing content
        if (t.SequenceEqual("return".AsSpan()) || t.SequenceEqual("debugger".AsSpan()))
            return false;

        // A bare opening brace in statement position is a block, not an object literal
        if (t[0] == '{')
            return false;

        return true;
    }

    private static bool StartsWithReturnKeyword(string s)
    {
        var t = s.AsSpan().TrimStart();
        if (!t.StartsWith("return", StringComparison.Ordinal))
            return false;
        if (t.Length == 6)
            return true;
        var next = t[6];
        return !char.IsLetterOrDigit(next) && next != '_';
    }

    private static bool StartsWithStatementPrefix(string s)
    {
        var t = s.AsSpan().TrimStart();
        ReadOnlySpan<string> prefixes =
        [
            "if(", "if ", "for(", "for ", "while(", "while ", "do ", "do{", "switch", "try", "throw ",
            "class ", "import ", "export "
        ];
        foreach (var prefix in prefixes)
        {
            if (t.StartsWith(prefix.AsSpan(), StringComparison.Ordinal))
                return true;
        }
        return false;
    }

    /// <summary>Semicolon before trailing whitespace/end implies multiple statements.</summary>
    private static bool ContainsInteriorSemicolon(string s)
    {
        var end = s.AsSpan().TrimEnd().Length;
        if (end == 0)
            return false;

        var scan = s.AsSpan(0, end);
        for (var i = 0; i < scan.Length; i++)
        {
            if (scan[i] != ';')
                continue;
            if (scan.Slice(i + 1).Trim().IsEmpty)
                return false;
            if (IsOutsideStringsAndComments(s, i))
                return true;
        }
        return false;
    }

    private static bool ContainsKeyword(string s, string keyword)
    {
        for (var i = 0; i <= s.Length - keyword.Length; i++)
        {
            if (!s.AsSpan(i, keyword.Length).Equals(keyword.AsSpan(), StringComparison.Ordinal))
                continue;
            if (i > 0 && (char.IsLetterOrDigit(s[i - 1]) || s[i - 1] == '_'))
                continue;
            var after = i + keyword.Length;
            if (after < s.Length && (char.IsLetterOrDigit(s[after]) || s[after] == '_'))
                continue;
            if (IsOutsideStringsAndComments(s, i))
                return true;
        }
        return false;
    }

    private static bool IsOutsideStringsAndComments(string s, int index)
    {
        var inSingle = false;
        var inDouble = false;
        var inTemplate = false;
        var inLineComment = false;
        var inBlockComment = false;

        for (var i = 0; i < index; i++)
        {
            var c = s[i];
            if (inLineComment)
            {
                if (c == '\n')
                    inLineComment = false;
                continue;
            }

            if (inBlockComment)
            {
                if (c == '*' && i + 1 < s.Length && s[i + 1] == '/')
                {
                    inBlockComment = false;
                    i++;
                }
                continue;
            }

            if (!inSingle && !inDouble && !inTemplate)
            {
                if (c == '/' && i + 1 < s.Length && s[i + 1] == '/')
                {
                    inLineComment = true;
                    i++;
                    continue;
                }

                if (c == '/' && i + 1 < s.Length && s[i + 1] == '*')
                {
                    inBlockComment = true;
                    i++;
                    continue;
                }
            }

            if (!inDouble && !inTemplate && c == '\'' && !IsEscaped(s, i))
                inSingle = !inSingle;
            else if (!inSingle && !inTemplate && c == '"' && !IsEscaped(s, i))
                inDouble = !inDouble;
            else if (!inSingle && !inDouble && c == '`' && !IsEscaped(s, i))
                inTemplate = !inTemplate;
        }

        return !inSingle && !inDouble && !inTemplate && !inLineComment && !inBlockComment;
    }

    private static bool IsEscaped(string s, int index)
    {
        var slashes = 0;
        for (var i = index - 1; i >= 0 && s[i] == '\\'; i--)
            slashes++;
        return (slashes & 1) == 1;
    }
}
